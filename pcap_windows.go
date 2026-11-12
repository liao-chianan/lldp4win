//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 動態載入 Npcap（或舊版 WinPcap）的 wpcap.dll，不需要 cgo 也不需要 SDK。

const pcapErrbufSize = 256

type pcapLib struct {
	openLive   uintptr
	sendPacket uintptr
	close      uintptr
	getErr     uintptr
	libVersion uintptr
}

var (
	pcapOnce sync.Mutex
	pcap     *pcapLib
)

func loadPcap() (*pcapLib, error) {
	pcapOnce.Lock()
	defer pcapOnce.Unlock()
	if pcap != nil {
		return pcap, nil
	}

	var h windows.Handle
	var err error
	// 1) Npcap 預設安裝位置：%SystemRoot%\System32\Npcap\wpcap.dll
	if sysDir, e := windows.GetSystemDirectory(); e == nil {
		p := filepath.Join(sysDir, "Npcap", "wpcap.dll")
		h, err = windows.LoadLibraryEx(p, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
	}
	// 2) Npcap「WinPcap 相容模式」或舊版 WinPcap
	if h == 0 {
		h, err = windows.LoadLibraryEx("wpcap.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	}
	if h == 0 {
		return nil, fmt.Errorf("找不到 wpcap.dll，請先安裝 Npcap (https://npcap.com/): %w", err)
	}

	l := &pcapLib{}
	for name, dst := range map[string]*uintptr{
		"pcap_open_live":   &l.openLive,
		"pcap_sendpacket":  &l.sendPacket,
		"pcap_close":       &l.close,
		"pcap_geterr":      &l.getErr,
		"pcap_lib_version": &l.libVersion,
	} {
		p, e := windows.GetProcAddress(h, name)
		if e != nil {
			windows.FreeLibrary(h)
			return nil, fmt.Errorf("wpcap.dll 缺少 %s: %w", name, e)
		}
		*dst = p
	}
	pcap = l
	return l, nil
}

func cString(p uintptr) string {
	if p == 0 {
		return ""
	}
	// p 指向 wpcap.dll 內部（非 Go 管理）的 C 字串
	return windows.BytePtrToString(*(**byte)(unsafe.Pointer(&p)))
}

func (l *pcapLib) Version() string {
	r, _, _ := syscall.SyscallN(l.libVersion)
	return cString(r)
}

// Send 開啟指定網卡並送出一個訊框。device 例如 \Device\NPF_{GUID}。
func (l *pcapLib) Send(device string, frame []byte) error {
	if len(frame) == 0 {
		return errors.New("empty frame")
	}
	dev, err := windows.BytePtrFromString(device)
	if err != nil {
		return err
	}
	errbuf := make([]byte, pcapErrbufSize)
	h, _, _ := syscall.SyscallN(l.openLive,
		uintptr(unsafe.Pointer(dev)),
		100, // snaplen
		0,   // promisc
		1000,
		uintptr(unsafe.Pointer(&errbuf[0])))
	if h == 0 {
		return fmt.Errorf("pcap_open_live(%s): %s", device, windows.ByteSliceToString(errbuf))
	}
	defer syscall.SyscallN(l.close, h)

	r, _, _ := syscall.SyscallN(l.sendPacket, h,
		uintptr(unsafe.Pointer(&frame[0])),
		uintptr(len(frame)))
	if int32(r) != 0 {
		e, _, _ := syscall.SyscallN(l.getErr, h)
		return fmt.Errorf("pcap_sendpacket: %s", cString(e))
	}
	return nil
}
