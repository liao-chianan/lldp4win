//go:build windows

package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// 以 Windows API / 登錄檔取代原本的 wmic 呼叫。

func computerName(kind uint32) string {
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(kind, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// Hostname 回傳 DNS 主機名稱（不含網域）。
func Hostname() string {
	if h := computerName(windows.ComputerNameDnsHostname); h != "" {
		return h
	}
	return computerName(windows.ComputerNameNetBIOS)
}

// PrimaryDomain 回傳電腦的主要 DNS 尾碼（加入網域時才有值）。
func PrimaryDomain() string {
	return computerName(windows.ComputerNameDnsDomain)
}

var serverRe = regexp.MustCompile(`Windows Server \d{4}( R2)?`)

// OSDescription 產生簡短的作業系統描述，例如：
//
//	"Windows 11 25H2 x64"
//	"Windows 10 22H2 x64"
//	"Windows Server 2022 21H2 x64"
func OSDescription() string {
	v := windows.RtlGetVersion()
	var product, release string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		product, _, _ = k.GetStringValue("ProductName")
		if release, _, _ = k.GetStringValue("DisplayVersion"); release == "" {
			release, _, _ = k.GetStringValue("ReleaseId") // 舊版 Windows 10
		}
		k.Close()
	}
	return shortOSName(product, release, v.MajorVersion, v.BuildNumber, osArch())
}

// shortOSName 組出 "<系列> <版本> <架構>"；拆出來方便測試。
func shortOSName(product, release string, major, build uint32, arch string) string {
	var family string
	switch {
	case strings.Contains(product, "Server"):
		if family = serverRe.FindString(product); family == "" {
			family = "Windows Server"
		}
	case major >= 10 && build >= 22000:
		// Windows 11 的登錄檔 ProductName 仍寫 "Windows 10"，以組建號碼判斷
		family = "Windows 11"
	case major >= 10:
		family = "Windows 10"
	default:
		family = "Windows"
	}
	if release == "" {
		release = fmt.Sprintf("build %d", build)
	}
	return family + " " + release + " " + arch
}

func osArch() string {
	var info struct {
		ProcessorArchitecture uint16
		_                     [64]byte
	}
	procGetNativeSystemInfo := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNativeSystemInfo")
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&info)))
	switch info.ProcessorArchitecture {
	case 9: // PROCESSOR_ARCHITECTURE_AMD64
		return "x64"
	case 12: // PROCESSOR_ARCHITECTURE_ARM64
		return "ARM64"
	default:
		return "x86"
	}
}

// Adapter 是一張可送 LLDP 的網卡。
type Adapter struct {
	Name        string // GUID，例如 {xxxxxxxx-...}
	Device      string // \Device\NPF_{GUID}
	Description string
	Friendly    string
	MAC         net.HardwareAddr
	IfIndex     uint32
	DNSSuffix   string
	IPv4        net.IP
	IPv6        net.IP
	Virtual     bool // Hyper-V / VMware / VirtualBox / VPN 等虛擬網卡
}

// 常見虛擬網卡的描述關鍵字（小寫）
var virtualKeywords = []string{
	"hyper-v", "virtual", "vmware", "virtualbox", "vbox", "parallels", "qemu", "xen ",
	"tap-windows", "tap adapter", "wintun", "wireguard", "openvpn", "vpn", "tunnel",
	"loopback", "docker", "wsl", "zerotier", "tailscale", "npcap", "kernel debug",
	"wi-fi direct", "microsoft wi-fi direct",
}

// 常見虛擬化平台的 MAC OUI
var virtualOUIs = [][3]byte{
	{0x00, 0x15, 0x5d}, // Hyper-V
	{0x00, 0x50, 0x56}, // VMware
	{0x00, 0x0c, 0x29}, // VMware
	{0x00, 0x05, 0x69}, // VMware
	{0x08, 0x00, 0x27}, // VirtualBox
	{0x0a, 0x00, 0x27}, // VirtualBox host-only
	{0x00, 0x1c, 0x42}, // Parallels
	{0x52, 0x54, 0x00}, // QEMU/KVM
	{0x00, 0x16, 0x3e}, // Xen
}

// isVirtual 綜合「是否為硬體介面」旗標、描述文字與 MAC OUI 判斷是否為虛擬網卡。
func isVirtual(ifIndex uint32, desc, friendly string, mac net.HardwareAddr) bool {
	row := windows.MibIfRow2{InterfaceIndex: ifIndex}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row) == nil {
		if row.InterfaceAndOperStatusFlags&0x01 == 0 { // HardwareInterface 位元
			return true
		}
	}
	s := strings.ToLower(desc + " | " + friendly)
	for _, k := range virtualKeywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	if len(mac) >= 3 {
		for _, o := range virtualOUIs {
			if mac[0] == o[0] && mac[1] == o[1] && mac[2] == o[2] {
				return true
			}
		}
	}
	return false
}

func adapterAddresses() ([]byte, error) {
	size := uint32(16 * 1024)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			return buf, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer too small")
}

// Adapters 列出已連線、具有乙太網路 MAC 的實體網卡。
func Adapters() ([]Adapter, error) {
	buf, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.PhysicalAddressLength != 6 {
			continue
		}
		if a.IfType != windows.IF_TYPE_ETHERNET_CSMACD && a.IfType != windows.IF_TYPE_IEEE80211 {
			continue
		}
		ad := Adapter{
			Name:        windows.BytePtrToString(a.AdapterName),
			Description: windows.UTF16PtrToString(a.Description),
			Friendly:    windows.UTF16PtrToString(a.FriendlyName),
			MAC:         append(net.HardwareAddr(nil), a.PhysicalAddress[:6]...),
			IfIndex:     a.IfIndex,
			DNSSuffix:   windows.UTF16PtrToString(a.DnsSuffix),
		}
		ad.Device = `\Device\NPF_` + ad.Name
		ad.Virtual = isVirtual(ad.IfIndex, ad.Description, ad.Friendly, ad.MAC)
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			ip := u.Address.IP()
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if ad.IPv4 == nil && !ip4.IsLinkLocalUnicast() && !ip4.IsUnspecified() {
					ad.IPv4 = ip4
				}
			} else if ad.IPv6 == nil && ip.IsGlobalUnicast() {
				ad.IPv6 = ip
			}
		}
		out = append(out, ad)
	}
	return out, nil
}
