//go:build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// 點兩下執行檔時的互動式安裝流程。

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	shell32                   = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW       = shell32.NewProc("ShellExecuteExW")
)

// launchedByDoubleClick：從檔案總管點兩下時，主控台視窗只屬於本程式自己。
// 從 cmd / PowerShell 執行時，主控台至少還有 shell 這個行程。
func launchedByDoubleClick() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

func askYesNo(q string, def bool) bool {
	hint := "[Y/n]"
	if !def {
		hint = "[y/N]"
	}
	fmt.Printf("%s %s ", q, hint)
	switch strings.ToLower(readLine()) {
	case "":
		return def
	case "y", "yes", "是":
		return true
	default:
		return false
	}
}

func waitEnter() {
	fmt.Print("\n按 Enter 鍵關閉視窗…")
	readLine()
}

func stateText(st svc.State) string {
	switch st {
	case svc.Running:
		return "執行中"
	case svc.Stopped:
		return "已停止"
	case svc.StartPending:
		return "啟動中"
	case svc.StopPending:
		return "停止中"
	default:
		return fmt.Sprintf("狀態 %d", st)
	}
}

func openURL(url string) {
	_ = windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(url), nil, nil, windows.SW_SHOWNORMAL)
}

func interactiveSetup() {
	defer waitEnter()

	fmt.Printf("lldp4win %s\n", version)
	fmt.Println(strings.Repeat("=", 40))

	if _, err := loadPcap(); err != nil {
		fmt.Println("\n⚠ 尚未安裝 Npcap，無法送出 LLDP 封包。")
		fmt.Println("  服務仍可先安裝；Npcap 裝好後服務會自動開始送出（不需重新開機）。")
		if askYesNo("  是否開啟 Npcap 下載頁面？", true) {
			openURL("https://npcap.com/#download")
		}
	}

	exists, st, bin := serviceState()
	if !exists {
		fmt.Println("\n偵測到此電腦尚未安裝 lldp4win 服務。")
		fmt.Printf("安裝後會複製到 %s，\n並設定為開機自動啟動、每 30 秒送出一次 LLDP。\n\n", installDir())
		if !askYesNo("是否立即安裝？（需要系統管理員權限）", true) {
			fmt.Println("已取消，未做任何變更。")
			return
		}
		doPrivileged("install")
		return
	}

	fmt.Printf("\n服務已安裝：%s\n位置：%s\n", stateText(st), strings.Trim(bin, `"`))
	fmt.Println("\n請選擇：")
	fmt.Println("  [1] 更新 / 重新安裝為目前這個版本")
	fmt.Println("  [2] 移除服務")
	if st == svc.Stopped {
		fmt.Println("  [3] 啟動服務")
	} else {
		fmt.Println("  [3] 重新啟動服務")
	}
	fmt.Println("  [Enter] 離開")
	fmt.Print("> ")
	switch readLine() {
	case "1":
		doPrivileged("reinstall")
	case "2":
		if askYesNo("確定要移除 lldp4win 服務？", false) {
			doPrivileged("remove")
		}
	case "3":
		doPrivileged("restart")
	}
}

// privilegedAction 實際執行需要系統管理員權限的動作。
func privilegedAction(action string) error {
	switch action {
	case "install":
		return installService(nil)
	case "reinstall":
		_, _, bin := serviceState()
		args := serviceArgs(bin)
		if err := removeService(); err != nil {
			return err
		}
		time.Sleep(500 * time.Millisecond)
		return installService(args)
	case "remove":
		return removeService()
	case "restart":
		_ = controlService(false)
		return controlService(true)
	}
	return fmt.Errorf("未知的動作 %q", action)
}

// serviceArgs 從服務的執行路徑取出參數，讓重新安裝時保留原本的設定。
func serviceArgs(binPath string) []string {
	if binPath == "" {
		return nil
	}
	p, err := windows.UTF16PtrFromString(binPath)
	if err != nil {
		return nil
	}
	var argc int32
	argv, err := windows.CommandLineToArgv(p, &argc)
	if err != nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(argv)))
	var out []string
	for i := 1; i < int(argc); i++ {
		out = append(out, windows.UTF16PtrToString(&argv[i][0]))
	}
	return out
}

func doPrivileged(action string) {
	var err error
	if windows.GetCurrentProcessToken().IsElevated() {
		err = privilegedAction(action)
	} else {
		fmt.Println("\n正在要求系統管理員權限（請在 UAC 視窗按「是」）…")
		err = runElevated(action)
	}
	if err != nil {
		fmt.Println("\n✗ 失敗:", err)
		return
	}

	exists, st, bin := serviceState()
	switch {
	case action == "remove" && !exists:
		fmt.Println("\n✓ 服務已移除。")
	case exists:
		fmt.Printf("\n✓ 完成！服務狀態：%s（開機自動啟動）\n  位置：%s\n", stateText(st), strings.Trim(bin, `"`))
		fmt.Println("  執行紀錄可在「事件檢視器 → Windows 記錄 → 應用程式」中查看（來源 lldp4win）。")
	default:
		fmt.Println("\n✗ 動作已執行，但找不到服務，請以系統管理員身分重試。")
	}
}

type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

// runElevated 以 UAC 提升權限、隱藏視窗執行 "lldp4win __elevated <action> <結果檔>"，
// 等待完成後讀回結果。
func runElevated(action string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	result := filepath.Join(os.TempDir(), "lldp4win-"+strconv.Itoa(os.Getpid())+".txt")
	_ = os.Remove(result)
	defer os.Remove(result)

	params := fmt.Sprintf(`__elevated %s "%s"`, action, result)
	sei := shellExecuteInfo{
		fMask:        0x00000040 | 0x00000100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr(exe),
		lpParameters: windows.StringToUTF16Ptr(params),
		nShow:        windows.SW_HIDE,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	r, _, e := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return errors.New("已取消（未取得系統管理員權限）")
		}
		return fmt.Errorf("無法以系統管理員執行: %v", e)
	}
	if sei.hProcess != 0 {
		defer windows.CloseHandle(sei.hProcess)
		windows.WaitForSingleObject(sei.hProcess, 60*1000)
	}
	b, err := os.ReadFile(result)
	if err != nil {
		return errors.New("無法取得執行結果")
	}
	if msg := strings.TrimSpace(string(b)); msg != "OK" {
		return errors.New(msg)
	}
	return nil
}

// elevatedMain 是 runElevated 啟動的子行程進入點。
func elevatedMain(args []string) {
	if len(args) < 2 {
		os.Exit(2)
	}
	msg := "OK"
	if err := privilegedAction(args[0]); err != nil {
		msg = err.Error()
	}
	_ = os.WriteFile(args[1], []byte(msg), 0o644)
	if msg != "OK" {
		os.Exit(1)
	}
}
