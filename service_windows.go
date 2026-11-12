//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// eventWriter 讓 log.Logger 寫到 Windows 事件檢視器（應用程式記錄）。
type eventWriter struct{ el *eventlog.Log }

func (w eventWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "失敗") || strings.Contains(msg, "找不到") || strings.Contains(msg, "沒有可用") {
		w.el.Warning(2, msg)
	} else {
		w.el.Info(1, msg)
	}
	return len(p), nil
}

type beaconService struct{ cfg *Config }

func (s *beaconService) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	var lg *log.Logger
	if el, err := eventlog.Open(serviceName); err == nil {
		defer el.Close()
		lg = log.New(eventWriter{el}, "", 0)
	} else {
		lg = log.New(os.Stderr, "", log.LstdFlags)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		lg.Printf("lldp4win %s 服務啟動，每 %s 送出一次", version, s.cfg.Interval)
		runLoop(ctx, s.cfg, lg, false)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending, WaitHint: 3000}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
			return false, 0
		}
	}
	cancel()
	return false, 0
}

func runService(cfg *Config) {
	if err := svc.Run(serviceName, &beaconService{cfg: cfg}); err != nil {
		if el, e := eventlog.Open(serviceName); e == nil {
			el.Error(3, "服務執行失敗: "+err.Error())
			el.Close()
		}
		os.Exit(1)
	}
}

// installDir 是服務執行檔的固定安裝位置：C:\Program Files\lldp4win
func installDir() string {
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "lldp4win")
}

// deployExe 把目前的執行檔複製到 installDir()，避免使用者刪掉下載的檔案後服務失效。
func deployExe() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", err
	}
	src, _ = filepath.Abs(src)
	dst := filepath.Join(installDir(), "lldp4win.exe")
	if strings.EqualFold(src, dst) {
		return dst, nil
	}
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return "", err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return "", fmt.Errorf("無法複製到 %s: %w", dst, err)
	}
	return dst, nil
}

// legacyServiceName 是 drxaos/lldp-beacon（原版）與本專案舊版使用的服務名稱。
const legacyServiceName = "LLDPBeacon"

// removeLegacyService 移除舊版服務，避免兩個服務同時送出 LLDP。
func removeLegacyService(m *mgr.Mgr) {
	s, err := m.OpenService(legacyServiceName)
	if err != nil {
		return
	}
	defer s.Close()
	fmt.Printf("偵測到舊版服務 %s，將停止並移除…\n", legacyServiceName)
	stopAndWait(s)
	if err := s.Delete(); err != nil {
		fmt.Fprintf(os.Stderr, "警告: 無法移除舊版服務 %s: %v\n", legacyServiceName, err)
		return
	}
	_ = eventlog.Remove(legacyServiceName)
}

func installService(args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("無法連線服務管理員（請以系統管理員身分執行）: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("服務 %s 已存在，請先執行 remove", serviceName)
	}

	removeLegacyService(m)

	exe, err := deployExe()
	if err != nil {
		return err
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "lldp4win (LLDP for Windows)",
		Description: "定期在各網卡送出 LLDP 封包，讓交換器可辨識此電腦。",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("建立服務失敗: %w", err)
	}
	defer s.Close()

	// 失敗時自動重新啟動
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)

	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "exists") {
		fmt.Fprintln(os.Stderr, "警告: 無法註冊事件記錄來源:", err)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("服務已安裝但啟動失敗: %w", err)
	}
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("無法連線服務管理員（請以系統管理員身分執行）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服務 %s 未安裝", serviceName)
	}
	defer s.Close()
	var binPath string
	if c, err := s.Config(); err == nil {
		binPath = c.BinaryPathName
	}
	stopAndWait(s)
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	cleanupInstalledExe(binPath)
	return nil
}

// cleanupInstalledExe 只刪除由 deployExe 放到 installDir() 的檔案。
func cleanupInstalledExe(binPath string) {
	exe := strings.Trim(binPath, `"`)
	if i := strings.Index(strings.ToLower(exe), ".exe"); i >= 0 {
		exe = exe[:i+4]
	}
	dir := installDir()
	if exe == "" || !strings.EqualFold(filepath.Dir(exe), dir) {
		return
	}
	// 服務剛停止，檔案可能還被鎖住一下；正在執行的就是這個檔案時則排程在重開機後刪除
	for i := 0; i < 10; i++ {
		if err := os.Remove(exe); err == nil || os.IsNotExist(err) {
			_ = os.Remove(dir)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	if p, err := windows.UTF16PtrFromString(exe); err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	if p, err := windows.UTF16PtrFromString(dir); err == nil {
		_ = windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}

// serviceState 回傳服務是否存在、狀態與執行檔路徑。
func serviceState() (exists bool, state svc.State, binPath string) {
	// 只要求查詢權限，一般使用者（未提升權限）也能查詢
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, 0, ""
	}
	defer windows.CloseServiceHandle(scm)
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(serviceName),
		windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return false, 0, ""
	}
	s := &mgr.Service{Name: serviceName, Handle: h}
	defer s.Close()
	if st, err := s.Query(); err == nil {
		state = st.State
	}
	if c, err := s.Config(); err == nil {
		binPath = c.BinaryPathName
	}
	return true, state, binPath
}

func controlService(start bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("無法連線服務管理員（請以系統管理員身分執行）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服務 %s 未安裝", serviceName)
	}
	defer s.Close()
	if start {
		return s.Start()
	}
	return stopAndWait(s)
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for st.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}
