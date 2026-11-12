//go:build windows

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

// version 會在建置時以 -ldflags "-X main.version=v1.0.0" 覆寫。
var version = "dev"

const (
	serviceName = "lldp4win"
	projectURL  = "https://github.com/liao-chianan/lldp4win"
)

type Config struct {
	Hostname   string
	SysDesc    string
	Interval   time.Duration
	TTL        int
	Interfaces []string
	NoMED      bool
	Verbose    bool

	IncludeVirtual bool
	PortIDMode     string // ip-mac（預設）| ip | mac | name
}

func portIDText(c *Config, a *Adapter) string {
	if p := c.portID(a); p != "" {
		return p
	}
	return a.MAC.String() + "（MAC）"
}

// portID 依 -portid 產生 Port ID 文字；回傳空字串表示使用 MAC。
// LibreNMS 等網管系統的「Remote Port」顯示的就是這個欄位。
func (c *Config) portID(a *Adapter) string {
	switch c.PortIDMode {
	case "mac":
		return ""
	case "name":
		return a.Friendly
	case "ip-mac":
		if a.IPv4 != nil {
			return fmt.Sprintf("%s (%s)", a.IPv4, a.MAC)
		}
		if a.IPv6 != nil {
			return fmt.Sprintf("%s (%s)", a.IPv6, a.MAC)
		}
		return "" // 沒有 IP 時退回 MAC
	default: // "ip"
		if a.IPv4 != nil {
			return a.IPv4.String()
		}
		if a.IPv6 != nil {
			return a.IPv6.String()
		}
		return "" // 沒有 IP 時退回 MAC
	}
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `lldp4win %s - 在 Windows 上定期廣播 LLDP 封包（不需要 WMIC）

用法:
  lldp4win [選項]              以前景模式執行（Ctrl+C 結束）
  lldp4win install [選項]      安裝並啟動 Windows 服務（需系統管理員）
  lldp4win remove              停止並移除 Windows 服務（需系統管理員）
  lldp4win start | stop        啟動 / 停止已安裝的服務
  lldp4win list                列出會送出 LLDP 的網卡
  lldp4win version             顯示版本

選項:
`, version)
	fs.PrintDefaults()
}

func parseFlags(args []string) (*Config, *flag.FlagSet, bool) {
	fs := flag.NewFlagSet("lldp4win", flag.ExitOnError)
	fs.Usage = func() { usage(fs) }
	var cfg Config
	var interval, ifaces string
	fs.StringVar(&cfg.Hostname, "h", "", "System Name / Chassis ID（預設：主機名稱 + DNS 尾碼）")
	fs.StringVar(&cfg.Hostname, "hostname", "", "同 -h")
	fs.StringVar(&cfg.SysDesc, "s", "", "System Description（預設：自動偵測作業系統版本）")
	fs.StringVar(&cfg.SysDesc, "sysdesc", "", "同 -s")
	fs.StringVar(&interval, "interval", "30s", "送出間隔，例如 30s、1m")
	fs.IntVar(&cfg.TTL, "ttl", 120, "LLDP TTL（秒）")
	fs.StringVar(&ifaces, "i", "", "只在符合的網卡送出，逗號分隔；比對名稱/描述/GUID（不分大小寫）")
	fs.StringVar(&cfg.PortIDMode, "portid", "ip-mac", "Port ID 內容（網管的 Remote Port）：ip | ip-mac | mac | name")
	fs.BoolVar(&cfg.IncludeVirtual, "include-virtual", false, "也在虛擬網卡（Hyper-V、VMware、VPN…）送出；預設略過")
	fs.BoolVar(&cfg.NoMED, "no-med", false, "不送出 IEEE 802.3 / LLDP-MED 擴充 TLV")
	fs.BoolVar(&cfg.Verbose, "v", false, "顯示封包十六進位內容")
	once := fs.Bool("once", false, "只送一次就結束")
	fs.Parse(args)

	d, err := time.ParseDuration(interval)
	if err != nil {
		if n, e := time.ParseDuration(interval + "s"); e == nil {
			d = n
		} else {
			log.Fatalf("無效的 -interval: %v", err)
		}
	}
	if d < time.Second {
		log.Fatal("-interval 至少 1s")
	}
	if cfg.TTL < 1 || cfg.TTL > 65535 {
		log.Fatal("-ttl 必須在 1..65535")
	}
	cfg.Interval = d
	cfg.PortIDMode = strings.ToLower(cfg.PortIDMode)
	switch cfg.PortIDMode {
	case "ip", "ip-mac", "mac", "name":
	default:
		log.Fatalf("無效的 -portid %q（可用 ip、ip-mac、mac、name）", cfg.PortIDMode)
	}
	for _, s := range strings.Split(ifaces, ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.Interfaces = append(cfg.Interfaces, strings.ToLower(s))
		}
	}
	return &cfg, fs, *once
}

func main() {
	log.SetFlags(log.LstdFlags)

	isSvc, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("無法判斷是否以服務執行: %v", err)
	}
	if isSvc {
		cfg, _, _ := parseFlags(os.Args[1:])
		runService(cfg)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "__elevated" {
		elevatedMain(os.Args[2:])
		return
	}
	// 從檔案總管點兩下：進入互動式安裝
	if len(os.Args) == 1 && launchedByDoubleClick() {
		interactiveSetup()
		return
	}

	cmd := ""
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = strings.ToLower(args[0]), args[1:]
	}

	switch cmd {
	case "install":
		parseFlags(args) // 先驗證參數
		check(installService(args))
		fmt.Println("服務已安裝並啟動:", serviceName)
	case "remove", "uninstall":
		check(removeService())
		fmt.Println("服務已移除:", serviceName)
	case "start":
		check(controlService(true))
		fmt.Println("服務已啟動")
	case "stop":
		check(controlService(false))
		fmt.Println("服務已停止")
	case "list":
		cfg, _, _ := parseFlags(args)
		check(listAdapters(cfg))
	case "version", "--version":
		fmt.Println("lldp4win", version)
	case "help", "-?", "/?":
		parseFlags([]string{"-help"})
	case "", "run", "debug":
		cfg, _, once := parseFlags(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		lg := log.New(os.Stdout, "", log.LstdFlags)
		if once {
			sendAll(cfg, lg, true)
			return
		}
		lg.Printf("lldp4win %s 啟動，每 %s 送出一次（Ctrl+C 結束）", version, cfg.Interval)
		runLoop(ctx, cfg, lg, true)
	default:
		fmt.Fprintf(os.Stderr, "未知的指令: %s\n\n", cmd)
		parseFlags([]string{"-help"})
		os.Exit(2)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "錯誤:", err)
		os.Exit(1)
	}
}

// match 判斷是否要在這張網卡送出。
// 未指定 -i 時預設略過虛擬網卡；用 -i 明確指定的網卡則一律允許。
func (c *Config) match(a *Adapter) bool {
	if len(c.Interfaces) == 0 {
		return !a.Virtual || c.IncludeVirtual
	}
	hay := strings.ToLower(a.Name + "|" + a.Description + "|" + a.Friendly)
	for _, f := range c.Interfaces {
		if strings.Contains(hay, f) {
			return true
		}
	}
	return false
}

func (c *Config) systemName(a *Adapter) string {
	if c.Hostname != "" {
		return c.Hostname
	}
	host := Hostname()
	suffix := a.DNSSuffix
	if suffix == "" {
		suffix = PrimaryDomain()
	}
	if suffix != "" {
		return host + "." + suffix
	}
	return host
}

func (c *Config) sysDesc() string {
	if c.SysDesc != "" {
		return c.SysDesc
	}
	return OSDescription()
}

func listAdapters(cfg *Config) error {
	ads, err := Adapters()
	if err != nil {
		return err
	}
	fmt.Println("System Description:", cfg.sysDesc())
	n := 0
	for i := range ads {
		a := &ads[i]
		status := "送出"
		if cfg.match(a) {
			n++
		} else if a.Virtual && len(cfg.Interfaces) == 0 {
			status = "略過（虛擬網卡，可用 -include-virtual 開啟）"
		} else {
			status = "略過（不符合 -i）"
		}
		fmt.Printf("\n[%s] %s\n  狀態:   %s\n  GUID:   %s\n  MAC:    %s\n  IPv4:   %v\n  IPv6:   %v\n  ifIndex:%d\n  Name:   %s\n  PortID: %s\n",
			a.Friendly, a.Description, status, a.Name, a.MAC, a.IPv4, a.IPv6, a.IfIndex, cfg.systemName(a), portIDText(cfg, a))
	}
	if n == 0 {
		fmt.Println("\n沒有符合條件且已連線的乙太網路/Wi-Fi 網卡")
	}
	return nil
}

// sendAll 在所有符合的網卡上送出一次 LLDP，回傳成功數與摘要訊息。
func sendAll(cfg *Config, lg *log.Logger, verbose bool) (int, string) {
	lib, err := loadPcap()
	if err != nil {
		if verbose {
			lg.Print(err)
		}
		return 0, err.Error()
	}
	ads, err := Adapters()
	if err != nil {
		if verbose {
			lg.Printf("列舉網卡失敗: %v", err)
		}
		return 0, "列舉網卡失敗: " + err.Error()
	}
	desc := cfg.sysDesc()
	sent := 0
	var errs []string
	for i := range ads {
		a := &ads[i]
		if !cfg.match(a) {
			continue
		}
		name := cfg.systemName(a)
		f := Frame{
			SrcMAC:     a.MAC,
			ChassisID:  name,
			PortID:     cfg.portID(a),
			PortDesc:   a.Description,
			SystemName: name,
			SystemDesc: desc,
			TTL:        uint16(cfg.TTL),
			IfIndex:    a.IfIndex,
			MgmtIPv4:   a.IPv4,
			MgmtIPv6:   a.IPv6,
			IncludeMED: !cfg.NoMED,
		}
		pkt, err := f.Build()
		if err == nil {
			err = lib.Send(a.Device, pkt)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", a.Friendly, err))
			if verbose {
				lg.Printf("✗ %s (%s): %v", a.Friendly, a.Description, err)
			}
			continue
		}
		sent++
		if verbose {
			lg.Printf("✓ %s (%s) MAC=%s IP=%v name=%s, %d bytes", a.Friendly, a.Description, a.MAC, a.IPv4, name, len(pkt))
			if cfg.Verbose {
				fmt.Print(hex.Dump(pkt))
			}
		}
	}
	summary := fmt.Sprintf("已送出 %d 個 LLDP 封包", sent)
	if sent == 0 && len(errs) == 0 {
		summary = "沒有可用的網卡（需已連線的乙太網路/Wi-Fi 網卡）"
	}
	if len(errs) > 0 {
		summary += "；失敗: " + strings.Join(errs, "; ")
	}
	if verbose {
		lg.Print(summary)
	}
	return sent, summary
}

// runLoop 每隔 cfg.Interval 送一次，直到 ctx 結束。
// 服務模式下 (verbose=false) 只在狀態改變時寫入事件記錄，避免洗版。
func runLoop(ctx context.Context, cfg *Config, lg *log.Logger, verbose bool) {
	last := ""
	tick := time.NewTicker(cfg.Interval)
	defer tick.Stop()
	for {
		_, summary := sendAll(cfg, lg, verbose)
		if !verbose && summary != last {
			lg.Print(summary)
		}
		last = summary
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
