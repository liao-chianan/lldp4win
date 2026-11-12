# lldp4win

**LLDP for Windows** — a tiny LLDP agent (transmit-only) for Windows. It periodically sends [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) frames on every connected network adapter, so switches (`show lldp neighbors`) can see the PC's hostname, IP, MAC and OS.

在 Windows 上定期送出 LLDP 封包的小工具，讓交換器可以看到這台電腦的主機名稱、IP、MAC 與作業系統版本。

> Re-implementation inspired by [drxaos/lldp-beacon](https://github.com/drxaos/lldp-beacon).
> 與原版不同：**不再需要 `wmic`**（Windows 11 24H2 起已移除），改用 Windows API 取得系統資訊；改用 [Npcap](https://npcap.com/)，單一執行檔、無其他相依。

## 需求 Requirements

- Windows 10 / 11 / Server 2016+（x64、ARM64、x86）
- [Npcap](https://npcap.com/#download)（安裝時保持預設即可；舊版 WinPcap 也可）

## 下載 Download

到 [Releases](../../releases) 下載 `lldp4win-windows-amd64.exe`（或 arm64 / 386 版本），可改名為 `lldp4win.exe`。

## 使用方式 Usage

```
lldp4win [選項]              前景執行（Ctrl+C 結束）
lldp4win install [選項]      安裝並啟動 Windows 服務（需系統管理員）
lldp4win remove              停止並移除 Windows 服務
lldp4win start | stop        啟動 / 停止服務
lldp4win list                列出會送出 LLDP 的網卡
lldp4win version             顯示版本
```

| 選項 | 說明 | 預設 |
|---|---|---|
| `-h <name>` / `-hostname` | System Name / Chassis ID | 主機名稱 + 網卡 DNS 尾碼（或網域） |
| `-s <desc>` / `-sysdesc` | System Description | 自動偵測，如 `Windows 11 25H2 x64`、`Windows Server 2022 21H2 x64` |
| `-portid <mode>` | Port ID 內容，也就是 LibreNMS 等網管顯示的 **Remote Port**：`ip-mac`（`192.168.1.45 (fc:34:97:9f:c0:4a)`）、`ip`（只有 IP）、`mac`（原版行為）、`name`（網卡名稱）；IPv4 優先，無則 IPv6，都沒有時退回 MAC | `ip-mac` |
| `-interval <d>` | 送出間隔 | `30s` |
| `-ttl <sec>` | LLDP TTL | `120` |
| `-i <filter>` | 只在符合的網卡送出（逗號分隔，比對名稱/描述/GUID）；明確指定時虛擬網卡也會送 | 全部實體網卡 |
| `-include-virtual` | 也在虛擬網卡送出（Hyper-V、VMware、VirtualBox、VPN、WSL、Docker…） | 關（略過） |
| `-no-med` | 不送 IEEE 802.3 / LLDP-MED 擴充 TLV | 關 |
| `-once` | 只送一次就結束 | 關 |
| `-v` | 顯示封包十六進位內容 | 關 |

範例：

```bat
:: 測試：送一次並顯示封包
lldp4win -once -v

:: 只在「乙太網路」送，每 60 秒一次
lldp4win -i 乙太網路 -interval 60s

:: 安裝為服務（參數會一併存入服務設定）
lldp4win install -i Ethernet -interval 30s
```

## 安裝為服務 Windows service

### 最簡單：點兩下執行檔

直接在檔案總管點兩下 `lldp4win.exe`：

- **尚未安裝**：詢問是否安裝，按 Enter（Y）後在 UAC 視窗按「是」即完成安裝，並設定開機自動啟動
- **已安裝**：顯示服務狀態，可選擇 更新／重新安裝、移除、（重新）啟動
- 若尚未安裝 Npcap 會提示並可開啟下載頁面；服務會在 Npcap 安裝後自動開始送出

### 命令列

以**系統管理員**開啟命令提示字元：

```bat
lldp4win install            :: 安裝並啟動（可附加選項，例如 -interval 60s）
lldp4win remove             :: 停止並移除
```

- 執行檔會自動複製到 `C:\Program Files\lldp4win\lldp4win.exe`，原本下載的檔案可以刪除；移除服務時會一併刪除
- 服務名稱為 `lldp4win`，開機自動啟動，失敗會自動重啟
- 執行狀態會寫入「事件檢視器 → Windows 記錄 → 應用程式」（來源 `lldp4win`），只在狀態改變時記錄
- 若偵測到原版 [drxaos/lldp-beacon](https://github.com/drxaos/lldp-beacon) 的 `LLDPBeacon` 服務，安裝時會自動停止並移除，避免重複送出

## 送出的 TLV

| TLV | 內容 |
|---|---|
| Chassis ID | subtype 7 (locally assigned)：系統名稱 |
| Port ID | 預設 subtype 7 (locally assigned)：`IP (MAC)`，例如 `192.168.1.45 (fc:34:97:9f:c0:4a)`；`-portid mac` 時為 subtype 3 (MAC address) |
| TTL | 120 秒（可調） |
| Port Description | 網卡描述 |
| System Name | 主機名稱（含 DNS 尾碼） |
| System Description | 作業系統版本 |
| System Capabilities | Station only |
| Management Address | 網卡的 IPv4（及全域 IPv6）、ifIndex |
| IEEE 802.3 / LLDP-MED | MAC/PHY、Max Frame Size、MED Capabilities、Network Policy（與原版相同，可用 `-no-med` 關閉） |

目的位址為 `01:80:c2:00:00:0e`，EtherType `0x88cc`。

## 建置 Build

需要 [Go](https://go.dev/dl/) 1.26 以上，不需要 cgo 或 Npcap SDK：

```bat
go test ./...
go build -trimpath -ldflags "-s -w -X main.version=v1.0.0" -o lldp4win.exe .
```

推送 `v*` 標籤（例如 `git tag v1.0.0 && git push --tags`）時，GitHub Actions 會自動建置 amd64 / arm64 / 386 並建立 Release。

## 疑難排解 Troubleshooting

- **找不到 wpcap.dll**：請安裝 Npcap。
- **pcap_open_live 失敗**：若安裝 Npcap 時勾選了「Restrict Npcap driver's access to Administrators only」，需以系統管理員執行（服務模式以 LocalSystem 執行，不受影響）。
- **在虛擬機內使用**：VM 的網卡（如 Hyper-V Network Adapter）會被判定為虛擬網卡而略過，請加 `-include-virtual`。用 `lldp4win list` 可查看每張網卡是否會送出。
- **交換器看不到**：確認交換器有啟用 LLDP 接收（例如 Cisco `lldp run`），並用 `lldp4win -once -v` 或 Wireshark (`lldp` 過濾) 確認有送出。

## License

MIT
