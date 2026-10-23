# PA-1420 智能監控聯防系統 (Go 原生高效版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的自動化監控與日誌分析系統。本專案已全面使用 **Go 語言 (Golang)** 重構，具備極低的記憶體佔用與極高的併發處理能力。

系統整合了 DHCP 租約追蹤、ARP 聯防比對、硬體效能歷史圖表，並導入 **Parquet 列式資料庫** 與 **UDP 514 Syslog 即時串流**，能以毫秒級延遲處理每日數十萬筆的 Traffic 流量與 Threat 資安威脅日誌，是網管與資安維運的絕佳利器。

---

## 🌟 系統核心功能特性

### 1. 網路租約與資安防護 (SQLite)
* **DHCP / ARP 聯防比對**
  * 排程自動透過 XML API 擷取最新 DHCP 租約，排除重複並建立歷史軌跡。
  * 即時比對 `show arp all`，揪出「手動設定固定 IP 的未授權設備」或「IP/MAC 衝突」。
  * 內建 **多執行緒背景非同步 DNS (PTR) 查詢**，自動快取解析主機名稱。
* **系統硬體效能歷史監控**
  * 背景每分鐘自動採樣 MP CPU、DP CPU、記憶體、活躍連線數與 SSD 分區容量。
  * 提供最近 3 小時動態歷史折線圖 (Chart.js)，精確拆分實質佔用與系統快取。

### 2. 海量日誌分析 (Parquet + Syslog)
* **UDP 514 Syslog 即時串流接收**
  * 內建高效能 UDP 伺服器，即時接收 PA-1420 轉發的 Traffic 日誌。
  * 採用 **記憶體緩衝 + 5 秒 / 300 筆自動批次寫入 (Batch Flush)**，極大化降低磁碟 I/O 負擔。
* **每日單一 Parquet 檔案儲存 (Columnar Storage)**
  * 自動將 Traffic 與 Threat 日誌按日分檔儲存於 `traffic_logs/` 與 `threat_logs/`。
  * 具備**開機自動整併碎片**與 **`.tmp` 原子安全替換 (Atomic Rename)** 技術，斷電絕不損毀資料。
  * 支援跨日、跨欄位高速聚合檢索（Top 應用程式、位元組傳輸量、直方圖統計）。
* **資安威脅日誌分析 (Threat Logs)**
  * 自動與內部 DHCP IP 交叉比對，找出中毒設備的主機名稱與 MAC。
  * 提供視覺化威脅等級分佈、Top 5 來源 IP、Top 5 威脅特徵排行。

### 3. 智慧接力歷史回溯 (Smart Backfill)
* **自動對齊時間線**：系統會自動尋找資料庫中「最舊的歷史紀錄時間」，無縫向更早的過去發起接力回溯，自動跨日掃描。
* **分輪冷卻防卡死**：單次最高支援 10 輪 (50,000 筆) API 調用，每輪之間自動冷卻 1.5 秒，完美保護防火牆管理平面 (MP) CPU 不逾時、不當機。
* **HTTP 分塊串流輸出 (Chunked Transfer)**：支援終端機即時印出每一輪抓取進度。

---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go             # 程式進入點與系統初始化
├── core.go             # 核心邏輯 (PA-1420 API、Parquet 讀寫、Syslog 引擎)
├── routes.go           # Gin Web 路由、API 端點與串流輸出
├── go.mod / go.sum     # Go 模組依賴清單
├── auto_backfill.bat   # 自動接力歷史回溯批次檔
├── pa1420key.txt       # 防火牆設定檔 (啟動時自動產生範本)
├── dhcp_records.db     # SQLite 關聯式資料庫 (自動建立)
├── traffic_logs/       # 連線流量日誌 (按日儲存的 Parquet 檔)
├── threat_logs/        # 資安威脅日誌 (按日儲存的 Parquet 檔)
└── templates/          # 前端 Web UI (Pongo2 樣板、Bootstrap 5)

```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

首次執行程式時，系統會自動在目錄下產生 `pa1420key.txt` 範本檔。請依序填入三行內容：

```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==

```

* **第 1 行**：PA-1420 管理介面 IP。
* **第 2 行**：監控的 DHCP 網路介面（例如 `ethernet1/1`；若欲取得所有介面可填 `all`）。
* **第 3 行**：PA-1420 XML API Key。

---

## 🔄 歷史日誌回溯與自動化腳本

系統提供強大的 API 供歷史資料補齊，您可以透過 cURL 指令或專屬的批次檔進行操作：

### 方法一：使用內建批次檔 `auto_backfill.bat` (推薦)

支援直接雙擊互動式輸入，或在命令提示字元 (CMD) 中帶入參數執行。腳本內建 3 秒冷卻防護機制。

* **回溯連線流量 (Traffic)**：執行 5 次 (共 25 輪 / 125,000 筆)

```cmd
  auto_backfill.bat 5 traffic
  

```

* **回溯資安威脅 (Threat)**：執行 3 次 (共 15 輪 / 75,000 筆)

```cmd
  auto_backfill.bat 3 threat
  

```

### 方法二：透過 PowerShell 直接呼叫 API

* **自動接力回溯 5 輪** (自動從最舊時間往前撈)：

```powershell
  curl.exe -N -s -X POST [http://127.0.0.1:5006/api/traffic-backfill](http://127.0.0.1:5006/api/traffic-backfill) -d "rounds=5"
  

```

* **指定特定時間點跳躍回溯**：

```powershell
  curl.exe -N -s -X POST [http://127.0.0.1:5006/api/threat-backfill](http://127.0.0.1:5006/api/threat-backfill) -d "rounds=3" -d "before=2026-10-22 14:00:00"
  

```

*(💡 加上 `-N` 參數可停用緩衝，讓終端機即時分輪印出最新進度。)*

---

## 🚀 專案編譯與執行 (Build & Run)

受惠於 Go 語言的特性，**不需要虛擬環境，也不需要額外安裝 PyInstaller**。編譯後的單一執行檔不依賴目標機器的任何環境，啟動速度極快。

### 1. 初始化與下載依賴套件

在專案根目錄下執行：

```cmd
go mod tidy

```

### 2. 編譯為單一執行檔 (.exe)

為獲得體積更小、無除錯資訊的最佳化發布版本，請執行以下指令：

```cmd
go build -ldflags "-s -w" -o PA1420_Monitor.exe .

```

*(💡 `-s -w` 參數會移除符號表與除錯資訊，能顯著縮減執行檔體積。)*

### 3. 部署與啟動

1. 將編譯好的 `PA1420_Monitor.exe` 以及 `templates/` 資料夾（必須在同級目錄）複製到任意伺服器。
2. 確保同目錄下有正確設定的 `pa1420key.txt`。
3. 雙擊執行 `PA1420_Monitor.exe`。
4. 打開瀏覽器，造訪：`http://localhost:5006`，系統將在背景同步監聽 UDP 514 埠號。

---

## 📄 授權條款

本專案採用 **[MIT License](https://opensource.org/licenses/MIT)** 授權。可自由修改、整合與商業使用。

```