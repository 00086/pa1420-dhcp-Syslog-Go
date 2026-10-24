# PA-1420 防火牆日誌分析與 DHCP 監控系統 (Go 原生版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的日誌分析與網路監控系統。本專案最初以 **DHCP 租約管理與 ARP 聯防比對** 為核心基礎開發，後續採用 **Go 語言 (Golang)** 原生架構全面重構，大幅擴展了海量資料的處理能力。

系統整合了內部網路設備追蹤、硬體健康歷史監控，並導入 **Parquet 列式資料庫**、**UDP 514 Syslog 即時串流** 與 **DuckDB 向量化 SQL 引擎**，能以極低記憶體佔用穩定承載每日高達 **400 萬筆以上** 的 Traffic 流量與 Threat 威脅日誌。

## 🌟 系統核心功能特性

### 1. DHCP 網路租約與 ARP 聯防 (dhcp.html)

**本系統最初開發的核心基礎模組**，專注於內部網路的實體設備與 IP 分配安全：

* **DHCP 租約追蹤**：排程自動透過 XML API 擷取防火牆最新 DHCP 租約，自動排除重複紀錄並建立完整的設備歷史上線軌跡。
* **ARP 交叉聯防比對**：即時比對防火牆的 `show arp all` 紀錄，精準揪出「手動設定固定 IP 的未授權私設設備」或「IP/MAC 衝突」的潛在管理盲區。
* **背景 DNS 智能解析**：內建多執行緒非同步 DNS (PTR) 查詢引擎，自動快取並解析內部網路的主機名稱 (Hostname)，讓生硬的 IP 位址轉化為具備識別度的設備名稱。

### 2. 海量日誌雙引擎架構 (Traffic & Threat)

系統針對「連線流量 (Traffic)」與「資安威脅 (Threat)」日誌，採用雙軌高效儲存與分析架構：

* **毫秒級向量化查詢 (DuckDB Integration) 🦆**
  * 突破純 Go 語言在 400 萬筆日誌下的 GC (垃圾回收) 記憶體風暴。系統採用免安裝的 DuckDB 命令行引擎，直接對磁碟上的 Parquet 檔案進行 SQL 向量化平行聚合。
  * 實現 **零 Go 記憶體指標負擔**，精準只讀取需要的統計欄位，將原先數十秒的查詢耗時極限壓縮至 **0.05 \~ 0.1 秒**。
* **資安威脅深度剖析 (Threat Engine)**
  * 支援威脅事件的 24 小時直方圖分佈、高危險 (Critical/High) 統計，以及 Top 1 觸發威脅/受駭主機。
  * 自動與前述的 **DHCP/DNS 資料庫** 交叉比對，將中毒端 IP 即時轉換為**主機名稱與 MAC 位址**，加速資安事件應變。
  * 支援多維度精準檢索（嚴重性 Severity、動作 Action、威脅特徵 Threat Name 等）。

### 3. 流量專屬串流與動態整併 (Syslog + Consolidation)

* **Fast Segment Appender（極速微秒即時分塊）**
  * 日誌引擎不對百萬筆當日主檔進行全量讀寫，而是透過 UDP 514 Syslog 接收器直接寫入輕量化的獨立即時分塊（例如 `traffic_YYYY-MM-DD_live_*.parquet`），單次落盤僅需 2～5 毫秒。
  * 前端查詢與聚合引擎自動跨「每日主檔 + 當日即時分塊」進行聯合檢索，確保大數據統計與即時串流並存。
* **動態背景整併機制（Consolidation）**
  * 專為海量規模調優，以 **20\~60 個分塊（約 5\~20 分鐘）** 為整併週期，由背景 DuckDB 引擎安靜去重合併回單一主檔。
  * 大幅降低 SSD 寫入放大損耗，徹底消除讀寫鎖競爭（Lock Contention）。

### 4. 智慧接力歷史回溯 (Smart Backfill Engine)

* **先參後流（Pre-parsing Stream）**
  * 修正 HTTP Chunked 串流下的參數讀取順序，優先解析 URL Query 與 POST 參數後再開啟即時傳輸，支援精準自訂起點。
* **當日智慧斷點續傳（Smart Resume）**
  * 指定日期回溯時，系統自動探測該日 Parquet 檔案中已存在的最舊連線/威脅時間點，自動接關往前回溯，完全不浪費 API 額度重抓已有資料。
* **狀態檔輕量協同（IPC Coordination）與硬體邊界探測**
  * 核心引擎透過 `backfill_status.txt` 實時拋出進度，批次腳本利用單行命令連接符 (`&`) 完美免疫 Windows CMD 的跳轉 Bug。
  * 自動適配 PA-1420 內部的 FIFO 循環覆蓋限制，遭遇實體儲存極限即安全終止。

### 5. 系統硬體效能歷史監控 (SQLite)

* 背景每分鐘自動採樣防火牆的 MP CPU、DP CPU、記憶體佔用、活躍連線數 (Active Sessions) 與 SSD 磁碟分區容量，提供歷史折線圖供維運參考。

## 📁 專案目錄架構

```
dhcpxml-go/
├── main.go                     # 程式進入點、排程器與背景服務初始化
├── core.go                     # 核心邏輯 (PA API、Parquet 讀寫、DuckDB 檢索、Syslog 引擎)
├── routes.go                   # Web 路由、API 端點與分塊串流回溯
├── go.mod / go.sum             # Go 模組依賴清單
├── duckdb.exe                  # 🦆 DuckDB 向量化查詢引擎 (需手動下載放入)
├── auto_backfill_day.bat       # 指定日期區間回溯腳本 (至當日 00:00:00 止)
├── auto_backfill_to_limit.bat  # 全自動歷史接力回溯腳本 (直至硬體極限)
├── backfill_status.txt         # 回溯狀態即時中繼檔 (程式自動維護)
├── pa1420key.txt               # 防火牆 IP、介面與 API Key 配置檔
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP、硬體健康日誌)
├── traffic_logs/               # 流量日誌目錄 (每日單一 Parquet 主檔與 Live 串流分塊)
├── threat_logs/                # 威脅日誌目錄 (每日單一 Parquet 威脅主檔)
└── templates/                  # 前端 Web 介面 (Pongo2 樣板引擎)
    ├── base.html               # 核心共用框架 (Bootstrap 5, Chart.js)
    ├── dhcp.html               # DHCP 租約與 ARP 聯防管理前端 (系統核心起點)
    ├── traffic.html            # 流量分析前端 (具備滿版 Flexbox 排版與非同步載入)
    └── threat.html             # 威脅分析前端 (與 traffic 採 1:1 彈性統一設計)
```

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

首次啟動時系統會自動建立範本檔，請依序配置三行內容：

```
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==
```

* **第 1 行**：PA-1420 管理介面 IP。
* **第 2 行**：監控之 DHCP 介面（例如 `ethernet1/1`；欲監控所有介面請填 `all`）。
* **第 3 行**：PA-1420 XML API 金鑰。

## 🔄 API 端點與命令列 (CURL) 呼叫參考

您可以透過 Windows 內建的 `curl.exe` 或任何排程系統直接呼叫背景 API 來執行擷取與回溯動作。

### 1. 即時最新日誌擷取 (Fetch Now)
立即向 PA-1420 拉取「當下」最新產生的高達 5000 筆日誌。
* **擷取最新流量 (Traffic)**：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/traffic-fetch-now -d "count=5000"
  ```
* **擷取最新資安威脅 (Threat)**：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/threat-fetch-now -d "count=5000"
  ```

### 2. 歷史日誌單輪回溯 (Backfill)
觸發背景引擎執行 1 輪 (1 Round = 5,000 筆) 的歷史回溯。系統會自動偵測 Parquet 斷點並向過去深挖。
* **回溯一輪歷史流量 (Traffic)**：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/traffic-backfill -d "rounds=1&date=2026-10-24"
  ```
* **回溯一輪歷史資安威脅 (Threat)**：
  *(威脅回溯會全自動銜接系統斷點，無須指定日期)*
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/threat-backfill -d "rounds=1"
  ```

### 3. 日誌查詢 API
透過 DuckDB 極速查詢分析結果 (回傳 JSON 格式)：
```cmd
curl.exe "http://127.0.0.1:5006/api/traffic-query?date=2026-10-24&page=1&per_page=50"
curl.exe "http://127.0.0.1:5006/api/threat-query?date=2026-10-24&severity=high"
```

## 🔄 歷史日誌自動化回溯腳本說明

針對 PA-1420 的海量日誌，專案內建兩款免除字元編碼異常、支援斷點續傳的純 CMD 自動化批次檔：

### 1. 單日目標回溯：`auto_backfill_day.bat`

用於補齊特定整天的日誌。每批次自動遞迴推進，一旦達當日 **`00:00:00`**（跨入前一天）即自動安全停機。
支援自動斷點續傳（若已存在部分資料，會自最舊記錄點接力往前補）。

* **回溯連線流量 (Traffic)**：
  ```
  auto_backfill_day.bat 2026-10-23
  ```
* **指定起點時間開始倒推 (Traffic)**：
  ```
  auto_backfill_day.bat 2026-10-23 18:30:00
  ```
* **指定回溯資安威脅日誌 (Threat)**：
  ```
  auto_backfill_day.bat 2026-10-23 threat
  ```
*(亦可雙擊直接執行，透過互動介面依序輸入參數)*

### 2. 全自動歷史推進：`auto_backfill_to_limit.bat`

無需指定日期，系統自動定位資料庫最舊記錄點，持續跨日往過去深挖，直到遭遇防火牆實體硬體儲存 FIFO 極限（自動探測 `LIMIT`）為止。

* **全自動回溯連線流量 (Traffic)**：
  ```
  auto_backfill_to_limit.bat
  ```
* **全自動回溯資安威脅 (Threat)**：
  ```
  auto_backfill_to_limit.bat threat
  ```
*(💡 執行期間可隨時按下 `Ctrl + C` 中斷，下次啟動將自動銜接斷點續跑)*

## 🚀 專案部署與啟動指南

本系統維持純 Go 靜態編譯優勢，無需複雜的 CGO 設定，亦無需常駐資料庫服務（除內建的 SQLite 外）。

### 1. 下載並編譯 Go 後端程式

在專案根目錄執行：
```
go mod tidy
go build -ldflags "-s -w" -o PA1420_Monitor.exe .
```
*(使用 `-ldflags "-s -w"` 去除除錯標籤，可大幅縮減編譯體積)*

### 2. 準備 DuckDB 查詢引擎 (必備)

系統的海量檢索依賴 DuckDB CLI 執行檔（免安裝、即用即棄）：
1. 進入 [DuckDB 官方發布頁面](https://github.com/duckdb/duckdb/releases/latest)。
2. 下載 Windows 穩定版本（例如 `duckdb_cli-windows-amd64.zip`）。
3. 解壓縮後，將 **`duckdb.exe`** 直接放入與 `PA1420_Monitor.exe` 相同的根目錄下。

### 3. 正式啟動

1. 確保 `PA1420_Monitor.exe`、`duckdb.exe`、批次檔與 `templates/` 目錄皆在同一層級。
2. 檢查 `pa1420key.txt` 是否配置完成。
3. 雙擊執行 `PA1420_Monitor.exe`，系統即刻在背景啟動 HTTP 服務（預設 Port: 5006）並持續監聽 UDP 514 接收 Syslog 串流。
4. 使用瀏覽器訪問 `http://localhost:5006` 即可進入系統操作介面。

## 📄 授權條款

本專案採用 [**MIT License**](https://opensource.org/licenses/MIT) 授權。可自由修改、整合與商業使用。