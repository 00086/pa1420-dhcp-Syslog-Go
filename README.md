# PA-1420 防火牆日誌分析與 DHCP 監控系統 (Go 原生版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的日誌分析與網路監控系統。本專案最初以 **DHCP 租約管理與 ARP 聯防比對** 為核心基礎開發，後續採用 **Go 語言 (Golang)** 原生架構全面重構，大幅擴展了海量資料的處理能力。

系統整合了內部網路設備追蹤、硬體健康歷史監控，並導入 **Parquet 列式資料庫**、**UDP 514 Syslog 即時串流** 與 **DuckDB 向量化 SQL 引擎**，能以極低記憶體佔用穩定承載每日高達 **400 萬筆以上** 的 Traffic 流量與 Threat 威脅日誌。

---

## 🌟 系統核心功能特性

### 1. DHCP 網路租約與 ARP 聯防 (dhcp.html)
**本系統最初開發的核心基礎模組**，專注於內部網路的實體設備與 IP 分配安全：
* **DHCP 租約追蹤**：排程自動透過 XML API 擷取防火牆最新 DHCP 租約，自動排除重複紀錄並建立完整的設備歷史上線軌跡。
* **ARP 交叉聯防比對**：即時比對防火牆的 `show arp all` 紀錄，精準揪出「手動設定固定 IP 的未授權私設設備」或「IP/MAC 衝突」的潛在管理盲區。
* **背景 DNS 智能解析**：內建多執行緒非同步 DNS (PTR) 查詢引擎，自動快取並解析內部網路的主機名稱 (Hostname)，讓生硬的 IP 位址轉化為具備識別度的設備名稱。

### 2. 海量日誌雙引擎架構 (Traffic & Threat)
系統針對「連線流量 (Traffic)」與「資安威脅 (Threat)」日誌，採用雙軌高效儲存與分析架構：
* **毫秒級向量化查詢 (DuckDB Integration) 🦆**
  * 突破純 Go 語言在百萬筆日誌下的 GC 記憶體風暴，採用免安裝的 DuckDB 引擎，直接對磁碟上的 Parquet 檔案進行 SQL 向量化平行聚合。
  * 實現 **零 Go 記憶體指標負擔**，將數十秒的查詢耗時極限壓縮至 **0.05 ~ 0.1 秒**。
* **資安威脅深度剖析 (Threat Engine)**
  * 支援威脅事件的 24 小時直方圖分佈、高危險統計，以及 Top 1 觸發威脅/受駭主機。
  * 自動與 **DHCP/DNS 資料庫** 交叉比對，將中毒端 IP 即時轉換為主機名稱與 MAC 位址。

### 3. 流量專屬串流與動態整併 (Syslog + Consolidation)
* **Fast Segment Appender（極速微秒即時分塊）**
  * 日誌引擎不對百萬筆當日主檔進行全量讀寫，透過 UDP 514 Syslog 接收器直接寫入輕量化的即時分塊（`traffic_YYYY-MM-DD_live_*.parquet`），單次落盤僅需 2～5 毫秒。
* **動態背景整併機制（Consolidation）**
  * 以 **20~60 個分塊（約 5~20 分鐘）** 為週期，由背景 DuckDB 引擎安靜去重合併回單一主檔，大幅降低 SSD 寫入放大損耗，徹底消除讀寫鎖競爭。

### 4. 智慧接力歷史回溯 (Smart Backfill Engine)
* **當日智慧斷點續傳（Smart Resume）**
  * 指定日期回溯時，系統探測該日 Parquet 檔案中最舊的時間點，自動接關往前回溯，不浪費 API 額度重抓已有資料。
* **狀態檔輕量協同（IPC）與硬體邊界探測**
  * 核心引擎透過 `backfill_status.txt` 實時拋出進度，批次腳本免疫 Windows CMD 跳轉 Bug。自動適配 PA-1420 內部的 FIFO 循環覆蓋限制。

---

## ⚡ 高併發與多執行緒架構 (Goroutines & Concurrency)

本系統深入運用 Go 語言原生的高併發優勢，透過 Goroutines 將任務分派至多核心平行運算：

1. **DuckDB 3 路並行化 (`sync.WaitGroup`)**
   日誌檢索並非循序等待，而是同時發動 3 個獨立 Goroutine：**執行緒 1** 算總數與 Top 1 排行、**執行緒 2** 算直方圖、**執行緒 3** 撈取分頁明細。三個最耗時的 I/O 任務完全重疊，將查詢延遲縮減 30%~50%。
2. **15 執行緒非同步 DNS 工作池 (Worker Pool)**
   解析數千筆 IP 時，建立包含 15 個併發 Worker 的通道佇列，遇到 DNS 逾時的 IP 不會卡死主執行緒，確保解析流暢。
3. **Syslog 生產者-消費者管線 (Lock-Free Atomics)**
   主監聽執行緒只負責快速接收 UDP 封包解碼，以無鎖原子操作 (`atomic.AddInt64`) 推進萬級 Channel；後端 Consumer Goroutine 每 3 秒定時落盤，讀寫完全解耦，保障最高網路吞吐不掉包。
4. **執行緒安全與鎖隔離**
   全域使用 `sync.RWMutex` (讀寫鎖保護排程狀態) 與 `sync.Mutex` (互斥鎖保護 Parquet 檔案覆寫)，確保資料一致性並最大化併發效能。

---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go                     # 程式進入點、排程器與 HTTP 路由
├── core.go                     # 核心邏輯 (多執行緒、API、Parquet、DuckDB、Syslog)
├── routes.go                   # Web API 端點與分塊串流回溯
├── go.mod / go.sum             # Go 模組依賴清單
├── duckdb.exe                  # 🦆 DuckDB 向量化查詢引擎 (需手動下載)
├── auto_backfill_day.bat       # 單日歷史接力回溯批次檔
├── auto_backfill_to_limit.bat  # 全自動跨日歷史推進批次檔
├── backfill_status.txt         # 回溯狀態 IPC 中繼檔
├── pa1420key.txt               # 防火牆 IP、介面與 API Key 配置檔
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP、系統狀態)
├── traffic_logs/               # 流量日誌目錄 (Parquet 主檔與 Live 分塊)
├── threat_logs/                # 威脅日誌目錄 (Parquet 威脅主檔)
└── templates/                  # 前端 Web 介面 (Pongo2 樣板引擎)
    ├── base.html               # 核心共用框架 (Bootstrap 5, Chart.js)
    ├── dhcp.html               # DHCP 租約與 ARP 聯防管理前端 (系統核心起點)
    ├── traffic.html            # 流量分析前端 (具備滿版 Flexbox 排版)
    └── threat.html             # 威脅分析前端 (與 traffic 採 1:1 彈性統一設計)
```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

首次啟動時系統自動建立範本檔，請依序配置三行內容：
```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==
```
*(第 1 行: 防火牆 IP | 第 2 行: 監控 DHCP 介面 | 第 3 行: API 金鑰)*

---

## 🔄 API 端點與命令列 (CURL) 呼叫參考

系統提供完整 API，可透過 Linux Crontab 或 Windows `curl.exe` 直接呼叫。

### 1. 即時最新日誌擷取 (Fetch Now)
立即向防火牆拉取「當下」最新產生的高達 5000 筆日誌並寫入 Parquet。
* **擷取最新流量 (Traffic)**：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/traffic-fetch-now -d "count=5000"
  ```
* **擷取最新資安威脅 (Threat)**：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/threat-fetch-now -d "count=5000"
  ```

### 2. 歷史日誌單輪回溯 (Backfill)
觸發背景引擎執行 1 輪 (`1 round = 5,000 筆`) 的歷史回溯，自動偵測斷點向過去深挖。
* **回溯 1 輪歷史流量 (Traffic)** (需指定日期參數)：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/traffic-backfill -d "rounds=1&date=2026-10-24"
  ```
* **回溯 1 輪歷史資安威脅 (Threat)** (全自動銜接，無須指定日期)：
  ```cmd
  curl.exe -X POST http://127.0.0.1:5006/api/threat-backfill -d "rounds=1"
  ```

---

## 🔄 歷史日誌自動化回溯腳本 (.bat)

專為 Windows 環境設計的斷點續傳純 CMD 自動化腳本：

1. **單日目標回溯：`auto_backfill_day.bat`**
   遞迴推進，直到跨越當日 00:00:00 自動停機。
   ```cmd
   auto_backfill_day.bat 2026-10-24
   auto_backfill_day.bat 2026-10-24 18:30:00  (指定倒推起點)
   auto_backfill_day.bat 2026-10-24 threat    (威脅日誌專用)
   ```
2. **全自動歷史推進：`auto_backfill_to_limit.bat`**
   系統自動深挖過往天數，直到遭遇防火牆實體硬體儲存 FIFO 極限 (自動探測 `LIMIT`)。
   ```cmd
   auto_backfill_to_limit.bat
   auto_backfill_to_limit.bat threat
   ```

---

## 🚀 專案部署與啟動指南

1. **編譯 Go 後端程式**：
   ```cmd
   go mod tidy
   go build -ldflags "-s -w" -o PA1420_Monitor.exe .
   ```
2. **準備 DuckDB 查詢引擎**：前往 [DuckDB 官方 GitHub Releases](https://github.com/duckdb/duckdb/releases/latest) 下載 `duckdb_cli-windows-amd64.zip`，解壓縮出 `duckdb.exe` 並放入根目錄。
3. **啟動服務**：確保配置檔與前端樣板就緒後，直接雙擊 `PA1420_Monitor.exe`。系統即在背景啟動 HTTP (Port 5006) 與 UDP (Port 514) 串流監聽。
4. 使用瀏覽器訪問 `http://localhost:5006`。

---
**License**: [MIT License](https://opensource.org/licenses/MIT)