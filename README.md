# PA-1420 防火牆日誌分析與 DHCP 監控系統 (Go 湖倉進階版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的日誌分析與網路監控系統。本專案最初以 **DHCP 租約管理與 ARP 聯防比對** 為核心基礎開發，後續採用 **Go 語言 (Golang)** 原生架構全面重構，並正式升級為現代化的 **Lakehouse (資料湖倉) 冷熱分離架構**。

系統無縫整合了 **HTTP JSON Webhook 即時串流**、**UDP 514 Syslog**、**Parquet 列式壓縮** 與 **DuckDB 向量化 SQL 引擎**，不僅能以極低記憶體佔用穩定承載每日高達百萬筆的 Traffic 流量與 Threat 威脅日誌，更具備 100% 原始報文留存的資安稽核能力。

---

## 🌟 系統核心功能特性

### 1. DHCP 網路租約與 ARP 聯防 (dhcp.html)
**本系統最初開發的核心基礎模組**，專注於內部網路的實體設備與 IP 分配安全：
* **DHCP 租約追蹤**：排程自動透過 XML API 擷取防火牆最新 DHCP 租約，自動排除重複紀錄並建立完整的設備歷史上線軌跡。
* **ARP 交叉聯防比對**：即時比對防火牆的 `show arp all` 紀錄，精準揪出「手動設定固定 IP 的未授權私設設備」或「IP/MAC 衝突」的潛在管理盲區。
* **背景 DNS 智能解析**：內建多執行緒非同步 DNS (PTR) 查詢引擎，將生硬的 IP 位址轉化為具備識別度的設備名稱。

### 2. Lakehouse 冷熱分離架構 (Cold-Hot Data Storage)
系統針對流量與威脅日誌，全面導入企業級冷熱分離雙軌落盤機制：
* **熱資料分析層 (`traffic_logs/`)**：
  Go 後端將日誌精煉為強型別結構，寫入 ZSTD 壓縮的 Parquet 主檔。DuckDB 查詢引擎只需讀取特定欄位（如 Bytes、IP），實現零記憶體指標負擔，將百萬筆 24 小時直方圖查詢極限壓縮至 **0.05 ~ 0.1 秒**。
* **冷資料稽核層 (`traffic_raw_logs/`)**：
  系統將接收到的 100% 原始封包（JSON / CSV / XML）原封不動寫入 `raw_content` 欄位並高壓落盤。專供資安事件複查、封包還原佐證與法規留存，即使防火牆韌體升級新增欄位也絕對不漏接。

### 3. 多重接收引擎與智慧去重 (Deduplication)
* **Webhook & Syslog 雙軌並行接收**：
  支援最新 HTTP JSON Webhook (Port 5006) 與傳統 UDP Syslog (Port 514) 同時運作，共用極速記憶體佇列，每 3 秒自動非同步批次落盤 (`live_*.parquet`)。
* **DuckDB 全域視窗去重 (True Sessions)**：
  透過 SQL 視窗函數 `ROW_NUMBER() OVER (PARTITION BY timestamp, source, destination, to_port, session_id)`，系統能自動在背景將「連線 Start/End 重複報送」、「Syslog 與 API 雙重抓取」的冗餘雜訊徹底清洗（例如將 380 萬筆原始紀錄壓實為 200 萬筆真實獨立會話），確保統計數據絕對精準。

### 4. 智慧接力歷史回溯 (Smart Backfill Engine)
* **當日智慧斷點續傳（Smart Resume）**
  指定日期回溯時，系統探測該日 Parquet 檔案中最舊的時間點，自動接關往前回溯，不浪費 API 額度重抓已有資料。
* **跨格式無縫融合**
  透過 API 回溯的原生 XML 日誌，經過 Go 引擎正規化後，能與 Webhook 即時寫入的 JSON 日誌完美融合於同一張 Parquet 數據表中。

---

## 🆚 架構升級：HTTP Webhook vs. UDP Syslog

本系統強烈建議從傳統 Syslog 升級為 Palo Alto **HTTP JSON Webhook** 轉發，兩者在架構上的決定性差異如下：

| 評比維度 | Syslog (UDP 514) | HTTP JSON Webhook (TCP 5006) 🌟 |
| :--- | :--- | :--- |
| **傳輸可靠度** | ❌ **不保證（靜默掉包）**。高流量時 Windows Socket 緩衝區易滿載，封包被 OS 丟棄且防火牆不知情。 | ✔️ **極高（TCP ACK保證）**。帶有流量控制與自動重傳機制，保證 100% 不掉日誌。 |
| **後端解析效能** | ❌ **開銷極大**。需使用 CSV 解析器、防跳脫、字串切割與大量正規表示式。 | ✔️ **極簡高效**。Go 原生 `json.Unmarshal` 直接對齊記憶體 Struct，耗時僅數百微秒。 |
| **版本容錯性** | ❌ **脆弱**。PAN-OS 升級若插入新欄位，後端 Index 全面錯位導致解析崩潰。 | ✔️ **強健 (Key-Value)**。欄位完全解耦，新增未知欄位會被 Go 引擎優雅忽略，業務邏輯不中斷。 |
| **冷資料原貌** | ⚠️ 雜亂的逗號分隔字串，肉眼難以閱讀排查。 | ✔️ 結構清晰的 JSON 封包，利於日後第三方 SIEM 系統匯入。 |

---

## ⚡ 高併發與多執行緒架構 (Goroutines & Concurrency)

本系統深入運用 Go 語言原生的高併發優勢，透過 Goroutines 將任務分派至多核心平行運算：

1. **DuckDB 3 路並行化 (`sync.WaitGroup`)**
   日誌檢索同時發動 3 個獨立 Goroutine：算總數與 Top排行、算直方圖、撈取分頁明細。三個最耗時的 I/O 任務完全重疊，將查詢延遲縮減 30%~50%。
2. **15 執行緒非同步 DNS 工作池 (Worker Pool)**
   解析數千筆 IP 時，建立包含 15 個併發 Worker 的通道佇列，遇到 DNS 逾時的 IP 不會卡死主執行緒，確保解析流暢。
3. **記憶體佇列與消費者管線 (Lock-Free Atomics)**
   主監聽執行緒只負責快速接收 JSON/UDP 解碼，以無鎖原子操作推進萬級 Channel；後端 Consumer Goroutine 每 3 秒定時落盤，讀寫完全解耦，保障最高網路吞吐。

---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go                     # 程式進入點、排程器與 HTTP 路由
├── core.go                     # 核心邏輯 (多執行緒、Parquet、DuckDB、Syslog/JSON)
├── routes.go                   # Web API 端點、Webhook 接收器與分塊串流
├── go.mod / go.sum             # Go 模組依賴清單
├── duckdb.exe                  # 🦆 DuckDB 向量化查詢引擎 (需手動下載)
├── auto_backfill_day.bat       # 單日歷史接力回溯批次檔
├── auto_backfill_to_limit.bat  # 全自動跨日歷史推進批次檔
├── pa1420key.txt               # 防火牆 IP、介面與 API Key 配置檔
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP、系統狀態)
├── traffic_logs/               # 流量「熱資料」目錄 (結構化 Parquet)
├── traffic_raw_logs/           # 流量「冷資料」目錄 (原始 JSON/XML Parquet)
├── threat_logs/                # 威脅「熱資料」目錄
├── threat_raw_logs/            # 威脅「冷資料」目錄
└── templates/                  # 前端 Web 介面 (Pongo2 樣板引擎)
    ├── base.html               # 核心共用框架
    ├── dhcp.html               # DHCP 租約與 ARP 聯防管理前端
    ├── traffic.html            # 流量分析前端
    └── threat.html             # 威脅分析前端
```

---

## 🔄 關鍵 API 端點參考

系統提供完整 HTTP API，防火牆或外部系統可直接呼叫：

### 1. Webhook 接收端點 (供 PA-1420 Log Forwarding 設定)
* **流量日誌 (Traffic)**：`POST http://<伺服器IP>:5006/api/webhook/traffic`
* **威脅日誌 (Threat)**：`POST http://<伺服器IP>:5006/api/webhook/threat`
*(接收到 Payload 後，伺服器會立即回傳 HTTP 200 OK，並於背景執行冷熱分流落盤)*

### 2. 歷史日誌單輪回溯 (Backfill)
觸發背景引擎執行 1 輪 (`1 round = 5,000 筆`) 的歷史回溯，自動偵測斷點向過去深挖。
* **回溯歷史流量**：`curl -X POST http://127.0.0.1:5006/api/traffic-backfill -d "rounds=1&date=2026-10-24"`
* **回溯歷史威脅**：`curl -X POST http://127.0.0.1:5006/api/threat-backfill -d "rounds=1"`

---

## 🚀 專案部署與啟動指南

1. **編譯 Go 後端程式**：
   ```cmd
   go mod tidy
   go build -trimpath -ldflags="-s -w" -o PA1420_Monitor.exe .
   ```
2. **準備 DuckDB 查詢引擎**：前往 [DuckDB 官方 GitHub Releases](https://github.com/duckdb/duckdb/releases/latest) 下載 `duckdb_cli-windows-amd64.zip`，解壓縮出 `duckdb.exe` 並放入根目錄。
3. **啟動服務**：確保 `pa1420key.txt` 配置檔與前端樣板就緒後，直接雙擊 `PA1420_Monitor.exe`。
4. 系統即在背景啟動 HTTP (Port 5006) 與 UDP (Port 514) 雙引擎監聽，請使用瀏覽器訪問 `http://localhost:5006`。

---
**License**: [MIT License](https://opensource.org/licenses/MIT)
`