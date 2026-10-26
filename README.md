# PA-1420 防火牆日誌分析與 DHCP 監控系統 (Go 湖倉進階版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的日誌分析與網路監控系統。本專案最初以 **DHCP 租約管理與 ARP 聯防比對** 為核心基礎開發，後續採用 **Go 語言 (Golang)** 原生架構全面重構，並正式升級為現代化的 **Lakehouse (資料湖倉) 冷熱分離架構**。

系統無縫整合了 **HTTP JSON Webhook 即時串流**、**UDP 514 Syslog**、**Parquet 列式壓縮** 與 **DuckDB 向量化 SQL 引擎**，不僅能以極低記憶體佔用穩定承載每日高達 400 萬筆以上的 Traffic 流量與 Threat 威脅日誌，更具備 100% 原始報文留存的資安稽核能力。

---

## 🆕 更新亮點
* **🌐 NAS 歷史日誌多檔案智能匯入**：Web 介面支援按住 `Ctrl/Shift` 一次選取多個 Synology NAS 匯出檔 (.txt/.csv)。系統會全自動解析檔案內的所有日期與日誌類型 (Traffic/Threat)，**「逐日自動切分落盤」**，完全不需人工輸入日期！
* **🎯 百萬級精確報文錨定解析**：捨棄傳統死板的字元偏移量，改以 `,TRAFFIC,` 與 `,THREAT,` 特徵錨定技術，並動態補正 117 欄位，徹底解決 Synology 匯出格式前綴變動導致的漏抓問題（實測將 340 萬筆被誤濾的日誌 100% 完美還原）。
* **🔄 DuckDB 全自動背景整併 (Auto-Consolidation)**：新增每小時整點觸發的背景維護引擎，以及 CLI 匯出後的即時整併。系統會自動將零碎的即時串流塊 (`_live_`) 與臨時檔 (`_nas_`) 執行嚴格去重，合併為每日單一純淨 ZSTD 主檔。
* **📅 極致流暢的原生 UI 體驗**：前端查詢日期輸入全面升級為 HTML5 原生月曆挑選器 (`showPicker`)，點擊即彈出，捨棄繁瑣的手動輸入與肥大的下拉選單。
* **📂 動態相對路徑支援**：CLI FTP 高速匯出 (`ftppa.bat`) 已全面解耦絕對路徑，採用動態生成與自動銷毀的 `ftp_data/` 相對目錄，程式搬到任何磁碟機皆可隨插即用。

---

## 🌟 系統核心功能特性

### 1. DHCP 網路租約與 ARP 聯防
**本系統最初開發的核心基礎模組**，專注於內部網路的實體設備與 IP 分配安全：
* **DHCP 租約追蹤**：排程自動透過 XML API 擷取防火牆最新 DHCP 租約，自動排除重複紀錄並建立完整的設備歷史上線軌跡。
* **ARP 交叉聯防比對**：即時比對防火牆的 `show arp all` 紀錄，精準揪出「手動設定固定 IP 的未授權私設設備」或「IP/MAC 衝突」的潛在管理盲區。
* **背景 DNS 智能解析**：內建多執行緒非同步 DNS (PTR) 查詢引擎，自動快取並解析內部網路的主機名稱 (Hostname)，讓生硬的 IP 位址轉化為具備識別度的設備名稱。

### 2. Lakehouse 冷熱分離架構 (Cold-Hot Data Storage)
系統針對「連線流量 (Traffic)」與「資安威脅 (Threat)」日誌，全面導入企業級冷熱分離雙軌落盤機制：
* **熱資料分析層 (`traffic_logs/`, `threat_logs/`)**：
  Go 後端將日誌精煉為強型別的純淨結構，寫入 ZSTD 壓縮的 Parquet 主檔。DuckDB 查詢引擎只需讀取特定欄位（如 Bytes、IP），實現**零 Go 記憶體指標負擔**，將百萬筆 24 小時直方圖查詢極限壓縮至 **0.05 ~ 0.1 秒**。
* **冷資料稽核層 (`traffic_raw_logs/`, `threat_raw_logs/`)**：
  系統將接收到的 100% 原始封包（JSON / CSV / XML）原封不動寫入 `raw_content` 欄位並高壓落盤。專供資安事件複查、封包還原佐證與法規留存。即使防火牆韌體升級新增了未知欄位，底層證據也絕對不漏接。

### 3. 多重接收引擎與智慧去重 (Deduplication)
* **Webhook & Syslog 雙軌並行接收**：
  支援最新 HTTP JSON Webhook (Port 5006) 與傳統 UDP Syslog (Port 514) 同時運作。兩者共用極速記憶體佇列，每 3 秒自動非同步批次落盤為輕量化的即時分塊 (`live_*.parquet`)，單次落盤僅需 2～5 毫秒。
* **DuckDB 全域視窗去重 (True Sessions)**：
  透過 SQL 視窗函數 `ROW_NUMBER() OVER (PARTITION BY timestamp, source, destination, to_port, session_id)`，系統能自動在背景將「連線 Start/End 雙重報送」、「Syslog 與 API 雙管重複抓取」的冗餘雜訊徹底清洗（例如將 380 萬筆原始紀錄擠乾水分，壓實為 200 萬筆真實獨立會話），確保統計數據絕對精準。

### 4. 智慧接力歷史回溯 (Smart Backfill Engine)
* **當日智慧斷點續傳（Smart Resume）**：
  指定日期回溯時，系統會自動探測該日 Parquet 檔案中最舊的時間點（例如 18:30:00），並自動接關往前回推至 00:00:00，絕不浪費 API 額度重抓已存在的資料。
* **跨格式無縫融合**：
  透過 API 回溯的原生 XML 日誌，經過 Go 引擎正規化後，能與 Webhook 即時寫入的 JSON 日誌完美融合於同一張 Parquet 數據表中，對前端查詢完全透明。

### 5. 內建輕量化 FTP 伺服器與 CLI 高速自動化匯出 🌟 
針對單日百萬筆歷史日誌的「大補帖式」還原，系統已整合 **Go 原生內建 FTP 伺服器** 與 **SSH 模擬登入自動化** 引擎，達成零外部依賴的極速管線：
* **純 Go 內建 FTP 接收器 (Port 21)**：直接於 `PA1420_Monitor.exe` 內部接管 Port 21 (支援 PASV / PORT 模式)，徹底免除安裝 Python 或第三方 FTP 軟體的需求。
* **自動化 PTY 虛擬終端登入**：自動透過 SSH 連線至 PA 防火牆、請求 PTY 虛擬終端，並模擬管理員敲擊 `ftp export log...` 指令，將 200 多萬筆資料觸發串流傾印。
* **全自動湖倉整合與空間清理**：自動監控並接收防火牆切分的 CSV 區塊。接收完畢後 0.1 秒內由 DuckDB 向量化引擎自動接手，執行全核心平行冷熱分離，**並於完成後自動刪除臨時 CSV 與 `ftp_data` 資料夾，隨即呼叫背景執行緒完成終極去重整併。**

---

## 📊 四種匯出方式綜合評比 (PA-1420 日誌提取策略)

在 Palo Alto 系統中提取日誌有多種方式，本系統目前已將最快的 **CLI FTP Export** 與自動化的 **XML API** 完美融合。各方式優劣對比如下：

| 匯出方式 | 適合情境 | 速度評比 | 限制與優缺點 |
| :--- | :--- | :--- | :--- |
| **CLI (SCP / FTP Export)** | 大量歷史補檔、整天百萬筆還原 | ⚡ **極快** (幾分鐘搞定) | 需要有可連線的網路路由與本機 SCP/FTP 伺服器接收。 |
| **Scheduled Export** | 全自動每日離線備份 | ⚡ **極快** (背景排程傳輸) | 屬於定期排程機制，無法當下隨按隨抓。 |
| **WebUI CSV 匯出** | 臨時調查、單一 IP/事件調閱 | 🚀 **中等** | 受限於單次最大匯出筆數上限，超大資料無法一次匯出。 |
| **XML API (自動接力回溯)** | 即時斷點續傳、自動整合進湖倉 | 🐢 **最慢** (每輪 5000 筆輪詢) | 程式整合度最高，但對 Management CPU 運算與網路往返負擔較大。 |

---

## 🆚 架構升級：HTTP Webhook vs. UDP Syslog

本系統同時支援並強烈建議從傳統 Syslog 升級為 Palo Alto **HTTP JSON Webhook** 轉發。兩種傳輸模式的全方位對比如下：

| 評比維度 | Syslog (UDP 514) | HTTP JSON Webhook (TCP 5006) 🌟 |
| :--- | :--- | :--- |
| **傳輸可靠度** | ❌ **不保證（掉包無通知）**。 | ✔️ **極高（TCP 重傳 + HTTP ACK）**。 |
| **高流量承載能力** | ❌ 容易塞爆 UDP Socket 緩衝。 | ✔️ **優異（非同步佇列 + 毫秒級秒回）**。 |
| **後端解析複雜度** | ❌ 繁瑣（CSV 逗號切割、防跳脫）。 | ✔️ **極簡（原生結構體直接對齊）**。 |
| **韌體版本容錯** | ❌ 脆弱（欄位順序偏移即破壞資料）。 | ✔️ **強健 (Key-Value 格式完全解耦)**。 |
| **安全性擴充** | ❌ 難以加密，極易偽造 (Spoofing)。 | ✔️ **高（隨時可無痛升級 HTTPS TLS 與 Token）**。 |
| **冷熱資料分離** | ❌ 原始字串雜亂，需二次格式化。 | ✔️ **天然支援（JSON 字串直接壓縮落盤）**。 |

---

## ⚡ 高併發與多執行緒架構 (Goroutines & Concurrency)

本系統深入運用 Go 語言原生的高併發優勢，透過 Goroutines 將任務分派至多核心平行運算：

1. **DuckDB 3 路並行化 (`sync.WaitGroup`)**
   日誌檢索並非循序等待，而是同時發動 3 個獨立 Goroutine：執行緒 1 算總數與 Top 1 排行、執行緒 2 算直方圖、執行緒 3 撈取分頁明細。三個最耗時的 I/O 任務完全重疊，將查詢延遲縮減 30%~50%。
2. **15 執行緒非同步 DNS 工作池 (Worker Pool)**
   解析數千筆 IP 時，建立包含 15 個併發 Worker 的通道佇列，遇到 DNS 逾時的 IP 絕不會卡死主執行緒，確保解析流暢。
3. **生產者-消費者管線 (Lock-Free Atomics)**
   主監聽執行緒只負責快速接收解碼，以無鎖原子操作 (`atomic.AddInt64`) 推進萬級 Channel；後端 Consumer Goroutine 每 3 秒定時落盤，讀寫完全解耦，保障最高網路吞吐。
4. **執行緒安全與鎖隔離**
   全域使用 `sync.RWMutex` (讀寫鎖保護排程狀態) 與 `sync.Mutex` (互斥鎖保護 Parquet 檔案覆寫)，確保資料一致性。

---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go                     # 程式進入點、排程器、HTTP 路由與內建 FTP 伺服器啟動
├── core.go                     # 核心邏輯 (多執行緒、Parquet 落盤、背景去重、解析引擎)
├── routes.go                   # Web API 端點、Webhook 接收器與動態相對路徑處理
├── cli_export.go               # PA-1420 虛擬終端自動化登入與 DuckDB 湖倉轉換核心
├── ftp_server.go               # Go 原生輕量化 FTP 伺服器 (支援 PASV / PORT)
├── go.mod / go.sum             # Go 模組依賴清單
├── duckdb.exe                  # 🦆 DuckDB 向量化查詢引擎 (需手動下載)
├── ftppa.bat                   # CLI 高速串流匯出批次檔 (相對路徑支援，自動去重)
├── auto_backfill_day.bat       # 單日歷史接力回溯批次檔 (XML API 方案)
├── auto_backfill_to_limit.bat  # 全自動跨日歷史推進批次檔 (XML API 方案)
├── pa1420key.txt               # 系統防護庫 (存放 PA IP、API Key、SSH 帳密與 FTP 帳密)
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP、系統狀態)
├── ftp_data/                   # FTP 臨時接收資料夾 (動態建立，任務完成後自動銷毀)
├── traffic_logs/               # 流量「熱資料」目錄 (結構化 Parquet)
├── traffic_raw_logs/           # 流量「冷資料」目錄 (原始 JSON/XML Parquet)
├── threat_logs/                # 威脅「熱資料」目錄
├── threat_raw_logs/            # 威脅「冷資料」目錄
└── templates/                  # 前端 Web 介面 (Pongo2 樣板引擎)
    ├── base.html               
    ├── dhcp.html               # DHCP 租約與 ARP 聯防管理前端
    ├── traffic.html            # 流量分析前端 (原生 HTML5 月曆)
    └── threat.html             # 威脅分析前端

```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

首次啟動時系統自動建立範本檔，為確保 API 連線與自動化 SSH / FTP 功能正常運作，請依序配置七行內容：

```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==
FWusername
（您的防火牆 SSH 密碼）
username
password

```

*(第 1 行: 防火牆 IP | 第 2 行: 監控介面 | 第 3 行: API 金鑰 | 第 4-5 行: PA SSH 帳密 | 第 6-7 行: 內建 FTP 帳密)*

---

## 🔄 API 端點與命令列 (CURL) 呼叫參考

系統提供完整 HTTP API，防火牆或外部系統可直接呼叫，亦可透過 Windows `curl.exe` 執行自動化排程：

### 1. Webhook 接收端點 (供 PA-1420 Log Forwarding 設定)

* **流量日誌 (Traffic)**：`POST http://<伺服器IP>:5006/api/webhook/traffic`
* **威脅日誌 (Threat)**：`POST http://<伺服器IP>:5006/api/webhook/threat`
*(伺服器接收到 JSON Payload 後會立即秒回 HTTP 200 OK，並於背景非同步執行冷熱分流落盤)*

### 2. 即時最新日誌擷取 API (Fetch Now)

立即向防火牆拉取「當下」最新產生的高達 5000 筆日誌並寫入 Parquet（適用於無 Webhook 轉發時的定時排程抓取）。

* **擷取最新流量 (Traffic)**：

```cmd
  curl.exe -X POST [http://127.0.0.1:5006/api/traffic-fetch-now](http://127.0.0.1:5006/api/traffic-fetch-now) -d "count=5000"
  

```

* **擷取最新資安威脅 (Threat)**：

```cmd
  curl.exe -X POST [http://127.0.0.1:5006/api/threat-fetch-now](http://127.0.0.1:5006/api/threat-fetch-now) -d "count=5000"
  

```

### 3. 歷史日誌單輪回溯 API (Backfill)

觸發背景引擎執行 1 輪 (`1 round = 5,000 筆`) 的歷史回溯，自動偵測 Parquet 最舊斷點向過去深挖。

* **回溯歷史流量 (需指定日期)**：

```cmd
  curl.exe -X POST [http://127.0.0.1:5006/api/traffic-backfill](http://127.0.0.1:5006/api/traffic-backfill) -d "rounds=1&date=2026-10-24"
  

```

* **回溯歷史威脅 (全自動銜接，無須指定日期)**：

```cmd
  curl.exe -X POST [http://127.0.0.1:5006/api/threat-backfill](http://127.0.0.1:5006/api/threat-backfill) -d "rounds=1"
  

```

---

## 🔄 自動化日誌匯出與回溯腳本 (.bat)

專為 Windows 環境設計的斷點續傳純 CMD 自動化腳本：

### 1. CLI 高速匯出與湖倉自動整合（推薦使用🌟）

透過內建 FTP 伺服器與 PTY 虛擬終端，單日百萬筆連線僅需 2~3 分鐘即可完成匯出、冷熱分離與 DuckDB 壓縮落盤。

* **腳本：`ftppa.bat**`

```cmd
  ftppa.bat 2026-10-24           (預設匯出 traffic 流量日誌)
  ftppa.bat 2026-10-24 threat    (指定匯出 threat 威脅日誌)
  ftppa.bat                      (無參數執行時將提供互動式選單)
  

```

### 2. XML API 歷史回溯方案

採用 API 輪詢機制，適合即時少量補檔或斷點續傳。

* **單日目標回溯：`auto_backfill_day.bat**`
遞迴推進，直到跨越當日 00:00:00 自動停機。

```cmd
  auto_backfill_day.bat 2026-10-24
  auto_backfill_day.bat 2026-10-24 18:30:00  (指定倒推起點)
  auto_backfill_day.bat 2026-10-24 threat    (威脅日誌專用)
  

```

* **全自動跨日歷史推進：`auto_backfill_to_limit.bat**`
系統自動深挖過往天數，直到遭遇防火牆實體硬體儲存 FIFO 極限。

```cmd
  auto_backfill_to_limit.bat
  

```

---

## 🚀 專案部署與啟動指南

1. **編譯 Go 後端程式**：

```cmd
   go mod tidy
   go build -trimpath -ldflags="-s -w" -o PA1420_Monitor.exe .
   

```

2. **準備 DuckDB 查詢引擎**：前往 [DuckDB 官方 GitHub Releases](https://github.com/duckdb/duckdb/releases/latest) 下載 `duckdb_cli-windows-amd64.zip`，解壓縮出 `duckdb.exe` 並放入專案根目錄。
3. **啟動服務**：確保配置檔與前端樣板就緒後，直接雙擊 `PA1420_Monitor.exe`。系統即在背景自動啟動 HTTP (Port 5006)、UDP Syslog (Port 514) 以及 FTP 接收端 (Port 21)。
4. 使用瀏覽器訪問 `http://localhost:5006`。

---

**License**: [MIT License](https://opensource.org/licenses/MIT)
