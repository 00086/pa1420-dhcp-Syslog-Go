# PA-1420 智能監控聯防系統 (Go 原生高效版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的自動化監控與日誌分析系統。本系統使用 **Go 語言 (Golang)** 原生架構重構，具備極低的記憶體佔用與高併發處理能力。

系統整合了 DHCP 租約追蹤、ARP 聯防比對、硬體健康歷史監控，並導入 **Parquet 列式資料庫**、**UDP 514 Syslog 即時串流** 與 **Fast Segment Appender 極速分塊機制**，能以微秒級延遲穩定承載每日高達 **150 萬 ～ 170 萬筆** 的 Traffic 流量與 Threat 威脅日誌。

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





### 2. 海量日誌高效架構 (Parquet 列式儲存 + UDP 514 Syslog)

* **Fast Segment Appender（極速微秒即時分塊）**
* Syslog 接收引擎不再對百萬筆的當日主檔進行全量重複讀寫，而是直接寫入輕量化的獨立即時分塊（`traffic_YYYY-MM-DD_live_*.parquet`），單次落盤僅需 2～5 毫秒。
* 前端查詢與聚合引擎自動跨「每日主檔 + 當日即時分塊」進行秒級聯合檢索，確保即時性與零延遲。


* **動態背景整併機制（Consolidation）**
* 專為每日 150～170 萬筆規模調優，以 **60 個分塊（約 3～4 分鐘）** 為整併週期，由背景執行緒安靜去重合併回單一主檔。
* 降低 SSD 寫入放大損耗高達 75%，同時避免檢索鎖競爭（Lock Contention）。


* **狀態完全解耦（Decoupled Pipeline）**
* Syslog 實時吞吐指標與 API 回溯、手動擷取任務完全隔離，杜絕狀態覆蓋與全域死鎖（Deadlock）。


* **資安威脅日誌管理 (Threat Logs)**

* 自動與內部 DHCP IP 交叉比對，標註中毒設備的主機名稱與 MAC。


* 支援 `/api/threat-fetch-now` 立即手動同步最新威脅日誌。



### 3. 智慧接力歷史回溯 (Smart Backfill Engine)

* **先參後流（Pre-parsing Stream）**
* 修正 HTTP Chunked 串流下的參數讀取順序，優先解析 URL Query 與 POST 參數後再開啟即時傳輸，支援精準自訂起點。


* **當日智慧斷點續傳（Smart Resume）**
* 指定日期回溯時，系統自動探測該日 Parquet 檔案中已存在的最舊連線時間點，自動接關往前回溯，完全不浪費 API 額度重抓已有資料。


* **狀態檔輕量協同（IPC Coordination）**
* 核心引擎透過 `backfill_status.txt` 實時向作業系統拋出推進進度，批次腳本無需依賴脆弱的文字解析即可精準判斷邊界與極限。


* **全自動硬體邊界探測**
* 自動適配 PA-1420 內部的 FIFO 循環覆蓋限制（如流量日誌覆蓋至 10/8 上下），一旦防火牆無更早日誌即回傳 `LIMIT` 標記並安全終止回溯。



---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go                     # 程式進入點、排程器與背景服務初始化
├── core.go                     # 核心邏輯 (PA API、Parquet 讀寫、Fast Segment Syslog 引擎)
├── routes.go                   # Web 路由、API 端點與分塊串流回溯
├── go.mod / go.sum             # Go 模組依賴清單
├── auto_backfill_day.bat       # 指定日期區間回溯腳本 (至當日 00:00:00 止)
├── auto_backfill_to_limit.bat  # 全自動歷史接力回溯腳本 (直至硬體極限)
├── backfill_status.txt         # 回溯狀態即時中繼檔 (程式自動維護)
├── pa1420key.txt               # 防火牆 IP、介面與 API Key 配置檔
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP、硬體健康日誌)
├── traffic_logs/               # 流量日誌目錄 (按日保存之 Parquet 主檔與 Live 分塊)
├── threat_logs/                # 威脅日誌目錄 (按日保存之 Parquet 威脅主檔)
└── templates/                  # 前端 Web 介面 (Pongo2 樣板、Bootstrap 5)

```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)



首次啟動時系統會自動建立範本檔，請依序配置三行內容：

```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 API Key）...==

```

* **第 1 行**：PA-1420 管理介面 IP。


* **第 2 行**：監控之 DHCP 介面（例如 `ethernet1/1`；欲監控所有介面請填 `all`）。


* **第 3 行**：PA-1420 XML API 金鑰。



---

## 🔄 歷史日誌回溯與自動化腳本說明

針對 PA-1420 的海量連線回溯需求，專案內建兩款免除字元編碼異常、支援斷點續傳的自動化批次檔：

### 1. 單日目標回溯：`auto_backfill_day.bat`

專門用於「補齊特定整天（或當天某時間段前）的日誌」，每批次抓取 5 輪（25,000 筆），一旦推進至當日 **`00:00:00`**（或跨入前一天）即自動安全停機。

* **整日自動續傳（推薦）**：若該日已存在部分日誌，腳本自動自當日最遠記錄點接力往前補；若無記錄則自 `23:59:59` 開始：
```cmd
auto_backfill_day.bat 2026-10-23

```


* **指定起點時間開始倒推**：
```cmd
auto_backfill_day.bat 2026-10-23 18:30:00

```


* **指定回溯資安威脅日誌 (Threat)**：
```cmd
auto_backfill_day.bat 2026-10-23 threat

```


*(亦可雙擊直接執行，透過互動介面依序輸入參數)*

### 2. 全自動歷史推進：`auto_backfill_to_limit.bat`

無需指定任何日期或時間，系統會自動定位資料庫現存最舊的一筆連線，持續不間斷地跨日往過去深挖，直到遭遇 PA-1420 實體硬體儲存極限（例如抵達 10/8 無更早資料）為止。

* **全自動回溯連線流量 (Traffic)**：
```cmd
auto_backfill_to_limit.bat

```


* **全自動回溯資安威脅 (Threat)**：
```cmd
auto_backfill_to_limit.bat threat

```


*(💡 執行期間可隨時按下 `Ctrl + C` 中斷，下次啟動將自動銜接斷點續跑)*

---

## 🛠️ API 端點快速參考

| 方法 | API 路徑 | 參數範例 | 說明 |
| --- | --- | --- | --- |
| `POST` | `/api/traffic-fetch-now` | `count=5000` | 立即自 PA-1420 擷取當前最新連線並入庫（預設 2500 筆，最高 5000 筆）。

 |
| `POST` | `/api/threat-fetch-now` | `count=5000` | 立即自 PA-1420 擷取當前最新資安威脅並入庫（最高 5000 筆）。 |
| `POST` | `/api/traffic-backfill` | `rounds=5&date=2026-10-23` | 分塊串流回溯流量日誌（支援 `before`、`date` 與 `rounds`）。 |
| `POST` | `/api/threat-backfill` | `rounds=5&before=2026-08-27+18:00:00` | 分塊串流回溯資安威脅日誌。 |
| `GET` | `/api/syslog-status` | *(無)* | 查詢 UDP 514 即時接收與當批落盤統計。

 |
| `GET` | `/api/traffic-query` | `date=2026-10-23&page=1&per_page=50` | 查詢指定日期之聚合流量統計、直方圖與日誌列表。 |

---

## 🚀 專案編譯與發布 (Go Build)



Go 語言具備跨平台靜態編譯優勢，編譯後為單一原生執行檔，無需安裝 Python 或虛擬環境。

### 1. 下載與整理依賴套件



在專案根目錄執行：

```cmd
go mod tidy

```

### 2. 編譯為高最佳化單一執行檔 (.exe)



使用去除符號表與除錯標籤的參數編譯，大幅縮減體積：

```cmd
go build -ldflags "-s -w" -o PA1420_Monitor.exe .

```

### 3. 部署與正式啟動



1. 將編譯出的 `PA1420_Monitor.exe`、批次檔與 `templates/` 樣板資料夾放置於伺服器同一目錄下。


2. 確認同目錄下已配置正確之 `pa1420key.txt`。


3. 執行 `PA1420_Monitor.exe`，系統即刻在背景啟動 HTTP 服務（Port: 5006）並持續監聽 UDP 514 連線。


4. 使用瀏覽器訪問：`http://localhost:5006` 即可進入監控儀表板。



---

## 📄 授權條款



本專案採用 **[MIT License](https://opensource.org/licenses/MIT)** 授權。可自由修改、整合與商業使用。