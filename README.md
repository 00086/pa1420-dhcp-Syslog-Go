# PA-1420 / PA-5250 防火牆日誌分析與 DHCP 監控系統 (Go 湖倉進階版) 📡

專為 Palo Alto Networks PA-1420 次世代防火牆設計的日誌分析與網路監控系統。本專案最初以 **DHCP 租約管理與 ARP 聯防比對** 為核心基礎開發，後續採用 **Go 語言 (Golang)** 原生架構全面重構，並正式升級為現代化的 **Lakehouse (資料湖倉) 冷熱分離架構**[cite: 23]。

系統無縫整合了 **HTTP JSON Webhook 即時串流**、**UDP 514 Syslog**、**Parquet 列式壓縮** 與 **DuckDB 向量化 SQL 引擎**，不僅能以極低記憶體佔用穩定承載每日高達 400 萬筆以上的 Traffic 流量與 Threat 威脅日誌，更具備 100% 原始報文留存的資安稽核能力[cite: 23]。

> **🚀 旗艦級雙機型與跨平台架構演進（PA-1420 & PA-5250 / Windows & Linux）**：
> 系統現已全面支援 **Windows (.exe)** 與 **Linux 原生 ELF 執行檔** 跨平台編譯部署，並具備**防火牆硬體型號自動偵測引擎**，可無縫適配標準機型（**PA-1420**）與高吞吐旗艦機型（**PA-5250 / PA-5200 / PA-5400 / PA-7000**）。透過 **64MB UDP 核心接收緩衝區**、**無鎖單專職 I/O 管線**、**DuckDB ETL/UI 雙通道併發隔離** 以及 **Parquet Footer Metadata 時間窗剪枝**，在 Linux 生產環境下已實測穩定承載單日 **22 億筆以上（22+ GB/日）** 連線日誌且達成**核心層級零掉包**，前端檢索依然維持毫秒級秒開體驗。

---

## 🆕 更新亮點
* **🏢 PA-1420 與 PA-5250 雙機型自適應引擎**：啟動時自動向防火牆查詢並識別真實硬體型號 (`getFWModelName` / `isHighEndFirewall`)。針對 **PA-1420** 維持每日單檔整併與防護型 API 輪詢間隔（600ms / 1.5s）；針對 **PA-5250** 等高階機種自動啟用旗艦極速模式（API 輪詢縮減至 200ms、分時熱檔 `_00`~`_23` 獨立儲存與保護），跨日整併時自動保留分時主檔不動，僅將零碎 Syslog 分塊融合為獨立歸檔，徹底杜絕數十 GB 重寫逾時。
* **🐧 Windows / Linux 跨平台原生支援與核心網路調優**：全面解除 Windows API 依賴，支援 `GOOS=linux` 單一執行檔部署與 `systemd` 守護服務。在 Linux 下自動切換為 30 分鐘高精度切片排程，並直接讀取 Linux 核心 `/proc/net/arp` 提取區網實體 MAC 位址（毫秒級提取，零外部工具依賴），ARP 介面自動標註為 `Linux ARP` / `Windows ARP`。
* **📡 64MB UDP 核心緩衝區與無鎖零掉包接收管線**：UDP 514 監聽器配置 `64MB` Socket 接收緩衝區 (`SO_RCVBUF`)，搭配「單一專職極速 I/O 讀取器 + 100,000 容量緩衝通道 + 多核心並行剖析池 (`runtime.NumCPU()`)」。全面捨棄高 GC 負擔的 `csv.Reader`，改用零配置字串分割極速解析，每 2 秒或達 5,000 筆自動批次寫入日期子目錄 (`traffic_logs/YYYY-MM-DD/`)，在 25,000+ EPS 高密度流量下達成 `RcvbufErrors` 零增長。
* **🛡️ 冷熱雙軌自動反哺與自癒對賬巡檢 (`reconcileSyslogMissingRecords`)**：針對 PA-5250 每日數十億筆流量，建立「30 分鐘切片 ➔ 整點 RAW 冷主檔 ➔ 14 欄熱主檔」全自動管線。整點冷檔一旦完成，立即動態偵測表頭（同時相容具名表頭與無表頭 `column0`~`column46`）萃取 14 欄熱資料，與即時 Syslog 進行 `ROW_NUMBER()` 全量去重融合。內建開機全盤對賬與每半小時巡邏 (`ReconcileMissingHours`)，自動補抓缺失切片、補合延遲完成的整點切片，並自動補轉缺失的熱資料檔案。
* **⚡ Parquet Footer 時間窗剪枝與確定性排序**：針對單日超過 20 億筆（22GB+）的巨量熱資料，查詢引擎讀取 Parquet 檔尾 Metadata (`parquet_file_metadata` 與 `parquet_metadata` 的 `stats_min`/`stats_max`)，耗時 `< 10ms` 即算出目標時間邊界並進行 Row Group 區塊剪枝，直接跳過 99.6% 舊區塊，同時保留完整 `ORDER BY timestamp DESC` 確定性排序，徹底消除非當日與當日切換檢索時的紀錄時間跳動問題。
* **🔀 DuckDB ETL / UI 雙通道併發隔離與整併瞬時重試容錯**：將重型背景轉檔 (`COPY`) 與前端互動查詢 (`SELECT`) 拆分為獨立信號量通道（`duckdbETLSem` 限制 1 路獨佔 32GB–45GB 記憶體防爆；`duckdbUISem` 允許 3 路並行各配 8GB 記憶體）並隔離各自獨立的 `duckdb_temp/job_*` 暫存目錄，確保轉檔期間前端查詢零阻塞。同時內建**背景檔案整併自動重讀容錯機制**（後端自動重試 3 次 + 前端靜默重試），徹底消除微整併刪除舊 `_live_` 碎片瞬間造成的 `Cannot open file` 報錯。
* **🔎 PA Monitor 風格統一查詢命令列與 CIDR / 萬用字元過濾**：流量頁面 (`/traffic`) 升級為全寬單一查詢命令列，支援 `and` 多條件串接與 **10 大欄位過濾鍵名**（`src`、`natsrc`、`dst`、`natdst`、`dport`、`app`、`action`、`zone`、`rule`、`reason`）。點擊明細表格任一欄位自動組裝並填入查詢列（呈現淺黃提示框，待按下「執行檢索」才正式查詢，組合條件期間自動暫停背景自動更新）。IP 查詢原生支援 **CIDR 網段**（如 `192.168.1.0/24` 結合前綴剪枝與 32-bit 整數區間運算）、**萬用字元**（`*` 與 `?`）及精準單一 IP 比對；動作過濾嚴格區分 `allow`、`deny` 與 `drop`，剔除 `reset-*` 干擾。
* **📜 WORM 不可變湖倉稽核中心與冷轉熱互動維護 (`/audit`)**：新增湖倉切分與整併稽核頁面，完整記錄 `chunk切片`、`分時parquet`、`rollup整併`、`14欄熱資料` 與 `NAS切分` 的執行狀態、毫秒級 Metadata 精確處理筆數 (`num_rows`)、容量、耗時與重試控制。內建**「冷轉熱維護」互動視窗**，可自動掃描跨平台冷資料目錄並展開逐小時檔案清單，支援單選、多選與缺失時段一鍵重建熱資料。
* **🕵️ 單一主機 360° 全景鑑識時序軸 (`/timeline`)**：輸入任意內網或外網 IP，即可跨 System (DHCP)、Threat、Config 與 Traffic 四大 Parquet 湖倉進行全時間軸關聯鑑識，並自動串接 SQLite ARP/DHCP/DNS 資產庫反查主機名稱與實體 MAC。
* **🚀 多執行緒 Ping 掃描與 Windows 本機 ARP 融合**：針對跨網段或防火牆未及時學習到的設備，新增即時 Ping 範圍掃描 (支援 CIDR 與 IP 區間，預設 `192.168.1.1`)。以 40 個並發 Goroutine 極速喚醒區網，並自動調用 Windows 核心 `arp -a` 提取實體 MAC 位址，無縫與 PA-1420 防火牆 ARP 紀錄進行聯集合併與持久化落盤[cite: 23]。
* **🎯 跨網段 MAC 手動維護與 Excel 式直接編輯**：全網 IP 資產清冊新增「實體網卡 MAC」就地編輯功能。專門解決 L2 ARP 無法跨越路由器 (不同 Subnet/VLAN) 取得 MAC 的痛點，手動輸入後自動賦予最高優先級，並永久保存於 SQLite 資料庫[cite: 23]。
* **🔍 ARP 五大獨立指標卡片與離線設備追蹤**：將 ARP 聯防升級為 5 大精確指標（總設備、DHCP、固定 IP、疑似私設、衝突），並支援比照 Traffic 頁面的「點擊光暈高亮動態篩選」。獨創「離線固定 IP 反查機制」，能自動從 SQLite 歷史快取 (`dhcp_leases` 與 `arp_records`) 提取關機設備的 MAC 位址，確保線上/線下資產總數 100% 嚴格對齊[cite: 23]。
* **🛡️ 動態資安預警與 SQLite 持久化**：預警中心 (`/security`) 全新上線，支援 6 大威脅 (DDoS、暴力破解、Port Scan、巨量外洩等) 靈敏度閥值 UI 動態設定。設定值自動寫入 SQLite (`flow_security_settings`) 永久保存，並由 Go 背景協程每 30 秒即時套用生效[cite: 23]。
* **📊 時間錨定全量聚合圖表與極速分頁**：流量軌跡檢索 (`/search`) 導入「結束時間凍結」技術與 1:1 標準 10 頁滑動分頁，徹底杜絕時間窗錯位。點擊圖表時，DuckDB 瞬間對全域時間窗內（如數萬筆）進行向量聚合，精準繪製時序波動、Top 6 App 圓餅圖與 Top 8 Port 長條圖[cite: 23]。
* **⚙️ 系統紀錄 (System) 與組態變更 (Config) 湖倉模組全面上線**：正式納管 `/system` 與 `/config` 分析頁面，後端具備專屬 Parquet 列式儲存、DuckDB 向量化檢索、Syslog 514 自動分流落盤與背景定時整併能力，構築完整的四大日誌監控支柱[cite: 23]。
* **🎯 DuckDB 局部時間窗隔離去重與防 OOM 引擎**：API 歷史回溯 (`auto_backfill`) 導入 `.tmp` 子目錄隔離檢測機制，杜絕通配符自我誤判比對。直接透過 DuckDB 在極窄時間窗內進行向量化比對，徹底消除 Go 陣列讀取造成的記憶體溢出 (OOM)，並能持續向前深挖已記錄區間，精準捕獲重啟或中斷期間的零碎缺漏日誌[cite: 23]。
* **🧭 頂部導覽列整合式功能下拉選單**：因應模組擴充並釋放垂直/水平檢視空間，將 DHCP、流量、威脅、系統、組態、軌跡檢索、資安預警及 NAS 匯入等所有模組收納為高質感整合式下拉選單，並 1:1 完整保留專屬圖示與色彩識別[cite: 23]。
* **📋 全網 IP/MAC 資產靜態庫與一鍵匯出**：將 PA-1420 擷取之 ARP 紀錄（含私設 / 固定 IP）自動落盤寫入 `arp_records`。彈窗提供三級聯防反查 (DHCP ➔ ARP ➔ DNS 快取)，並支援 `/api/tools/export-network-devices` 匯出全網 CSV[cite: 23]。
* **🧠 公網 IP 機構智能識別**：右鍵點擊任意公網 IP (如 `8.8.8.8` 或 `140.111.x.x`)，自動進行 rDNS 反查並秒級辨識所屬組織單位 (如 Google、教育部 TANet、微軟、Cloudflare 等)[cite: 23]。
* **🌐 NAS 歷史日誌單檔循序佇列匯入**：Web 介面支援按住 `Ctrl/Shift` 一次選取多個 Synology NAS 匯出檔 (.txt/.csv)。系統採用**單檔循序串流架構（傳送一個、處理一個、立即釋放）**，徹底消除數十 GB 同時上傳造成伺服器記憶體與磁碟崩潰問題，並自動依 PA 真實時間「逐日自動切分落盤」[cite: 23]。
* **⏱️ 原生事件時間精準分類與排序 (Time-Sorting)**：全面統一以 PA 防火牆內部的真實事件時間（`Generate Time`）為唯一基準，結合 DuckDB 外部排序引擎，自動將拆分後的文字檔依 `00:00:00 -> 23:59:59` 進行時間序列重整與覆寫，免除 NAS 接收延遲或跨日亂序干擾[cite: 23]。
* **🚀 巨量文字檔極速檢視器 (BigLogViewer)**：專為 4GB+ 巨大文字檔設計的獨立檢視引擎。內建 Notepad++ 風格雙向螢光檢索（上一個 / 下一個）、全域真實行號精確定位與 10 頁滑動導覽，數百萬行日誌隨點隨開零卡頓[cite: 23]。
* **🎯 百萬級精確報文錨定解析**：捨棄傳統死板的字元偏移量，改以 `,TRAFFIC,` 與 `,THREAT,` 特徵錨定技術，並動態補正 117 欄位，徹底解決 Synology 匯出格式前綴變動導致的漏抓問題（實測將 340 萬筆被誤濾的日誌 100% 完美還原）[cite: 23]。
* **🔄 DuckDB 全自動背景整併 (Auto-Consolidation)**：新增每小時整點觸發的背景維護引擎，以及 CLI 匯出後的即時整併。系統會自動將零碎的即時串流塊 (`_live_`) 與臨時檔 (`_nas_`) 執行嚴格去重，合併為每日單一純淨 ZSTD 主檔[cite: 23]。
* **📅 極致流暢的原生 UI 體驗**：前端查詢日期輸入全面升級為 HTML5 原生月曆挑選器 (`showPicker`)，並整合 `<` (前一日) 與 `>` (後一日) 快速切換按鈕，點擊立即無縫檢索[cite: 23]。
* **📂 動態相對路徑支援**：CLI FTP 高速匯出 (`ftppa.bat`) 已全面解耦絕對路徑，採用動態生成與自動銷毀的 `ftp_data/` 相對目錄，程式搬到任何磁碟機皆可隨插即用[cite: 23]。

---

## 🌟 系統核心功能特性

### 1. DHCP 網路租約與 ARP 聯防
**本系統最初開發的核心基礎模組**，專注於內部網路的實體設備與 IP 分配安全[cite: 23]：
* **DHCP 租約追蹤**：排程自動透過 XML API 擷取防火牆最新 DHCP 租約，自動排除重複紀錄並建立完整的設備歷史上線軌跡，消除跨日租約誤判[cite: 23]。
* **ARP 交叉聯防比對與資產庫**：即時比對防火牆的 `<show><arp><all/></show>` 紀錄 **（並可疊加 Windows / Linux 跨平台多執行緒 Ping 掃描與本機 ARP `/proc/net/arp` / `arp -a` 結果）** 並自動寫入 `arp_records` 靜態庫。精準揪出「手動設定固定 IP 的未授權私設設備」或「IP/MAC 衝突」，**內建 5 大指標互動卡片與離線設備歷史 MAC 智能反查，且全表格支援 Excel 式就地編輯（包含 MAC 手動覆寫）**，並支援一鍵匯出 CSV 全網資產清冊[cite: 23]。
* **背景 DNS 智能解析**：內建多執行緒非同步 DNS (PTR) 查詢引擎，自動快取並解析內部網路的主機名稱 (Hostname)，讓生硬的 IP 位址轉化為具備識別度的設備名稱[cite: 23]。

### 2. Lakehouse 冷熱分離架構 (Cold-Hot Data Storage)
系統針對四大日誌模組（Traffic 流量、Threat 威脅、System 系統、Config 組態），全面導入企業級冷熱分離雙軌落盤機制[cite: 23]：
* **熱資料分析層 (`traffic_logs/`, `threat_logs/`, `system_logs/`, `config_logs/`)**：
  Go 後端將日誌精煉為強型別的純淨結構，寫入 ZSTD 壓縮的 Parquet 主檔（在 PA-5250 高密度場景下自動依日期與小時分片為 `traffic_logs/YYYY-MM-DD/traffic_YYYY-MM-DD_HH.parquet`）。DuckDB 查詢引擎只需讀取特定欄位（如 Bytes、IP），實現**零 Go 記憶體指標負擔**，結合 Footer Metadata 剪枝將十億級 24 小時直方圖與首屏明細查詢極限壓縮至 **0.02 ~ 0.1 秒**[cite: 23]。
* **冷資料稽核層 (`traffic_raw_logs/`, `threat_raw_logs/`, `system_raw_logs/`, `config_raw_logs/`)**：
  系統將接收到的 100% 原始封包（JSON / CSV / XML）原封不動寫入 `raw_content` 或全欄位 RAW Parquet 並高壓落盤。專供資安事件複查、封包還原佐證與法規留存。即使防火牆韌體升級新增了未知欄位，底層證據也絕對不漏接[cite: 23]。

### 3. 多重接收引擎與智慧去重 (Deduplication)
* **Webhook & Syslog 雙軌並行接收**：
  支援最新 HTTP JSON Webhook (Port 5006) 與傳統 UDP Syslog (Port 514) 同時運作。Syslog 514 UDP 接收器具備多軌自動分流引擎，即時識別 TRAFFIC、THREAT、SYSTEM 與 CONFIG 封包。各軌共用極速記憶體佇列，每 2～3 秒或達 5,000 筆自動非同步批次落盤為輕量化的即時分塊 (`live_*.parquet`)，單次落盤僅需 2～5 毫秒[cite: 23]。
* **DuckDB 全域視窗去重 (True Sessions)**：
  透過 SQL 視窗函數 `ROW_NUMBER() OVER (PARTITION BY timestamp, source, destination, to_port, session_id, action, bytes)`，系統能自動在背景將「連線 Start/End 雙重報送」、「Syslog 與 API 雙管重複抓取」的冗餘雜訊徹底清洗（例如將 380 萬筆原始紀錄擠乾水分，壓實為 200 萬筆真實獨立會話），確保統計數據絕對精準[cite: 23]。

### 4. 智慧流量軌跡檢索與資安預警中心 🌟
* **流量軌跡深鑽檢索 (`/search`)**：超越傳統系統的 5,000 筆限制。提供毫秒級的 Port、App-ID 左鍵點擊連動過濾與右鍵 IP 身分反查。內建 DuckDB 向量即時聚合圖表，視覺化呈現每分鐘流量起伏[cite: 23]。
* **資安威脅預警防禦 (`/security`)**：過濾海量 Informational 噪音，專注於 Critical / High 重大威脅。Go 背景協程每 30 秒自動偵測「Port Scan、DDoS、密碼爆破、巨量資料外洩、內網橫向擴散、採礦木馬」等 6 大異常行為[cite: 23]。

### 5. 智慧接力歷史回溯 (Smart Backfill Engine)
* **當日智慧斷點續傳（Smart Resume）**：
  指定日期回溯時，系統會自動探測該日 Parquet 檔案中最舊的時間點（例如 18:30:00），並自動接關往前回推至 00:00:00，絕不浪費 API 額度重抓已存在的資料。回溯引擎已完整支援 traffic、threat、system 與 config 四大資料流，自動向前深挖並完成 ZSTD 壓縮落盤[cite: 23]。
* **跨格式無縫融合**：
  透過 API 回溯的原生 XML 日誌，經過 Go 引擎正規化後，能與 Webhook 即時寫入的 JSON 日誌完美融合於同一張 Parquet 數據表中，對前端查詢完全透明[cite: 23]。

### 6. 內建輕量化 FTP 伺服器與 CLI 高速自動化匯出 🌟 
針對單日百萬至數十億筆歷史日誌的「大補帖式」還原，系統已整合 **Go 原生內建 FTP 伺服器** 與 **SSH 模擬登入自動化** 引擎，達成零外部依賴的極速管線[cite: 23]：
* **純 Go 內建 FTP 接收器 (Port 21)**：直接於 `PA1420_Monitor` 內部接管 Port 21 (支援 PASV / PORT 模式)，徹底免除安裝 Python 或第三方 FTP 軟體的需求[cite: 23]。
* **自動化 PTY 虛擬終端登入**：自動透過 SSH 連線至 PA 防火牆、請求 PTY 虛擬終端，並模擬管理員敲擊 `ftp export log...` 指令，將巨量資料觸發串流傾印[cite: 23]。
* **全自動湖倉整合與空間清理**：自動監控並接收防火牆切分的 CSV 區塊。接收完畢後 0.1 秒內由 DuckDB 向量化引擎自動接手，執行全核心平行冷熱分離，**並於完成後自動刪除臨時 CSV 與 `ftp_data` 暫存檔，隨即呼叫背景執行緒完成終極去重整併[cite: 23]。**

### 7. FW 原生 CSV 與 NAS Syslog 雙軌無損直轉引擎 🌟 
為徹底解決 DuckDB 在解析巨量資安日誌時常遇到的「未閉合雙引號導致欄位錯位」與「韌體版本欄位數不一致」導致大量行數被靜默捨棄的問題，系統設計了雙軌解耦的直轉引擎[cite: 23]：
* **FW 原生匯出 (CLI/FTP)**：維持 `read_csv_auto` 載入原生 CSV 表頭，並強制關閉引號解析 (`quote='', escape=''`)，確保高達 117 欄的原生欄位全數對齊不遺漏[cite: 23]。
* **NAS 歷史日誌匯入 (TXT)**：完全捨棄傳統「強加 63 欄固定表頭中繼 CSV」的做法。改以 `read_csv` 搭配不可見字元 (`delim=E'\x1f'`) 將整行日誌視為單一字串載入，後續利用 DuckDB 的 `split_part` 函數精準切分。完全免疫欄位數量超標（PAN-OS 10+ 擴充欄位）與特殊字元干擾，實測 225 萬筆瑕疵資料可 100% 完美去重還原為 211 萬筆真實會話，資料零遺失[cite: 23]。

### 8. PA-5250 旗艦級高密度湖倉與冷熱雙軌自動反哺架構 🌟
專為企業核心防火牆（PA-5250 等級，單日流量可達數十億筆 / 20GB+）打造的分時切片與雙軌融合引擎：
* **分時切片自動排程 (`StartAutoExportScheduler`)**：Linux 環境每 30 分鐘（`:00` / `:30`）自動觸發 CLI 傾印切片，Windows 環境每 10 分鐘自動切片，透過容量 288 的循序工作佇列 (`sliceTaskQueue`) 配合 SQLite 標註庫 (`export_checkpoints`) 確保任務零重複執行。
* **整點自動融合與雙軌反哺 (`reconcileSyslogMissingRecords`)**：當該小時的切片全數集齊後，自動融合為整點冷主檔 (`traffic_raw_YYYY-MM-DD_HH.parquet`)，並立即非同步啟動 14 欄熱資料萃取，與即時 Syslog 514 接收的碎片進行全量去重融合，產出標準分時熱主檔 (`traffic_YYYY-MM-DD_HH.parquet`)，確保即時 Syslog 突波零遺漏。
* **延遲切片與缺漏自動自癒 (`ReconcileMissingHours`)**：每次整點巡檢與服務重啟時，自動掃描過去 24 小時磁碟狀態；若因網路波動或轉檔耗時較長導致切片延遲完成，系統會自動補合缺漏整點並補轉熱資料。

### 9. 網路層 64MB UDP 零掉包接收與無鎖多核心剖析管線 ⚡
* **核心層緩衝擴容**：UDP Socket 主動申請 `64MB` (`64 * 1024 * 1024`) 核心接收緩衝區，結合 Linux 核心 `net.core.rmem_max` 調優，有效吸收防火牆瞬間突發的數十萬筆封包浪潮。
* **I/O 與 CPU 運算完全解耦**：單一專職接收 Goroutine 以最高物理速率從 Kernel Socket 讀取封包並推入 `100,000` 容量通道；後端啟動等同於實體 CPU 核心數 (`runtime.NumCPU()`) 的並行剖析 Worker 進行無配置字串切割，徹底避免高併發下的記憶體碎片與掉包 (`RcvbufErrors`)。

### 10. PA Monitor 風格統一查詢命令列與 CIDR / 萬用字元精準檢索 🔍
* **單一命令列與點擊疊加條件**：`/traffic` 頁面採用 PA Monitor 風格統一查詢列，支援 `and` 串接 `src`、`natsrc`、`dst`、`natdst`、`dport`、`app`、`action`、`zone`、`rule`、`reason` 共 10 種欄位過濾。點擊表格任一儲存格可將條件自動組裝填入查詢列，按下「執行檢索」後才正式發起查詢。
* **智慧 IP 網段與萬用字元解析 (`buildIPFilterSQL`)**：支援標準 IPv4 CIDR 網段（如 `src:192.50.10.0/24`、自動加入前綴剪枝與 32-bit 整數區間比對）、星號與問號萬用字元（`dst:163.21.*`、`src:192.50.10.1?`）以及精準單一 IP 比對；並將 `action` 嚴格區分為 `allow`、`deny`、`drop`，排除 `reset-*` 干擾。

### 11. WORM 不可變湖倉稽核中心與單一主機 360° 全景鑑識 🛡️
* **不可變安全稽核 (`/audit`)**：所有背景切片、整點合併、冷轉熱反哺與 NAS 匯入皆寫入 Parquet 稽核庫，精準記錄實際處理筆數、容量、耗時與執行詳情，並提供前端「冷轉熱維護」互動視窗進行多日或分時重建。
* **主機 360° 全景鑑識 (`/timeline`)**：針對單一 IP 橫向串聯 DHCP 配發、ARP 實體位置、威脅攔截、組態異動與流量連線軌跡，實現秒級資安事件溯源。

---

## 🛠️ 獨立巨量日誌處理工具集 (Standalone Tools)

除了主系統外，專案已將兩支專為解決「數十 GB 巨量文字檔」而生的獨立工具統一歸檔於 `tools/` 資料夾中[cite: 23]：

1. **`tools/palogsplitter.go`**：
   * **功能**：專門吞吐 Synology 匯出的混合 Syslog 巨獸檔 (可達 50GB+)。採用極低記憶體串流掃描，嚴格依據防火牆真實時間（`Generate Time`）將日誌切分至各日期的獨立 TXT 檔[cite: 23]。
   * **自動排序**：切分完畢後，背景自動呼叫 DuckDB 將各日期的文字檔依照 `00:00:00` 至 `23:59:59` 進行精準的時間序列重整與覆寫[cite: 23]。
2. **`tools/bigLogviewer.go`**：
   * **功能**：專治 Windows 記事本或一般文字編輯器無法開啟的超大日誌檔 (2GB~4GB+)[cite: 23]。
   * **特性**：內建 Web 伺服器 (Port: 9090)，採用「稀疏索引」與「虛擬分頁」技術。頂端提供全域真實行號即時統計，支援像 Notepad++ / VS Code 般任意行號跳轉，並具備**高對比螢光雙向尋找（Shift+Enter / Enter）**，毫秒級定位命中資料[cite: 23]。

---

## 📊 四種匯出方式綜合評比 (PA-1420 / PA-5250 日誌提取策略)

在 Palo Alto 系統中提取日誌有多種方式，本系統目前已將最快的 **CLI FTP Export** 與自動化的 **XML API** 完美融合。各方式優劣對比如下[cite: 23]：

| 匯出方式 | 適合情境 | 速度評比 | 限制與優缺點 |
| :--- | :--- | :--- | :--- |
| **CLI (SCP / FTP Export)** | 大量歷史補檔、整天百萬至數十億筆還原 | ⚡ **極快** (幾分鐘搞定) | 需要有可連線的網路路由與本機 SCP/FTP 伺服器接收[cite: 23]。 |
| **Scheduled Export** | 全自動每日離線備份 | ⚡ **極快** (背景排程傳輸) | 屬於定期排程機制，無法當下隨按隨抓[cite: 23]。 |
| **WebUI CSV 匯出** | 臨時調查、單一 IP/事件調閱 | 🚀 **中等** | 受限於單次最大匯出筆數上限，超大資料無法一次匯出[cite: 23]。 |
| **XML API (自動接力回溯)** | 即時斷點續傳、自動整合進湖倉 | 🐢 **最慢** (每輪 5000 筆輪詢) | 程式整合度最高，但對 Management CPU 運算與網路往返負擔較大[cite: 23]。 |

---

## 🆚 架構升級：HTTP Webhook vs. UDP Syslog

本系統同時支援並強烈建議從傳統 Syslog 升級為 Palo Alto **HTTP JSON Webhook** 轉發。兩種傳輸模式的全方位對比如下[cite: 23]：

| 評比維度 | Syslog (UDP 514) | HTTP JSON Webhook (TCP 5006) 🌟 |
| :--- | :--- | :--- |
| **傳輸可靠度** | ❌ **不保證（掉包無通知）**。 | ✔️ **極高（TCP 重傳 + HTTP ACK）**[cite: 23]。 |
| **高流量承載能力** | ⚠️ 需配置 64MB 核心緩衝與無鎖佇列方能零掉包。 | ✔️ **優異（非同步佇列 + 毫秒級秒回）**[cite: 23]。 |
| **後端解析複雜度** | ❌ 繁瑣（CSV 逗號切割、防跳脫）。 | ✔️ **極簡（原生結構體直接對齊）**[cite: 23]。 |
| **韌體版本容錯** | ❌ 脆弱（欄位順序偏移即破壞資料）。 | ✔️ **強健 (Key-Value 格式完全解耦)**[cite: 23]。 |
| **安全性擴充** | ❌ 難以加密，極易偽造 (Spoofing)。 | ✔️ **高（隨時可無痛升級 HTTPS TLS 與 Token）**[cite: 23]。 |
| **冷熱資料分離** | ❌ 原始字串雜亂，需二次格式化。 | ✔️ **天然支援（JSON 字串直接壓縮落盤）**[cite: 23]。 |

---

## ⚡ 高併發與多執行緒架構 (Goroutines & Concurrency)

本系統深入運用 Go 語言原生的高併發優勢，透過 Goroutines 將任務分派至多核心平行運算[cite: 23]：

1. **DuckDB 3 路並行化 (`sync.WaitGroup`)**
   日誌檢索並非循序等待，而是同時發動 3 個獨立 Goroutine：執行緒 1 算總數與 Top 1 排行、執行緒 2 算直方圖、執行緒 3 撈取分頁明細。三個最耗時的 I/O 任務完全重疊，將查詢延遲縮減 30%~50%[cite: 23]。
2. **多執行緒網路掃描與 DNS 工作池 (Worker Pool)**
   針對區網 ARP 聯防發動包含高達 40 個並發 Worker 的 Ping 引擎極速喚醒網路；解析數千筆 IP 時，建立包含 15 個併發 Worker 的通道佇列，遇到 DNS 逾時的 IP 絕不會卡死主執行緒，保障介面與掃描流暢度[cite: 23]。
3. **生產者-消費者管線 (Lock-Free Atomics)**
   主監聽執行緒只負責快速接收解碼，以無鎖原子操作 (`atomic.AddInt64`) 推進萬級 Channel；後端 Consumer Goroutine 每 2～3 秒定時落盤，讀寫完全解耦，保障最高網路吞吐[cite: 23]。
4. **執行緒安全與鎖隔離**
   全域使用 `sync.RWMutex` (讀寫鎖保護排程狀態) 與 `sync.Mutex` (互斥鎖保護 Parquet 檔案覆寫)，確保資料一致性[cite: 23]。
5. **DuckDB ETL / UI 雙通道併發隔離 (`duckdbETLSem` & `duckdbUISem`)**
   將背景重型轉檔 (`COPY`) 限制為單通道執行（上限 32GB–45GB 記憶體）並隔離於專屬暫存資料夾 (`duckdb_temp/job_*`)，同時開放 3 路獨立 UI 查詢通道（每路 8GB 記憶體），徹底避免巨量轉檔期間阻塞前端網頁檢索。
6. **Parquet Footer Metadata 剪枝與整併瞬時重試容錯**
   優先透過 `parquet_file_metadata` 與 `parquet_metadata` 的 `stats_min`/`stats_max` 實現毫秒級直方圖統計與時間窗區塊剪枝；並針對微整併刪除舊 `_live_` 碎片造成的瞬時 `Cannot open file` 錯誤實作自動重試機制，確保高併發讀寫零報錯。

---

## 📁 專案目錄架構

```text
dhcpxml-go/
├── main.go                     # 程式進入點、排程器、HTTP 路由與內建 FTP 伺服器啟動
├── core.go                     # 核心邏輯 (64MB UDP 管線、Metadata 剪枝、雙通道 DuckDB、IP/CIDR 過濾)
├── routes.go                   # Web API 端點、Webhook 接收器、冷轉熱轉換與 360° 鑑識 API
├── cli_export.go               # PA-1420 / PA-5250 虛擬終端自動化登入、分時切片與冷熱雙軌反哺核心
├── audit.go                    # WORM 不可變湖倉稽核紀錄寫入、查詢與任務重試控制
├── ftp_server.go               # Go 原生輕量化 FTP 伺服器 (支援 PASV / PORT)
├── tools/                      # 🆕 獨立巨量日誌處理工具集
│   ├── palogsplitter.go        # PA 日誌自動分類 (依真實時間) 與 DuckDB 排序引擎
│   └── bigLogviewer.go         # 巨量日誌檔檢視器 (Web 介面 / 毫秒級跳轉)
├── go.mod / go.sum             # Go 模組依賴清單
├── duckdb.exe                  # 🦆 DuckDB 向量化查詢引擎 (Windows 版；Linux 請安裝 duckdb CLI)
├── PA1420_Monitor              # 🐧 Linux 64-bit 編譯執行檔 (放置於 /opt/pa_monitor/)
├── ftppa.bat                   # CLI 高速串流匯出批次檔 (相對路徑支援，自動去重)
├── auto_backfill_day.bat       # 單日歷史接力回溯批次檔 (XML API 方案，支援四大日誌)
├── auto_backfill_to_limit.bat  # 全自動跨日歷史推進批次檔 (XML API 方案，支援四大日誌)
├── sort_log.bat                # 獨立 DuckDB TXT 時間排序批次檔
├── pa1420key.txt               # 系統防護庫 (存放 PA IP、API Key、SSH 帳密與 FTP 帳密)
├── dhcp_records.db             # SQLite 資料庫 (DHCP、ARP 資產庫、系統狀態、資安閥值、切片標註庫)
├── ftp_data/                   # FTP 臨時接收資料夾 (動態建立，任務完成後自動銷毀)
├── duckdb_temp/                # DuckDB 獨立行程暫存隔離目錄 (查詢結束自動清理)
├── traffic_logs/               # 流量「熱資料」目錄 (按 YYYY-MM-DD 子目錄與分時 _00~_23.parquet 儲存)
├── traffic_raw_logs/           # 流量「冷資料」目錄 (按 YYYY-MM-DD 子目錄與原始 JSON/CSV/XML Parquet 儲存)
├── threat_logs/                # 威脅「熱資料」目錄
├── threat_raw_logs/            # 威脅「冷資料」目錄
├── system_logs/                # 🆕 系統紀錄「熱資料」目錄 (結構化 Parquet)
├── system_raw_logs/            # 🆕 系統紀錄「冷資料」目錄 (原始 XML Parquet)
├── config_logs/                # 🆕 組態紀錄「熱資料」目錄 (結構化 Parquet)
├── config_raw_logs/            # 🆕 組態紀錄「冷資料」目錄 (原始 XML Parquet)
├── audit_logs/                 # 🆕 WORM 不可變湖倉切分與整併稽核 Parquet 目錄
└── templates/                  # 前端 Web 介面 (Pongo2 樣板引擎)
    ├── base.html               # 🆕 共用框架 (整合式下拉功能選單與即時狀態看板)
    ├── dhcp.html               # DHCP 租約與 ARP 聯防管理前端 (含五大卡片篩選與跨平台 Ping 掃描)
    ├── devices.html            # 🆕 全網 IP 取得與設備資產清冊前端 (支援 MAC 手動與 Excel 編輯)
    ├── traffic.html            # 流量分析前端 (PA Monitor 統一查詢命令列 + 點擊欄位疊加 + 月曆切換)
    ├── threat.html             # 威脅分析前端 (前後日切換)
    ├── system.html             # 🆕 系統紀錄分析與即時動態追蹤前端
    ├── config.html             # 🆕 組態變更紀錄稽核前端
    ├── search.html             # 流量通訊軌跡深鑽檢索與全量聚合圖表前端
    ├── security.html           # 資安威脅預警、動態閥值設定與重大防禦中心前端
    ├── timeline.html           # 🆕 單一主機 360° 全景鑑識時序軸前端
    └── audit.html              # 🆕 湖倉切分、整併稽核與冷轉熱互動維護前端
```

---

## ⚙️ 防火牆連線配置 (`pa1420key.txt`)

首次啟動時系統自動建立範本檔，為確保 API 連線與自動化 SSH / FTP 功能正常運作，請依序配置七行內容[cite: 23]：

```text
192.168.1.1
ethernet1/1
LUFRPT14MW55QW...（您的 PA-1420 / PA-5250 API Key）...==
FWusername
（您的防火牆 SSH 密碼）
username
password
```

*(第 1 行: 防火牆 IP | 第 2 行: 監控介面 | 第 3 行: API 金鑰 | 第 4-5 行: PA SSH 帳密 | 第 6-7 行: 內建 FTP 帳密)*[cite: 23]

---

## 🔄 API 端點與命令列 (CURL) 呼叫參考

系統提供完整 HTTP API，防火牆或外部系統可直接呼叫，亦可透過 Windows `curl.exe` 或 Linux `curl` 執行自動化排程[cite: 23]：

### 1. Webhook 接收端點 (供 PA-1420 / PA-5250 Log Forwarding 設定)

* **流量日誌 (Traffic)**：`POST http://<伺服器IP>:5006/api/webhook/traffic`[cite: 23]
* **威脅日誌 (Threat)**：`POST http://<伺服器IP>:5006/api/webhook/threat`[cite: 23]
*(伺服器接收到 JSON Payload 後會立即秒回 HTTP 200 OK，並於背景非同步執行冷熱分流落盤)*[cite: 23]

### 2. 即時最新日誌擷取 API (Fetch Now)

立即向防火牆拉取「當下」最新產生的高達 5000 筆日誌並寫入 Parquet（適用於無 Webhook 轉發時的定時排程抓取）[cite: 23]。

* **擷取最新流量 (Traffic)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/traffic-fetch-now](http://127.0.0.1:5006/api/traffic-fetch-now) -d "count=5000"
```

* **擷取最新資安威脅 (Threat)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/threat-fetch-now](http://127.0.0.1:5006/api/threat-fetch-now) -d "count=5000"
```

* **擷取最新系統紀錄 (System)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/system-fetch-now](http://127.0.0.1:5006/api/system-fetch-now) -d "count=5000"
```

* **擷取最新組態紀錄 (Config)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/config-fetch-now](http://127.0.0.1:5006/api/config-fetch-now) -d "count=5000"
```

### 3. 歷史日誌單輪回溯 API (Backfill)

觸發背景引擎執行 1 輪 (`1 round = 5,000 筆`) 的歷史回溯，自動偵測 Parquet 最舊斷點向過去深挖[cite: 23]。

* **回溯歷史流量 (需指定日期)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/traffic-backfill](http://127.0.0.1:5006/api/traffic-backfill) -d "rounds=1&date=2026-10-24"
```

* **回溯歷史威脅 (全自動銜接，無須指定日期)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/threat-backfill](http://127.0.0.1:5006/api/threat-backfill) -d "rounds=1"
```

* **回溯歷史系統紀錄 (需指定日期)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/system-backfill](http://127.0.0.1:5006/api/system-backfill) -d "rounds=1&date=2026-10-24"
```

* **回溯歷史組態變更 (需指定日期)**：
```cmd
curl.exe -X POST [http://127.0.0.1:5006/api/config-backfill](http://127.0.0.1:5006/api/config-backfill) -d "rounds=1&date=2026-10-24"
```

### 4. 湖倉稽核、冷轉熱維護與 360° 鑑識 API

* **查詢湖倉稽核明細**：`GET /api/audit-query?date=2026-11-13&status=all&category=all`
* **手動觸發缺漏切片對賬與補齊**：`POST /api/audit/reconcile -d "hours=0"` (`0` 為全天盤點，`>0` 為回溯最近 N 小時)
* **掃描可用冷資料清單**：`GET /api/cold-archives/list`
* **手動冷資料轉換熱資料**：`POST /api/cold-to-hot -d "date=2026-11-13"`
* **單一主機 360° 全景鑑識**：`GET /api/host-timeline?ip=192.50.10.162&date=2026-11-13`

---

## 🔄 自動化日誌匯出與回溯腳本 (.bat)

專為 Windows 環境設計的斷點續傳純 CMD 自動化腳本[cite: 23]：

### 1. CLI 高速匯出與湖倉自動整合（推薦使用🌟）

透過內建 FTP 伺服器與 PTY 虛擬終端，單日百萬筆連線僅需 2~3 分鐘即可完成匯出、冷熱分離與 DuckDB 壓縮落盤[cite: 23]。

* **腳本：`ftppa.bat`**
```cmd
ftppa.bat 2026-10-24           (預設匯出 traffic 流量日誌)
ftppa.bat 2026-10-24 threat    (指定匯出 threat 威脅日誌)
ftppa.bat                      (無參數執行時將提供互動式選單)
```

### 2. XML API 歷史回溯方案

採用 API 輪詢機制，適合即時少量補檔或斷點續傳。腳本已全面支援 `traffic`、`threat`、`system` 與 `config` 四大類別切換[cite: 23]：

* **單日目標回溯：`auto_backfill_day.bat`**
遞迴推進，直到跨越當日 00:00:00 自動停機[cite: 23]。
```cmd
auto_backfill_day.bat 2026-10-24
auto_backfill_day.bat 2026-10-24 18:30:00  (指定倒推起點)
auto_backfill_day.bat 2026-10-24 threat    (威脅日誌專用)
auto_backfill_day.bat 2026-10-24 system    (系統日誌專用)
auto_backfill_day.bat 2026-10-24 config    (組態日誌專用)
```

* **全自動跨日歷史推進：`auto_backfill_to_limit.bat`**
系統自動深挖過往天數，直到遭遇防火牆實體硬體儲存 FIFO 極限[cite: 23]。
```cmd
auto_backfill_to_limit.bat
auto_backfill_to_limit.bat threat          (威脅日誌一路向前深挖)
auto_backfill_to_limit.bat system          (系統日誌一路向前深挖)
auto_backfill_to_limit.bat config          (組態日誌一路向前深挖)
```

---

## 🚀 專案部署與啟動指南

### 一、 Windows 環境部署

1. **編譯 Go 主後端程式**：
```cmd
go mod tidy
go build -trimpath -ldflags="-s -w" -o PA1420_Monitor.exe .
```

2. **編譯獨立巨量日誌工具 (選擇性)**：
```cmd
go build -ldflags="-s -w" -o PA_Log_Splitter.exe tools\palogsplitter.go
go build -ldflags="-s -w" -o BigLogViewer.exe tools\bigLogviewer.go
```

3. **準備 DuckDB 查詢引擎**：前往 [DuckDB 官方 GitHub Releases](https://github.com/duckdb/duckdb/releases/latest) 下載 `duckdb_cli-windows-amd64.zip`，解壓縮出 `duckdb.exe` 並放入專案根目錄[cite: 23]。
4. **啟動服務**：確保配置檔與前端樣板就緒後，直接雙擊 `PA1420_Monitor.exe`。系統即在背景自動啟動 HTTP (Port 5006)、UDP Syslog (Port 514) 以及 FTP 接收端 (Port 21)[cite: 23]。
5. 使用瀏覽器訪問 `http://localhost:5006`[cite: 23]。

### 二、 Linux 生產環境部署與核心網路調優 (PA-5250 高吞吐推薦)

1. **跨平台編譯 Linux 執行檔（於 Windows 開發機執行）**：
```cmd
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -trimpath -ldflags="-s -w" -o PA1420_Monitor .
```

2. **配置 Linux 核心 64MB UDP 接收緩衝區（徹底消除高流量掉包）**：
```bash
sudo tee /etc/sysctl.d/99-pa-monitor.conf << 'EOF'
net.core.rmem_max = 134217728
net.core.rmem_default = 67108864
net.core.netdev_max_backlog = 250000
EOF
sudo sysctl --system
```

3. **安裝 DuckDB CLI 與部署執行檔**：
```bash
sudo mkdir -p /opt/pa_monitor
# 將編譯好的 PA1420_Monitor、pa1420key.txt 與 Linux 版 duckdb 放入 /opt/pa_monitor/
sudo chmod +x /opt/pa_monitor/PA1420_Monitor /opt/pa_monitor/duckdb
```

4. **建立 `systemd` 背景守護服務 (`/etc/systemd/system/pa_monitor.service`)**：
```ini
[Unit]
Description=PA-1420 / PA-5250 Lakehouse Log & DHCP Monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/pa_monitor
ExecStart=/opt/pa_monitor/PA1420_Monitor
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```
啟動並設定開機自動執行：
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pa_monitor
```

---

**License**: [MIT License](https://opensource.org/licenses/MIT)[cite: 23]