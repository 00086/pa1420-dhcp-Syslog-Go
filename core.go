package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/csv"
	"encoding/json" // 👈 補上
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"       // 👈 補上
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/parquet-go/parquet-go"
	_ "modernc.org/sqlite"
)

var (
	appDir       string
	paConfigFile string
	trafficDir   string
	threatDir    string // 👈 威脅日誌專屬目錄路徑
	trafficRawDir string // 👈 新增：流量原始冷資料目錄
	threatRawDir  string // 👈 新增：威脅原始冷資料目錄
	dbConn       *sql.DB
	dbMutex      sync.Mutex
	
	threatFileMutex sync.Mutex // 👈 威脅檔案安全互斥鎖
	
	// 🌟 單日 Parquet 記憶體極速快取 (徹底消除 30 秒重複讀盤)
	//dailyCacheMutex sync.RWMutex
	//cachedDate      string
	//cachedMainRows  []TrafficParquetRow

	lastJobInfo = JobInfo{
		Timestamp: 0,
		Type:      "system",
		Status:    "waiting",
		Message:   "等待排程或手動更新...",
	}
	jobMutex sync.RWMutex

	dnsWorkerStatus = DNSWorkerProgress{
		IsRunning: false,
		Total:     0,
		Done:      0,
	}
	dnsMutex sync.RWMutex
	
	// 🌟 冷資料 Raw 專屬批次寫入佇列
	rawTrafficQueue = make(chan RawLogParquetRow, 50000)
	rawThreatQueue  = make(chan RawLogParquetRow, 10000)

	// 🌟 Syslog 即時接收佇列與 Flush 狀態統計
	syslogQueue                = make(chan TrafficParquetRow, 50000)
	syslogReceivedCount        int64
	syslogLastReceivedTime     time.Time
	syslogLastFlushInsertCount int
	syslogLastFlushTotalCount  int
	syslogLastFlushTime        time.Time
	syslogStatusMutex          sync.RWMutex
	
	// 🚨 新增：Threat 專屬 Syslog 即時接收佇列與統計
	threatSyslogQueue         = make(chan ThreatParquetRow, 10000)
	threatSyslogReceivedCount int64
	threatSyslogLastFlushCount int
	threatSyslogLastFlushTime  time.Time

	// 後端流量 API 自動排程狀態 (維持原樣)
	trafficSchedulerInterval int
	trafficSchedulerStopChan chan struct{}
	trafficSchedulerMutex    sync.Mutex
	trafficLastCollectTime   time.Time
	trafficLastCollectCount  int
	trafficLastCollectStatus = "idle"
	trafficLastCollectMsg    = "尚未啟動排程"

	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	httpLongClient = &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

type JobInfo struct {
	Timestamp       int64  `json:"timestamp"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	Message         string `json:"message,omitempty"`
	SuccessCount    int    `json:"success_count"`
	DuplicateCount  int    `json:"duplicate_count"`
	MultiLeaseCount int    `json:"multi_lease_count"`
	UniqueIPCount   int    `json:"unique_ip_count"`
	Date            string `json:"date"`
	FwIP            string `json:"fw_ip,omitempty"`
	Interface       string `json:"interface,omitempty"`
}

type DNSWorkerProgress struct {
	IsRunning bool `json:"is_running"`
	Total     int  `json:"total"`
	Done      int  `json:"done"`
}

type PartitionInfo struct {
	Mount      string `json:"mount"`
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Avail      string `json:"avail"`
	Percent    int    `json:"percent"`
}

type DiskInfo struct {
	Total         string          `json:"total"`
	Used          string          `json:"used"`
	Avail         string          `json:"avail"`
	Percent       int             `json:"percent"`
	Desc          string          `json:"desc"`
	AllPartitions []PartitionInfo `json:"all_partitions"`
}

type SystemHealthData struct {
	Status          string          `json:"status"`
	Hostname        string          `json:"hostname"`
	Model           string          `json:"model"`
	SwVersion       string          `json:"sw_version"`
	Uptime          string          `json:"uptime"`
	MpCPU           float64         `json:"mp_cpu"`
	DpCPU           float64         `json:"dp_cpu"`
	MemUsagePct     float64         `json:"mem_usage_pct"`
	MemDesc         string          `json:"mem_desc"`
	ActiveSessions  int             `json:"active_sessions"`
	MaxSessions     int             `json:"max_sessions"`
	SessionUsagePct float64         `json:"session_usage_pct"`
	DiskUsagePct    int             `json:"disk_usage_pct"`
	DiskDesc        string          `json:"disk_desc"`
	DiskPartitions  []PartitionInfo `json:"disk_partitions"`
}

type DHCPEntry struct {
	IP        string `xml:"ip"`
	MAC       string `xml:"mac"`
	Hostname  string `xml:"hostname"`
	State     string `xml:"state"`
	Duration  string `xml:"duration"`
	Leasetime string `xml:"leasetime"`
}

type ARPEntry struct {
	IP        string `xml:"ip"`
	MAC       string `xml:"mac"`
	Interface string `xml:"interface"`
	Status    string `xml:"status"`
}

// -------------------------------------------------------------
// 🌟 流量與威脅日誌核心資料結構定義 (對齊 Parquet ZSTD 壓縮)
// -------------------------------------------------------------
type TrafficEntry struct {
	Timestamp        string `xml:"time_generated"`
	ReceiveTime      string `xml:"receive_time"`
	Type             string `xml:"subtype"`
	FromZone         string `xml:"from"`
	ToZone           string `xml:"to"`
	Source           string `xml:"src"`
	NatSourceIP      string `xml:"natsrc"`
	Destination      string `xml:"dst"`
	NatDestIP        string `xml:"natdst"`
	ToPort           int    `xml:"dport"`
	Application      string `xml:"app"`
	Action           string `xml:"action"`
	Rule             string `xml:"rule"`
	SessionEndReason string `xml:"session_end_reason"`
	Bytes            int64  `xml:"bytes"`
	SessionID        string `xml:"sessionid"`
	RawXML           string `xml:",innerxml"` // 🌟 核心關鍵：將防火牆回傳的整段原始 XML 內容完整截獲
}

type TrafficParquetRow struct {
	Timestamp        string `parquet:"timestamp,zstd"`
	Type             string `parquet:"type,zstd"`
	FromZone         string `parquet:"from_zone,zstd"`
	ToZone           string `parquet:"to_zone,zstd"`
	Source           string `parquet:"source,zstd"`
	NatSourceIP      string `parquet:"nat_source_ip,zstd"`
	Destination      string `parquet:"destination,zstd"`
	NatDestIP        string `parquet:"nat_dest_ip,zstd"`
	ToPort           int32  `parquet:"to_port"`
	Application      string `parquet:"application,zstd"`
	Action           string `parquet:"action,zstd"`
	Rule             string `parquet:"rule,zstd"`
	SessionEndReason string `parquet:"session_end_reason,zstd"`
	Bytes            int64  `parquet:"bytes"`
	SessionID        string `parquet:"session_id,zstd"`
}

type ThreatEntry struct {
	TimeGenerated string `xml:"time_generated"` // 👈 保持 TimeGenerated 讓 XML 解析與回溯相容
	ReceiveTime   string `xml:"receive_time"`
	Subtype       string `xml:"subtype"`
	ThreatID      string `xml:"threatid"`
	ThreatName    string `xml:"threat_name"`
	FromZone      string `xml:"from"`
	ToZone        string `xml:"to"`
	Src           string `xml:"src"`
	Dst           string `xml:"dst"`
	ToPort        int    `xml:"dport"`
	App           string `xml:"app"`
	Action        string `xml:"action"`
	Severity      string `xml:"severity"`
	URL           string `xml:"misc"`
	SessionID     string `xml:"sessionid"`
	RawXML        string `xml:",innerxml"` // 👈 補上這行，解決 e.RawXML 編譯錯誤！
}

// 🌟 冷資料備份用：極度精簡，只靠時間與 SessionID 定位，存放完整的 XML/Syslog
type RawLogParquetRow struct {
	Timestamp  string `parquet:"timestamp,zstd"`
	SessionID  string `parquet:"session_id,zstd"`
	RawContent string `parquet:"raw_content,zstd"`
}

type ThreatParquetRow struct {
	Timestamp   string `parquet:"timestamp,zstd"`
	Subtype     string `parquet:"subtype,zstd"`
	ThreatID    string `parquet:"threat_id,zstd"`
	ThreatName  string `parquet:"threat_name,zstd"`
	FromZone    string `parquet:"from_zone,zstd"`
	ToZone      string `parquet:"to_zone,zstd"`
	Src         string `parquet:"src,zstd"`
	Dst         string `parquet:"dst,zstd"`
	ToPort      int32  `parquet:"to_port"`
	Application string `parquet:"application,zstd"`
	Action      string `parquet:"action,zstd"`
	Severity    string `parquet:"severity,zstd"`
	URL         string `parquet:"url,zstd"`
	SessionID   string `parquet:"session_id,zstd"`
}

type ThreatLogItem struct {
	Timestamp      string `json:"timestamp"`
	Subtype        string `json:"subtype"`
	ThreatName     string `json:"threat_name"`
	FromZone       string `json:"from_zone"`
	ToZone         string `json:"to_zone"`
	Source         string `json:"source"`
	SrcHostname    string `json:"src_hostname"`
	Destination    string `json:"destination"`
	ToPort         int    `json:"to_port"`
	Application    string `json:"application"`
	Action         string `json:"action"`
	Severity       string `json:"severity"`
	URL            string `json:"url"`
	SessionID      string `json:"session_id"`
}

type ThreatAnalyticsResult struct {
	TotalThreats  int               `json:"total_threats"`
	CriticalHigh  int               `json:"critical_high"`
	TopThreat     string            `json:"top_threat"`
	TopVictimIP   string            `json:"top_victim_ip"`
	TopVictimHost string            `json:"top_victim_host"`
	DbSize        string            `json:"db_size"`
	Histogram     []HistogramBucket `json:"histogram"`
	Logs          []ThreatLogItem   `json:"logs"`
	CurrentPage   int               `json:"current_page"`
	TotalPages    int               `json:"total_pages"`
}

type HistogramBucket struct {
	TimeBucket string `json:"time_bucket"`
	Count      int    `json:"count"`
}

type TrafficLogItem struct {
	Timestamp        string `json:"timestamp"`
	Type             string `json:"type"`
	FromZone         string `json:"from_zone"`
	ToZone           string `json:"to_zone"`
	Source           string `json:"source"`
	SrcHostname      string `json:"src_hostname"`
	NatSourceIP      string `json:"nat_source_ip"`
	Destination      string `json:"destination"`
	NatDestIP        string `json:"nat_dest_ip"`
	ToPort           int    `json:"to_port"`
	Application      string `json:"application"`
	Action           string `json:"action"`
	Rule             string `json:"rule"`
	SessionEndReason string `json:"session_end_reason"`
	Bytes            int64  `json:"bytes"`
	BytesFormatted   string `json:"bytes_formatted"`
}

type TrafficAnalyticsResult struct {
	TotalFlows  int               `json:"total_flows"`
	TotalBytes  string            `json:"total_bytes"`
	TopApp      string            `json:"top_app"`
	DenyFlows   int               `json:"deny_flows"`
	DbSize      string            `json:"db_size"`  // 👈 新增：當日 Parquet 檔案總大小
	Histogram   []HistogramBucket `json:"histogram"`
	Logs        []TrafficLogItem  `json:"logs"`
	CurrentPage int               `json:"current_page"`
	TotalPages  int               `json:"total_pages"`
}

var rawTrafficChunkCounter int64

// 🌟 獨立冷資料快速落盤機制 (Atomic .tmp 替換 + 依真實日期歸檔 + 即時戰報輸出)
func saveRawLogBatchFast(logType string, rows []RawLogParquetRow) error {
	if len(rows) == 0 {
		return nil
	}

	targetDir := trafficRawDir
	if logType == "threat" {
		targetDir = threatRawDir
	}

	todayStr := time.Now().Format("2006-01-02")
	entriesByDate := make(map[string][]RawLogParquetRow)

	for _, r := range rows {
		recordDate := todayStr
		if len(r.Timestamp) >= 10 {
			recordDate = r.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], r)
	}

	for dateKey, dateRows := range entriesByDate {
		chunkPath := filepath.Join(targetDir, fmt.Sprintf("%s_raw_%s_%d.parquet", logType, dateKey, time.Now().UnixNano()))
		tmpPath := chunkPath + ".tmp"

		if err := parquet.WriteFile(tmpPath, dateRows); err != nil {
			_ = os.Remove(tmpPath)
			fmt.Printf("[冷資料寫入失敗] ❌ %s: %v\n", chunkPath, err)
			return err
		}

		if err := os.Rename(tmpPath, chunkPath); err != nil {
			fmt.Printf("[冷資料更名失敗] ❌ %s: %v\n", chunkPath, err)
			return err
		}

		// 🌟 核心增補：即時於 CLI 終端機顯示 Raw Log 存檔進度
		var sizeStr string
		if info, err := os.Stat(chunkPath); err == nil {
			sizeStr = fmt.Sprintf("%.2f MB", float64(info.Size())/(1024*1024))
		}
		fmt.Printf("   ↳ ❄️ [Raw Log 備份] %s 原始 XML 已儲存: %d 筆 ➔ %s (%s)\n",
			logType, len(dateRows), filepath.Base(chunkPath), sizeStr)
	}

	return nil
}

// 🌟 支援時間條件向後回溯的 Threat API 擷取函式 (最多 5,000 筆)
func fetchPAThreatLogsWithFilter(count int, filter string) ([]ThreatEntry, error) {
	if count <= 0 {
		count = 5000
	}
	if count > 5000 {
		count = 5000
	}

	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	var apiURL string
	if filter != "" {
		escapedFilter := strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=threat&nlogs=%d&query=%s&key=%s", fwIP, count, escapedFilter, apiKey)
	} else {
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=threat&nlogs=%d&key=%s", fwIP, count, apiKey)
	}

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("發起 Threat 查詢失敗: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 {
		return nil, errors.New("無法取得 Threat Log Job ID")
	}
	jobID := string(mJob[1])

	var pollBody []byte
	for i := 0; i < 30; i++ {
		time.Sleep(600 * time.Millisecond)
		pollURL := fmt.Sprintf("https://%s/api/?type=log&action=get&job-id=%s&key=%s", fwIP, jobID, apiKey)
		pResp, err := httpClient.Get(pollURL)
		if err == nil {
			pBody, _ := io.ReadAll(pResp.Body)
			pResp.Body.Close()
			if bytes.Contains(pBody, []byte("<status>FIN</status>")) {
				pollBody = pBody
				break
			}
		}
	}

	if pollBody == nil {
		return nil, errors.New("查詢 Threat 日誌逾時")
	}

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []ThreatEntry
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e ThreatEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.TimeGenerated), "/", "-")
				if e.TimeGenerated == "" {
					e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-")
				}
				entries = append(entries, e)
			}
		}
	}

	return entries, nil
}

func initCore() {
	exe, err := os.Executable()
	if err == nil {
		appDir = filepath.Dir(exe)
	} else {
		appDir, _ = os.Getwd()
	}
	paConfigFile = filepath.Join(appDir, "pa1420key.txt")
	trafficDir = filepath.Join(appDir, "traffic_logs")
	_ = os.MkdirAll(trafficDir, 0755)

	// 🌟 1. 建立威脅日誌專屬目錄 threat_logs
	threatDir = filepath.Join(appDir, "threat_logs")
	_ = os.MkdirAll(threatDir, 0755)
	
	// 🌟 新增建立 Raw 日誌專屬備份目錄
	trafficRawDir = filepath.Join(appDir, "traffic_raw_logs")
	_ = os.MkdirAll(trafficRawDir, 0755)

	threatRawDir = filepath.Join(appDir, "threat_raw_logs")
	_ = os.MkdirAll(threatRawDir, 0755)

	// 🌟 2. 自動將根目錄現有的 threat_*.parquet 搬移歸位到 threat_logs/
	rootThreatFiles, _ := filepath.Glob(filepath.Join(appDir, "threat_*.parquet"))
	
	// 🌟 啟動冷資料每小時自動維護整合排程
	startHourlyRawConsolidator()
	
	for _, rf := range rootThreatFiles {
		targetPath := filepath.Join(threatDir, filepath.Base(rf))
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			_ = os.Rename(rf, targetPath)
		} else {
			// 若目標目錄已存在同名檔案，改名移入供後續整合器自動去重合併
			_ = os.Rename(rf, filepath.Join(threatDir, fmt.Sprintf("migrate_%d_%s", time.Now().UnixNano(), filepath.Base(rf))))
		}
	}

	db, err := initDB()
	if err == nil {
		var savedInterval string
		err := db.QueryRow("SELECT value FROM system_settings WHERE key = 'traffic_scheduler_interval'").Scan(&savedInterval)
		if err == nil {
			sec, _ := strconv.Atoi(savedInterval)
			if sec > 0 {
				SetTrafficSchedulerInterval(sec)
			}
		}
	}
}

func showWindowsAlert(title, message string) {
	if runtime.GOOS != "windows" {
		return
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	msgBox := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(message)
	msgBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x30)
}

func ensurePAConfigTemplate() {
	if _, err := os.Stat(paConfigFile); os.IsNotExist(err) {
		sample := "# 第 1 行：PA-1420 防火牆 IP\n192.168.1.1\n# 第 2 行：監控介面 (例如 ethernet1/1 或 all)\nall\n# 第 3 行：PA-1420 XML API Key\nYOUR_API_KEY_HERE\n"
		_ = os.WriteFile(paConfigFile, []byte(sample), 0644)
		fmt.Printf("[提示] 已自動在同級目錄建立設定檔範本：%s\n", paConfigFile)
		showWindowsAlert(
			"PA-1420 監控系統 - 缺少設定檔",
			fmt.Sprintf("【系統提醒】未偵測到 PA-1420 設定檔案！\n\n系統已自動於以下路徑建立範本檔：\n%s\n\n請以文字編輯器開啟並填入真實的防火牆 IP、介面與 API Key，儲存後即可正常連線。", paConfigFile),
		)
	}
}

func getPAConfig() (string, string, string, string, error) {
	if _, err := os.Stat(paConfigFile); os.IsNotExist(err) {
		return "", "", "", "", fmt.Errorf("找不到設定檔案：%s", paConfigFile)
	}

	content, err := os.ReadFile(paConfigFile)
	if err != nil {
		return "", "", "", "", err
	}

	var lines []string
	for _, l := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, trimmed)
		}
	}

	if len(lines) < 3 {
		return "", "", "", "", errors.New("pa1420key.txt 格式錯誤！必須包含三行有效內容")
	}

	if lines[0] == "192.168.1.1" || strings.Contains(lines[2], "YOUR_API_KEY") {
		return "", "", "", "", errors.New("pa1420key.txt 仍為範本預設值，請填入實際的防火牆 IP 與 API Key")
	}

	fwIP := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(lines[0], "http://"), "https://"), "/")
	iface := lines[1]
	apiKey := lines[2]

	var cmd string
	if strings.ToLower(iface) == "all" {
		cmd = "<show><dhcp><server><lease><all/></lease></server></dhcp></show>"
	} else {
		cmd = fmt.Sprintf("<show><dhcp><server><lease><interface>%s</interface></lease></server></dhcp></show>", iface)
	}

	return fwIP, iface, apiKey, cmd, nil
}

func runPACommand(cmdXML string) ([]byte, error) {
	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://%s/api/?type=op&cmd=%s&key=%s", fwIP, cmdXML, apiKey)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if bytes.Contains(body, []byte(`status="error"`)) {
		reMsg := regexp.MustCompile(`<msg>(.*?)</msg>`)
		matches := reMsg.FindSubmatch(body)
		if len(matches) > 1 {
			return nil, errors.New(string(matches[1]))
		}
		return nil, errors.New("PA API 回傳錯誤")
	}

	return body, nil
}

func initDB() (*sql.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if dbConn != nil {
		return dbConn, nil
	}

	dbPath := filepath.Join(appDir, "dhcp_records.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS dhcp_leases (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			record_date TEXT NOT NULL,
			ip TEXT NOT NULL,
			mac TEXT NOT NULL,
			hostname TEXT,
			state TEXT,
			duration INTEGER,
			leasetime TEXT
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_lease_unique ON dhcp_leases(record_date, ip, mac, leasetime);`,
		`CREATE TABLE IF NOT EXISTS system_health_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			record_time TEXT NOT NULL,
			mp_cpu REAL,
			dp_cpu REAL,
			mem_usage_pct REAL,
			active_sessions INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS ip_hostname_cache (
			ip TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS system_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return nil, err
		}
	}

	rows, err := db.Query("PRAGMA table_info(system_health_log);")
	if err == nil {
		defer rows.Close()
		hasDisk := false
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt sql.NullString
			_ = rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
			if name == "disk_usage_pct" {
				hasDisk = true
				break
			}
		}
		if !hasDisk {
			_, _ = db.Exec("ALTER TABLE system_health_log ADD COLUMN disk_usage_pct REAL DEFAULT 0.0;")
		}
	}

	dbConn = db
	return dbConn, nil
}

func parseAndInsertXML(xmlBytes []byte, recordDate string) (int, int, int, int, error) {
	if recordDate == "" {
		recordDate = time.Now().Format("2006-01-02")
	}

	db, err := initDB()
	if err != nil {
		return 0, 0, 0, 0, err
	}

	decoder := xml.NewDecoder(bytes.NewReader(xmlBytes))
	var entries []DHCPEntry
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e DHCPEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.IP = strings.TrimSpace(e.IP)
				e.MAC = strings.TrimSpace(e.MAC)
				e.Hostname = strings.TrimSpace(e.Hostname)
				e.State = strings.TrimSpace(e.State)
				e.Duration = strings.TrimSpace(e.Duration)
				e.Leasetime = strings.TrimSpace(e.Leasetime)
				if e.IP != "" && e.MAC != "" {
					entries = append(entries, e)
				}
			}
		}
	}

	successCount, duplicateCount, multiLeaseCount := 0, 0, 0
	for _, e := range entries {
		var existsCount int
		_ = db.QueryRow("SELECT COUNT(*) FROM dhcp_leases WHERE record_date = ? AND ip = ?", recordDate, e.IP).Scan(&existsCount)
		ipExists := existsCount > 0

		dur, _ := strconv.Atoi(e.Duration)
		res, err := db.Exec(`
			INSERT OR IGNORE INTO dhcp_leases (record_date, ip, mac, hostname, state, duration, leasetime)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, recordDate, e.IP, e.MAC, e.Hostname, e.State, dur, e.Leasetime)

		if err == nil {
			aff, _ := res.RowsAffected()
			if aff == 1 {
				successCount++
				if ipExists {
					multiLeaseCount++
				}
			} else {
				duplicateCount++
			}
		}
	}

	var uniqueCount int
	_ = db.QueryRow("SELECT COUNT(DISTINCT ip) FROM dhcp_leases WHERE record_date = ?", recordDate).Scan(&uniqueCount)

	return successCount, duplicateCount, multiLeaseCount, uniqueCount, nil
}

func fetchPADhcpJob(jobType string) JobInfo {
	todayStr := time.Now().Format("2006-01-02")
	fmt.Printf("\n[%s] 啟動 PA-1420 DHCP 抓取作業 (%s)...\n", time.Now().Format("2006-01-02 15:04:05"), jobType)

	fwIP, iface, apiKey, cmd, err := getPAConfig()
	if err != nil {
		info := JobInfo{
			Timestamp: time.Now().Unix(),
			Type:      jobType,
			Status:    "error",
			Message:   err.Error(),
		}
		jobMutex.Lock()
		lastJobInfo = info
		jobMutex.Unlock()
		return info
	}

	apiURL := fmt.Sprintf("https://%s/api/?type=op&cmd=%s&key=%s", fwIP, cmd, apiKey)
	resp, err := httpLongClient.Get(apiURL)
	if err != nil {
		info := JobInfo{
			Timestamp: time.Now().Unix(),
			Type:      jobType,
			Status:    "error",
			Message:   err.Error(),
		}
		jobMutex.Lock()
		lastJobInfo = info
		jobMutex.Unlock()
		return info
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		info := JobInfo{
			Timestamp: time.Now().Unix(),
			Type:      jobType,
			Status:    "error",
			Message:   err.Error(),
		}
		jobMutex.Lock()
		lastJobInfo = info
		jobMutex.Unlock()
		return info
	}

	success, duplicate, multiLease, uniqueCount, err := parseAndInsertXML(body, todayStr)
	if err != nil {
		info := JobInfo{
			Timestamp: time.Now().Unix(),
			Type:      jobType,
			Status:    "error",
			Message:   err.Error(),
		}
		jobMutex.Lock()
		lastJobInfo = info
		jobMutex.Unlock()
		return info
	}

	fmt.Printf("[%s] PA-1420 抓取完成！新增：%d 筆，略過重複：%d 筆，今日不重複 IP：%d 筆\n",
		time.Now().Format("2006-01-02 15:04:05"), success, duplicate, uniqueCount)

	info := JobInfo{
		Timestamp:       time.Now().Unix(),
		Type:            jobType,
		Status:          "success",
		SuccessCount:    success,
		DuplicateCount:  duplicate,
		MultiLeaseCount: multiLease,
		UniqueIPCount:   uniqueCount,
		Date:            todayStr,
		FwIP:            fwIP,
		Interface:       iface,
	}

	jobMutex.Lock()
	lastJobInfo = info
	jobMutex.Unlock()
	return info
}

func fetchPADiskSpace() DiskInfo {
	def := DiskInfo{Total: "-", Used: "-", Avail: "-", Percent: 0, Desc: "-", AllPartitions: []PartitionInfo{}}
	body, err := runPACommand("<show><system><disk-space/></system></show>")
	if err != nil {
		return def
	}

	lines := strings.Split(string(body), "\n")
	var partitions []PartitionInfo
	var panlogs *PartitionInfo

	for _, l := range lines {
		parts := strings.Fields(l)
		if len(parts) >= 6 && parts[0] != "Filesystem" && !strings.Contains(parts[0], "<") {
			pct, _ := strconv.Atoi(strings.TrimSuffix(parts[4], "%"))
			info := PartitionInfo{
				Filesystem: parts[0],
				Size:       parts[1],
				Used:       parts[2],
				Avail:      parts[3],
				Percent:    pct,
				Mount:      parts[5],
			}
			partitions = append(partitions, info)
			if parts[5] == "/opt/panlogs" {
				panlogs = &info
			}
		}
	}

	if panlogs == nil {
		for _, p := range partitions {
			if p.Mount == "/" {
				panlogs = &p
				break
			}
		}
	}

	if panlogs != nil {
		return DiskInfo{
			Total:         panlogs.Size,
			Used:          panlogs.Used,
			Avail:         panlogs.Avail,
			Percent:       panlogs.Percent,
			Desc:          fmt.Sprintf("%s / %s", panlogs.Used, panlogs.Size),
			AllPartitions: partitions,
		}
	}

	return DiskInfo{Total: "-", Used: "-", Avail: "-", Percent: 0, Desc: "-", AllPartitions: partitions}
}

func fetchPAHealthData() (SystemHealthData, error) {
	data := SystemHealthData{
		Status:         "success",
		Hostname:       "PA-1420",
		Model:          "PA-1420",
		SwVersion:      "-",
		Uptime:         "-",
		DiskPartitions: []PartitionInfo{},
	}

	infoBody, err := runPACommand("<show><system><info/></system></show>")
	if err == nil {
		reHost := regexp.MustCompile(`<hostname>(.*?)</hostname>`)
		reModel := regexp.MustCompile(`<model>(.*?)</model>`)
		reVer := regexp.MustCompile(`<sw-version>(.*?)</sw-version>`)
		reUp := regexp.MustCompile(`<uptime>(.*?)</uptime>`)

		if m := reHost.FindSubmatch(infoBody); len(m) > 1 {
			data.Hostname = string(m[1])
		}
		if m := reModel.FindSubmatch(infoBody); len(m) > 1 {
			data.Model = string(m[1])
		}
		if m := reVer.FindSubmatch(infoBody); len(m) > 1 {
			data.SwVersion = string(m[1])
		}
		if m := reUp.FindSubmatch(infoBody); len(m) > 1 {
			data.Uptime = string(m[1])
		}
	}

	sessBody, err := runPACommand("<show><session><info/></session></show>")
	if err == nil {
		reAct := regexp.MustCompile(`<num-active>(\d+)</num-active>`)
		reMax := regexp.MustCompile(`<num-max>(\d+)</num-max>`)
		if m := reAct.FindSubmatch(sessBody); len(m) > 1 {
			data.ActiveSessions, _ = strconv.Atoi(string(m[1]))
		}
		if m := reMax.FindSubmatch(sessBody); len(m) > 1 {
			data.MaxSessions, _ = strconv.Atoi(string(m[1]))
		}
		if data.MaxSessions > 0 {
			data.SessionUsagePct = math.Round((float64(data.ActiveSessions)/float64(data.MaxSessions))*10000) / 100
		}
	}

	resBody, err := runPACommand("<show><system><resources/></system></show>")
	if err == nil {
		resText := string(resBody)
		reCPU := regexp.MustCompile(`(?:%?Cpu\(s\)|Cpu\(s\)):\s*[\d\.]+%?\s*us,.*?([\d\.]+)%?\s*id`)
		if m := reCPU.FindStringSubmatch(resText); len(m) > 1 {
			idle, _ := strconv.ParseFloat(m[1], 64)
			data.MpCPU = math.Round(math.Max(0.0, 100.0-idle)*10) / 10
		}

		reMem := regexp.MustCompile(`(?i)[^\n\r]*\bMem\b[^\n\r]*total[^\n\r]*`)
		if line := reMem.FindString(resText); line != "" {
			reTot := regexp.MustCompile(`(?i)([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*total`)
			reUsd := regexp.MustCompile(`(?i)([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*used`)
			reCache := regexp.MustCompile(`(?i)([\d\.]+)\s*([kKmMgGtT]?i?B?)?\s*(?:buff/cache|cache|buffers)`)

			mTot := reTot.FindStringSubmatch(line)
			mUsd := reUsd.FindStringSubmatch(line)
			mCache := reCache.FindStringSubmatch(line)

			if len(mTot) > 1 {
				totVal, _ := strconv.ParseFloat(mTot[1], 64)
				lineLower := strings.ToLower(line)
				var unitFactor float64
				if strings.Contains(lineLower, "mib") {
					unitFactor = 1.0 / 1024.0
				} else if strings.Contains(lineLower, "gib") {
					unitFactor = 1.0
				} else if strings.Contains(lineLower, "kib") || strings.Contains(lineLower, "k total") {
					unitFactor = 1.0 / (1024.0 * 1024.0)
				} else {
					if totVal > 1000000 {
						unitFactor = 1.0 / (1024.0 * 1024.0)
					} else if totVal > 1000 {
						unitFactor = 1.0 / 1024.0
					} else {
						unitFactor = 1.0
					}
				}

				totG := math.Round(totVal*unitFactor*10) / 10
				var usdG, cacheG float64
				if len(mUsd) > 1 {
					usdVal, _ := strconv.ParseFloat(mUsd[1], 64)
					usdG = math.Round(usdVal*unitFactor*10) / 10
				}
				if len(mCache) > 1 {
					cacheVal, _ := strconv.ParseFloat(mCache[1], 64)
					cacheG = math.Round(cacheVal*unitFactor*10) / 10
				}

				if totG > 0 {
					data.MemUsagePct = math.Round((usdG/totG)*1000) / 10
					if cacheG > 0 {
						data.MemDesc = fmt.Sprintf("%.1fG + %.1fG快取 / %.1fG", usdG, cacheG, totG)
					} else {
						data.MemDesc = fmt.Sprintf("%.1fG / %.1fG", usdG, totG)
					}
				}
			}
		}
	}

	dpBody, err := runPACommand("<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>")
	if err == nil {
		reVal := regexp.MustCompile(`<value>\s*([\d\.]+)\s*</value>`)
		matches := reVal.FindAllStringSubmatch(string(dpBody), -1)
		if len(matches) == 0 {
			dpBody, _ = runPACommand("<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>")
			matches = reVal.FindAllStringSubmatch(string(dpBody), -1)
		}
		if len(matches) > 0 {
			var sum float64
			for _, m := range matches {
				v, _ := strconv.ParseFloat(m[1], 64)
				sum += v
			}
			data.DpCPU = math.Round((sum/float64(len(matches)))*10) / 10
		}
	}

	disk := fetchPADiskSpace()
	data.DiskUsagePct = disk.Percent
	data.DiskDesc = disk.Desc
	data.DiskPartitions = disk.AllPartitions

	return data, nil
}

func logSystemHealthJob() {
	data, err := fetchPAHealthData()
	if err != nil {
		return
	}

	db, err := initDB()
	if err != nil {
		return
	}

	nowStr := time.Now().Format("2006-01-02T15:04:05")
	_, _ = db.Exec(`
		INSERT INTO system_health_log (record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct)
		VALUES (?, ?, ?, ?, ?, ?)
	`, nowStr, data.MpCPU, data.DpCPU, data.MemUsagePct, data.ActiveSessions, float64(data.DiskUsagePct))

	threshold := time.Now().Add(-24 * time.Hour).Format("2006-01-02T15:04:05")
	_, _ = db.Exec("DELETE FROM system_health_log WHERE record_time < ?", threshold)
}

func backgroundDNSWorker(targetIPs []string) {
	dnsMutex.Lock()
	if dnsWorkerStatus.IsRunning {
		dnsMutex.Unlock()
		return
	}
	dnsWorkerStatus.IsRunning = true
	dnsWorkerStatus.Total = len(targetIPs)
	dnsWorkerStatus.Done = 0
	dnsMutex.Unlock()

	go func() {
		jobs := make(chan string, len(targetIPs))
		var wg sync.WaitGroup

		for w := 0; w < 15; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range jobs {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					names, err := net.DefaultResolver.LookupAddr(ctx, ip)
					cancel()

					if err == nil && len(names) > 0 {
						fqdn := strings.TrimSuffix(names[0], ".")
						shortName := fqdn
						if idx := strings.Index(fqdn, "."); idx != -1 {
							shortName = fqdn[:idx]
						}

						db, err := initDB()
						if err == nil {
							nowStr := time.Now().Format("2006-01-02 15:04:05")
							_, _ = db.Exec("INSERT OR REPLACE INTO ip_hostname_cache (ip, hostname, updated_at) VALUES (?, ?, ?)", ip, shortName, nowStr)
						}
					}

					dnsMutex.Lock()
					dnsWorkerStatus.Done++
					dnsMutex.Unlock()
				}
			}()
		}

		for _, ip := range targetIPs {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()

		dnsMutex.Lock()
		dnsWorkerStatus.IsRunning = false
		dnsMutex.Unlock()
	}()
}

func fetchPAThreatLogs(count int) ([]ThreatEntry, error) {
	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://%s/api/?type=log&log-type=threat&nlogs=%d&key=%s", fwIP, count, apiKey)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 {
		return nil, errors.New("無法取得 Log Job ID")
	}
	jobID := string(mJob[1])

	var pollBody []byte
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		pollURL := fmt.Sprintf("https://%s/api/?type=log&action=get&job-id=%s&key=%s", fwIP, jobID, apiKey)
		pResp, err := httpClient.Get(pollURL)
		if err == nil {
			pBody, _ := io.ReadAll(pResp.Body)
			pResp.Body.Close()
			if bytes.Contains(pBody, []byte("<status>FIN</status>")) {
				pollBody = pBody
				break
			}
		}
	}

	if pollBody == nil {
		return nil, errors.New("查詢威脅日誌逾時")
	}

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []ThreatEntry
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e ThreatEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				entries = append(entries, e)
			}
		}
	}

	return entries, nil
}

// -------------------------------------------------------------
// 🌟 流量日誌 (Traffic Logs) API 擷取 (最高支援 5000 筆，預設 2500 筆)
// -------------------------------------------------------------
func fetchPATrafficLogs(count int) ([]TrafficEntry, error) {
	if count <= 0 {
		count = 2500
	}
	if count > 5000 {
		count = 5000
	}

	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://%s/api/?type=log&log-type=traffic&nlogs=%d&key=%s", fwIP, count, apiKey)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 {
		return nil, errors.New("無法取得 Traffic Log Job ID")
	}
	jobID := string(mJob[1])

	var pollBody []byte
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		pollURL := fmt.Sprintf("https://%s/api/?type=log&action=get&job-id=%s&key=%s", fwIP, jobID, apiKey)
		pResp, err := httpClient.Get(pollURL)
		if err == nil {
			pBody, _ := io.ReadAll(pResp.Body)
			pResp.Body.Close()
			if bytes.Contains(pBody, []byte("<status>FIN</status>")) {
				pollBody = pBody
				break
			}
		}
	}

	if pollBody == nil {
		return nil, errors.New("查詢流量日誌逾時")
	}

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []TrafficEntry
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e TrafficEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.Timestamp = strings.ReplaceAll(strings.TrimSpace(e.Timestamp), "/", "-")
				if e.Timestamp == "" {
					e.Timestamp = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-")
				}
				e.Type = strings.TrimSpace(e.Type)
				e.FromZone = strings.TrimSpace(e.FromZone)
				e.ToZone = strings.TrimSpace(e.ToZone)
				e.Source = strings.TrimSpace(e.Source)
				e.NatSourceIP = strings.TrimSpace(e.NatSourceIP)
				e.Destination = strings.TrimSpace(e.Destination)
				e.NatDestIP = strings.TrimSpace(e.NatDestIP)
				e.Application = strings.TrimSpace(e.Application)
				e.Action = strings.TrimSpace(e.Action)
				e.Rule = strings.TrimSpace(e.Rule)
				e.SessionEndReason = strings.TrimSpace(e.SessionEndReason)
				e.SessionID = strings.TrimSpace(e.SessionID)

				if e.Source != "" && e.Destination != "" {
					entries = append(entries, e)
				}
			}
		}
	}

	return entries, nil
}

// 🌟 支援時間條件向後回溯的 API 擷取函式 (URL 正確轉義)
func fetchPATrafficLogsWithFilter(count int, filter string) ([]TrafficEntry, error) {
	if count <= 0 {
		count = 5000
	}
	if count > 5000 {
		count = 5000
	}

	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	var apiURL string
	if filter != "" {
		// 👈 關鍵修復：將過濾條件進行百分比編碼，空格轉為 %20
		escapedFilter := strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=traffic&nlogs=%d&query=%s&key=%s", fwIP, count, escapedFilter, apiKey)
	} else {
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=traffic&nlogs=%d&key=%s", fwIP, count, apiKey)
	}

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("發起查詢失敗: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 {
		return nil, errors.New("無法取得 Traffic Log Job ID")
	}
	jobID := string(mJob[1])

	var pollBody []byte
	for i := 0; i < 30; i++ {
		time.Sleep(600 * time.Millisecond)
		pollURL := fmt.Sprintf("https://%s/api/?type=log&action=get&job-id=%s&key=%s", fwIP, jobID, apiKey)
		pResp, err := httpClient.Get(pollURL)
		if err == nil {
			pBody, _ := io.ReadAll(pResp.Body)
			pResp.Body.Close()
			if bytes.Contains(pBody, []byte("<status>FIN</status>")) {
				pollBody = pBody
				break
			}
		}
	}

	if pollBody == nil {
		return nil, errors.New("查詢流量日誌逾時")
	}

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []TrafficEntry
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e TrafficEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.Timestamp = strings.ReplaceAll(strings.TrimSpace(e.Timestamp), "/", "-")
				if e.Timestamp == "" {
					e.Timestamp = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-")
				}
				e.Type = strings.TrimSpace(e.Type)
				e.FromZone = strings.TrimSpace(e.FromZone)
				e.ToZone = strings.TrimSpace(e.ToZone)
				e.Source = strings.TrimSpace(e.Source)
				e.NatSourceIP = strings.TrimSpace(e.NatSourceIP)
				e.Destination = strings.TrimSpace(e.Destination)
				e.NatDestIP = strings.TrimSpace(e.NatDestIP)
				e.Application = strings.TrimSpace(e.Application)
				e.Action = strings.TrimSpace(e.Action)
				e.Rule = strings.TrimSpace(e.Rule)
				e.SessionEndReason = strings.TrimSpace(e.SessionEndReason)
				e.SessionID = strings.TrimSpace(e.SessionID)

				if e.Source != "" && e.Destination != "" {
					entries = append(entries, e)
				}
			}
		}
	}

	return entries, nil
}

// -------------------------------------------------------------
// 🌟 核心整併器：由 DuckDB 接管背景極速整併 (零記憶體消耗)
// -------------------------------------------------------------
func ConsolidateParquetFiles() (int, int, error) {
	parquetFileMutex.Lock()
	defer parquetFileMutex.Unlock()

	entries, err := os.ReadDir(trafficDir)
	if err != nil { return 0, 0, err }

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`^traffic_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") { continue }
		if m := re.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateFiles[m[1]] = append(dateFiles[m[1]], filepath.Join(trafficDir, e.Name()))
		}
	}

	totalMergedFiles := 0

	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", dateKey))
		if len(files) == 1 && files[0] == targetMainFile { continue }

		fmt.Printf("[資料整合] ⏳ DuckDB 引擎啟動：正在將 %s 的 %d 個分塊日誌極速整併...\n", dateKey, len(files))

		tmpFile := targetMainFile + ".tmp"
		globPath := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", dateKey)))
		tmpSlash := filepath.ToSlash(tmpFile)

		// 🦆 讓 DuckDB 執行 SQL：開啟 union_by_name=true，確保新舊結構無縫相容
		copyQuery := fmt.Sprintf(`
			COPY (
				SELECT 
					timestamp, type, from_zone, to_zone, source, nat_source_ip, 
					destination, nat_dest_ip, to_port, application, action, rule, 
					session_end_reason, bytes, session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY timestamp, source, destination, to_port, session_id 
						ORDER BY timestamp DESC
					) as row_num
					FROM read_parquet('%s', union_by_name=true)
				) WHERE row_num = 1
				ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, globPath, tmpSlash)

		_, err := runDuckDBQuery(copyQuery)
		if err != nil {
			_ = os.Remove(tmpFile)
			fmt.Printf("[資料整合] ❌ DuckDB 整併 %s 失敗: %v\n", dateKey, err)
			continue
		}

		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err == nil {
			for _, f := range files {
				if f != targetMainFile {
					_ = os.Remove(f)
					totalMergedFiles++
				}
			}
			fmt.Printf("[資料整合] ✅ %s 整併完成！已合併為單一 ZSTD 主檔，清除 %d 個碎片檔案。\n", dateKey, len(files)-1)
		} else {
			_ = os.Remove(tmpFile)
		}
	}

	return totalMergedFiles, 0, nil
}

// -------------------------------------------------------------
// 🌟 每日單一 Parquet 檔案寫入 (Atomic .tmp 替換，零碎檔產生)
// -------------------------------------------------------------
var parquetFileMutex sync.Mutex

func saveParquetRowsDirect(rows []TrafficParquetRow) (int, int, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}

	parquetFileMutex.Lock()
	defer parquetFileMutex.Unlock()

	entriesByDate := make(map[string][]TrafficParquetRow)
	for _, r := range rows {
		recordDate := time.Now().Format("2006-01-02")
		if len(r.Timestamp) >= 10 {
			recordDate = r.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], r)
	}

	totalInserted := 0
	totalForToday := 0
	todayStr := time.Now().Format("2006-01-02")

	for dateKey, newRows := range entriesByDate {
		mainPath := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", dateKey))
		tmpPath := mainPath + ".tmp"

		existingKeys := make(map[string]bool)
		var combinedRows []TrafficParquetRow

		// 讀取當日現有的唯一主檔
		if _, err := os.Stat(mainPath); err == nil {
			oldRows, err := parquet.ReadFile[TrafficParquetRow](mainPath)
			if err == nil {
				for _, r := range oldRows {
					key := fmt.Sprintf("%s|%s|%s|%d|%s", r.Timestamp, r.Source, r.Destination, r.ToPort, r.SessionID)
					if !existingKeys[key] {
						existingKeys[key] = true
						combinedRows = append(combinedRows, r)
					}
				}
			} else {
				return 0, 0, fmt.Errorf("現有主檔讀取異常，中止寫入以防覆蓋: %w", err)
			}
		}

		// 合併去重
		newCount := 0
		for _, r := range newRows {
			key := fmt.Sprintf("%s|%s|%s|%d|%s", r.Timestamp, r.Source, r.Destination, r.ToPort, r.SessionID)
			if !existingKeys[key] {
				existingKeys[key] = true
				combinedRows = append(combinedRows, r)
				newCount++
			}
		}

		if newCount == 0 && len(combinedRows) > 0 {
			if dateKey == todayStr {
				totalForToday = len(combinedRows)
			}
			continue
		}

		totalInserted += newCount

		// 排序
		sort.Slice(combinedRows, func(i, j int) bool {
			return combinedRows[i].Timestamp > combinedRows[j].Timestamp
		})

		// 先寫入 .tmp 檔
		if err := parquet.WriteFile(tmpPath, combinedRows); err != nil {
			_ = os.Remove(tmpPath)
			return 0, 0, fmt.Errorf("寫入臨時 Parquet 檔案失敗: %w", err)
		}

		// 原子替換主檔案 (Windows 安全覆蓋)
		_ = os.Remove(mainPath)
		if err := os.Rename(tmpPath, mainPath); err != nil {
			_ = os.Remove(tmpPath)
			return 0, 0, fmt.Errorf("替換 Parquet 主檔案失敗: %w", err)
		}

		if dateKey == todayStr {
			totalForToday = len(combinedRows)
		}
	}

	return totalInserted, totalForToday, nil
}

// 🌟 Syslog 專屬極速落盤：直接寫入即時分塊，耗時僅需 2~5ms，絕不讀寫 100 萬筆主檔
func saveSyslogBatchFast(rows []TrafficParquetRow) (int, int, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}

	todayStr := time.Now().Format("2006-01-02")
	chunkPath := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_live_%d.parquet", todayStr, time.Now().UnixNano()))

	if err := parquet.WriteFile(chunkPath, rows); err != nil {
		return 0, 0, err
	}

	return len(rows), int(atomic.LoadInt64(&syslogReceivedCount)), nil
}

func saveTrafficLogsToParquet(entries []TrafficEntry) (int, int, error) {
	var rows []TrafficParquetRow
	var rawRows []RawLogParquetRow // 👈 準備冷資料陣列

	for _, e := range entries {
		ts := strings.ReplaceAll(strings.TrimSpace(e.Timestamp), "/", "-")
		if ts == "" { ts = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-") }
		
		rows = append(rows, TrafficParquetRow{
			Timestamp:        ts,
			Type:             e.Type,
			FromZone:         e.FromZone,
			ToZone:           e.ToZone,
			Source:           e.Source,
			NatSourceIP:      e.NatSourceIP,
			Destination:      e.Destination,
			NatDestIP:        e.NatDestIP,
			ToPort:           int32(e.ToPort),
			Application:      e.Application,
			Action:           e.Action,
			Rule:             e.Rule,
			SessionEndReason: e.SessionEndReason,
			Bytes:            e.Bytes,
			SessionID:        e.SessionID,
		})

		// 🌟 備份完整 XML 到冷資料
		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  e.SessionID,
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
	}
	
	// 非同步把冷資料寫進 traffic_raw_logs/，完全不阻擋主線
	go saveRawLogBatchFast("traffic", rawRows)
	
	return saveParquetRowsDirect(rows)
}

// -------------------------------------------------------------
// 🌟 Syslog UDP 514 接收與解析雙引擎 (含 RawMessage 完整保留)
// -------------------------------------------------------------
func parsePaloAltoSyslog(msg string) (*TrafficParquetRow, error) {
	if !strings.Contains(msg, "TRAFFIC") {
		return nil, errors.New("not traffic log")
	}

	reader := csv.NewReader(strings.NewReader(msg))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	fields, err := reader.Read()
	if err != nil {
		return nil, err
	}

	idx := -1
	for i, f := range fields {
		if strings.TrimSpace(f) == "TRAFFIC" {
			idx = i
			break
		}
	}

	if idx == -1 || len(fields) <= idx+28 {
		return nil, errors.New("insufficient fields")
	}

	rawTime := strings.TrimSpace(fields[idx+3])
	if rawTime == "" && idx >= 2 {
		rawTime = strings.TrimSpace(fields[idx-2])
	}
	formattedTime := strings.ReplaceAll(rawTime, "/", "-")

	toPort, _ := strconv.Atoi(strings.TrimSpace(fields[idx+22]))
	bytesVal, _ := strconv.ParseInt(strings.TrimSpace(fields[idx+28]), 10, 64)

	endReason := ""
	if len(fields) > idx+43 {
		endReason = strings.TrimSpace(fields[idx+43])
	}

	row := &TrafficParquetRow{
		Timestamp:        formattedTime,
		Type:             strings.TrimSpace(fields[idx+1]),
		FromZone:         strings.TrimSpace(fields[idx+13]),
		ToZone:           strings.TrimSpace(fields[idx+14]),
		Source:           strings.TrimSpace(fields[idx+4]),
		NatSourceIP:      strings.TrimSpace(fields[idx+6]),
		Destination:      strings.TrimSpace(fields[idx+5]),
		NatDestIP:        strings.TrimSpace(fields[idx+7]),
		ToPort:           int32(toPort),
		Application:      strings.TrimSpace(fields[idx+11]),
		Action:           strings.TrimSpace(fields[idx+27]),
		Rule:             strings.TrimSpace(fields[idx+8]),
		SessionEndReason: endReason,
		Bytes:            bytesVal,
		SessionID:        strings.TrimSpace(fields[idx+19]),
	}

	if row.Source == "" || row.Destination == "" {
		return nil, errors.New("empty src/dst")
	}

	return row, nil
}

// 🌟 解析 Palo Alto THREAT Syslog 封包
func parsePaloAltoThreatSyslog(msg string) (*ThreatParquetRow, error) {
	if !strings.Contains(msg, "THREAT") {
		return nil, errors.New("not threat log")
	}

	reader := csv.NewReader(strings.NewReader(msg))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	fields, err := reader.Read()
	if err != nil {
		return nil, err
	}

	idx := -1
	for i, f := range fields {
		if strings.TrimSpace(f) == "THREAT" {
			idx = i
			break
		}
	}

	if idx == -1 || len(fields) <= idx+31 {
		return nil, errors.New("insufficient threat fields")
	}

	rawTime := strings.TrimSpace(fields[idx+3])
	if rawTime == "" && idx >= 2 {
		rawTime = strings.TrimSpace(fields[idx-2])
	}
	formattedTime := strings.ReplaceAll(rawTime, "/", "-")

	toPort, _ := strconv.Atoi(strings.TrimSpace(fields[idx+22]))
	
	threatName := strings.TrimSpace(fields[idx+29])
	threatID := threatName
	if idx+30 < len(fields) && threatName == "" {
		threatName = strings.TrimSpace(fields[idx+30])
	}

	urlMisc := ""
	if idx+33 < len(fields) {
		urlMisc = strings.TrimSpace(fields[idx+33])
	}

	row := &ThreatParquetRow{
		Timestamp:   formattedTime,
		Subtype:     strings.TrimSpace(fields[idx+1]),
		ThreatID:    threatID,
		ThreatName:  threatName,
		FromZone:    strings.TrimSpace(fields[idx+13]),
		ToZone:      strings.TrimSpace(fields[idx+14]),
		Src:         strings.TrimSpace(fields[idx+4]),
		Dst:         strings.TrimSpace(fields[idx+5]),
		ToPort:      int32(toPort),
		Application: strings.TrimSpace(fields[idx+11]),
		Action:      strings.TrimSpace(fields[idx+27]),
		Severity:    strings.ToLower(strings.TrimSpace(fields[idx+31])),
		URL:         urlMisc,
		SessionID:   strings.TrimSpace(fields[idx+19]),
	}

	if row.Src == "" || row.Dst == "" {
		return nil, errors.New("empty src/dst in threat log")
	}

	return row, nil
}

// 🌟 威脅日誌極速分塊存檔
func saveThreatSyslogBatchFast(rows []ThreatParquetRow) (int, int, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	todayStr := time.Now().Format("2006-01-02")
	chunkPath := filepath.Join(threatDir, fmt.Sprintf("threat_%s_live_%d.parquet", todayStr, time.Now().UnixNano()))

	if err := parquet.WriteFile(chunkPath, rows); err != nil {
		return 0, 0, err
	}
	return len(rows), int(atomic.LoadInt64(&threatSyslogReceivedCount)), nil
}

// 🌟 雙引擎 Syslog 接收器 (熱資料與冷資料雙佇列分流)
func startSyslogReceiver(port int) {
	addr := &net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("[Syslog] ⚠️ 無法監聽 UDP %d: %v\n", port, err)
		return
	}
	fmt.Printf("[Syslog] 🚀 成功啟動 UDP %d 即時接收服務 (流量與威脅雙引擎串流就緒)...\n", port)
	defer conn.Close()

	buf := make([]byte, 8192)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		rawMsg := string(buf[:n])

		// 🚨 分流 1：威脅日誌 (THREAT)
		if strings.Contains(rawMsg, "THREAT") {
			tRow, err := parsePaloAltoThreatSyslog(rawMsg)
			if err == nil && tRow != nil {
				// 1. 推入威脅熱資料佇列
				select {
				case threatSyslogQueue <- *tRow:
					atomic.AddInt64(&threatSyslogReceivedCount, 1)
				default:
					atomic.AddInt64(&threatSyslogReceivedCount, 1)
				}

				// 2. 推入威脅冷資料佇列 (非同步備份原始字串)
				select {
				case rawThreatQueue <- RawLogParquetRow{
					Timestamp:  tRow.Timestamp,
					SessionID:  tRow.SessionID,
					RawContent: strings.TrimSpace(rawMsg),
				}:
				default:
				}
			}
			continue
		}

		// 📡 分流 2：流量日誌 (TRAFFIC)
		if strings.Contains(rawMsg, "TRAFFIC") {
			row, err := parsePaloAltoSyslog(rawMsg)
			if err == nil && row != nil {
				// 1. 推入流量熱資料佇列
				select {
				case syslogQueue <- *row:
					atomic.AddInt64(&syslogReceivedCount, 1)
				default:
					atomic.AddInt64(&syslogReceivedCount, 1)
				}

				// 2. 推入流量冷資料佇列 (非同步備份原始字串)
				select {
				case rawTrafficQueue <- RawLogParquetRow{
					Timestamp:  row.Timestamp,
					SessionID:  row.SessionID,
					RawContent: strings.TrimSpace(rawMsg),
				}:
				default:
				}
			}
		}
	}
}

// 🌟 雙引擎 Syslog 落盤排程器 (熱分析資料 + 冷原始資料 統一批次落盤)
func startSyslogBatchFlusher() {
	go func() {
		ticker := time.NewTicker(3 * time.Second) // 每 3 秒固定 Flush 一次
		defer ticker.Stop()

		var batch []TrafficParquetRow
		var threatBatch []ThreatParquetRow
		var rawTrafficBatch []RawLogParquetRow
		var rawThreatBatch []RawLogParquetRow

		chunkCounter := 0
		threatChunkCounter := 0

		flushNow := func() {
			// 1. 流量熱資料落盤
			if len(batch) > 0 {
				ins, tot, err := saveSyslogBatchFast(batch)
				if err == nil {
					syslogStatusMutex.Lock()
					syslogLastFlushInsertCount = ins
					syslogLastFlushTotalCount = tot
					syslogLastFlushTime = time.Now()
					syslogStatusMutex.Unlock()

					fmt.Printf("[%s] 📡 [Syslog UDP 514] 流量極速入庫：%d 筆 (累計: %d 筆)\n",
						time.Now().Format("15:04:05"), ins, tot)

					chunkCounter++
					if chunkCounter >= 20 {
						chunkCounter = 0
						go ConsolidateParquetFiles()
					}
				}
				batch = nil
			}

			// 2. 威脅熱資料落盤
			if len(threatBatch) > 0 {
				ins, tot, err := saveThreatSyslogBatchFast(threatBatch)
				if err == nil {
					syslogStatusMutex.Lock()
					threatSyslogLastFlushCount = ins
					threatSyslogLastFlushTime = time.Now()
					syslogStatusMutex.Unlock()

					fmt.Printf("[%s] 🚨 [Syslog UDP 514] 威脅日誌入庫：%d 筆 (累計: %d 筆)\n",
						time.Now().Format("15:04:05"), ins, tot)

					threatChunkCounter++
					if threatChunkCounter >= 20 {
						threatChunkCounter = 0
						go ConsolidateThreatParquetFiles()
					}
				}
				threatBatch = nil
			}

			// 🌟 3. 流量冷資料 (Raw Parquet) 批次落盤
			if len(rawTrafficBatch) > 0 {
				_ = saveRawLogBatchFast("traffic", rawTrafficBatch)
				rawTrafficBatch = nil
			}

			// 🌟 4. 威脅冷資料 (Raw Parquet) 批次落盤
			if len(rawThreatBatch) > 0 {
				_ = saveRawLogBatchFast("threat", rawThreatBatch)
				rawThreatBatch = nil
			}
		}

		for {
			select {
			case row := <-syslogQueue:
				batch = append(batch, row)
				if len(batch) >= 1000 {
					flushNow()
				}
			case tRow := <-threatSyslogQueue:
				threatBatch = append(threatBatch, tRow)
				if len(threatBatch) >= 50 {
					flushNow()
				}
			case rawRow := <-rawTrafficQueue:
				rawTrafficBatch = append(rawTrafficBatch, rawRow)
				if len(rawTrafficBatch) >= 1000 {
					flushNow()
				}
			case rawTRow := <-rawThreatQueue:
				rawThreatBatch = append(rawThreatBatch, rawTRow)
				if len(rawThreatBatch) >= 50 {
					flushNow()
				}
			case <-ticker.C:
				flushNow()
			}
		}
	}()
}

func GetSyslogStatus() map[string]interface{} {
	syslogStatusMutex.RLock()
	lastStr := "-"
	if !syslogLastFlushTime.IsZero() {
		lastStr = syslogLastFlushTime.Format("15:04:05")
	}
	ins := syslogLastFlushInsertCount       // 流量當批筆數
	tot := syslogLastFlushTotalCount
	tIns := threatSyslogLastFlushCount     // 威脅當批筆數
	syslogStatusMutex.RUnlock()

	return map[string]interface{}{
		"port":                     514,
		"received_total":           tot,
		"last_flush_insert":        ins,  // 👈 流量當批
		"last_flush_total":         tot,
		"last_flush_time":          lastStr,
		"threat_last_flush_insert": tIns, // 👈 威脅當批
		"threat_received_total":    atomic.LoadInt64(&threatSyslogReceivedCount),
	}
}

// -------------------------------------------------------------
// 後端常駐自動排程控制器
// -------------------------------------------------------------
func SetTrafficSchedulerInterval(seconds int) {
	trafficSchedulerMutex.Lock()
	defer trafficSchedulerMutex.Unlock()

	if trafficSchedulerStopChan != nil {
		close(trafficSchedulerStopChan)
		trafficSchedulerStopChan = nil
	}

	trafficSchedulerInterval = seconds

	db, err := initDB()
	if err == nil {
		_, _ = db.Exec("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('traffic_scheduler_interval', ?)", strconv.Itoa(seconds))
	}

	if seconds <= 0 {
		trafficLastCollectStatus = "idle"
		trafficLastCollectMsg = "已切換為手動排程"
		return
	}

	trafficSchedulerStopChan = make(chan struct{})
	trafficLastCollectStatus = "running"
	trafficLastCollectMsg = fmt.Sprintf("後端排程運行中 (每 %d 秒循環採樣)", seconds)

	go func(intervalSec int, stopCh chan struct{}) {
		entries, err := fetchPATrafficLogs(2500)
		if err == nil {
			ins, tot, _ := saveTrafficLogsToParquet(entries)
			trafficSchedulerMutex.Lock()
			trafficLastCollectTime = time.Now()
			trafficLastCollectCount = ins
			trafficLastCollectStatus = "success"
			trafficLastCollectMsg = fmt.Sprintf("成功新增 %d 筆，累計 %d 筆", ins, tot)
			trafficSchedulerMutex.Unlock()
		}

		ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				entries, err := fetchPATrafficLogs(2500)
				trafficSchedulerMutex.Lock()
				trafficLastCollectTime = time.Now()
				if err == nil {
					ins, tot, _ := saveTrafficLogsToParquet(entries)
					trafficLastCollectCount = ins
					trafficLastCollectStatus = "success"
					trafficLastCollectMsg = fmt.Sprintf("成功新增 %d 筆，累計 %d 筆", ins, tot)
				} else {
					trafficLastCollectStatus = "error"
					trafficLastCollectMsg = err.Error()
				}
				trafficSchedulerMutex.Unlock()

			case <-stopCh:
				return
			}
		}
	}(seconds, trafficSchedulerStopChan)
}

func GetTrafficSchedulerStatus() map[string]interface{} {
	trafficSchedulerMutex.Lock()
	defer trafficSchedulerMutex.Unlock()

	lastTimeStr := "-"
	if !trafficLastCollectTime.IsZero() {
		lastTimeStr = trafficLastCollectTime.Format("15:04:05")
	}

	return map[string]interface{}{
		"interval":   trafficSchedulerInterval,
		"status":     trafficLastCollectStatus,
		"last_time":  lastTimeStr,
		"last_count": trafficLastCollectCount,
		"message":    trafficLastCollectMsg,
	}
}

// -------------------------------------------------------------
// 🦆 DuckDB 內部呼叫小幫手 (將 SQL 傳給 duckdb.exe 並回傳 JSON)
// -------------------------------------------------------------
func runDuckDBQuery(query string) ([]map[string]interface{}, error) {
	duckdbExe := filepath.Join(appDir, "duckdb.exe")
	if _, err := os.Stat(duckdbExe); os.IsNotExist(err) {
		return nil, fmt.Errorf("找不到 duckdb.exe！請前往官網下載並放入專案目錄: %s", appDir)
	}

	cmd := exec.Command(duckdbExe, "-json", "-c", query)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("DuckDB 執行失敗: %v, 詳細錯誤: %s", err, stderr.String())
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		return []map[string]interface{}{}, nil
	}

	var res []map[string]interface{}
	if err := json.Unmarshal([]byte(outStr), &res); err != nil {
		return nil, fmt.Errorf("解析 DuckDB 回傳失敗: %v", err)
	}
	return res, nil
}

// 🌟 安全解析 DuckDB JSON 欄位（相容 float64、int 與 HUGEINT 字串）
func parseDuckDBNumber(val interface{}) int64 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		// 解決 DuckDB 將 HUGEINT 序列化為字串的問題
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return int64(f)
		}
	}
	return 0
}

// -------------------------------------------------------------
// 🌟 聚合查詢：DuckDB 向量化極速引擎 (並行化與翻頁解耦版)
// -------------------------------------------------------------
func queryTrafficAnalytics(queryDate, src, dst, app, action, zone string, page, perPage int, onlyLogs bool) (*TrafficAnalyticsResult, error) {
	if queryDate == "" { queryDate = time.Now().Format("2006-01-02") }
	if page < 1 { page = 1 }
	if perPage < 1 { perPage = 50 }

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ { emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0} }

	pattern := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate))
	files, _ := filepath.Glob(pattern)

	var totalFileSize int64 = 0
	hasFiles := false
	for _, f := range files {
		if !strings.HasSuffix(f, ".tmp") {
			if info, err := os.Stat(f); err == nil {
				totalFileSize += info.Size()
				hasFiles = true
			}
		}
	}

	var dbSizeStr string
	if totalFileSize >= 1024*1024*1024 {
		dbSizeStr = fmt.Sprintf("%.2f GB", float64(totalFileSize)/(1024*1024*1024))
	} else if totalFileSize >= 1024*1024 {
		dbSizeStr = fmt.Sprintf("%.2f MB", float64(totalFileSize)/(1024*1024))
	} else if totalFileSize >= 1024 {
		dbSizeStr = fmt.Sprintf("%.1f KB", float64(totalFileSize)/1024)
	} else {
		dbSizeStr = fmt.Sprintf("%d B", totalFileSize)
	}

	if !hasFiles {
		return &TrafficAnalyticsResult{
			TotalFlows: 0, TotalBytes: "0 B", TopApp: "-", DbSize: "0 B",
			Histogram: emptyHistogram, Logs: make([]TrafficLogItem, 0), CurrentPage: 1, TotalPages: 1,
		}, nil
	}

	duckdbPattern := filepath.ToSlash(pattern)

	var conds []string
	conds = append(conds, "1=1")
	if src != "" { conds = append(conds, fmt.Sprintf("source ILIKE '%%%s%%'", strings.ReplaceAll(src, "'", "''"))) }
	if dst != "" { conds = append(conds, fmt.Sprintf("destination ILIKE '%%%s%%'", strings.ReplaceAll(dst, "'", "''"))) }
	if app != "" { conds = append(conds, fmt.Sprintf("application ILIKE '%%%s%%'", strings.ReplaceAll(app, "'", "''"))) }
	if action != "" && strings.ToLower(action) != "all" {
		act := strings.ToLower(action)
		if act == "allow" { conds = append(conds, "action = 'allow'") } else if act == "deny" { conds = append(conds, "(action IN ('deny', 'drop') OR action LIKE 'reset%')") }
	}
	if zone != "" && strings.ToLower(zone) != "all" {
		z := strings.ReplaceAll(strings.ToLower(zone), "'", "''")
		conds = append(conds, fmt.Sprintf("(from_zone ILIKE '%%%s%%' OR to_zone ILIKE '%%%s%%')", z, z))
	}
	whereClause := strings.Join(conds, " AND ")

	var statsRes, histRes, logsRes []map[string]interface{}
	var errStats, errHist, errLogs error
	var wg sync.WaitGroup

	// ==========================================
	// 🦆 任務 1 & 2：若非單純換頁，則平行執行統計與直方圖
	// ==========================================
	if !onlyLogs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			// 🌟 優化 SQL：將 SUM(bytes) 轉為 DOUBLE，並使用 COUNT 替代 SUM(CASE) 保持 BIGINT
			statsQuery := fmt.Sprintf(`
				SELECT 
					COUNT(*) AS total_flows, 
					CAST(COALESCE(SUM(bytes), 0) AS DOUBLE) AS total_bytes, 
					COUNT(CASE WHEN LOWER(action) IN ('deny','drop') OR LOWER(action) LIKE 'reset%%' THEN 1 END) AS deny_flows, 
					MODE(application) AS top_app 
				FROM '%s' WHERE %s
			`, duckdbPattern, whereClause)
			statsRes, errStats = runDuckDBQuery(statsQuery)
		}()
		go func() {
			defer wg.Done()
			histQuery := fmt.Sprintf(`SELECT SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS h, COUNT(*) AS c FROM '%s' WHERE %s GROUP BY h`, duckdbPattern, whereClause)
			histRes, errHist = runDuckDBQuery(histQuery)
		}()
	}

	// ==========================================
	// 🦆 任務 3：同時撈取目前頁面的 50 筆明細
	// ==========================================
	wg.Add(1)
	go func() {
		defer wg.Done()
		offset := (page - 1) * perPage
		logsQuery := fmt.Sprintf(`SELECT * FROM '%s' WHERE %s ORDER BY timestamp DESC LIMIT %d OFFSET %d`, duckdbPattern, whereClause, perPage, offset)
		logsRes, errLogs = runDuckDBQuery(logsQuery)
	}()

	wg.Wait()
	if errStats != nil { return nil, errStats }
	if errHist != nil { return nil, errHist }
	if errLogs != nil { return nil, errLogs }

	// 處理結果
	var totalFlows int
	var totalBytesNum int64
	var denyFlows int
	topApp := "-"

	if !onlyLogs && len(statsRes) > 0 {
		totalFlows = int(parseDuckDBNumber(statsRes[0]["total_flows"]))
		totalBytesNum = parseDuckDBNumber(statsRes[0]["total_bytes"])
		denyFlows = int(parseDuckDBNumber(statsRes[0]["deny_flows"]))
		if v, ok := statsRes[0]["top_app"].(string); ok && v != "" { 
			topApp = v 
		}
	}

	var totalBytesStr string
	if totalBytesNum >= 1024*1024*1024 { totalBytesStr = fmt.Sprintf("%.2f GB", float64(totalBytesNum)/(1024*1024*1024))
	} else if totalBytesNum >= 1024*1024 { totalBytesStr = fmt.Sprintf("%.2f MB", float64(totalBytesNum)/(1024*1024))
	} else if totalBytesNum >= 1024 { totalBytesStr = fmt.Sprintf("%.1f KB", float64(totalBytesNum)/1024)
	} else { totalBytesStr = fmt.Sprintf("%d B", totalBytesNum) }

	if !onlyLogs {
		histMap := make(map[string]int)
		for _, row := range histRes {
			if h, ok := row["h"].(string); ok {
				if c, ok := row["c"].(float64); ok { histMap[h] = int(c) }
			}
		}
		for h := 0; h < 24; h++ {
			emptyHistogram[h].Count = histMap[fmt.Sprintf("%02d:00", h)]
		}
	}

	dhcpMap := make(map[string]string)
	db, _ := initDB()
	if db != nil {
		rDHCP, _ := db.Query("SELECT ip, hostname FROM dhcp_leases WHERE record_date = ?", queryDate)
		if rDHCP != nil {
			defer rDHCP.Close()
			for rDHCP.Next() {
				var ip, hn string; _ = rDHCP.Scan(&ip, &hn)
				if hn != "" { dhcpMap[ip] = hn }
			}
		}
		rCache, _ := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
		if rCache != nil {
			defer rCache.Close()
			for rCache.Next() {
				var ip, hn string; _ = rCache.Scan(&ip, &hn)
				if hn != "" && dhcpMap[ip] == "" { dhcpMap[ip] = hn }
			}
		}
	}

	logs := make([]TrafficLogItem, 0, len(logsRes))
	safeStr := func(v interface{}) string {
		if v == nil { return "" }; return fmt.Sprintf("%v", v)
	}

	for _, r := range logsRes {
		bytesVal := int64(0)
		if v, ok := r["bytes"].(float64); ok { bytesVal = int64(v) }
		var bFmt string
		if bytesVal >= 1024*1024 { bFmt = fmt.Sprintf("%.2f MB", float64(bytesVal)/(1024*1024))
		} else if bytesVal >= 1024 { bFmt = fmt.Sprintf("%.1f KB", float64(bytesVal)/1024)
		} else { bFmt = fmt.Sprintf("%d B", bytesVal) }

		logs = append(logs, TrafficLogItem{
			Timestamp: safeStr(r["timestamp"]), Type: safeStr(r["type"]), FromZone: safeStr(r["from_zone"]), ToZone: safeStr(r["to_zone"]),
			Source: safeStr(r["source"]), SrcHostname: dhcpMap[safeStr(r["source"])], NatSourceIP: safeStr(r["nat_source_ip"]), Destination: safeStr(r["destination"]),
			NatDestIP: safeStr(r["nat_dest_ip"]), ToPort: int(r["to_port"].(float64)), Application: safeStr(r["application"]), Action: safeStr(r["action"]),
			Rule: safeStr(r["rule"]), SessionEndReason: safeStr(r["session_end_reason"]), Bytes: bytesVal, BytesFormatted: bFmt,
		})
	}

	totalPages := int(math.Ceil(float64(totalFlows) / float64(perPage)))
	if totalPages == 0 { totalPages = 1 }

	return &TrafficAnalyticsResult{
		TotalFlows: totalFlows, TotalBytes: totalBytesStr, TopApp: topApp,
		DenyFlows: denyFlows, DbSize: dbSizeStr, Histogram: emptyHistogram,
		Logs: logs, CurrentPage: page, TotalPages: totalPages,
	}, nil
}

// 🌟 Threat 多檔合併器：將同一日期的碎片/多次回補合併為每日單一主檔，核心整併器：由 DuckDB 接管背景極速整併 (零記憶體消耗)
func ConsolidateThreatParquetFiles() (int, int, error) {
	threatFileMutex.Lock()
	defer threatFileMutex.Unlock()

	entries, err := os.ReadDir(threatDir)
	if err != nil { return 0, 0, err }

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`threat_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") { continue }
		if m := re.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateFiles[m[1]] = append(dateFiles[m[1]], filepath.Join(threatDir, e.Name()))
		}
	}

	totalMergedFiles := 0

	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", dateKey))
		if len(files) == 1 && files[0] == targetMainFile { continue }

		fmt.Printf("[威脅整合] ⏳ DuckDB 引擎啟動：正在將 %s 的 %d 個檔案極速整併...\n", dateKey, len(files))

		tmpFile := targetMainFile + ".tmp"
		globPath := filepath.ToSlash(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", dateKey)))
		tmpSlash := filepath.ToSlash(tmpFile)

		copyQuery := fmt.Sprintf(`
			COPY (
				SELECT 
					timestamp, subtype, threat_id, threat_name, from_zone, to_zone, 
					src, dst, to_port, application, action, severity, url, session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY timestamp, src, dst, threat_name, action 
						ORDER BY timestamp DESC
					) as row_num
					FROM read_parquet('%s', union_by_name=true)
				) WHERE row_num = 1
				ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, globPath, tmpSlash)

		_, err := runDuckDBQuery(copyQuery)
		if err != nil {
			_ = os.Remove(tmpFile)
			fmt.Printf("[威脅整合] ❌ DuckDB 整併 %s 失敗: %v\n", dateKey, err)
			continue
		}

		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err == nil {
			for _, f := range files {
				if f != targetMainFile {
					_ = os.Remove(f)
					totalMergedFiles++
				}
			}
			fmt.Printf("[威脅整合] ✅ %s 整併完成！已合併為單一 ZSTD 主檔，清除 %d 個碎片檔案。\n", dateKey, len(files)-1)
		} else {
			_ = os.Remove(tmpFile)
		}
	}

	return totalMergedFiles, 0, nil
}

// 🌟 冷資料 Raw Parquet 多檔自動整併器 (DuckDB 向量引擎接管)
func ConsolidateRawParquetFiles(logType string) (int, error) {
	targetDir := trafficRawDir
	if logType == "threat" {
		targetDir = threatRawDir
	}

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		return 0, err
	}

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(fmt.Sprintf(`^%s_raw_(\d{4}-\d{2}-\d{2})`, logType))

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		if m := re.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateFiles[m[1]] = append(dateFiles[m[1]], filepath.Join(targetDir, e.Name()))
		}
	}

	totalMerged := 0
	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(targetDir, fmt.Sprintf("%s_raw_%s.parquet", logType, dateKey))
		// 如果目錄裡只有該日期唯一的已整併主檔，跳過不重做
		if len(files) <= 1 && files[0] == targetMainFile {
			continue
		}

		fmt.Printf("[冷資料整併] ⏳ 正在整併 %s %s 原始資料 (%d 個檔案)...\n", dateKey, logType, len(files))

		tmpFile := targetMainFile + ".tmp"
		globPath := filepath.ToSlash(filepath.Join(targetDir, fmt.Sprintf("%s_raw_%s*.parquet", logType, dateKey)))
		tmpSlash := filepath.ToSlash(tmpFile)

		copyQuery := fmt.Sprintf(`
			COPY (
				SELECT timestamp, session_id, raw_content FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY timestamp, session_id 
						ORDER BY timestamp DESC
					) as row_num
					FROM read_parquet('%s', union_by_name=true)
				) WHERE row_num = 1
				ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, globPath, tmpSlash)

		_, err := runDuckDBQuery(copyQuery)
		if err != nil {
			_ = os.Remove(tmpFile)
			fmt.Printf("[冷資料整併] ❌ 失敗: %v\n", err)
			continue
		}

		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err == nil {
			for _, f := range files {
				if f != targetMainFile {
					_ = os.Remove(f)
					totalMerged++
				}
			}
			fmt.Printf("[冷資料整併] ✅ %s %s 成功合併為主檔，已清除 %d 個分塊。\n", dateKey, logType, len(files)-1)
		} else {
			_ = os.Remove(tmpFile)
		}
	}

	return totalMerged, nil
}

// 🌟 冷資料自動維護排程器：開機 10 秒預先整併 + 對齊時鐘整點 (XX:00:00) 循環
func startHourlyRawConsolidator() {
	go func() {
		// 1. 開機暖機 10 秒後，立刻對現存歷史碎檔執行一次全面整併
		time.Sleep(10 * time.Second)
		fmt.Printf("[%s] 🚀 [冷資料整併] 啟動初次歷史碎片清掃...\n", time.Now().Format("15:04:05"))
		ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")

		for {
			// 2. 精準計算距離下一個「時鐘整點 (XX:00:00)」的剩餘時間
			now := time.Now()
			nextHour := now.Truncate(time.Hour).Add(1 * time.Hour)
			sleepDuration := time.Until(nextHour)

			// 避免剛好在整點時 sleep 0 秒
			if sleepDuration <= 0 {
				sleepDuration = 1 * time.Hour
			}

			time.Sleep(sleepDuration)

			// 3. 抵達時鐘整點，準時觸發整併
			fmt.Printf("[%s] ⏱️ [時鐘整點 %02d:00] 冷資料維護排程觸發...\n", 
				time.Now().Format("15:04:05"), time.Now().Hour())
			ConsolidateRawParquetFiles("traffic")
			ConsolidateRawParquetFiles("threat")
		}
	}()
}

// 🌟 Threat 每日單一主檔寫入 (主分析檔維持純淨欄位 + 原始 XML 獨立寫入備份檔)
func saveThreatLogsToParquet(entries []ThreatEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	threatFileMutex.Lock()
	defer threatFileMutex.Unlock()

	var rawRows []RawLogParquetRow // 👈 收集獨立冷資料 (Raw XML)
	entriesByDate := make(map[string][]ThreatParquetRow)

	for _, e := range entries {
		tName := strings.TrimSpace(e.ThreatName)
		if tName == "" {
			tName = strings.TrimSpace(e.ThreatID)
		}

		// 從 TimeGenerated 提取時間，若為空則以 ReceiveTime 備援
		ts := strings.TrimSpace(e.TimeGenerated)
		if ts == "" {
			ts = strings.TrimSpace(e.ReceiveTime)
		}
		ts = strings.ReplaceAll(ts, "/", "-")

		// 1. 組裝純淨的分析主檔記錄 (不混雜巨大 XML)
		row := ThreatParquetRow{
			Timestamp:   ts,
			Subtype:     strings.TrimSpace(e.Subtype),
			ThreatID:    strings.TrimSpace(e.ThreatID),
			ThreatName:  tName,
			FromZone:    strings.TrimSpace(e.FromZone),
			ToZone:      strings.TrimSpace(e.ToZone),
			Src:         strings.TrimSpace(e.Src),
			Dst:         strings.TrimSpace(e.Dst),
			ToPort:      int32(e.ToPort),
			Application: strings.TrimSpace(e.App),
			Action:      strings.TrimSpace(e.Action),
			Severity:    strings.ToLower(strings.TrimSpace(e.Severity)),
			URL:         strings.TrimSpace(e.URL),
			SessionID:   strings.TrimSpace(e.SessionID),
		}

		recordDate := time.Now().Format("2006-01-02")
		if len(row.Timestamp) >= 10 {
			recordDate = row.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], row)

		// 2. 🌟 收集完整原始 XML 資料串到冷資料陣列
		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  strings.TrimSpace(e.SessionID),
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
	}

	// 3. 🌟 非同步將完整 XML 寫入 threat_raw_logs/，完全不拖慢主執行緒
	if len(rawRows) > 0 {
		go func(r []RawLogParquetRow) {
			_ = saveRawLogBatchFast("threat", r)
		}(rawRows)
	}

	totalInserted := 0
	totalToday := 0

	for dateKey, newRows := range entriesByDate {
		mainPath := filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", dateKey))
		tmpPath := mainPath + ".tmp"

		var combinedRows []ThreatParquetRow
		existingKeys := make(map[string]bool)

		if _, err := os.Stat(mainPath); err == nil {
			if oldRows, err := parquet.ReadFile[ThreatParquetRow](mainPath); err == nil {
				for _, r := range oldRows {
					key := fmt.Sprintf("%s|%s|%s|%s|%s", r.Timestamp, r.Src, r.Dst, r.ThreatName, r.Action)
					if !existingKeys[key] {
						existingKeys[key] = true
						combinedRows = append(combinedRows, r)
					}
				}
			}
		}

		newCount := 0
		for _, r := range newRows {
			key := fmt.Sprintf("%s|%s|%s|%s|%s", r.Timestamp, r.Src, r.Dst, r.ThreatName, r.Action)
			if !existingKeys[key] {
				existingKeys[key] = true
				combinedRows = append(combinedRows, r)
				newCount++
			}
		}

		if newCount == 0 && len(combinedRows) > 0 {
			totalToday = len(combinedRows)
			continue
		}
		totalInserted += newCount

		sort.Slice(combinedRows, func(i, j int) bool {
			return combinedRows[i].Timestamp > combinedRows[j].Timestamp
		})

		if err := parquet.WriteFile(tmpPath, combinedRows); err != nil {
			_ = os.Remove(tmpPath)
			continue
		}

		_ = os.Remove(mainPath)
		_ = os.Rename(tmpPath, mainPath)
		totalToday = len(combinedRows)
	}

	return totalInserted, totalToday, nil
}

// -------------------------------------------------------------
// 🦆 威脅日誌極速聚合查詢 (DuckDB 向量化引擎 - 新舊 Parquet 完整相容版)
// -------------------------------------------------------------
func queryThreatAnalytics(queryDate, src, dst, severity, action, threatName string, page, perPage int, onlyLogs bool) (*ThreatAnalyticsResult, error) {
	// 🌟 日期斜線防呆轉換 (2026/10/24 -> 2026-10-24)
	queryDate = strings.ReplaceAll(strings.TrimSpace(queryDate), "/", "-")
	if queryDate == "" { 
		queryDate = time.Now().Format("2006-01-02") 
	}
	if page < 1 { page = 1 }
	if perPage < 1 { perPage = 50 }

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0}
	}

	pattern := filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", queryDate))
	files, _ := filepath.Glob(pattern)

	var totalFileSize int64 = 0
	hasFiles := false
	for _, f := range files {
		if !strings.HasSuffix(f, ".tmp") {
			if info, err := os.Stat(f); err == nil {
				totalFileSize += info.Size()
				hasFiles = true
			}
		}
	}

	var dbSizeStr string
	if totalFileSize >= 1024*1024*1024 {
		dbSizeStr = fmt.Sprintf("%.2f GB", float64(totalFileSize)/(1024*1024*1024))
	} else if totalFileSize >= 1024*1024 {
		dbSizeStr = fmt.Sprintf("%.2f MB", float64(totalFileSize)/(1024*1024))
	} else if totalFileSize >= 1024 {
		dbSizeStr = fmt.Sprintf("%.1f KB", float64(totalFileSize)/1024)
	} else {
		dbSizeStr = fmt.Sprintf("%d B", totalFileSize)
	}

	// 若當日尚無任何檔案，秒回 0 筆空資料
	if !hasFiles {
		return &ThreatAnalyticsResult{
			TotalThreats: 0, CriticalHigh: 0, TopThreat: "-", TopVictimIP: "-", TopVictimHost: "-",
			DbSize: "0 B", Histogram: emptyHistogram, Logs: make([]ThreatLogItem, 0), CurrentPage: 1, TotalPages: 1,
		}, nil
	}

	duckdbPattern := filepath.ToSlash(pattern)
	var conds []string
	conds = append(conds, "1=1")
	if src != "" { conds = append(conds, fmt.Sprintf("src ILIKE '%%%s%%'", strings.ReplaceAll(src, "'", "''"))) }
	if dst != "" { conds = append(conds, fmt.Sprintf("dst ILIKE '%%%s%%'", strings.ReplaceAll(dst, "'", "''"))) }
	if threatName != "" { 
		t := strings.ReplaceAll(threatName, "'", "''")
		conds = append(conds, fmt.Sprintf("(threat_name ILIKE '%%%s%%' OR subtype ILIKE '%%%s%%')", t, t)) 
	}
	if severity != "" && strings.ToLower(severity) != "all" {
		conds = append(conds, fmt.Sprintf("LOWER(severity) = '%s'", strings.ToLower(severity)))
	}
	if action != "" && strings.ToLower(action) != "all" {
		conds = append(conds, fmt.Sprintf("LOWER(action) ILIKE '%%%s%%'", strings.ToLower(action)))
	}
	whereClause := strings.Join(conds, " AND ")

	var statsRes, histRes, logsRes []map[string]interface{}
	var errStats, errHist, errLogs error
	var wg sync.WaitGroup

	if !onlyLogs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			statsQuery := fmt.Sprintf(`
				SELECT 
					COUNT(*) AS total_threats,
					COALESCE(SUM(CASE WHEN LOWER(severity) IN ('critical', 'high') THEN 1 ELSE 0 END), 0) AS critical_high,
					MODE(threat_name) AS top_threat,
					MODE(src) AS top_victim
				FROM '%s' WHERE %s
			`, duckdbPattern, whereClause)
			statsRes, errStats = runDuckDBQuery(statsQuery)
		}()

		go func() {
			defer wg.Done()
			histQuery := fmt.Sprintf(`
				SELECT SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS h, COUNT(*) AS c
				FROM '%s' WHERE %s GROUP BY h
			`, duckdbPattern, whereClause)
			histRes, errHist = runDuckDBQuery(histQuery)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		offset := (page - 1) * perPage
		// 🌟 核心防護：使用 SELECT *，不指定單一欄位，新舊檔案完全零報錯！
		logsQuery := fmt.Sprintf(`
			SELECT * FROM '%s' WHERE %s 
			ORDER BY timestamp DESC 
			LIMIT %d OFFSET %d
		`, duckdbPattern, whereClause, perPage, offset)
		logsRes, errLogs = runDuckDBQuery(logsQuery)
	}()

	wg.Wait()
	if errStats != nil { return nil, errStats }
	if errHist != nil { return nil, errHist }
	if errLogs != nil { return nil, errLogs }

	var totalThreats, criticalHigh int
	topThreat := "-"
	topVictimIP := "-"

	if !onlyLogs && len(statsRes) > 0 {
		totalThreats = int(parseDuckDBNumber(statsRes[0]["total_threats"]))
		criticalHigh = int(parseDuckDBNumber(statsRes[0]["critical_high"]))
		if v, ok := statsRes[0]["top_threat"].(string); ok && v != "" { topThreat = v }
		if v, ok := statsRes[0]["top_victim"].(string); ok && v != "" { topVictimIP = v }
	}

	if !onlyLogs {
		histMap := make(map[string]int)
		for _, row := range histRes {
			if h, ok := row["h"].(string); ok {
				if c, ok := row["c"].(float64); ok { histMap[h] = int(c) }
			}
		}
		for h := 0; h < 24; h++ {
			emptyHistogram[h].Count = histMap[fmt.Sprintf("%02d:00", h)]
		}
	}

	dhcpMap := make(map[string]string)
	db, _ := initDB()
	if db != nil {
		rDHCP, _ := db.Query("SELECT ip, hostname FROM dhcp_leases WHERE record_date = ?", queryDate)
		if rDHCP != nil {
			defer rDHCP.Close()
			for rDHCP.Next() {
				var ip, hn string; _ = rDHCP.Scan(&ip, &hn)
				if hn != "" { dhcpMap[ip] = hn }
			}
		}
		rCache, _ := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
		if rCache != nil {
			defer rCache.Close()
			for rCache.Next() {
				var ip, hn string; _ = rCache.Scan(&ip, &hn)
				if hn != "" && dhcpMap[ip] == "" { dhcpMap[ip] = hn }
			}
		}
	}

	topVictimHost := dhcpMap[topVictimIP]
	if topVictimHost == "" { topVictimHost = "-" }

	// 🌟 安全取值小幫手：新舊 Parquet 缺少欄位自動補 "-"
	safeGet := func(m map[string]interface{}, key string) string {
		if v, ok := m[key]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" { return s }
		}
		return "-"
	}

	logs := make([]ThreatLogItem, 0, len(logsRes))
	for _, r := range logsRes {
		portVal := 0
		if v, ok := r["to_port"].(float64); ok { portVal = int(v) }

		srcIP := safeGet(r, "src")
		logs = append(logs, ThreatLogItem{
			Timestamp:   safeGet(r, "timestamp"),
			Subtype:     safeGet(r, "subtype"),
			ThreatName:  safeGet(r, "threat_name"),
			FromZone:    safeGet(r, "from_zone"),
			ToZone:      safeGet(r, "to_zone"),
			Source:      srcIP,
			SrcHostname: dhcpMap[srcIP],
			Destination: safeGet(r, "dst"),
			ToPort:      portVal,
			Application: safeGet(r, "application"),
			Action:      safeGet(r, "action"),
			Severity:    strings.ToLower(safeGet(r, "severity")),
			URL:         safeGet(r, "url"),
			SessionID:   safeGet(r, "session_id"),
		})
	}

	totalPages := int(math.Ceil(float64(totalThreats) / float64(perPage)))
	if totalPages == 0 { totalPages = 1 }

	return &ThreatAnalyticsResult{
		TotalThreats:  totalThreats,
		CriticalHigh:  criticalHigh,
		TopThreat:     topThreat,
		TopVictimIP:   topVictimIP,
		TopVictimHost: topVictimHost,
		DbSize:        dbSizeStr,
		Histogram:     emptyHistogram,
		Logs:          logs,
		CurrentPage:   page,
		TotalPages:    totalPages,
	}, nil
}

