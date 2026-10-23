package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
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
	dbConn       *sql.DB
	dbMutex      sync.Mutex
	
	threatFileMutex sync.Mutex // 👈 威脅檔案安全互斥鎖

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

	// 🌟 Syslog 即時接收佇列與 Flush 狀態統計
	syslogQueue                = make(chan TrafficParquetRow, 50000)
	syslogReceivedCount        int64
	syslogLastReceivedTime     time.Time
	syslogLastFlushInsertCount int
	syslogLastFlushTotalCount  int
	syslogLastFlushTime        time.Time
	syslogStatusMutex          sync.RWMutex

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

type ThreatEntry struct {
	Src           string `xml:"src"`
	Dst           string `xml:"dst"`
	ThreatID      string `xml:"threatid"`
	ThreatName    string `xml:"threat_name"`
	Subtype       string `xml:"subtype"`
	Severity      string `xml:"severity"`
	Action        string `xml:"action"`
	TimeGenerated string `xml:"time_generated"`
	ReceiveTime   string `xml:"receive_time"`
	App           string `xml:"app"`
}

type TrafficParquetRow struct {
	Timestamp        string `parquet:"timestamp,snappy"`
	Type             string `parquet:"type,snappy"`
	FromZone         string `parquet:"from_zone,snappy"`
	ToZone           string `parquet:"to_zone,snappy"`
	Source           string `parquet:"source,snappy"`
	NatSourceIP      string `parquet:"nat_source_ip,snappy"`
	Destination      string `parquet:"destination,snappy"`
	NatDestIP        string `parquet:"nat_dest_ip,snappy"`
	ToPort           int32  `parquet:"to_port"`
	Application      string `parquet:"application,snappy"`
	Action           string `parquet:"action,snappy"`
	Rule             string `parquet:"rule,snappy"`
	SessionEndReason string `parquet:"session_end_reason,snappy"`
	Bytes            int64  `parquet:"bytes"`
	SessionID        string `parquet:"session_id,snappy"`
}

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
	Histogram   []HistogramBucket `json:"histogram"`
	Logs        []TrafficLogItem  `json:"logs"`
	CurrentPage int               `json:"current_page"`
	TotalPages  int               `json:"total_pages"`
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

	// 🌟 2. 自動將根目錄現有的 threat_*.parquet 搬移歸位到 threat_logs/
	rootThreatFiles, _ := filepath.Glob(filepath.Join(appDir, "threat_*.parquet"))
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
// 🌟 核心整併器：啟動時將歷史所有零碎分塊整合成「每日單一主檔」
// -------------------------------------------------------------
func ConsolidateParquetFiles() (int, int, error) {
	parquetFileMutex.Lock()
	defer parquetFileMutex.Unlock()

	entries, err := os.ReadDir(trafficDir)
	if err != nil {
		return 0, 0, err
	}

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`^traffic_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if len(m) > 1 {
			dateKey := m[1]
			dateFiles[dateKey] = append(dateFiles[dateKey], filepath.Join(trafficDir, e.Name()))
		}
	}

	totalMergedFiles := 0
	totalRowsRetained := 0

	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", dateKey))

		// 若已經只有一個且檔名正是主檔，則不需整併
		if len(files) == 1 && files[0] == targetMainFile {
			continue
		}

		fmt.Printf("[資料整合] ⏳ 正在將 %s 的 %d 個分塊日誌整合成單一檔案...\n", dateKey, len(files))

		var combinedRows []TrafficParquetRow
		existingKeys := make(map[string]bool)

		for _, f := range files {
			rows, err := parquet.ReadFile[TrafficParquetRow](f)
			if err == nil {
				for _, r := range rows {
					key := fmt.Sprintf("%s|%s|%s|%d|%s", r.Timestamp, r.Source, r.Destination, r.ToPort, r.SessionID)
					if !existingKeys[key] {
						existingKeys[key] = true
						combinedRows = append(combinedRows, r)
					}
				}
			}
		}

		if len(combinedRows) == 0 {
			continue
		}

		// 按接收時間倒序排序 (最新連線在最前)
		sort.Slice(combinedRows, func(i, j int) bool {
			return combinedRows[i].Timestamp > combinedRows[j].Timestamp
		})

		// 寫入臨時檔並原子替換為主檔
		tmpFile := targetMainFile + ".tmp"
		if err := parquet.WriteFile(tmpFile, combinedRows); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}

		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}

		// 刪除所有碎檔
		for _, f := range files {
			if f != targetMainFile {
				_ = os.Remove(f)
				totalMergedFiles++
			}
		}
		totalRowsRetained += len(combinedRows)
		fmt.Printf("[資料整合] ✅ %s 整併完成！已合併為單一檔案，保留 %d 筆唯一紀錄，清除 %d 個碎片檔案。\n",
			dateKey, len(combinedRows), len(files)-1)
	}

	return totalMergedFiles, totalRowsRetained, nil
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

func saveTrafficLogsToParquet(entries []TrafficEntry) (int, int, error) {
	var rows []TrafficParquetRow
	for _, e := range entries {
		rows = append(rows, TrafficParquetRow{
			Timestamp:        e.Timestamp,
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
	}
	ins, tot, err := saveParquetRowsDirect(rows)
	if err == nil {
		syslogStatusMutex.Lock()
		syslogLastFlushInsertCount = ins
		syslogLastFlushTotalCount = tot
		syslogLastFlushTime = time.Now()
		syslogStatusMutex.Unlock()
	}
	return ins, tot, err
}

// -------------------------------------------------------------
// 🌟 Syslog UDP 514 接收與解析引擎
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

func startSyslogReceiver(port int) {
	addr := &net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("[Syslog] ⚠️ 無法監聽 UDP %d: %v\n", port, err)
		return
	}
	fmt.Printf("[Syslog] 🚀 成功啟動 UDP %d 即時接收服務 (正在等待 PA-1420 封包串流)...\n", port)
	defer conn.Close()

	buf := make([]byte, 8192)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		rawMsg := string(buf[:n])
		row, err := parsePaloAltoSyslog(rawMsg)
		if err == nil && row != nil {
			select {
			case syslogQueue <- *row:
				atomic.AddInt64(&syslogReceivedCount, 1)
				syslogStatusMutex.Lock()
				syslogLastReceivedTime = time.Now()
				syslogStatusMutex.Unlock()
			default:
			}
		}
	}
}

func startSyslogBatchFlusher() {
	go func() {
		// 🌟 縮短至 5 秒週期 Flush，反應更即時、終端機即時反饋
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		var batch []TrafficParquetRow
		for {
			select {
			case row := <-syslogQueue:
				batch = append(batch, row)
				if len(batch) >= 300 {
					ins, tot, err := saveParquetRowsDirect(batch)
					if err == nil {
						syslogStatusMutex.Lock()
						syslogLastFlushInsertCount = ins
						syslogLastFlushTotalCount = tot
						syslogLastFlushTime = time.Now()
						syslogStatusMutex.Unlock()
						if ins > 0 {
							fmt.Printf("[%s] 📡 [Syslog UDP 514] 批次寫入 Parquet：新增 %d 筆 (當日累計: %d 筆)\n",
								time.Now().Format("15:04:05"), ins, tot)
						}
					}
					batch = nil
				}
			case <-ticker.C:
				if len(batch) > 0 {
					ins, tot, err := saveParquetRowsDirect(batch)
					if err == nil {
						syslogStatusMutex.Lock()
						syslogLastFlushInsertCount = ins
						syslogLastFlushTotalCount = tot
						syslogLastFlushTime = time.Now()
						syslogStatusMutex.Unlock()
						if ins > 0 {
							fmt.Printf("[%s] 📡 [Syslog UDP 514] 定時 Flush Parquet：新增 %d 筆 (當日累計: %d 筆)\n",
								time.Now().Format("15:04:05"), ins, tot)
						}
					}
					batch = nil
				}
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
	ins := syslogLastFlushInsertCount
	tot := syslogLastFlushTotalCount
	syslogStatusMutex.RUnlock()

	return map[string]interface{}{
		"port":              514,
		"received_total":    atomic.LoadInt64(&syslogReceivedCount),
		"last_flush_insert": ins,
		"last_flush_total":  tot,
		"last_flush_time":   lastStr,
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
// 🌟 聚合查詢：直接讀取「每日單一主檔」，秒級載入
// -------------------------------------------------------------
func queryTrafficAnalytics(queryDate, src, dst, app, action, zone string, page, perPage int) (*TrafficAnalyticsResult, error) {
	if queryDate == "" {
		queryDate = time.Now().Format("2006-01-02")
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		emptyHistogram[h] = HistogramBucket{
			TimeBucket: fmt.Sprintf("%02d:00", h),
			Count:      0,
		}
	}

	dhcpMap := make(map[string]string)
	db, _ := initDB()
	if db != nil {
		rDHCP, err := db.Query("SELECT ip, hostname FROM dhcp_leases WHERE record_date = ?", queryDate)
		if err == nil {
			defer rDHCP.Close()
			for rDHCP.Next() {
				var ip, hn string
				_ = rDHCP.Scan(&ip, &hn)
				if hn != "" {
					dhcpMap[ip] = hn
				}
			}
		}
		rCache, err := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
		if err == nil {
			defer rCache.Close()
			for rCache.Next() {
				var ip, hn string
				_ = rCache.Scan(&ip, &hn)
				if hn != "" && dhcpMap[ip] == "" {
					dhcpMap[ip] = hn
				}
			}
		}
	}

	mainPath := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", queryDate))

	parquetFileMutex.Lock()
	var allRows []TrafficParquetRow

	// 直接讀取單一主檔案
	if _, err := os.Stat(mainPath); err == nil {
		rows, err := parquet.ReadFile[TrafficParquetRow](mainPath)
		if err == nil {
			allRows = rows
		}
	} else {
		// 若主檔尚不存在，相容性讀取可能尚未整併的零星碎片
		pattern := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate))
		files, _ := filepath.Glob(pattern)
		existingKeys := make(map[string]bool)
		for _, f := range files {
			if strings.HasSuffix(f, ".tmp") {
				continue
			}
			rows, err := parquet.ReadFile[TrafficParquetRow](f)
			if err == nil {
				for _, r := range rows {
					key := fmt.Sprintf("%s|%s|%s|%d|%s", r.Timestamp, r.Source, r.Destination, r.ToPort, r.SessionID)
					if !existingKeys[key] {
						existingKeys[key] = true
						allRows = append(allRows, r)
					}
				}
			}
		}
	}
	parquetFileMutex.Unlock()

	if len(allRows) == 0 {
		return &TrafficAnalyticsResult{
			TotalFlows:  0,
			TotalBytes:  "0 B",
			TopApp:      "-",
			DenyFlows:   0,
			Histogram:   emptyHistogram,
			Logs:        make([]TrafficLogItem, 0),
			CurrentPage: 1,
			TotalPages:  1,
		}, nil
	}

	// 篩選與指標聚合
	srcLower := strings.ToLower(src)
	dstLower := strings.ToLower(dst)
	appLower := strings.ToLower(app)
	actionLower := strings.ToLower(action)
	zoneLower := strings.ToLower(zone)

	var filteredRows []TrafficParquetRow
	var totalBytesNum int64
	var denyFlows int
	appBytesMap := make(map[string]int64)
	hourCountMap := make(map[string]int)

	for _, r := range allRows {
		if src != "" && !strings.Contains(strings.ToLower(r.Source), srcLower) {
			continue
		}
		if dst != "" && !strings.Contains(strings.ToLower(r.Destination), dstLower) {
			continue
		}
		if app != "" && !strings.Contains(strings.ToLower(r.Application), appLower) {
			continue
		}
		if action != "" && actionLower != "all" {
			rAct := strings.ToLower(r.Action)
			if actionLower == "allow" && rAct != "allow" {
				continue
			}
			if actionLower == "deny" && rAct != "deny" && rAct != "drop" && !strings.HasPrefix(rAct, "reset") {
				continue
			}
		}
		if zone != "" && zoneLower != "all" {
			if strings.ToLower(r.FromZone) != zoneLower && strings.ToLower(r.ToZone) != zoneLower {
				continue
			}
		}

		filteredRows = append(filteredRows, r)
		totalBytesNum += r.Bytes

		rAct := strings.ToLower(r.Action)
		if rAct == "deny" || rAct == "drop" || strings.HasPrefix(rAct, "reset") {
			denyFlows++
		}
		appBytesMap[r.Application] += r.Bytes

		if len(r.Timestamp) >= 13 {
			hStr := r.Timestamp[11:13] + ":00"
			hourCountMap[hStr]++
		}
	}

	topApp := "-"
	var maxAppBytes int64
	for a, b := range appBytesMap {
		if b > maxAppBytes {
			maxAppBytes = b
			topApp = a
		}
	}

	var totalBytesStr string
	if totalBytesNum >= 1024*1024*1024 {
		totalBytesStr = fmt.Sprintf("%.2f GB", float64(totalBytesNum)/(1024*1024*1024))
	} else if totalBytesNum >= 1024*1024 {
		totalBytesStr = fmt.Sprintf("%.2f MB", float64(totalBytesNum)/(1024*1024))
	} else if totalBytesNum >= 1024 {
		totalBytesStr = fmt.Sprintf("%.1f KB", float64(totalBytesNum)/1024)
	} else {
		totalBytesStr = fmt.Sprintf("%d B", totalBytesNum)
	}

	histogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		hb := fmt.Sprintf("%02d:00", h)
		histogram[h] = HistogramBucket{
			TimeBucket: hb,
			Count:      hourCountMap[hb],
		}
	}

	totalFlows := len(filteredRows)
	totalPages := int(math.Ceil(float64(totalFlows) / float64(perPage)))
	if totalPages == 0 {
		totalPages = 1
	}

	offset := (page - 1) * perPage
	logs := make([]TrafficLogItem, 0)

	if offset < totalFlows {
		end := offset + perPage
		if end > totalFlows {
			end = totalFlows
		}
		for _, r := range filteredRows[offset:end] {
			var bytesFormatted string
			if r.Bytes >= 1024*1024 {
				bytesFormatted = fmt.Sprintf("%.2f MB", float64(r.Bytes)/(1024*1024))
			} else if r.Bytes >= 1024 {
				bytesFormatted = fmt.Sprintf("%.1f KB", float64(r.Bytes)/1024)
			} else {
				bytesFormatted = fmt.Sprintf("%d B", r.Bytes)
			}

			logs = append(logs, TrafficLogItem{
				Timestamp:        r.Timestamp,
				Type:             r.Type,
				FromZone:         r.FromZone,
				ToZone:           r.ToZone,
				Source:           r.Source,
				SrcHostname:      dhcpMap[r.Source],
				NatSourceIP:      r.NatSourceIP,
				Destination:      r.Destination,
				NatDestIP:        r.NatDestIP,
				ToPort:           int(r.ToPort),
				Application:      r.Application,
				Action:           r.Action,
				Rule:             r.Rule,
				SessionEndReason: r.SessionEndReason,
				Bytes:            r.Bytes,
				BytesFormatted:   bytesFormatted,
			})
		}
	}

	return &TrafficAnalyticsResult{
		TotalFlows:  totalFlows,
		TotalBytes:  totalBytesStr,
		TopApp:      topApp,
		DenyFlows:   denyFlows,
		Histogram:   histogram,
		Logs:        logs,
		CurrentPage: page,
		TotalPages:  totalPages,
	}, nil
}

// 🌟 威脅日誌 Parquet 儲存結構
type ThreatParquetRow struct {
	Timestamp   string `parquet:"timestamp,snappy"`
	Src         string `parquet:"src,snappy"`
	Dst         string `parquet:"dst,snappy"`
	ThreatID    string `parquet:"threat_id,snappy"`
	ThreatName  string `parquet:"threat_name,snappy"`
	Subtype     string `parquet:"subtype,snappy"`
	Severity    string `parquet:"severity,snappy"`
	Action      string `parquet:"action,snappy"`
	Application string `parquet:"application,snappy"`
}

// 🌟 Threat 多檔合併器：將同一日期的碎片/多次回補合併為每日單一主檔
func ConsolidateThreatParquetFiles() (int, int, error) {
	threatFileMutex.Lock()
	defer threatFileMutex.Unlock()

	entries, err := os.ReadDir(threatDir)
	if err != nil {
		return 0, 0, err
	}

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`threat_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if len(m) > 1 {
			dateKey := m[1]
			dateFiles[dateKey] = append(dateFiles[dateKey], filepath.Join(threatDir, e.Name()))
		}
	}

	totalMergedFiles := 0
	totalRowsRetained := 0

	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", dateKey))

		// 若已經只有一個且檔名正是標準主檔，則不需整併
		if len(files) == 1 && files[0] == targetMainFile {
			continue
		}

		fmt.Printf("[威脅整合] ⏳ 正在將 %s 的 %d 個檔案整合成每日單一主檔...\n", dateKey, len(files))

		var combinedRows []ThreatParquetRow
		existingKeys := make(map[string]bool)

		for _, f := range files {
			rows, err := parquet.ReadFile[ThreatParquetRow](f)
			if err == nil {
				for _, r := range rows {
					key := fmt.Sprintf("%s|%s|%s|%s|%s", r.Timestamp, r.Src, r.Dst, r.ThreatName, r.Action)
					if !existingKeys[key] {
						existingKeys[key] = true
						combinedRows = append(combinedRows, r)
					}
				}
			}
		}

		if len(combinedRows) == 0 {
			continue
		}

		sort.Slice(combinedRows, func(i, j int) bool {
			return combinedRows[i].Timestamp > combinedRows[j].Timestamp
		})

		tmpFile := targetMainFile + ".tmp"
		if err := parquet.WriteFile(tmpFile, combinedRows); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}

		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}

		for _, f := range files {
			if f != targetMainFile {
				_ = os.Remove(f)
				totalMergedFiles++
			}
		}
		totalRowsRetained += len(combinedRows)
		fmt.Printf("[威脅整合] ✅ %s 整併完成！保留 %d 筆唯一紀錄，清除 %d 個碎片檔案。\n",
			dateKey, len(combinedRows), len(files)-1)
	}

	return totalMergedFiles, totalRowsRetained, nil
}

// 🌟 Threat 每日單一主檔寫入 (Atomic .tmp 替換)
func saveThreatLogsToParquet(entries []ThreatEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	threatFileMutex.Lock()
	defer threatFileMutex.Unlock()

	entriesByDate := make(map[string][]ThreatParquetRow)
	for _, e := range entries {
		tName := strings.TrimSpace(e.ThreatID)
		if tName == "" {
			tName = strings.TrimSpace(e.ThreatName)
		}
		row := ThreatParquetRow{
			Timestamp:   e.TimeGenerated,
			Src:         strings.TrimSpace(e.Src),
			Dst:         strings.TrimSpace(e.Dst),
			ThreatID:    strings.TrimSpace(e.ThreatID),
			ThreatName:  tName,
			Subtype:     strings.TrimSpace(e.Subtype),
			Severity:    strings.ToLower(strings.TrimSpace(e.Severity)),
			Action:      strings.TrimSpace(e.Action),
			Application: strings.TrimSpace(e.App),
		}

		recordDate := time.Now().Format("2006-01-02")
		if len(row.Timestamp) >= 10 {
			recordDate = row.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], row)
	}

	totalInserted := 0
	totalToday := 0
	todayStr := time.Now().Format("2006-01-02")

	for dateKey, newRows := range entriesByDate {
		mainPath := filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", dateKey))
		tmpPath := mainPath + ".tmp"

		existingKeys := make(map[string]bool)
		var combinedRows []ThreatParquetRow

		if _, err := os.Stat(mainPath); err == nil {
			oldRows, err := parquet.ReadFile[ThreatParquetRow](mainPath)
			if err == nil {
				for _, r := range oldRows {
					key := fmt.Sprintf("%s|%s|%s|%s|%s", r.Timestamp, r.Src, r.Dst, r.ThreatName, r.Action)
					if !existingKeys[key] {
						existingKeys[key] = true
						combinedRows = append(combinedRows, r)
					}
				}
			} else {
				return 0, 0, fmt.Errorf("威脅主檔讀取異常: %w", err)
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
			if dateKey == todayStr {
				totalToday = len(combinedRows)
			}
			continue
		}

		totalInserted += newCount

		sort.Slice(combinedRows, func(i, j int) bool {
			return combinedRows[i].Timestamp > combinedRows[j].Timestamp
		})

		if err := parquet.WriteFile(tmpPath, combinedRows); err != nil {
			_ = os.Remove(tmpPath)
			return 0, 0, err
		}

		_ = os.Remove(mainPath)
		if err := os.Rename(tmpPath, mainPath); err != nil {
			_ = os.Remove(tmpPath)
			return 0, 0, err
		}

		if dateKey == todayStr {
			totalToday = len(combinedRows)
		}
	}

	return totalInserted, totalToday, nil
}

