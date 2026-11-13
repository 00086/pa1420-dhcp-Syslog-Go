package main

import (
	"bufio" // 🌟 補上此行，解決 undefined: bufio 錯誤
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
	"time"

	"github.com/parquet-go/parquet-go"
	_ "modernc.org/sqlite"
)

// -------------------------------------------------------------
// 🌟 單一主機 360° 全景鑑識時序軸 (Host 360° Timeline) 引擎
// -------------------------------------------------------------
type TimelineEvent struct {
	Timestamp   string `json:"timestamp"`
	Category    string `json:"category"`     // traffic, threat, system, config
	Level       string `json:"level"`        // info, warning, danger, success
	Icon        string `json:"icon"`         // 前端對應的 Bootstrap Icon
	Title       string `json:"title"`        // 事件標題 (如 "DHCP 租約配發", "觸發高危威脅")
	Description string `json:"description"`  // 詳細內容
}

type Host360Profile struct {
	IP          string          `json:"ip"`
	Hostname    string          `json:"hostname"`
	MAC         string          `json:"mac"`
	TotalEvents int             `json:"total_events"`
	ThreatCount int             `json:"threat_count"`
	BlockCount  int             `json:"block_count"`
	Events      []TimelineEvent `json:"events"`
}

var (
	cachedFWModel    string
	cachedFWModelMux sync.RWMutex
)

var (
	appDir       string
	paConfigFile string
	trafficDir   string
	threatDir    string // 👈 威脅日誌專屬目錄路徑
	trafficRawDir string // 👈 新增：流量原始冷資料目錄
	threatRawDir  string // 👈 新增：威脅原始冷資料目錄
	systemDir       string // 👈 系統日誌專屬目錄路徑
	systemRawDir    string // 👈 系統原始冷資料目錄
	systemFileMutex sync.Mutex // 👈 系統檔案安全互斥鎖
	configDir       string // 👈 🌟 補上：組態日誌專屬目錄路徑
	configRawDir    string // 👈 🌟 補上：組態原始冷資料目錄
	configFileMutex sync.Mutex // 👈 🌟 補上：組態檔案安全互斥鎖
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
	syslogQueue                = make(chan TrafficParquetRow, 50000) // 👈 將 50000 改為 500000
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
	
	// 🔔 新增：System 專屬 Syslog 即時接收佇列與統計
	systemSyslogQueue         = make(chan SystemParquetRow, 10000)
	systemSyslogReceivedCount int64
	systemSyslogLastFlushCount int
	systemSyslogLastFlushTime  time.Time
	rawSystemQueue            = make(chan RawLogParquetRow, 10000)
	
	// 🌟 新增：Config 專屬 Syslog 即時接收佇列與統計
	configSyslogQueue         = make(chan ConfigParquetRow, 10000)
	configSyslogReceivedCount int64
	configSyslogLastFlushCount int
	configSyslogLastFlushTime  time.Time
	rawConfigQueue            = make(chan RawLogParquetRow, 10000)

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

// 🌟 組態日誌 (Config Logs) 資料結構定義 (完美支援 PAN-OS XML 標籤)
type ConfigEntry struct {
	TimeGenerated string `xml:"time_generated"`
	ReceiveTime   string `xml:"receive_time"`
	Host          string `xml:"host"`
	ClientIP      string `xml:"client_ip"`
	Admin         string `xml:"admin"`
	Client        string `xml:"client"`
	Command       string `xml:"cmd"`
	Result        string `xml:"result"`
	Path          string `xml:"path"`
	FullPath1     string `xml:"full-path"`
	FullPath2     string `xml:"full_path"`
	XPath         string `xml:"xpath"`
	Before1       string `xml:"before-change-detail"`
	Before2       string `xml:"before_change_detail"`
	Before3       string `xml:"before-change"`
	Before4       string `xml:"before_change"`
	After1        string `xml:"after-change-detail"`
	After2        string `xml:"after_change_detail"`
	After3        string `xml:"after-change"`
	After4        string `xml:"after_change"`
	SequenceNO    string `xml:"seqno"`
	RawXML        string `xml:",innerxml"`
}

// 🌟 動態取得防火牆真實型號 (例如 PA-5250, PA-1420)，若尚未快取則自動發查
func getFWModelName() string {
	cachedFWModelMux.RLock()
	m := cachedFWModel
	cachedFWModelMux.RUnlock()
	if m != "" && m != "PA-1420" && m != "PA 防火牆" {
		return m
	}

	// 即時向防火牆請求系統資訊
	body, err := runPACommand("<show><system><info/></system></show>")
	if err == nil {
		reModel := regexp.MustCompile(`<model>(.*?)</model>`)
		if match := reModel.FindSubmatch(body); len(match) > 1 {
			modelStr := strings.TrimSpace(string(match[1]))
			if modelStr != "" {
				cachedFWModelMux.Lock()
				cachedFWModel = modelStr
				cachedFWModelMux.Unlock()
				return modelStr
			}
		}
	}

	if m != "" {
		return m
	}
	return "PA 防火牆"
}

// 🌟 強力 XML 差異萃取函式 (相容 Go 原生 RE2 引擎，無後向引用)
func extractConfigDiff(rawXML, tagPrefix string) string {
	if strings.TrimSpace(rawXML) == "" {
		return ""
	}

	// 🌟 核心修正：前後標籤皆以 %s 匹配，不使用 \1 後向引用，杜絕 Go 正則 panic
	pattern := fmt.Sprintf(`(?is)<%s[_\-a-z0-9]*[^>]*>(.*?)</%s[_\-a-z0-9]*>`, tagPrefix, tagPrefix)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(rawXML)
	if len(matches) > 1 {
		val := strings.TrimSpace(matches[1])
		// 去除 CDATA 標籤包裹
		if strings.HasPrefix(val, "<![CDATA[") && strings.HasSuffix(val, "]]>") {
			val = strings.TrimSuffix(strings.TrimPrefix(val, "<![CDATA["), "]]>")
		}
		// 若內容含有內部子標籤，將其剝除保留純文字內容
		if strings.Contains(val, "<") && strings.Contains(val, ">") {
			tagStrip := regexp.MustCompile(`<[^>]*>`)
			val = tagStrip.ReplaceAllString(val, " ")
		}
		// 基礎 HTML Entity 轉義字符還原
		val = strings.ReplaceAll(val, "&lt;", "<")
		val = strings.ReplaceAll(val, "&gt;", ">")
		val = strings.ReplaceAll(val, "&amp;", "&")
		val = strings.ReplaceAll(val, "&quot;", "\"")
		// 將連續空格或換行收斂為單一空格
		return strings.Join(strings.Fields(val), " ")
	}
	return ""
}

type ConfigParquetRow struct {
	Timestamp    string `parquet:"timestamp,zstd"`
	Admin        string `parquet:"admin,zstd"`
	Client       string `parquet:"client,zstd"`
	ClientApp    string `parquet:"client_app,zstd"`
	Command      string `parquet:"command,zstd"`
	Result       string `parquet:"result,zstd"`
	ConfigPath   string `parquet:"config_path,zstd"`
	FullPath     string `parquet:"full_path,zstd"`
	BeforeChange string `parquet:"before_change,zstd"`
	AfterChange  string `parquet:"after_change,zstd"`
	SequenceNO   string `parquet:"sequence_no,zstd"`
}

type ConfigLogItem struct {
	Timestamp    string `json:"timestamp"`
	Admin        string `json:"admin"`
	Client       string `json:"client"`
	ClientApp    string `json:"client_app"`
	Command      string `json:"command"`
	Result       string `json:"result"`
	ConfigPath   string `json:"config_path"`
	FullPath     string `json:"full_path"`
	BeforeChange string `json:"before_change"`
	AfterChange  string `json:"after_change"`
	SequenceNO   string `json:"sequence_no"`
}

type ConfigAnalyticsResult struct {
	TotalLogs     int               `json:"total_logs"`
	TopAdmin      string            `json:"top_admin"`
	TopCommand    string            `json:"top_command"`
	DbSize        string            `json:"db_size"`
	Histogram     []HistogramBucket `json:"histogram"`
	Logs          []ConfigLogItem   `json:"logs"`
	CurrentPage   int               `json:"current_page"`
	TotalPages    int               `json:"total_pages"`
}

// -------------------------------------------------------------
// 🌟 系統日誌 (System Logs) 資料結構定義 (對齊 Parquet ZSTD 壓縮)
// -------------------------------------------------------------
type SystemEntry struct {
	TimeGenerated string `xml:"time_generated"`
	ReceiveTime   string `xml:"receive_time"`
	Subtype       string `xml:"subtype"`
	Severity      string `xml:"severity"`
	EventID       string `xml:"eventid"`
	Object        string `xml:"object"`
	Module        string `xml:"module"`
	Opaque        string `xml:"opaque"`
	Description   string `xml:"description"`
	RawXML        string `xml:",innerxml"`
}

type SystemParquetRow struct {
	Timestamp   string `parquet:"timestamp,zstd"`
	Subtype     string `parquet:"subtype,zstd"`
	Severity    string `parquet:"severity,zstd"`
	EventID     string `parquet:"event_id,zstd"`
	Object      string `parquet:"object,zstd"`
	Description string `parquet:"description,zstd"`
}

type SystemLogItem struct {
	Timestamp   string `json:"timestamp"`
	Subtype     string `json:"subtype"`
	Severity    string `json:"severity"`
	EventID     string `json:"event_id"`
	Object      string `json:"object"`
	Description string `json:"description"`
}

type SystemAnalyticsResult struct {
	TotalLogs     int               `json:"total_logs"`
	ImportantLogs int               `json:"important_logs"`
	TopSubtype    string            `json:"top_subtype"`
	TopEvent      string            `json:"top_event"`
	DbSize        string            `json:"db_size"`
	Histogram     []HistogramBucket `json:"histogram"`
	Logs          []SystemLogItem   `json:"logs"`
	CurrentPage   int               `json:"current_page"`
	TotalPages    int               `json:"total_pages"`
}

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
	// 🌟 核心防線：流量日誌 (traffic) 徹底禁止落盤與輸出；威脅、系統、組態維持正常
	if len(rows) == 0 || logType == "traffic" {
		return nil
	}

	var targetDir string
	switch logType {
	case "threat":
		targetDir = threatRawDir
	case "system":
		targetDir = systemRawDir
	case "config":
		targetDir = configRawDir
	default:
		return nil // 👈 非三大資安稽核日誌，直接略過
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

		// 🌟 核心增補：即時於 CLI 終端機顯示 Raw Log 存檔進度 (僅 threat / system / config 會顯示)
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
	
	// 🌟 若需要真正落盤儲存原始 XML，加在這裡：
	/*
	rawFileName := fmt.Sprintf("traffic_backfill_%s_%d.xml", time.Now().Format("20060102"), time.Now().UnixNano())
	_ = os.WriteFile(filepath.Join(trafficRawDir, rawFileName), pollBody, 0644)
	*/

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
	// 🌟 自動修正：將先前誤存入 traffic_raw_logs 的 system 與 config 冷資料自動搬移歸位
	if misSystemFiles, err := filepath.Glob(filepath.Join(trafficRawDir, "system_raw_*.parquet*")); err == nil {
		for _, f := range misSystemFiles {
			_ = os.Rename(f, filepath.Join(systemRawDir, filepath.Base(f)))
		}
	}
	if misConfigFiles, err := filepath.Glob(filepath.Join(trafficRawDir, "config_raw_*.parquet*")); err == nil {
		for _, f := range misConfigFiles {
			_ = os.Rename(f, filepath.Join(configRawDir, filepath.Base(f)))
		}
	}
	
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
	
	// 🌟 建立系統日誌專屬目錄
	systemDir = filepath.Join(appDir, "system_logs")
	_ = os.MkdirAll(systemDir, 0755)

	systemRawDir = filepath.Join(appDir, "system_raw_logs")
	_ = os.MkdirAll(systemRawDir, 0755)
	
	// 🌟 建立組態日誌專屬目錄
	configDir = filepath.Join(appDir, "config_logs")
	_ = os.MkdirAll(configDir, 0755)

	configRawDir = filepath.Join(appDir, "config_raw_logs")
	_ = os.MkdirAll(configRawDir, 0755)

	// 🌟 2. 自動將根目錄現有的 threat_*.parquet 搬移歸位到 threat_logs/
	rootThreatFiles, _ := filepath.Glob(filepath.Join(appDir, "threat_*.parquet"))
	
	// 🌟 開機自動向防火牆識別型號
	go func() {
		time.Sleep(1 * time.Second)
		_ = getFWModelName()
	}()
	
	// 🌟 開機立刻對現存歷史碎片執行一次全域整合
	/*
	go func() {
		time.Sleep(3 * time.Second)
		ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")
		ConsolidateRawParquetFiles("system")
		ConsolidateRawParquetFiles("config")
	}()
	*/

	// 啟動冷資料每小時自動維護整合排程
	startHourlyRawConsolidator()
	
	// 🌟 新增：啟動熱資料的雙層排程器
	startChunkConsolidatorWorker() // 👈 每 30 分鐘把 _chunk_ 合併
	startMidnightDailyArchiver()   // 👈 每天半夜 00:05 把前一日主檔與 chunk 全量去重封存

	// 🌟 【新增：開機歷史碎片自動補整機制】
	go func() {
		time.Sleep(5 * time.Second) // 等待 5 秒讓資料庫與網路就緒
		todayStr := time.Now().Format("2006-01-02")
		
		// 🌟 同時掃描 traffic_logs 根目錄與所有 YYYY-MM-DD 日期子目錄下的碎片檔案 (_live_, _chunk_, _rollup_)
		rootFiles, _ := filepath.Glob(filepath.Join(trafficDir, "traffic_*_*_*.parquet"))
		subFiles, _ := filepath.Glob(filepath.Join(trafficDir, "*", "traffic_*_*_*.parquet"))
		files := append(rootFiles, subFiles...)
		pendingDates := make(map[string]bool)

		for _, f := range files {
			if strings.HasSuffix(f, ".tmp") {
				continue
			}
			base := filepath.Base(f)
			parts := strings.Split(base, "_")
			if len(parts) >= 4 {
				datePart := parts[1]
				// 只要不是「今天」，代表是歷史遺留的未整併分塊，必須立即補跑
				if len(datePart) == 10 && datePart < todayStr {
					pendingDates[datePart] = true
				}
			}
		}

		for d := range pendingDates {
			fmt.Printf("[啟動修復] 🔍 偵測到歷史殘留碎片日期 %s，自動補跑去重整併...\n", d)
			_ = consolidateDailyTraffic(d)
		}

		for d := range pendingDates {
			fmt.Printf("[啟動修復] 🔍 偵測到歷史殘留碎片日期 %s，自動補跑全量去重整併...\n", d)
			_ = consolidateDailyTraffic(d)
		}
	}()
		
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
	// 🌟 跨平台相容：終端標準輸出，消除 user32.dll 在 Linux 下的編譯錯誤
	fmt.Printf("⚠️ 【%s】%s\n", title, message)
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

	// 🌟 核心防護：將 XML 指令進行百分比 URL 編碼，避免空格與引號造成 API 截斷
	escapedCmd := url.QueryEscape(cmdXML)
	apiURL := fmt.Sprintf("https://%s/api/?type=op&cmd=%s&key=%s", fwIP, escapedCmd, apiKey)

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PA API 回傳 HTTP 狀態碼: %d", resp.StatusCode)
	}

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
		
		`CREATE TABLE IF NOT EXISTS flow_security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			src_ip TEXT,
			dst_ip TEXT,
			attack_type TEXT,
			severity TEXT,
			details TEXT,
			status TEXT DEFAULT 'unhandled'
		);`,
		`CREATE TABLE IF NOT EXISTS flow_security_settings (
			key TEXT PRIMARY KEY,
			value TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS arp_records (
			ip TEXT PRIMARY KEY,
			mac TEXT,
			interface TEXT,
			hostname TEXT,
			dev_type TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		
		`CREATE TABLE IF NOT EXISTS external_devices (
			ip TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			location TEXT DEFAULT '',
			device_type TEXT DEFAULT '',
			brand TEXT DEFAULT '',
			model TEXT DEFAULT '',
			sys_descr TEXT DEFAULT '',
			imported_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
	
	// 🌟 新增這行：非同步將這批包含 Hostname 的租約送往 netmon！
	if len(entries) > 0 {
		go pushDHCPToNetmon(entries)
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
			// 🌟 同步更新全域型號快取
			cachedFWModelMux.Lock()
			cachedFWModel = data.Model
			cachedFWModelMux.Unlock()
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
	pollInterval, _ := getAdaptiveBackfillTimings() // 👈 自動偵測機型間隔

	for i := 0; i < 30; i++ {
		time.Sleep(pollInterval) // 🌟 5250 自動使用 200ms，1420 自動使用 600ms
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

// 🌟 極速微整併：僅合併 _liv// 🌟 輕量微整併互斥鎖，避免重複觸發
var compactMutex sync.Mutex

// 🌟 極速微整併：只合併 _live_ 小檔案，嚴禁碰 700MB 歷史主檔，耗時 < 0.2 秒，絕不逾時
func compactLiveFilesFast() {
	if !compactMutex.TryLock() {
		return // 若上一次整併尚未結束，直接跳過，絕不堆疊
	}
	defer compactMutex.Unlock()

	todayStr := time.Now().Format("2006-01-02")
	pattern := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_live_*.parquet", todayStr))
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) < 20 {
		return // 累積小於 20 個小檔不處理
	}

	chunkFile := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_chunk_%d.parquet", todayStr, time.Now().UnixNano()))
	tmpChunkFile := chunkFile + ".tmp"

	duckdbPattern := filepath.ToSlash(pattern)
	tmpSlash := filepath.ToSlash(tmpChunkFile)

	// 🌟 核心關鍵：只對 _live_ 檔案做純串流壓縮，不跑全域 ROW_NUMBER 排序，20 個小檔只需 0.1 秒！
	copySQL := fmt.Sprintf(`
		COPY (
			SELECT * FROM read_parquet('%s')
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, duckdbPattern, tmpSlash)

	_, err = runDuckDBQuery(copySQL)
	if err != nil {
		_ = os.Remove(tmpChunkFile)
		fmt.Printf("[%s] ⚠️ [微整併失敗]: %v\n", time.Now().Format("15:04:05"), err)
		return
	}

	// 寫入成功後，立刻刪除這批舊的 _live_ 小檔案
	if err := os.Rename(tmpChunkFile, chunkFile); err == nil {
		for _, f := range files {
			_ = os.Remove(f)
		}
		fmt.Printf("[%s] ⚡ [微整併完成] 成功將 %d 個 _live_ 小檔整合成 1 個 Chunk (零碎檔案歸零)\n",
			time.Now().Format("15:04:05"), len(files))
	} else {
		_ = os.Remove(tmpChunkFile)
	}
}

// -------------------------------------------------------------
// 🌟 核心整併器：僅合併 _live_ 零碎小檔，嚴禁碰 790MB 歷史主檔 (耗時 < 0.2s，絕不逾時)
// -------------------------------------------------------------
func ConsolidateParquetFiles() (int, int, error) {
	parquetFileMutex.Lock()
	defer parquetFileMutex.Unlock()

	todayStr := time.Now().Format("2006-01-02")
	// 🌟 對焦子目錄內的 live 檔案
	dayDir := filepath.Join(trafficDir, todayStr)
	pattern := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_live_*.parquet", todayStr))
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) < 15 {
		return 0, 0, nil
	}

	chunkFile := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_chunk_%d.parquet", todayStr, time.Now().UnixNano()))
	tmpChunkFile := chunkFile + ".tmp"

	duckdbPattern := filepath.ToSlash(pattern)
	tmpSlash := filepath.ToSlash(tmpChunkFile)

	copySQL := fmt.Sprintf(`
		COPY (
			SELECT * FROM read_parquet('%s')
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, duckdbPattern, tmpSlash)

	_, err = runDuckDBQuery(copySQL)
	if err != nil {
		_ = os.Remove(tmpChunkFile)
		return 0, 0, err
	}

	if err := os.Rename(tmpChunkFile, chunkFile); err == nil {
		for _, f := range files {
			_ = os.Remove(f)
		}
		fmt.Printf("[%s] ⚡ [微整併完成] 成功將 %d 個 _live_ 小檔整合成 1 個 Chunk！\n",
			time.Now().Format("15:04:05"), len(files))
	} else {
		_ = os.Remove(tmpChunkFile)
	}

	return len(files), 0, nil
}

// -------------------------------------------------------------
// 🌟 每日單一 Parquet 檔案寫入 (Atomic .tmp 替換，零碎檔產生)
// -------------------------------------------------------------
var parquetFileMutex sync.Mutex

// 🌟 API 流量日誌落盤引擎：透過 .tmp 子目錄隔離比對，杜絕自比對誤殺 (零 Go 記憶體負擔 + 精準回報真實新增)
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
		if len(newRows) == 0 {
			continue
		}

		// 🌟 1. 隔離暫存目錄：存放在 .tmp 子目錄且檔名以 check_ 開頭，絕不被主目錄的 traffic_*.parquet 萬用字元誤吸
		tmpDir := filepath.Join(trafficDir, ".tmp")
		_ = os.MkdirAll(tmpDir, 0755)

		tmpChunkPath := filepath.Join(tmpDir, fmt.Sprintf("check_%s_%d.parquet", dateKey, time.Now().UnixNano()))
		if err := parquet.WriteFile(tmpChunkPath, newRows); err != nil {
			return 0, 0, err
		}

		// 🌟 2. 取出該批資料時間窗
		minT := newRows[0].Timestamp
		maxT := newRows[0].Timestamp
		for _, r := range newRows {
			if r.Timestamp < minT { minT = r.Timestamp }
			if r.Timestamp > maxT { maxT = r.Timestamp }
		}

		// 🌟 3. 搜尋既有檔案 (排除 .tmp 目錄與臨時檔)
		existingPattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", dateKey)))
		allExisting, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", dateKey)))

		var validExisting []string
		for _, f := range allExisting {
			if !strings.HasSuffix(f, ".tmp") && !strings.Contains(f, "check_") {
				validExisting = append(validExisting, f)
			}
		}

		var actualNewCount int = len(newRows)

		// 🌟 4. 只有在本地確實存在舊檔案時，才透過 DuckDB 進行時間窗比對
		if len(validExisting) > 0 {
			checkSQL := fmt.Sprintf(`
				SELECT COUNT(*) as new_cnt 
				FROM read_parquet('%s') t
				WHERE NOT EXISTS (
					SELECT 1 FROM read_parquet('%s', union_by_name=true) m
					WHERE m.timestamp >= '%s' AND m.timestamp <= '%s'
					  AND COALESCE(m.timestamp, '') = COALESCE(t.timestamp, '')
					  AND COALESCE(m.source, '') = COALESCE(t.source, '')
					  AND COALESCE(m.destination, '') = COALESCE(t.destination, '')
					  AND COALESCE(m.to_port, 0) = COALESCE(t.to_port, 0)
					  AND COALESCE(m.session_id, '') = COALESCE(t.session_id, '')
				)
			`, filepath.ToSlash(tmpChunkPath), existingPattern, minT, maxT)

			if res, err := runDuckDBQuery(checkSQL); err == nil && len(res) > 0 {
				actualNewCount = int(parseDuckDBNumber(res[0]["new_cnt"]))
			}
		}

		// 🌟 5. 若整批 5000 筆確實全部早已存在，刪除暫存檔避免產生垃圾碎片
		if actualNewCount == 0 {
			_ = os.Remove(tmpChunkPath)
		} else {
			finalChunkPath := filepath.Join(configDir, fmt.Sprintf("config_%s_api_%d.parquet", dateKey, time.Now().UnixNano()))
			_ = os.Rename(tmpChunkPath, finalChunkPath)
			go ConsolidateConfigParquetFiles()
			go ConsolidateRawParquetFiles("config") // 👈 🌟 立即將帶時間戳記的冷資料碎片整合成每日單一主檔
		}

		totalInserted += actualNewCount
		if dateKey == todayStr {
			totalForToday += actualNewCount
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
	// 🌟 自動建立並鎖定當日專屬子目錄：traffic_logs/YYYY-MM-DD/
	dayDir := filepath.Join(trafficDir, todayStr)
	_ = os.MkdirAll(dayDir, 0755)

	chunkPath := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_live_%d.parquet", todayStr, time.Now().UnixNano()))

	if err := parquet.WriteFile(chunkPath, rows); err != nil {
		return 0, 0, err
	}

	return len(rows), int(atomic.LoadInt64(&syslogReceivedCount)), nil
}

func saveTrafficLogsToParquet(entries []TrafficEntry) (int, int, error) {
	var rows []TrafficParquetRow
	//var rawRows []RawLogParquetRow // 👈 準備冷資料陣列

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
		/*
		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  e.SessionID,
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
		*/
	}
	
	// 非同步把冷資料寫進 traffic_raw_logs/，完全不阻擋主線
	//go saveRawLogBatchFast("traffic", rawRows)
	
	return saveParquetRowsDirect(rows)
}

// 🌟 輕量極速解析 Palo Alto TRAFFIC Syslog (拋棄 csv.Reader，杜絕記憶體碎片化)
func parsePaloAltoSyslog(msg string) (*TrafficParquetRow, error) {
	if !strings.Contains(msg, "TRAFFIC") {
		return nil, errors.New("not traffic log")
	}

	fields := strings.Split(msg, ",")
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

	src := strings.TrimSpace(fields[idx+4])
	dst := strings.TrimSpace(fields[idx+5])
	if src == "" || dst == "" {
		return nil, errors.New("empty src/dst")
	}

	return &TrafficParquetRow{
		Timestamp:        formattedTime,
		Type:             strings.TrimSpace(fields[idx+1]),
		FromZone:         strings.TrimSpace(fields[idx+13]),
		ToZone:           strings.TrimSpace(fields[idx+14]),
		Source:           src,
		NatSourceIP:      strings.TrimSpace(fields[idx+6]),
		Destination:      dst,
		NatDestIP:        strings.TrimSpace(fields[idx+7]),
		ToPort:           int32(toPort),
		Application:      strings.TrimSpace(fields[idx+11]),
		Action:           strings.TrimSpace(fields[idx+27]),
		Rule:             strings.TrimSpace(fields[idx+8]),
		SessionEndReason: endReason,
		Bytes:            bytesVal,
		SessionID:        strings.TrimSpace(fields[idx+19]),
	}, nil
}

// 🌟 輕量極速解析 Palo Alto THREAT Syslog (拋棄 csv.Reader，杜絕記憶體碎片化)
func parsePaloAltoThreatSyslog(msg string) (*ThreatParquetRow, error) {
	if !strings.Contains(msg, "THREAT") {
		return nil, errors.New("not threat log")
	}

	fields := strings.Split(msg, ",")
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

	src := strings.TrimSpace(fields[idx+4])
	dst := strings.TrimSpace(fields[idx+5])
	if src == "" || dst == "" {
		return nil, errors.New("empty src/dst in threat log")
	}

	return &ThreatParquetRow{
		Timestamp:   formattedTime,
		Subtype:     strings.TrimSpace(fields[idx+1]),
		ThreatID:    threatID,
		ThreatName:  threatName,
		FromZone:    strings.TrimSpace(fields[idx+13]),
		ToZone:      strings.TrimSpace(fields[idx+14]),
		Src:         src,
		Dst:         dst,
		ToPort:      int32(toPort),
		Application: strings.TrimSpace(fields[idx+11]),
		Action:      strings.TrimSpace(fields[idx+27]),
		Severity:    strings.ToLower(strings.TrimSpace(fields[idx+31])),
		URL:         urlMisc,
		SessionID:   strings.TrimSpace(fields[idx+19]),
	}, nil
}

// 🌟 解析 Palo Alto SYSTEM Syslog 封包 (對齊 PAN-OS 標準欄位索引)
func parsePaloAltoSystemSyslog(msg string) (*SystemParquetRow, error) {
	if !strings.Contains(msg, "SYSTEM") {
		return nil, errors.New("not system log")
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
		if strings.TrimSpace(f) == "SYSTEM" {
			idx = i
			break
		}
	}

	// 確保封包具備完整欄位 (至 Description 至少需 idx+11)
	if idx == -1 || len(fields) <= idx+11 {
		return nil, errors.New("insufficient system fields")
	}

	rawTime := strings.TrimSpace(fields[idx+3])
	if rawTime == "" && idx >= 2 {
		rawTime = strings.TrimSpace(fields[idx-2])
	}
	formattedTime := strings.ReplaceAll(rawTime, "/", "-")

	objectStr := ""
	if idx+6 < len(fields) {
		objectStr = strings.TrimSpace(fields[idx+6])
	}

	// 🌟 關鍵修復：Severity 位於 idx+10 (第 13 欄)，Description 位於 idx+11 (第 14 欄)
	severityStr := "informational"
	if idx+10 < len(fields) && strings.TrimSpace(fields[idx+10]) != "" {
		severityStr = strings.ToLower(strings.TrimSpace(fields[idx+10]))
	}

	descStr := ""
	if idx+11 < len(fields) && strings.TrimSpace(fields[idx+11]) != "" {
		descStr = strings.TrimSpace(fields[idx+11])
	} else if idx+9 < len(fields) {
		descStr = strings.TrimSpace(fields[idx+9])
	}

	row := &SystemParquetRow{
		Timestamp:   formattedTime,
		Subtype:     strings.TrimSpace(fields[idx+1]),
		Severity:    severityStr,                        // 👈 正確取得 informational 等級
		EventID:     strings.TrimSpace(fields[idx+5]),   // 👈 lease-start
		Object:      objectStr,
		Description: descStr,                            // 👈 正確取得完整的 DHCP 租約 IP/MAC 訊息
	}

	return row, nil
}

// 🌟 解析 Palo Alto CONFIG Syslog 封包 (精準對齊 PAN-OS 原生欄位，杜絕序號/Flags錯位)
func parsePaloAltoConfigSyslog(msg string) (*ConfigParquetRow, error) {
	if !strings.Contains(msg, ",CONFIG,") {
		return nil, errors.New("not config log")
	}

	reader := csv.NewReader(strings.NewReader(msg))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	fields, err := reader.Read()
	if err != nil { return nil, err }

	idx := -1
	for i, f := range fields {
		if strings.TrimSpace(f) == "CONFIG" {
			idx = i
			break
		}
	}

	// 必須命中標準 Type 欄位 (通常 idx 為 3)，且具備充足欄位
	if idx == -1 || idx > 5 || len(fields) <= idx+11 {
		return nil, errors.New("insufficient config fields")
	}

	rawTime := strings.TrimSpace(fields[idx+3])
	if rawTime == "" && idx >= 2 { rawTime = strings.TrimSpace(fields[idx-2]) }
	formattedTime := strings.ReplaceAll(rawTime, "/", "-")

	getF := func(offset int) string {
		if idx+offset < len(fields) {
			return strings.TrimSpace(fields[idx+offset])
		}
		return ""
	}

	admin := getF(7) // idx+7: Admin (newtp1)
	cmd := getF(6)   // idx+6: Command (commit / edit)

	// 排除無效幽靈封包
	if admin == "" && cmd == "" {
		return nil, errors.New("invalid ghost config entry")
	}

	// 🌟 核心修復：精準識別 Sequence Number 與 Action Flags
	var seqNo, beforeChange, afterChange string

	f11 := getF(11) // 序號 (如 7616931376251535614)
	f12 := getF(12) // Action Flags (如 0x8000000000000000)

	if strings.HasPrefix(f12, "0x") {
		// 👉 PAN-OS 標準預設 Syslog 格式：
		// idx+11 為標準 64-bit 序號，idx+12 為 Action Flags，預設 Syslog 不含詳細變更字串
		seqNo = f11
		beforeChange = ""
		afterChange = ""
	} else {
		// 👉 自訂 Custom Syslog 格式 (若有手動掛載 before/after)
		seqNo = getF(13)
		if seqNo == "" || seqNo == "0" {
			seqNo = f11
		}
		beforeChange = f11
		afterChange = f12
	}

	configPath := getF(10)

	return &ConfigParquetRow{
		Timestamp:    formattedTime,
		Admin:        admin,
		Client:       getF(4),      // idx+4: Host IP (192.168.1.1
		ClientApp:    getF(8),      // idx+8: Client (Web / CLI)
		Command:      cmd,          // idx+6: Command (commit / edit)
		Result:       getF(9),      // idx+9: Result (Submitted / Succeeded)
		ConfigPath:   configPath,   // idx+10: Configuration Path
		FullPath:     configPath,   // FULL PATH
		SequenceNO:   seqNo,        // 👈 正確填入 7616931376251535614
		BeforeChange: beforeChange, // 👈 不再被誤填為序號
		AfterChange:  afterChange,  // 👈 不再被誤填為 0x8000...
	}, nil
}

func saveConfigSyslogBatchFast(rows []ConfigParquetRow) (int, int, error) {
	if len(rows) == 0 { return 0, 0, nil }
	todayStr := time.Now().Format("2006-01-02")
	chunkPath := filepath.Join(configDir, fmt.Sprintf("config_%s_live_%d.parquet", todayStr, time.Now().UnixNano()))
	if err := parquet.WriteFile(chunkPath, rows); err != nil { return 0, 0, err }
	return len(rows), int(atomic.LoadInt64(&configSyslogReceivedCount)), nil
}

// 🌟 系統日誌極速分塊存檔 (2~5ms 落盤)
func saveSystemSyslogBatchFast(rows []SystemParquetRow) (int, int, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	todayStr := time.Now().Format("2006-01-02")
	chunkPath := filepath.Join(systemDir, fmt.Sprintf("system_%s_live_%d.parquet", todayStr, time.Now().UnixNano()))

	if err := parquet.WriteFile(chunkPath, rows); err != nil {
		return 0, 0, err
	}
	return len(rows), int(atomic.LoadInt64(&systemSyslogReceivedCount)), nil
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

// 🌟 專用原始日誌非同步剖析隊列 (容量 10 萬，平滑吸收突波)
var rawSyslogPacketChan = make(chan string, 100000)

func startSyslogReceiver(port int) {
	addr := &net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("[Syslog] ⚠️ 無法監聽 UDP %d: %v\n", port, err)
		return
	}
	defer conn.Close()

	// 🌟 1. 配置 64MB 核心緩衝區 (Windows / Linux 通用標準方法)
	if err := conn.SetReadBuffer(64 * 1024 * 1024); err != nil {
		fmt.Printf("[Syslog] ⚠️ 警告: 無法設定 64MB 接收緩衝區: %v\n", err)
	} else {
		fmt.Printf("🔍 [Socket 緩衝區配置] 已成功套用 64MB 核心接收緩衝區 (SO_RCVBUF)\n")
	}

	fmt.Printf("[Syslog] 🚀 成功啟動 UDP %d 極速接收服務 (單專職 I/O + 多核心並行剖析就緒)...\n", port)

	// 🌟 3. 啟動多核心剖析協程池 (Worker Pool 專注字串剖析與正規化，不碰 Socket)
	workers := runtime.NumCPU()
	if workers < 4 {
		workers = 4
	}

	for w := 0; w < workers; w++ {
		go func() {
			for rawMsg := range rawSyslogPacketChan {
				// 快速前綴分類，避免無效處理
				if strings.Contains(rawMsg, "TRAFFIC") {
					if row, err := parsePaloAltoSyslog(rawMsg); err == nil && row != nil {
						select {
						case syslogQueue <- *row:
							atomic.AddInt64(&syslogReceivedCount, 1)
						default:
							atomic.AddInt64(&syslogReceivedCount, 1)
						}
					}
					continue
				}

				if strings.Contains(rawMsg, "THREAT") {
					if tRow, err := parsePaloAltoThreatSyslog(rawMsg); err == nil && tRow != nil {
						select {
						case threatSyslogQueue <- *tRow:
							atomic.AddInt64(&threatSyslogReceivedCount, 1)
						default:
						}
					}
					continue
				}

				if strings.Contains(rawMsg, ",SYSTEM,") {
					if sRow, err := parsePaloAltoSystemSyslog(rawMsg); err == nil && sRow != nil {
						select {
						case systemSyslogQueue <- *sRow:
							atomic.AddInt64(&systemSyslogReceivedCount, 1)
						default:
						}
					}
					continue
				}

				if strings.Contains(rawMsg, ",CONFIG,") {
					if cRow, err := parsePaloAltoConfigSyslog(rawMsg); err == nil && cRow != nil {
						select {
						case configSyslogQueue <- *cRow:
							atomic.AddInt64(&configSyslogReceivedCount, 1)
						default:
						}
					}
					continue
				}
			}
		}()
	}

	// 🌟 4. 單一專職極速 I/O 讀取器 (零鎖爭搶，以最高物理速率拔出 UDP 封包)
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		rawMsg := string(buf[:n])

		// 非阻塞投遞至多核心剖析佇列
		select {
		case rawSyslogPacketChan <- rawMsg:
		default:
			// 佇列滿載時防禦 (通常 10 萬容量極難滿載)
		}
	}
}

// 🌟 雙引擎 Syslog 落盤排程器 (熱分析資料 + 冷原始資料 統一批次落盤)
func startSyslogBatchFlusher() {
	go func() {
		ticker := time.NewTicker(2 * time.Second) // 每 3 秒固定 Flush 一次
		defer ticker.Stop()

		var batch []TrafficParquetRow
		var threatBatch []ThreatParquetRow
		var systemBatch []SystemParquetRow
		var rawTrafficBatch []RawLogParquetRow
		var rawThreatBatch []RawLogParquetRow
		var rawSystemBatch []RawLogParquetRow
		var configBatch []ConfigParquetRow
		var rawConfigBatch []RawLogParquetRow // 👈 🌟 補上此行

		chunkCounter := 0
		threatChunkCounter := 0
		systemChunkCounter := 0 // 👈 補上此行
		configChunkCounter := 0


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

					// 🌟 核心改進：每 30 個分塊執行輕量微整併，絕不吃 64GB 記憶體，永遠保持檔案小於 10 個
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

			// 🔔 3. 系統熱資料落盤 (新增)
			if len(systemBatch) > 0 {
				ins, tot, err := saveSystemSyslogBatchFast(systemBatch)
				if err == nil {
					syslogStatusMutex.Lock()
					systemSyslogLastFlushCount = ins
					systemSyslogLastFlushTime = time.Now()
					syslogStatusMutex.Unlock()

					fmt.Printf("[%s] ⚙️ [Syslog UDP 514] 系統日誌入庫：%d 筆 (累計: %d 筆)\n",
						time.Now().Format("15:04:05"), ins, tot)

					systemChunkCounter++
					if systemChunkCounter >= 20 {
						systemChunkCounter = 0
						go ConsolidateSystemParquetFiles()
					}
				}
				systemBatch = nil
			}
			
			// 🔔 4. 組態熱資料落盤 (新增)
			if len(configBatch) > 0 {
				ins, tot, err := saveConfigSyslogBatchFast(configBatch)
				if err == nil {
					syslogStatusMutex.Lock()
					configSyslogLastFlushCount = ins
					configSyslogLastFlushTime = time.Now()
					syslogStatusMutex.Unlock()

					// 🌟 補上 Printf 使用 tot 變數，同時在 CMD 保持與其他日誌一致的即時戰報輸出
					fmt.Printf("[%s] 🔧 [Syslog UDP 514] 組態日誌入庫：%d 筆 (累計: %d 筆)\n",
						time.Now().Format("15:04:05"), ins, tot)

					configChunkCounter++
					if configChunkCounter >= 20 {
						configChunkCounter = 0
						go ConsolidateConfigParquetFiles()
					}
				}
				configBatch = nil
			}

			// 5. 冷資料批次落盤
			if len(rawTrafficBatch) > 0 {
				_ = saveRawLogBatchFast("traffic", rawTrafficBatch)
				rawTrafficBatch = nil
			}
			if len(rawThreatBatch) > 0 {
				_ = saveRawLogBatchFast("threat", rawThreatBatch)
				rawThreatBatch = nil
			}
			if len(rawSystemBatch) > 0 {
				_ = saveRawLogBatchFast("system", rawSystemBatch)
				rawSystemBatch = nil
			}
			if len(rawConfigBatch) > 0 {
				_ = saveRawLogBatchFast("config", rawConfigBatch)
				rawConfigBatch = nil
			}
		}

		for {
			select {
			case row := <-syslogQueue:
				batch = append(batch, row)
				if len(batch) >= 5000 { flushNow() } // 🌟 核心甜蜜點：調為 5,000 筆
			case tRow := <-threatSyslogQueue:
				threatBatch = append(threatBatch, tRow)
				if len(threatBatch) >= 50 { flushNow() }
			case sRow := <-systemSyslogQueue: // 👈 接收 System
				systemBatch = append(systemBatch, sRow)
				if len(systemBatch) >= 50 { flushNow() }
			case rawRow := <-rawTrafficQueue:
				rawTrafficBatch = append(rawTrafficBatch, rawRow)
				if len(rawTrafficBatch) >= 1000 { flushNow() } 
			case rawTRow := <-rawThreatQueue:
				rawThreatBatch = append(rawThreatBatch, rawTRow)
				if len(rawThreatBatch) >= 50 { flushNow() }
			case rawSRow := <-rawSystemQueue: // 👈 接收 Raw System
				rawSystemBatch = append(rawSystemBatch, rawSRow)
				if len(rawSystemBatch) >= 50 { flushNow() }
			case cRow := <-configSyslogQueue:
				configBatch = append(configBatch, cRow)
				if len(configBatch) >= 50 { flushNow() }
			case rawCRow := <-rawConfigQueue:
				rawConfigBatch = append(rawConfigBatch, rawCRow)
				if len(rawConfigBatch) >= 50 { flushNow() }
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
	sIns := systemSyslogLastFlushCount     // 系統當批筆數
	cIns := configSyslogLastFlushCount     // 組態當批筆數
	syslogStatusMutex.RUnlock()

	return map[string]interface{}{
		"port":                     514,
		"received_total":           tot,
		"last_flush_insert":        ins,  // 流量當批
		"last_flush_total":         tot,
		"last_flush_time":          lastStr,
		"threat_last_flush_insert": tIns, // 威脅當批
		"threat_received_total":    atomic.LoadInt64(&threatSyslogReceivedCount),
		"system_last_flush_insert": sIns, // 🌟 系統當批
		"system_received_total":    atomic.LoadInt64(&systemSyslogReceivedCount),
		"config_last_flush_insert": cIns, // 🌟 組態當批
		"config_received_total":    atomic.LoadInt64(&configSyslogReceivedCount),
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

// 🌟 跨平台 DuckDB 執行路徑解析器 (相容 Windows duckdb.exe 與 Linux duckdb，支援專案目錄與系統 PATH)
func getDuckDBExePath() string {
	exeName := "duckdb"
	if runtime.GOOS == "windows" {
		exeName = "duckdb.exe"
	}

	// 1. 優先檢查專案工作目錄 (appDir)
	localPath := filepath.Join(appDir, exeName)
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}

	// 2. 檢查系統全域 PATH (例如 Linux /usr/bin/duckdb, /usr/local/bin/duckdb)
	if p, err := exec.LookPath(exeName); err == nil {
		return p
	}

	return localPath
}

// 🌟 DuckDB 全域並行互斥鎖：強制循// 🌟 DuckDB 雙通道併發控制（Windows / Linux 通用）：
// 1. etlSem：重型寫入/整併通道 (COPY TO)，限制同時 1 個執行，防止吃光 64GB 記憶體
// 2. uiSem ：前端查詢/統計通道 (SELECT / Metadata)，允許最多 3 個 DuckDB 同時並行，絕不被轉檔阻塞
var (
	duckdbETLSem = make(chan struct{}, 1)
	duckdbUISem  = make(chan struct{}, 3)
)

// -------------------------------------------------------------
// 🦆 DuckDB 內部呼叫小幫手 (雙通道並行 + 獨立暫存隔離 + 跨平台相容)
// -------------------------------------------------------------
func runDuckDBQuery(query string) ([]map[string]interface{}, error) {
	duckdbExe := getDuckDBExePath()
	if _, err := os.Stat(duckdbExe); os.IsNotExist(err) {
		return nil, fmt.Errorf("找不到 DuckDB 執行檔！請放入專案目錄或安裝至系統 PATH: %s", duckdbExe)
	}

	// 1. 自動識別任務類型：包含 COPY ( 代表重型寫入轉檔，其餘為輕量前端查詢
	upperQ := strings.ToUpper(query)
	isHeavyETL := strings.Contains(upperQ, "COPY (") || strings.Contains(upperQ, "COPY(")

	var memLimit string
	var threadNum int

	if isHeavyETL {
		duckdbETLSem <- struct{}{}
		defer func() { <-duckdbETLSem }()

		memLimit = "24GB"
		threadNum = 8
		if runtime.GOOS == "linux" {
			memLimit = "32GB"
			threadNum = 12
		}
	} else {
		duckdbUISem <- struct{}{}
		defer func() { <-duckdbUISem }()

		// UI 查詢通道配置 8GB / 6 執行緒，在 Windows 下讀取大型單日檔不溢位
		memLimit = "8GB"
		threadNum = 6
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	// 2. 為每一次 DuckDB 子行程建立專屬獨立暫存目錄，多行程並行互不干擾，結束後自動刪除零殘留
	jobTempDir := filepath.Join(appDir, "duckdb_temp", fmt.Sprintf("job_%d", time.Now().UnixNano()))
	_ = os.MkdirAll(jobTempDir, 0755)
	defer os.RemoveAll(jobTempDir)

	safeSQL := fmt.Sprintf("SET max_memory = '%s'; SET threads = %d; SET preserve_insertion_order = false; SET temp_directory = '%s'; %s",
		memLimit, threadNum, filepath.ToSlash(jobTempDir), query)

	cmd := exec.CommandContext(ctx, duckdbExe, "-json", "-c", safeSQL)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("DuckDB 執行逾時 (已強制終止)")
		}
		return nil, fmt.Errorf("DuckDB 執行失敗: %v, 詳細錯誤: %s", err, stderr.String())
	}

	outStr := strings.TrimSpace(stdout.String())
	if outStr == "" {
		return []map[string]interface{}{}, nil
	}

	// 3. 剝除 Linux DuckDB CLI 可能輸出的 ANSI 顏色碼並精準解析 JSON 陣列
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	cleanOut := strings.TrimSpace(ansiRegex.ReplaceAllString(outStr, ""))
	if cleanOut == "" {
		return []map[string]interface{}{}, nil
	}

	var res []map[string]interface{}
	parsed := false
	searchFrom := 0
	for searchFrom < len(cleanOut) {
		relIdx := strings.Index(cleanOut[searchFrom:], "[")
		if relIdx == -1 {
			break
		}
		idx := searchFrom + relIdx
		decoder := json.NewDecoder(strings.NewReader(cleanOut[idx:]))
		if err := decoder.Decode(&res); err == nil {
			parsed = true
			break
		}
		searchFrom = idx + 1
	}

	if !parsed {
		if !strings.Contains(cleanOut, "{") && strings.Contains(cleanOut, "WARNING:") {
			return []map[string]interface{}{}, nil
		}
		preview := cleanOut
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("解析 DuckDB 回傳失敗: 找不到有效 JSON 陣列 (原始輸出: %s)", preview)
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

// =========================================================================
// 🌟 極速模式輔助函式：非當日 PA-5250 巨量日誌專用
// =========================================================================

// 1. 取得非當日「最新且存在的第一個完整分時主檔」（由 23 時倒序尋找至 00 時）
func getFirstCompleteHourlyTrafficFile(trafficDir, queryDate string) (string, int64) {
	dayDir := filepath.Join(trafficDir, queryDate)
	// 由 23 時倒序尋找分時檔
	for h := 23; h >= 0; h-- {
		candidates := []string{
			filepath.Join(dayDir, fmt.Sprintf("traffic_%s_%02d.parquet", queryDate, h)),
			filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_%02d.parquet", queryDate, h)),
		}
		for _, f := range candidates {
			if fi, err := os.Stat(f); err == nil && fi.Size() > 0 && !strings.HasSuffix(f, ".tmp") {
				// 快速讀取該單檔總行數 (< 5ms)
				cntSQL := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');", filepath.ToSlash(f))
				var rowCount int64 = 10000000 // 保底預設
				if res, err := runDuckDBQuery(cntSQL); err == nil && len(res) > 0 {
					rowCount = parseDuckDBNumber(res[0]["cnt"])
				}
				return f, rowCount
			}
		}
	}
	// 若無分時檔，檢查是否為單一全日主檔
	dailyCandidates := []string{
		filepath.Join(dayDir, fmt.Sprintf("traffic_%s.parquet", queryDate)),
		filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", queryDate)),
	}
	for _, f := range dailyCandidates {
		if fi, err := os.Stat(f); err == nil && fi.Size() > 0 && !strings.HasSuffix(f, ".tmp") {
			cntSQL := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');", filepath.ToSlash(f))
			var rowCount int64 = 10000000
			if res, err := runDuckDBQuery(cntSQL); err == nil && len(res) > 0 {
				rowCount = parseDuckDBNumber(res[0]["cnt"])
			}
			return f, rowCount
		}
	}
	return "", 0
}

// 2. 非當日無自訂過濾時：直接從 Parquet Metadata 彙整 24 檔總筆數 (< 20ms)
func getFastHistoricalTrafficTotal(trafficDir, queryDate string) int64 {
	metaPattern := filepath.ToSlash(filepath.Join(trafficDir, "**", fmt.Sprintf("traffic*%s*.parquet", queryDate)))
	metaSQL := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS total_rows FROM parquet_file_metadata('%s');", metaPattern)
	if res, err := runDuckDBQuery(metaSQL); err == nil && len(res) > 0 {
		return parseDuckDBNumber(res[0]["total_rows"])
	}
	return 0
}

// 🌟 PA-5250 專用：取得指定日期「最後一小時 (DESC 為 23->00，ASC 為 00->23)」的完整分時熱檔
func getEdgeHourlyTrafficFile(trafficDir, queryDate, order string) (string, int64) {
	dayDir := filepath.Join(trafficDir, queryDate)

	checkFile := func(h int) (string, int64) {
		candidates := []string{
			filepath.Join(dayDir, fmt.Sprintf("traffic_%s_%02d.parquet", queryDate, h)),
			filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_%02d.parquet", queryDate, h)),
		}
		for _, f := range candidates {
			if fi, err := os.Stat(f); err == nil && fi.Size() > 0 && !strings.HasSuffix(f, ".tmp") {
				cntSQL := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');", filepath.ToSlash(f))
				var rowCount int64 = 10000000
				if res, err := runDuckDBQuery(cntSQL); err == nil && len(res) > 0 {
					rowCount = parseDuckDBNumber(res[0]["cnt"])
				}
				return f, rowCount
			}
		}
		return "", 0
	}

	if order == "ASC" {
		for h := 0; h <= 23; h++ {
			if f, cnt := checkFile(h); f != "" {
				return f, cnt
			}
		}
	} else {
		for h := 23; h >= 0; h-- {
			if f, cnt := checkFile(h); f != "" {
				return f, cnt
			}
		}
	}

	// 若無分時主檔，回退檢查單一日主檔
	for _, f := range []string{
		filepath.Join(dayDir, fmt.Sprintf("traffic_%s.parquet", queryDate)),
		filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", queryDate)),
	} {
		if fi, err := os.Stat(f); err == nil && fi.Size() > 0 && !strings.HasSuffix(f, ".tmp") {
			cntSQL := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');", filepath.ToSlash(f))
			var rowCount int64 = 10000000
			if res, err := runDuckDBQuery(cntSQL); err == nil && len(res) > 0 {
				rowCount = parseDuckDBNumber(res[0]["cnt"])
			}
			return f, rowCount
		}
	}
	return "", 0
}

// 🌟 利用 Parquet Footer Metadata (stats_min/stats_max) 產生時間窗剪枝 SQL (< 10ms)
// 透過 Row Group 統計過濾掉 99% 舊區塊，同時保留完整 ORDER BY 確保順序 100% 確定不跳動
func buildTimeWindowPrunedLogsSQL(sourceExpr, whereClause, order string, offset int64, perPage int) string {
	if !strings.HasPrefix(sourceExpr, "'") && !strings.HasPrefix(sourceExpr, "[") {
		sourceExpr = fmt.Sprintf("'%s'", sourceExpr)
	}

	metaSQL := fmt.Sprintf(`
		SELECT 
			COALESCE(SUM(row_group_num_rows), 0) AS total_rows,
			MIN(stats_min) AS min_ts,
			MAX(stats_max) AS max_ts
		FROM parquet_metadata(%s)
		WHERE path_in_schema = 'timestamp';
	`, sourceExpr)

	res, err := runDuckDBQuery(metaSQL)
	if err != nil || len(res) == 0 {
		return ""
	}

	totalRows := parseDuckDBNumber(res[0]["total_rows"])
	minTs := strings.TrimSpace(fmt.Sprintf("%v", res[0]["min_ts"]))
	maxTs := strings.TrimSpace(fmt.Sprintf("%v", res[0]["max_ts"]))

	if totalRows <= 0 || len(minTs) < 19 || len(maxTs) < 19 || minTs == "<nil>" || maxTs == "<nil>" {
		return ""
	}

	tMin, err1 := time.Parse("2006-01-02 15:04:05", minTs[:19])
	tMax, err2 := time.Parse("2006-01-02 15:04:05", maxTs[:19])
	if err1 != nil || err2 != nil {
		return ""
	}

	spanSec := tMax.Sub(tMin).Seconds()
	if spanSec < 1 {
		spanSec = 1
	}

	// 依檔案平均每秒筆數估算所需時間窗（至少涵蓋目標筆數的 20 倍或 50,000 筆，且不少於 15 秒）
	avgRate := float64(totalRows) / spanSec
	if avgRate < 1 {
		avgRate = 1
	}
	neededRows := float64(offset + int64(perPage))
	targetSampleRows := math.Max(neededRows*20, 50000)
	windowSec := int(math.Ceil(targetSampleRows / avgRate))
	if windowSec < 15 {
		windowSec = 15
	}
	if float64(windowSec) >= spanSec {
		return ""
	}

	if order == "ASC" {
		cutoff := tMin.Add(time.Duration(windowSec) * time.Second).Format("2006-01-02 15:04:05")
		return fmt.Sprintf(`SELECT * FROM read_parquet(%s, union_by_name=true) WHERE %s AND timestamp <= '%s' ORDER BY timestamp ASC LIMIT %d OFFSET %d`,
			sourceExpr, whereClause, cutoff, perPage, offset)
	}

	cutoff := tMax.Add(-time.Duration(windowSec) * time.Second).Format("2006-01-02 15:04:05")
	return fmt.Sprintf(`SELECT * FROM read_parquet(%s, union_by_name=true) WHERE %s AND timestamp >= '%s' ORDER BY timestamp DESC LIMIT %d OFFSET %d`,
		sourceExpr, whereClause, cutoff, perPage, offset)
}

// 🌟 毫秒級讀取 Parquet 檔尾 Metadata：同時取得總筆數與每小時直方圖 (< 20ms，零資料解壓)
func getFastMetadataStats(duckdbSourceExpr string) (int64, []HistogramBucket, error) {
	hist := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		hist[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0}
	}

	metaSQL := fmt.Sprintf(`SELECT file_name, COALESCE(num_rows, 0) AS num_rows FROM parquet_file_metadata(%s);`, duckdbSourceExpr)
	rows, err := runDuckDBQuery(metaSQL)
	if err != nil {
		return 0, hist, err
	}

	var totalRows int64 = 0
	hourRegex := regexp.MustCompile(`_\d{4}-\d{2}-\d{2}_(\d{2})(?:_\d{2})?\.parquet$`)

	for _, r := range rows {
		cnt := parseDuckDBNumber(r["num_rows"])
		totalRows += cnt

		fname := filepath.Base(fmt.Sprintf("%v", r["file_name"]))
		if m := hourRegex.FindStringSubmatch(fname); len(m) > 1 {
			if hInt, err := strconv.Atoi(m[1]); err == nil && hInt >= 0 && hInt < 24 {
				hist[hInt].Count += int(cnt)
			}
		}
	}
	return totalRows, hist, nil
}

// 🌟 判斷是否為背景微整併刪除舊碎片造成的瞬時檔案遺失錯誤
func isTransientParquetCompactionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Cannot open file") ||
		strings.Contains(msg, "No such file or directory") ||
		strings.Contains(msg, "cannot find the file")
}

// 🌟 智慧 IP 條件建構器：同時支援 CIDR 網段 (192.168.1.0/24)、萬用字元 (192.168.1.* / 192.168.1.?) 與單一精準 IP
func buildIPFilterSQL(colName, rawVal string) string {
	val := strings.TrimSpace(rawVal)
	if val == "" {
		return ""
	}

	// 1. CIDR 網段查詢 (例如: 192.168.1.0/24, 10.50.0.0/16, 172.16.0.0/22)
	if strings.Contains(val, "/") {
		if _, ipNet, err := net.ParseCIDR(val); err == nil {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				ones, bits := ipNet.Mask.Size()
				startIP := uint64(ip4[0])<<24 | uint64(ip4[1])<<16 | uint64(ip4[2])<<8 | uint64(ip4[3])
				var hostMask uint64
				if bits == 32 && ones < 32 {
					hostMask = (uint64(1) << uint(32-ones)) - 1
				}
				endIP := startIP | hostMask

				// 依據遮罩長度加上前綴過濾，讓 DuckDB 向量引擎快速跳過不符網段
				prefixCond := ""
				if ones >= 24 {
					prefixCond = fmt.Sprintf("%s LIKE '%d.%d.%d.%%' AND ", colName, ip4[0], ip4[1], ip4[2])
				} else if ones >= 16 {
					prefixCond = fmt.Sprintf("%s LIKE '%d.%d.%%' AND ", colName, ip4[0], ip4[1])
				} else if ones >= 8 {
					prefixCond = fmt.Sprintf("%s LIKE '%d.%%' AND ", colName, ip4[0])
				}

				return fmt.Sprintf(
					"%s(TRY_CAST(split_part(%s, '.', 1) AS BIGINT) * 16777216 + TRY_CAST(split_part(%s, '.', 2) AS BIGINT) * 65536 + TRY_CAST(split_part(%s, '.', 3) AS BIGINT) * 256 + TRY_CAST(split_part(%s, '.', 4) AS BIGINT)) BETWEEN %d AND %d",
					prefixCond, colName, colName, colName, colName, startIP, endIP,
				)
			}
		}
	}

	// 2. 萬用字元查詢 (* 代表任意長度字元，? 代表單一字元，例如: 192.168.1.* 或 192.168.*.10)
	if strings.ContainsAny(val, "*?") {
		escaped := strings.ReplaceAll(val, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `''`)
		escaped = strings.ReplaceAll(escaped, `%`, `\%`)
		escaped = strings.ReplaceAll(escaped, `_`, `\_`)
		escaped = strings.ReplaceAll(escaped, `*`, `%`)
		escaped = strings.ReplaceAll(escaped, `?`, `_`)
		return fmt.Sprintf("%s ILIKE '%s' ESCAPE '\\'", colName, escaped)
	}

	// 3. 完整單一 IP 精準比對 (避免點選 192.168.1.1 時誤抓到 192.168.1.10 或 192.168.1.100)
	if net.ParseIP(val) != nil {
		return fmt.Sprintf("%s = '%s'", colName, strings.ReplaceAll(val, "'", "''"))
	}

	// 4. 部分片段模糊比對 (例如直接輸入 192.168.1)
	return fmt.Sprintf("%s ILIKE '%%%s%%'", colName, strings.ReplaceAll(val, "'", "''"))
}

// -------------------------------------------------------------
// 🌟 聚合查詢：DuckDB 向量化極速引擎 (含背景整併自動重讀容錯)
// -------------------------------------------------------------
func queryTrafficAnalytics(queryDate, src, dst, app, action, zone string, page, perPage int, onlyLogs bool, order string, knownTotal int64, firstLoad bool, countOnly bool) (*TrafficAnalyticsResult, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		res, err := queryTrafficAnalyticsOnce(queryDate, src, dst, app, action, zone, page, perPage, onlyLogs, order, knownTotal, firstLoad, countOnly)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if isTransientParquetCompactionError(err) && attempt < 2 {
			fmt.Printf("[查詢自動重試] 🔄 偵測到背景檔案整併替換，自動重新掃描目錄並重讀 (%d/2)...\n", attempt+1)
			time.Sleep(80 * time.Millisecond)
			continue
		}
		break
	}
	return nil, lastErr
}

// -------------------------------------------------------------
// 🌟 聚合查詢：DuckDB 向量化極速引擎 (PA-5250 與 PA-1420 雙適配極速版)
// -------------------------------------------------------------
func queryTrafficAnalyticsOnce(queryDate, src, dst, app, action, zone string, page, perPage int, onlyLogs bool, order string, knownTotal int64, firstLoad bool, countOnly bool) (*TrafficAnalyticsResult, error) {
	queryDate = strings.ReplaceAll(strings.TrimSpace(queryDate), "/", "-")
	if queryDate == "" {
		queryDate = time.Now().Format("2006-01-02")
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	if order != "ASC" && order != "DESC" {
		order = "DESC"
	}

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0}
	}

	// 🌟 1. 直接鎖定「日期子資料夾」與「根目錄同日檔案」，徹底消除 ** 遞迴掃描整個硬碟的延遲
	dayDir := filepath.Join(trafficDir, queryDate)
	subFiles, _ := filepath.Glob(filepath.Join(dayDir, "*.parquet"))
	rootFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))
	rawCandidateFiles := append(subFiles, rootFiles...)

	var validSlashPaths []string
	var totalFileSize int64 = 0
	for _, f := range rawCandidateFiles {
		if strings.HasSuffix(f, ".tmp") {
			continue
		}
		if info, err := os.Stat(f); err == nil && !info.IsDir() && info.Size() > 0 {
			totalFileSize += info.Size()
			validSlashPaths = append(validSlashPaths, filepath.ToSlash(f))
		}
	}

	hasFiles := len(validSlashPaths) > 0

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

	// 🌟 2. 組合精準檔案清單表達式 (單檔傳字串，多檔傳陣列，零萬用字元 glob 開銷)
	var duckdbSourceExpr string
	if len(validSlashPaths) == 1 {
		duckdbSourceExpr = fmt.Sprintf("'%s'", validSlashPaths[0])
	} else {
		quoted := make([]string, len(validSlashPaths))
		for i, p := range validSlashPaths {
			quoted[i] = fmt.Sprintf("'%s'", p)
		}
		duckdbSourceExpr = fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
	}

	// 🌟 解析前端統一查詢列擴充條件 (natsrc, natdst, dport, rule, reason)，完全相容既有 API 參數
	var natSrc, natDst, dport, ruleFilter, reasonFilter string
	if idx := strings.Index(app, "__EXT__"); idx != -1 {
		extJSON := app[idx+7:]
		app = app[:idx]
		var extMap map[string]string
		if err := json.Unmarshal([]byte(extJSON), &extMap); err == nil {
			natSrc = strings.TrimSpace(extMap["natsrc"])
			natDst = strings.TrimSpace(extMap["natdst"])
			dport = strings.TrimSpace(extMap["dport"])
			ruleFilter = strings.TrimSpace(extMap["rule"])
			reasonFilter = strings.TrimSpace(extMap["reason"])
		}
	}

	var conds []string
	conds = append(conds, "1=1")

	if src != "" {
		conds = append(conds, buildIPFilterSQL("source", src))
	}
	if natSrc != "" {
		conds = append(conds, buildIPFilterSQL("nat_source_ip", natSrc))
	}
	if dst != "" {
		conds = append(conds, buildIPFilterSQL("destination", dst))
	}
	if natDst != "" {
		conds = append(conds, buildIPFilterSQL("nat_dest_ip", natDst))
	}
	if dport != "" {
		if pNum, err := strconv.Atoi(dport); err == nil {
			conds = append(conds, fmt.Sprintf("to_port = %d", pNum))
		} else {
			conds = append(conds, fmt.Sprintf("CAST(to_port AS VARCHAR) ILIKE '%%%s%%'", strings.ReplaceAll(dport, "'", "''")))
		}
	}
	if app != "" {
		conds = append(conds, fmt.Sprintf("application ILIKE '%%%s%%'", strings.ReplaceAll(app, "'", "''")))
	}
	if action != "" && strings.ToLower(action) != "all" {
		act := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(action, "'", "''")))
		switch act {
		case "allow":
			conds = append(conds, "LOWER(TRIM(action)) = 'allow'")
		case "deny":
			conds = append(conds, "LOWER(TRIM(action)) = 'deny'")
		case "drop":
			conds = append(conds, "LOWER(TRIM(action)) = 'drop'")
		case "deny_drop":
			conds = append(conds, "LOWER(TRIM(action)) IN ('deny', 'drop')")
		default:
			conds = append(conds, fmt.Sprintf("LOWER(TRIM(action)) = '%s'", act))
		}
	}
	if zone != "" && strings.ToLower(zone) != "all" {
		z := strings.ReplaceAll(strings.ToLower(zone), "'", "''")
		conds = append(conds, fmt.Sprintf("(from_zone ILIKE '%%%s%%' OR to_zone ILIKE '%%%s%%')", z, z))
	}
	if ruleFilter != "" {
		conds = append(conds, fmt.Sprintf("rule ILIKE '%%%s%%'", strings.ReplaceAll(ruleFilter, "'", "''")))
	}
	if reasonFilter != "" {
		conds = append(conds, fmt.Sprintf("session_end_reason ILIKE '%%%s%%'", strings.ReplaceAll(reasonFilter, "'", "''")))
	}

	whereClause := strings.Join(conds, " AND ")

	// 🌟 PA-5250 高階機型專屬判斷
	todayStr := time.Now().Format("2006-01-02")
	isToday := (queryDate == todayStr)
	hasCustomFilter := (src != "" || natSrc != "" || dst != "" || natDst != "" ||
		dport != "" || app != "" || ruleFilter != "" || reasonFilter != "" ||
		(action != "" && strings.ToLower(action) != "all") ||
		(zone != "" && strings.ToLower(zone) != "all"))

	var statsRes, logsRes []map[string]interface{}
	var errStats, errLogs error
	var probeRows int64 = 0
	var fastMetaTotal int64 = 0
	var fastMetaHist []HistogramBucket
	var hasFastMeta bool = false
	var wg sync.WaitGroup

	// 🌟 無自訂過濾條件時：
	// - 當日 (isToday)：資料持續寫入中，每次查詢皆從 Metadata 秒讀最新總筆數
	// - 非當日 (!isToday)：資料已固定，僅在尚未取得總數 (knownTotal <= 0) 或初次統計時讀取一次，翻頁直接沿用 knownTotal
	needMetaRefresh := isToday || knownTotal <= 0 || firstLoad || countOnly || !onlyLogs
	if !hasCustomFilter && needMetaRefresh {
		if mTot, mHist, mErr := getFastMetadataStats(duckdbSourceExpr); mErr == nil && mTot > 0 {
			fastMetaTotal = mTot
			fastMetaHist = mHist
			hasFastMeta = true
		}
	}

	// ==========================================
	// 🦆 任務 1 & 2：單一 DuckDB 行程合併執行「統計 + 直方圖」(減少 Windows 行程啟動與重複讀檔)
	// ==========================================
	if countOnly || (!onlyLogs && !firstLoad) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hasHourlyBuckets := false
			for _, b := range fastMetaHist {
				if b.Count > 0 {
					hasHourlyBuckets = true
					break
				}
			}

			var combinedSQL string
			if hasHourlyBuckets {
				// PA-5250 分時檔已由檔名取得直方圖，僅需掃描 bytes / action / top_app
				combinedSQL = fmt.Sprintf(`
					SELECT 
						'stats' AS rec_type,
						'' AS h,
						CAST(%d AS BIGINT) AS total_flows,
						CAST(COALESCE(SUM(bytes), 0) AS DOUBLE) AS total_bytes, 
						COUNT(CASE WHEN LOWER(action) IN ('deny', 'drop') THEN 1 END) AS deny_flows,
						COALESCE((SELECT MODE(application) FROM (SELECT application FROM read_parquet(%s, union_by_name=true) LIMIT 100000)), '-') AS top_app 
					FROM read_parquet(%s, union_by_name=true)
				`, fastMetaTotal, duckdbSourceExpr, duckdbSourceExpr)
			} else if hasFastMeta {
				// PA-1420 單檔或無過濾條件：單趟掃描同時產出統計卡片 + 24 小時直方圖
				combinedSQL = fmt.Sprintf(`
					WITH base AS (
						SELECT timestamp, bytes, action, application
						FROM read_parquet(%s, union_by_name=true)
					)
					SELECT
						'stats' AS rec_type,
						'' AS h,
						CAST(%d AS BIGINT) AS total_flows,
						CAST(COALESCE(SUM(bytes), 0) AS DOUBLE) AS total_bytes,
						COUNT(CASE WHEN action IN ('deny', 'drop', 'reset-both', 'reset-client', 'reset-server', 'DENY', 'DROP') THEN 1 END) AS deny_flows,
						COALESCE((SELECT MODE(application) FROM (SELECT application FROM base LIMIT 100000)), '-') AS top_app
					FROM base
					UNION ALL
					SELECT
						'hist' AS rec_type,
						SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS h,
						COUNT(*) AS total_flows,
						0.0 AS total_bytes,
						0 AS deny_flows,
						'' AS top_app
					FROM base
					GROUP BY h
				`, duckdbSourceExpr, fastMetaTotal)
			} else {
				// 帶有自訂 IP / Port / App 過濾條件：單趟掃描同時產出過濾後統計 + 直方圖
				combinedSQL = fmt.Sprintf(`
					WITH base AS (
						SELECT timestamp, bytes, action, application
						FROM read_parquet(%s, union_by_name=true)
						WHERE %s
					)
					SELECT
						'stats' AS rec_type,
						'' AS h,
						COUNT(*) AS total_flows,
						CAST(COALESCE(SUM(bytes), 0) AS DOUBLE) AS total_bytes,
						COUNT(CASE WHEN action IN ('deny', 'drop', 'reset-both', 'reset-client', 'reset-server', 'DENY', 'DROP') THEN 1 END) AS deny_flows,
						COALESCE((SELECT MODE(application) FROM (SELECT application FROM base LIMIT 100000)), '-') AS top_app
					FROM base
					UNION ALL
					SELECT
						'hist' AS rec_type,
						SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS h,
						COUNT(*) AS total_flows,
						0.0 AS total_bytes,
						0 AS deny_flows,
						'' AS top_app
					FROM base
					GROUP BY h
				`, duckdbSourceExpr, whereClause)
			}

			statsRes, errStats = runDuckDBQuery(combinedSQL)
		}()
	}

	// ==========================================
	// 🦆 任務 3：撈取明細 (Metadata 時間窗剪枝 + 確定性 ORDER BY，兼顧秒開與精準時間順序)
	// ==========================================
	if !countOnly {
		offset := int64(page-1) * int64(perPage)
		probeLimit := int64(perPage) * 10

		// 鎖定邊緣分時/單日檔案（非當日無過濾條件且前 10,000 筆內優先掃描最後一小時單檔）
		targetScanExpr := duckdbSourceExpr
		hasEdgeFile := false

		if !isToday && !hasCustomFilter && offset < 10000 {
			edgeFile, edgeRows := getEdgeHourlyTrafficFile(trafficDir, queryDate, order)
			if edgeFile != "" && offset < edgeRows {
				targetScanExpr = fmt.Sprintf("'%s'", filepath.ToSlash(edgeFile))
				hasEdgeFile = true
				probeRows = edgeRows
			}
		}

		// 僅在無 Metadata 總數時才執行前 10 頁探測
		if !hasFastMeta && (firstLoad || (onlyLogs && knownTotal <= 0)) && probeRows <= 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probeSQL := fmt.Sprintf(`SELECT COUNT(*) AS c FROM (SELECT 1 FROM read_parquet(%s, union_by_name=true) WHERE %s LIMIT %d)`,
					targetScanExpr, whereClause, probeLimit)
				if pRes, pErr := runDuckDBQuery(probeSQL); pErr == nil && len(pRes) > 0 {
					probeRows = parseDuckDBNumber(pRes[0]["c"])
				}
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			oppositeOrder := "ASC"
			if order == "ASC" {
				oppositeOrder = "DESC"
			}

			// 🌟 1. 無自訂過濾且位於前段頁面 (offset < 10000) 時，優先使用 Footer 時間窗剪枝 + 確定性 ORDER BY
			if !hasCustomFilter && offset < 10000 {
				prunedSQL := buildTimeWindowPrunedLogsSQL(targetScanExpr, whereClause, order, offset, perPage)
				if prunedSQL != "" {
					pRes, pErr := runDuckDBQuery(prunedSQL)
					if pErr != nil && isTransientParquetCompactionError(pErr) {
						errLogs = pErr
						return
					}
					// 若該時間窗內已抓滿一頁所需筆數，直接採用（100% 精準排序且耗時 < 30ms）
					if pErr == nil && len(pRes) >= perPage {
						logsRes = pRes
						return
					}
				}
			}

			// 🌟 2. 若時間窗內筆數不足一頁（離峰時段）或帶過濾條件/深層翻頁，執行完整範圍查詢
			scanSource := duckdbSourceExpr
			if hasEdgeFile {
				scanSource = targetScanExpr
			}

			totalRows := knownTotal
			if totalRows <= 0 && hasFastMeta {
				totalRows = fastMetaTotal
			}
			if totalRows <= 0 && offset > 50000 && !firstLoad && !hasEdgeFile {
				cntSQL := fmt.Sprintf(`SELECT COUNT(*) AS c FROM read_parquet(%s, union_by_name=true) WHERE %s`, duckdbSourceExpr, whereClause)
				if cRes, err := runDuckDBQuery(cntSQL); err == nil && len(cRes) > 0 {
					totalRows = parseDuckDBNumber(cRes[0]["c"])
				}
			}

			var logsQuery string
			if totalRows > 0 && offset > totalRows/2 && !firstLoad && !hasEdgeFile {
				oppOffset := totalRows - (offset + int64(perPage))
				var actLimit, actOffset int64
				if oppOffset < 0 {
					actLimit = int64(perPage) + oppOffset
					actOffset = 0
				} else {
					actLimit = int64(perPage)
					actOffset = oppOffset
				}
				if actLimit <= 0 {
					actLimit = int64(perPage)
				}

				logsQuery = fmt.Sprintf(`
					SELECT * FROM (
						SELECT * FROM read_parquet(%s, union_by_name=true) WHERE %s ORDER BY timestamp %s LIMIT %d OFFSET %d
					) sub ORDER BY timestamp %s
				`, scanSource, whereClause, oppositeOrder, actLimit, actOffset, order)
			} else {
				logsQuery = fmt.Sprintf(`SELECT * FROM read_parquet(%s, union_by_name=true) WHERE %s ORDER BY timestamp %s LIMIT %d OFFSET %d`,
					scanSource, whereClause, order, perPage, offset)
			}
			logsRes, errLogs = runDuckDBQuery(logsQuery)
		}()
	}

	wg.Wait()
	if errStats != nil {
		return nil, errStats
	}
	if errLogs != nil && !countOnly {
		return nil, errLogs
	}

	// 處理結果
	var totalFlows int = int(knownTotal)
	var totalBytesNum int64
	var denyFlows int
	topApp := "-"

	if hasFastMeta {
		totalFlows = int(fastMetaTotal)
		emptyHistogram = fastMetaHist
	}

	if (countOnly || (!onlyLogs && !firstLoad)) && len(statsRes) > 0 {
		histMap := make(map[string]int)
		hasHistRows := false
		for _, row := range statsRes {
			recType := fmt.Sprintf("%v", row["rec_type"])
			if recType == "hist" {
				hasHistRows = true
				if h, ok := row["h"].(string); ok && h != "" {
					histMap[h] = int(parseDuckDBNumber(row["total_flows"]))
				}
			} else {
				if !hasFastMeta {
					totalFlows = int(parseDuckDBNumber(row["total_flows"]))
				}
				totalBytesNum = parseDuckDBNumber(row["total_bytes"])
				denyFlows = int(parseDuckDBNumber(row["deny_flows"]))
				if v, ok := row["top_app"].(string); ok && v != "" {
					topApp = v
				}
			}
		}
		if hasHistRows {
			for h := 0; h < 24; h++ {
				emptyHistogram[h].Count = histMap[fmt.Sprintf("%02d:00", h)]
			}
		}
	} else if !hasFastMeta && probeRows > 0 && totalFlows <= 0 {
		totalFlows = int(probeRows)
	} else if !hasFastMeta && !firstLoad && onlyLogs && totalFlows <= 0 {
		cntSQL := fmt.Sprintf(`SELECT COUNT(*) AS c FROM read_parquet(%s, union_by_name=true) WHERE %s`, duckdbSourceExpr, whereClause)
		if cRes, err := runDuckDBQuery(cntSQL); err == nil && len(cRes) > 0 {
			totalFlows = int(parseDuckDBNumber(cRes[0]["c"]))
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

	logs := make([]TrafficLogItem, 0, len(logsRes))
	if !countOnly {
		dhcpMap := make(map[string]string)
		db, _ := initDB()
		if db != nil {
			rDHCP, _ := db.Query("SELECT ip, hostname FROM dhcp_leases WHERE record_date = ?", queryDate)
			if rDHCP != nil {
				defer rDHCP.Close()
				for rDHCP.Next() {
					var ip, hn string
					_ = rDHCP.Scan(&ip, &hn)
					if hn != "" {
						dhcpMap[ip] = hn
					}
				}
			}
			rCache, _ := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
			if rCache != nil {
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

		safeStr := func(v interface{}) string {
			if v == nil {
				return ""
			}
			return fmt.Sprintf("%v", v)
		}

		for _, r := range logsRes {
			bytesVal := int64(0)
			if v, ok := r["bytes"].(float64); ok {
				bytesVal = int64(v)
			}
			var bFmt string
			if bytesVal >= 1024*1024 {
				bFmt = fmt.Sprintf("%.2f MB", float64(bytesVal)/(1024*1024))
			} else if bytesVal >= 1024 {
				bFmt = fmt.Sprintf("%.1f KB", float64(bytesVal)/1024)
			} else {
				bFmt = fmt.Sprintf("%d B", bytesVal)
			}

			portVal := 0
			if p, ok := r["to_port"].(float64); ok {
				portVal = int(p)
			}

			logs = append(logs, TrafficLogItem{
				Timestamp: safeStr(r["timestamp"]), Type: safeStr(r["type"]), FromZone: safeStr(r["from_zone"]), ToZone: safeStr(r["to_zone"]),
				Source: safeStr(r["source"]), SrcHostname: dhcpMap[safeStr(r["source"])], NatSourceIP: safeStr(r["nat_source_ip"]), Destination: safeStr(r["destination"]),
				NatDestIP: safeStr(r["nat_dest_ip"]), ToPort: portVal, Application: safeStr(r["application"]), Action: safeStr(r["action"]),
				Rule: safeStr(r["rule"]), SessionEndReason: safeStr(r["session_end_reason"]), Bytes: bytesVal, BytesFormatted: bFmt,
			})
		}
	}

	totalPages := 1
	if totalFlows > 0 {
		totalPages = int(math.Ceil(float64(totalFlows) / float64(perPage)))
	}
	if hasFiles && !isToday && totalPages < 10 {
		totalPages = 10
	}

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
	var targetDir string
	switch logType {
	case "threat":
		targetDir = threatRawDir
	case "system":
		targetDir = systemRawDir
	case "config":
		targetDir = configRawDir  // 👈 🌟 修正：精準導向 config_raw_logs
	default:
		targetDir = trafficRawDir
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
		//ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")
		ConsolidateRawParquetFiles("system")
		ConsolidateRawParquetFiles("config")

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
			//ConsolidateRawParquetFiles("traffic")
			ConsolidateRawParquetFiles("threat")
		}
	}()
}

// 🌟 Threat API 碎片寫入引擎 (隔離比對 + 零 Go 記憶體負擔)
func saveThreatLogsToParquet(entries []ThreatEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	threatFileMutex.Lock()
	defer threatFileMutex.Unlock()

	var rawRows []RawLogParquetRow 
	entriesByDate := make(map[string][]ThreatParquetRow)

	for _, e := range entries {
		tName := strings.TrimSpace(e.ThreatName)
		if tName == "" { tName = strings.TrimSpace(e.ThreatID) }

		ts := strings.TrimSpace(e.TimeGenerated)
		if ts == "" { ts = strings.TrimSpace(e.ReceiveTime) }
		ts = strings.ReplaceAll(ts, "/", "-")

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

		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  strings.TrimSpace(e.SessionID),
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
	}

	if len(rawRows) > 0 {
		go func(r []RawLogParquetRow) {
			_ = saveRawLogBatchFast("threat", r)
		}(rawRows)
	}

	totalInserted := 0
	totalToday := 0
	todayStr := time.Now().Format("2006-01-02")

	for dateKey, newRows := range entriesByDate {
		if len(newRows) == 0 {
			continue
		}

		tmpDir := filepath.Join(threatDir, ".tmp")
		_ = os.MkdirAll(tmpDir, 0755)

		tmpChunkPath := filepath.Join(tmpDir, fmt.Sprintf("check_%s_%d.parquet", dateKey, time.Now().UnixNano()))
		if err := parquet.WriteFile(tmpChunkPath, newRows); err != nil {
			continue
		}

		minT := newRows[0].Timestamp
		maxT := newRows[0].Timestamp
		for _, r := range newRows {
			if r.Timestamp < minT { minT = r.Timestamp }
			if r.Timestamp > maxT { maxT = r.Timestamp }
		}

		existingPattern := filepath.ToSlash(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", dateKey)))
		allExisting, _ := filepath.Glob(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", dateKey)))

		var validExisting []string
		for _, f := range allExisting {
			if !strings.HasSuffix(f, ".tmp") && !strings.Contains(f, "check_") {
				validExisting = append(validExisting, f)
			}
		}

		var actualNewCount int = len(newRows)

		if len(validExisting) > 0 {
			checkSQL := fmt.Sprintf(`
				SELECT COUNT(*) as new_cnt 
				FROM read_parquet('%s') t
				WHERE NOT EXISTS (
					SELECT 1 FROM read_parquet('%s', union_by_name=true) m
					WHERE m.timestamp >= '%s' AND m.timestamp <= '%s'
					  AND COALESCE(m.timestamp, '') = COALESCE(t.timestamp, '')
					  AND COALESCE(m.src, '') = COALESCE(t.src, '')
					  AND COALESCE(m.dst, '') = COALESCE(t.dst, '')
					  AND COALESCE(m.threat_name, '') = COALESCE(t.threat_name, '')
					  AND COALESCE(m.action, '') = COALESCE(t.action, '')
				)
			`, filepath.ToSlash(tmpChunkPath), existingPattern, minT, maxT)

			if res, err := runDuckDBQuery(checkSQL); err == nil && len(res) > 0 {
				actualNewCount = int(parseDuckDBNumber(res[0]["new_cnt"]))
			}
		}

		if actualNewCount == 0 {
			_ = os.Remove(tmpChunkPath)
		} else {
			// 🌟 修正：正確存入 traffic_logs 目錄，並命名為 traffic_%s_chunk_*.parquet
			finalChunkPath := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s_chunk_%d.parquet", dateKey, time.Now().UnixNano()))
			_ = os.Rename(tmpChunkPath, finalChunkPath)
		}

		totalInserted += actualNewCount
		if dateKey == todayStr {
			totalToday += actualNewCount
		}
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
	for h := 0; h < 24; h++ { emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0} }

	// 🌟 1. 實體檔案統計：同時掃描根目錄舊主檔與日期子目錄新檔 (Threat 威脅日誌)
	files, _ := filepath.Glob(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", queryDate)))
	if subFiles, err := filepath.Glob(filepath.Join(threatDir, queryDate, fmt.Sprintf("threat*%s*.parquet", queryDate))); err == nil {
		files = append(files, subFiles...)
	}

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

	// 🌟 2. DuckDB 查詢字串：直接使用 ** 遞迴萬用字元 (Threat 專屬目錄)
	duckdbPattern := filepath.ToSlash(filepath.Join(threatDir, "**", fmt.Sprintf("threat*%s*.parquet", queryDate)))
	var conds []string
	conds = append(conds, "1=1")
	if src != "" { conds = append(conds, fmt.Sprintf("src ILIKE '%%%s%%'", strings.ReplaceAll(src, "'", "''"))) }
	if dst != "" { conds = append(conds, fmt.Sprintf("dst ILIKE '%%%s%%'", strings.ReplaceAll(dst, "'", "''"))) }
	if threatName != "" { 
		t := strings.ReplaceAll(threatName, "'", "''")
		conds = append(conds, fmt.Sprintf("(threat_name ILIKE '%%%s%%' OR subtype ILIKE '%%%s%%')", t, t)) 
	}
	if severity != "" && strings.ToLower(severity) != "all" {
		s := strings.ToLower(severity)
		if s == "crit_high" {
			// 🌟 點擊卡片時：同時篩選 critical 與 high
			conds = append(conds, "LOWER(severity) IN ('critical', 'high')")
		} else {
			conds = append(conds, fmt.Sprintf("LOWER(severity) = '%s'", s))
		}
	}
	if action != "" && strings.ToLower(action) != "all" {
		act := strings.ToLower(strings.ReplaceAll(action, "'", "''"))
		if act == "allow" {
			conds = append(conds, "LOWER(action) = 'allow'")
		} else if act == "deny" {
			conds = append(conds, "(LOWER(action) IN ('deny', 'drop') OR LOWER(action) LIKE 'reset%')")
		} else if act == "reset" {
			conds = append(conds, "LOWER(action) LIKE 'reset%'")
		} else {
			// 精準比對 drop、reset-both、reset-client、reset-server 等指定動作
			conds = append(conds, fmt.Sprintf("LOWER(action) = '%s'", act))
		}
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

// 🌟 NAS 匯入全域即時進度追蹤器
type NASImportProgress struct {
	sync.RWMutex
	IsRunning     bool     `json:"is_running"`
	Stage         string   `json:"stage"` // "idle", "reading", "converting", "done", "error"
	FileName      string   `json:"file_name"`
	TotalLines    int      `json:"total_lines"`
	ValidLines    int      `json:"valid_lines"`
	CurrentDate   string   `json:"current_date"`
	ProcessedDays int      `json:"processed_days"`
	TotalDays     int      `json:"total_days"`
	Percent       int      `json:"percent"`
	Logs          []string `json:"logs"`
	Error         string   `json:"error"`
}

var globalNASProgress NASImportProgress

func (p *NASImportProgress) addLog(msg string) {
	p.Lock()
	defer p.Unlock()
	p.Logs = append(p.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(p.Logs) > 100 {
		p.Logs = p.Logs[len(p.Logs)-100:]
	}
}

// 🌟 處理 NAS 上傳檔案 (支援多檔案批次讀取、自動識別 TRAFFIC 與 THREAT、逐日分流落盤)
func processNASImport(nasFilePaths []string, logType string) {
	if len(nasFilePaths) == 0 {
		return
	}

	globalNASProgress.Lock()
	globalNASProgress.IsRunning = true
	globalNASProgress.Stage = "reading"
	globalNASProgress.FileName = fmt.Sprintf("共 %d 個檔案批次匯入", len(nasFilePaths))
	globalNASProgress.TotalLines = 0
	globalNASProgress.ValidLines = 0
	globalNASProgress.ProcessedDays = 0
	globalNASProgress.TotalDays = 0
	globalNASProgress.Percent = 10
	globalNASProgress.Error = ""
	globalNASProgress.Logs = []string{
		fmt.Sprintf("[%s] 🚀 開始批次解析 %d 個日誌檔案...", time.Now().Format("15:04:05"), len(nasFilePaths)),
		fmt.Sprintf("[%s] 🌐 自動按日誌日期與類型逐日自動切分落盤", time.Now().Format("15:04:05")),
	}
	globalNASProgress.Unlock()

	defer func() {
		for _, p := range nasFilePaths {
			_ = os.Remove(p)
		}
	}()

	baseTmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("nas_batch_%d", time.Now().UnixNano()))
	_ = os.MkdirAll(baseTmpDir, 0755)
	defer os.RemoveAll(baseTmpDir)

	type BatchTarget struct {
		LogType string
		Date    string
		Dir     string
		File    *os.File
		Count   int
	}

	batches := make(map[string]*BatchTarget)
	allDetectedDates := make(map[string]bool)

	trafficBaseHeaders := []string{
		"Domain", "Receive Time", "Serial", "Type", "Threat/Content Type", "Config Version",
		"Generate Time", "Source address", "Destination address", "NAT Source IP", "NAT Destination IP",
		"Rule", "Source User", "Destination User", "Application", "Virtual System", "Source Zone",
		"Destination Zone", "Inbound Interface", "Outbound Interface", "Log Action", "Time Logged",
		"Session ID", "Repeat Count", "Source Port", "Destination Port", "NAT Source Port",
		"NAT Destination Port", "Flags", "IP Protocol", "Action", "Bytes", "Bytes Sent",
		"Bytes Received", "Packets", "Start Time", "Elapsed Time", "Category", "padding", "seqno",
		"actionflags", "Source Country", "Destination Country", "cpadding", "pkts_sent",
		"pkts_received", "Session End Reason", "dg_hier_level_1", "dg_hier_level_2",
		"dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name", "action_source",
		"tunnelid/imsi", "monitor_tag/imei", "parent_session_id", "parent_start_time", "tunnel",
		"sctp_association_id", "sctp_chunks", "sctp_chunks_sent", "sctp_chunks_received",
	}

	threatBaseHeaders := []string{
		"Domain", "Receive Time", "Serial", "Type", "Threat/Content Type", "Config Version",
		"Generate Time", "Source address", "Destination address", "NAT Source IP", "NAT Destination IP",
		"Rule", "Source User", "Destination User", "Application", "Virtual System", "Source Zone",
		"Destination Zone", "Inbound Interface", "Outbound Interface", "Log Action", "Time Logged",
		"Session ID", "Repeat Count", "Source Port", "Destination Port", "NAT Source Port",
		"NAT Destination Port", "Flags", "IP Protocol", "Action", "Misc", "Threat/Content Name",
		"Category", "Severity", "Direction", "Sequence Number", "Action Flags", "Source Country",
		"Destination Country", "cpadding", "contenttype", "pcap_id", "filedigest", "cloud",
		"url_idx", "user_agent", "filetype", "xff", "referer", "sender", "subject", "recipient",
		"reportid", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
		"vsys_name", "device_name", "file_url",
	}

	lineCounter := 0
	validCounter := 0

	// 🌟 核心：外層迴圈遍歷所有上傳的檔案
	for fileIdx, filePath := range nasFilePaths {
		inFile, err := os.Open(filePath)
		if err != nil {
			globalNASProgress.addLog(fmt.Sprintf("⚠️ 無法開啟第 %d 個檔案: %v (略過)", fileIdx+1, err))
			continue
		}

		globalNASProgress.addLog(fmt.Sprintf("📖 [%d/%d] 正在讀取檔案：%s", fileIdx+1, len(nasFilePaths), filepath.Base(filePath)))

		scanner := bufio.NewScanner(inFile)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			lineCounter++

			if lineCounter%50000 == 0 {
				globalNASProgress.Lock()
				globalNASProgress.TotalLines = lineCounter
				globalNASProgress.ValidLines = validCounter
				globalNASProgress.Unlock()
				globalNASProgress.addLog(fmt.Sprintf("   ↳ 已累積掃描 %d 行 (有效 %d 筆)...", lineCounter, validCounter))
			}
			
			// 🌟 1. 改以 Palo Alto 標準日誌型態特徵錨定，徹底相容所有 Synology NAS 匯出格式
			isTraffic := strings.Contains(line, ",TRAFFIC,")
			isThreat := strings.Contains(line, ",THREAT,")
			if !isTraffic && !isThreat {
				continue
			}

			// 尋找 Palo Alto 訊息本體的起始位置 (去除 Synology 的時間與主機前綴)
			idx := -1
			if isTraffic {
				trafficPos := strings.Index(line, ",TRAFFIC,")
				lastTab := strings.LastIndex(line[:trafficPos], "\t")
				if lastTab != -1 {
					idx = lastTab + 1
				} else {
					idx = strings.LastIndex(line[:trafficPos], " 1,20")
					if idx == -1 { idx = strings.LastIndex(line[:trafficPos], " ") }
					if idx != -1 { idx++ } else { idx = 0 }
				}
			} else {
				threatPos := strings.Index(line, ",THREAT,")
				lastTab := strings.LastIndex(line[:threatPos], "\t")
				if lastTab != -1 {
					idx = lastTab + 1
				} else {
					idx = strings.LastIndex(line[:threatPos], " 1,20")
					if idx == -1 { idx = strings.LastIndex(line[:threatPos], " ") }
					if idx != -1 { idx++ } else { idx = 0 }
				}
			}

			if idx < 0 || idx >= len(line) {
				continue
			}

			cleanCSVLine := strings.ReplaceAll(line[idx:], "\t", " ")
			parts := strings.Split(cleanCSVLine, ",")
			if len(parts) < 6 {
				continue
			}

			// 🌟 2. 動態定位 TYPE 欄位所在索引 (TRAFFIC 或 THREAT)
			typeIdx := -1
			var currentType string
			for pIdx, pVal := range parts {
				uVal := strings.ToUpper(strings.TrimSpace(pVal))
				if uVal == "TRAFFIC" {
					typeIdx = pIdx
					currentType = "traffic"
					break
				} else if uVal == "THREAT" {
					typeIdx = pIdx
					currentType = "threat"
					break
				}
			}

			if typeIdx == -1 || typeIdx+3 >= len(parts) {
				continue
			}

			// 🌟 關鍵補正：若前面缺少 Domain 欄位 (如 10-01 只有 2 欄即到 TRAFFIC)，自動在前方補 "1," 讓 117 欄標頭精確對齊！
			if typeIdx == 2 {
				cleanCSVLine = "1," + cleanCSVLine
				parts = strings.Split(cleanCSVLine, ",")
				typeIdx = 3
			}

			if logType != "" && logType != "all" && currentType != logType {
				continue
			}

			// 🌟 3. 在 Palo Alto 規範中，Generate Time 永遠在 Type 後面第 3 個欄位
			rawTime := strings.TrimSpace(parts[typeIdx+3])
			sub := strings.Split(rawTime, " ")
			if len(sub) == 0 {
				continue
			}
			dateKey := strings.ReplaceAll(sub[0], "/", "-")
			allDetectedDates[dateKey] = true

			validCounter++

			batchKey := fmt.Sprintf("%s_%s", currentType, dateKey)
			b, exists := batches[batchKey]
			if !exists {
				dayDir := filepath.Join(baseTmpDir, currentType, dateKey)
				_ = os.MkdirAll(dayDir, 0755)

				dayCsvPath := filepath.Join(dayDir, fmt.Sprintf("%s_%s.txt", currentType, dateKey))
				outF, createErr := os.Create(dayCsvPath)
				if createErr != nil {
					continue
				}

				base := trafficBaseHeaders
				if currentType == "threat" {
					base = threatBaseHeaders
				}
				headerCols := append([]string{}, base...)
				for len(headerCols) < len(parts) {
					headerCols = append(headerCols, fmt.Sprintf("extra_col_%d", len(headerCols)+1))
				}
				outF.WriteString(strings.Join(headerCols, ",") + "\n")

				b = &BatchTarget{
					LogType: currentType,
					Date:    dateKey,
					Dir:     dayDir,
					File:    outF,
					Count:   0,
				}
				batches[batchKey] = b

				globalNASProgress.addLog(fmt.Sprintf("📅 識別到分流目標: [%s] %s", strings.ToUpper(currentType), dateKey))
			}

			b.File.WriteString(cleanCSVLine + "\n")
			b.Count++
		}
		inFile.Close()
	}

	for _, b := range batches {
		_ = b.File.Close()
	}

	globalNASProgress.Lock()
	globalNASProgress.TotalLines = lineCounter
	globalNASProgress.ValidLines = validCounter
	globalNASProgress.Unlock()

	if len(batches) == 0 {
		var foundList []string
		for d := range allDetectedDates {
			foundList = append(foundList, d)
		}
		errMsg := fmt.Sprintf("所有檔案中皆未找到相符的日誌紀錄！偵測到的日期為：%s。", strings.Join(foundList, ", "))
		globalNASProgress.Lock()
		globalNASProgress.Stage = "error"
		globalNASProgress.Error = errMsg
		globalNASProgress.IsRunning = false
		globalNASProgress.Unlock()
		globalNASProgress.addLog("❌ 錯誤: " + errMsg)
		return
	}

	totalBatches := len(batches)
	globalNASProgress.Lock()
	globalNASProgress.Stage = "converting"
	globalNASProgress.TotalDays = totalBatches
	globalNASProgress.Percent = 40
	globalNASProgress.Unlock()

	globalNASProgress.addLog(fmt.Sprintf("📊 全部 %d 個檔案掃描完畢 (共 %d 行)，辨識出 %d 個獨立批次，開始逐批進行 DuckDB 轉換...",
		len(nasFilePaths), lineCounter, totalBatches))

	var sortedKeys []string
	for k := range batches {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	hasConvertError := false
	batchIndex := 0
	for _, k := range sortedKeys {
		b := batches[k]
		batchIndex++

		typeName := "流量 (Traffic)"
		if b.LogType == "threat" {
			typeName = "威脅 (Threat)"
		}

		globalNASProgress.Lock()
		globalNASProgress.CurrentDate = fmt.Sprintf("%s [%s]", b.Date, typeName)
		globalNASProgress.ProcessedDays = batchIndex - 1
		globalNASProgress.Percent = 40 + int(float64(batchIndex)/float64(totalBatches)*55)
		globalNASProgress.Unlock()

		globalNASProgress.addLog(fmt.Sprintf("⚡ [%d/%d] 正在建立 [%s %s] 的 Parquet 湖倉 (共 %d 筆紀錄)...",
			batchIndex, totalBatches, typeName, b.Date, b.Count))

		req := CLIExportRequest{
			Date:        b.Date,
			LogType:     b.LogType,
			FTPFolder:   b.Dir,
			ConvertOnly: true,
			SkipCold:    false,
		}

		err := performCLIExportAndConvert(req, func(format string, a ...any) {
			msg := strings.TrimSpace(fmt.Sprintf(format, a...))
			if msg != "" {
				globalNASProgress.addLog("  " + msg)
			}
		})

		if err != nil {
			hasConvertError = true
			globalNASProgress.addLog(fmt.Sprintf("  ❌ [%s %s] 轉換失敗: %v", typeName, b.Date, err))
		} else {
			globalNASProgress.addLog(fmt.Sprintf("  ✅ [%s %s] 落盤完成！", typeName, b.Date))
		}
	}

	// 🌟 全部檔案轉換完畢後，立即啟動自動去重合併
	if !hasConvertError {
		globalNASProgress.addLog("🔄 啟動背景 DuckDB 去重整併作業，將新舊資料無縫融合...")
		for d := range allDetectedDates {
			_ = consolidateDailyTraffic(d)
		}
		ConsolidateThreatParquetFiles()
		ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")
	}

	globalNASProgress.Lock()
	if hasConvertError {
		globalNASProgress.Stage = "error"
		globalNASProgress.Error = "部分日期的 DuckDB 轉檔作業失敗，請檢視上方詳細日誌。"
		globalNASProgress.IsRunning = false
	} else {
		globalNASProgress.Stage = "done"
		globalNASProgress.ProcessedDays = totalBatches
		globalNASProgress.Percent = 100
		globalNASProgress.IsRunning = false
	}
	globalNASProgress.Unlock()

	if hasConvertError {
		globalNASProgress.addLog("❌ 部分批次轉檔發生異常，請檢視上方詳細日誌。")
	} else {
		globalNASProgress.addLog(fmt.Sprintf("🎉 全部 %d 個檔案批次轉檔與整合作業全數圓滿完成！", len(nasFilePaths)))
	}
}

// 🌟 處理單一 NAS 上傳檔案 (讀取、即時切分至臨時 CSV，並呼叫 DuckDB 產生 Parquet)
func processSingleNASImport(filePath, fileName string, fileIdx, totalFiles int, logType string) (int, int, []string, error) {
	globalNASProgress.Lock()
	globalNASProgress.IsRunning = true
	globalNASProgress.Stage = "reading"
	globalNASProgress.FileName = fileName
	globalNASProgress.Unlock()

	globalNASProgress.addLog(fmt.Sprintf("📖 [%d/%d] 開始串流讀取檔案: %s", fileIdx, totalFiles, fileName))

	inFile, err := os.Open(filePath)
	if err != nil {
		globalNASProgress.addLog(fmt.Sprintf("❌ 無法開啟檔案 %s: %v", fileName, err))
		return 0, 0, nil, err
	}
	defer inFile.Close()

	baseTmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("nas_s_%d", time.Now().UnixNano()))
	_ = os.MkdirAll(baseTmpDir, 0755)
	defer os.RemoveAll(baseTmpDir)

	type BatchTarget struct {
		LogType string
		Date    string
		Dir     string
		File    *os.File
		Count   int
	}

	batches := make(map[string]*BatchTarget)

	lineCounter := 0
	validCounter := 0

	scanner := bufio.NewScanner(inFile)
	buf := make([]byte, 0, 4*1024*1024)
	scanner.Buffer(buf, 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		lineCounter++

		isTraffic := strings.Contains(line, ",TRAFFIC,")
		isThreat := strings.Contains(line, ",THREAT,")
		if !isTraffic && !isThreat {
			continue
		}

		idx := -1
		if isTraffic {
			trafficPos := strings.Index(line, ",TRAFFIC,")
			lastTab := strings.LastIndex(line[:trafficPos], "\t")
			if lastTab != -1 {
				idx = lastTab + 1
			} else {
				idx = strings.LastIndex(line[:trafficPos], " 1,20")
				if idx == -1 { idx = strings.LastIndex(line[:trafficPos], " ") }
				if idx != -1 { idx++ } else { idx = 0 }
			}
		} else {
			threatPos := strings.Index(line, ",THREAT,")
			lastTab := strings.LastIndex(line[:threatPos], "\t")
			if lastTab != -1 {
				idx = lastTab + 1
			} else {
				idx = strings.LastIndex(line[:threatPos], " 1,20")
				if idx == -1 { idx = strings.LastIndex(line[:threatPos], " ") }
				if idx != -1 { idx++ } else { idx = 0 }
			}
		}

		if idx < 0 || idx >= len(line) {
			continue
		}

		cleanCSVLine := strings.ReplaceAll(line[idx:], "\t", " ")
		parts := strings.Split(cleanCSVLine, ",")
		if len(parts) < 6 {
			continue
		}

		typeIdx := -1
		var currentType string
		for pIdx, pVal := range parts {
			uVal := strings.ToUpper(strings.TrimSpace(pVal))
			if uVal == "TRAFFIC" {
				typeIdx = pIdx
				currentType = "traffic"
				break
			} else if uVal == "THREAT" {
				typeIdx = pIdx
				currentType = "threat"
				break
			}
		}

		if typeIdx == -1 || typeIdx+3 >= len(parts) {
			continue
		}

		if typeIdx == 2 {
			cleanCSVLine = "1," + cleanCSVLine
			parts = strings.Split(cleanCSVLine, ",")
			typeIdx = 3
		}

		if logType != "" && logType != "all" && currentType != logType {
			continue
		}

		// 🌟 錨定 Generate Time (在 Type 後方第 3 個欄位)
		rawTime := strings.TrimSpace(parts[typeIdx+3])
		sub := strings.Split(rawTime, " ")
		if len(sub) == 0 {
			continue
		}
		dateKey := strings.ReplaceAll(sub[0], "/", "-")
		validCounter++

		batchKey := fmt.Sprintf("%s_%s", currentType, dateKey)
		b, exists := batches[batchKey]
		if !exists {
			dayDir := filepath.Join(baseTmpDir, currentType, dateKey)
			_ = os.MkdirAll(dayDir, 0755)

			dayCsvPath := filepath.Join(dayDir, fmt.Sprintf("%s_%s.csv", currentType, dateKey))
			outF, createErr := os.Create(dayCsvPath)
			if createErr != nil {
				continue
			}

			// 🌟 修正：不預寫固定欄位表頭，避免後續 DuckDB 發生欄位數不合而整批拋棄
			// 保持原始日誌格式，後續由 DuckDB split_part 直接精準提取各欄位

			b = &BatchTarget{
				LogType: currentType,
				Date:    dateKey,
				Dir:     dayDir,
				File:    outF,
				Count:   0,
			}
			batches[batchKey] = b
		}

		b.File.WriteString(cleanCSVLine + "\n")
		b.Count++
	}

	for _, b := range batches {
		_ = b.File.Close()
	}

	var generatedDates []string
	// 逐個日期批次呼叫 DuckDB 進行 Parquet 湖倉落盤
	for _, b := range batches {
		typeName := "流量 (Traffic)"
		if b.LogType == "threat" {
			typeName = "威脅 (Threat)"
		}

		globalNASProgress.addLog(fmt.Sprintf("  ⚡ 正在建立 [%s %s] 的 Parquet 湖倉 (共 %d 筆)...", typeName, b.Date, b.Count))

		req := CLIExportRequest{
			Date:        b.Date,
			LogType:     b.LogType,
			FTPFolder:   b.Dir,
			ConvertOnly: true,
			SkipCold:    false,
		}

		_ = performCLIExportAndConvert(req, func(format string, a ...any) {
			msg := strings.TrimSpace(fmt.Sprintf(format, a...))
			if msg != "" {
				globalNASProgress.addLog("    " + msg)
			}
		})

		generatedDates = append(generatedDates, b.Date)
	}

	globalNASProgress.addLog(fmt.Sprintf("✅ [%d/%d] %s 處理完成！(掃描 %d 行，有效歸檔 %d 筆)", fileIdx, totalFiles, fileName, lineCounter, validCounter))
	return lineCounter, validCounter, generatedDates, nil
}

// -------------------------------------------------------------
// 🌟 資安預警 6 大靈敏度閥值設定結構與 SQLite 存取
// -------------------------------------------------------------
type SecuritySettings struct {
	WindowMins             int `json:"window_mins"`              // 1. 分析時間視窗 (分鐘)
	PortScanThreshold      int `json:"port_scan_threshold"`      // 2. Port Scan 連線埠門檻
	DDoSMBThreshold        int `json:"ddos_mb_threshold"`        // 3. DDoS 洪泛流量門檻 (MB)
	BruteForceThreshold    int `json:"brute_force_threshold"`    // 4. 密碼暴力破解次數門檻
	DataExfilThreshold     int `json:"data_exfil_threshold"`     // 5. 異常巨量外洩流量門檻 (MB)
	MiningPoolThreshold    int `json:"mining_pool_threshold"`    // 6. 採礦木馬外部連線門檻
	LateralSpreadThreshold int `json:"lateral_spread_threshold"` // 7. 內網橫向擴散主機數門檻
}

// 從 SQLite 讀取設定 (若無設定則給予預設值)
func getSecuritySettings(db *sql.DB) SecuritySettings {
	cfg := SecuritySettings{
		WindowMins:             5,
		PortScanThreshold:      50,
		DDoSMBThreshold:        300,
		BruteForceThreshold:    30,
		DataExfilThreshold:     500,
		MiningPoolThreshold:    20,
		LateralSpreadThreshold: 15,
	}
	if db == nil {
		return cfg
	}

	rows, err := db.Query("SELECT key, value FROM flow_security_settings")
	if err != nil {
		return cfg
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			val, _ := strconv.Atoi(v)
			if val <= 0 && k != "window_mins" {
				continue
			}
			switch k {
			case "window_mins":
				if val > 0 { cfg.WindowMins = val }
			case "port_scan_threshold":
				if val > 0 { cfg.PortScanThreshold = val }
			case "ddos_mb_threshold":
				if val > 0 { cfg.DDoSMBThreshold = val }
			case "brute_force_threshold":
				if val > 0 { cfg.BruteForceThreshold = val }
			case "data_exfil_threshold":
				if val > 0 { cfg.DataExfilThreshold = val }
			case "mining_pool_threshold":
				if val > 0 { cfg.MiningPoolThreshold = val }
			case "lateral_spread_threshold":
				if val > 0 { cfg.LateralSpreadThreshold = val }
			}
		}
	}
	return cfg
}

// 儲存設定至 SQLite (持久化靜態儲存)
func saveSecuritySettings(db *sql.DB, s SecuritySettings) error {
	if db == nil {
		return errors.New("db is nil")
	}
	if s.WindowMins <= 0 { s.WindowMins = 5 }
	if s.PortScanThreshold <= 0 { s.PortScanThreshold = 50 }
	if s.DDoSMBThreshold <= 0 { s.DDoSMBThreshold = 300 }
	if s.BruteForceThreshold <= 0 { s.BruteForceThreshold = 30 }
	if s.DataExfilThreshold <= 0 { s.DataExfilThreshold = 500 }
	if s.MiningPoolThreshold <= 0 { s.MiningPoolThreshold = 20 }
	if s.LateralSpreadThreshold <= 0 { s.LateralSpreadThreshold = 15 }

	items := map[string]int{
		"window_mins":              s.WindowMins,
		"port_scan_threshold":      s.PortScanThreshold,
		"ddos_mb_threshold":        s.DDoSMBThreshold,
		"brute_force_threshold":    s.BruteForceThreshold,
		"data_exfil_threshold":     s.DataExfilThreshold,
		"mining_pool_threshold":    s.MiningPoolThreshold,
		"lateral_spread_threshold": s.LateralSpreadThreshold,
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range items {
		_, err := tx.Exec("INSERT OR REPLACE INTO flow_security_settings (key, value) VALUES (?, ?)", k, strconv.Itoa(v))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// 🌟 啟動 PA-1420 專屬資安威脅自動分析引擎 (動態閥值版)
func startFlowSecurityWorker() {
	go func() {
		time.Sleep(5 * time.Second) // 開機暖機
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			todayStr := time.Now().Format("2006-01-02")
			trafficPattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", todayStr)))
			threatPattern := filepath.ToSlash(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", todayStr)))

			db, err := initDB()
			if err != nil {
				continue
			}

			// 🌟 動態從 SQLite 取得目前使用者設定之最新閥值
			cfg := getSecuritySettings(db)

			// ── 威脅 1: Palo Alto 原生重大威脅同步 (Critical / High) ──
			threatFiles, _ := filepath.Glob(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", todayStr)))
			if len(threatFiles) > 0 {
				sqlThreat := fmt.Sprintf(`
					SELECT timestamp, src, dst, threat_name, severity, action
					FROM read_parquet('%s')
					WHERE LOWER(severity) IN ('critical', 'high')
					ORDER BY timestamp DESC
				`, threatPattern)
				if tRows, err := runDuckDBQuery(sqlThreat); err == nil {
					for _, tr := range tRows {
						ts := fmt.Sprintf("%v", tr["timestamp"])
						src := fmt.Sprintf("%v", tr["src"])
						dst := fmt.Sprintf("%v", tr["dst"])
						tName := fmt.Sprintf("%v", tr["threat_name"])
						sev := strings.ToUpper(fmt.Sprintf("%v", tr["severity"]))
						details := fmt.Sprintf("Palo Alto 防火牆阻擋事件: %s (動作: %v)", tName, tr["action"])
						recordSecurityAlertWithTime(db, ts, src, dst, "NGFW 重大威脅", sev, details)
					}
				}
			}

			// 確保當日流量檔案存在，再執行行為閥值檢測
			tFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", todayStr)))
			if len(tFiles) == 0 {
				continue
			}

			// 以最新時間戳記倒推分析視窗 (分鐘)
			var refTime time.Time
			maxTSQL := fmt.Sprintf(`SELECT MAX(timestamp) as max_t FROM read_parquet('%s')`, trafficPattern)
			if mRows, err := runDuckDBQuery(maxTSQL); err == nil && len(mRows) > 0 && mRows[0]["max_t"] != nil {
				if tStr, ok := mRows[0]["max_t"].(string); ok && len(tStr) >= 19 {
					refTime, _ = time.Parse("2006-01-02 15:04:05", tStr[:19])
				}
			}
			if refTime.IsZero() { refTime = time.Now() }
			timeThreshold := refTime.Add(-time.Duration(cfg.WindowMins) * time.Minute).Format("2006-01-02 15:04:05")

			// ── 威脅 2: Port Scan 掃描探測 ──
			sqlScan := fmt.Sprintf(`
				SELECT source, COUNT(DISTINCT to_port) as p_count 
				FROM read_parquet('%s') 
				WHERE timestamp >= '%s' 
				GROUP BY source HAVING p_count >= %d
			`, trafficPattern, timeThreshold, cfg.PortScanThreshold)
			if rows, err := runDuckDBQuery(sqlScan); err == nil {
				for _, r := range rows {
					src := fmt.Sprintf("%v", r["source"])
					cnt := parseDuckDBNumber(r["p_count"])
					details := fmt.Sprintf("警報：主機 [%s] 於 %d 分鐘內探測了 %d 個不同 Port", src, cfg.WindowMins, cnt)
					recordSecurityAlert(db, src, "WAN/LAN", "Port 掃描探測", "HIGH", details)
				}
			}

			// ── 威脅 3: DDoS / 殭屍網路洪泛 (修正：僅偵測外部打進內網 WAN ➔ LAN) ──
			sqlDDoS := fmt.Sprintf(`
				SELECT destination, COUNT(DISTINCT source) as src_count, round(SUM(bytes)/1048576.0, 2) as mb_size
				FROM read_parquet('%s')
				WHERE timestamp >= '%s' 
				  AND from_zone = 'WAN' AND to_zone = 'LAN'
				GROUP BY destination HAVING src_count >= 10 AND mb_size >= %d
			`, trafficPattern, timeThreshold, cfg.DDoSMBThreshold)
			if rows, err := runDuckDBQuery(sqlDDoS); err == nil {
				for _, r := range rows {
					dst := fmt.Sprintf("%v", r["destination"])
					cnt := parseDuckDBNumber(r["src_count"])
					details := fmt.Sprintf("警報：內網目標 [%s] 遭 %d 個外部來源密集攻擊，累積流量達 %v MB", dst, cnt, r["mb_size"])
					recordSecurityAlert(db, "Botnet External WANs", dst, "DDoS / 殭屍網路洪泛", "CRITICAL", details)
				}
			}

			// ── 威脅 4: 密碼暴力破解猜測 ──
			sqlBrute := fmt.Sprintf(`
				SELECT source, destination, to_port, COUNT(*) as cnt
				FROM read_parquet('%s')
				WHERE timestamp >= '%s' AND to_port IN (22, 3389, 445, 23)
				GROUP BY source, destination, to_port HAVING cnt >= %d
			`, trafficPattern, timeThreshold, cfg.BruteForceThreshold)
			if rows, err := runDuckDBQuery(sqlBrute); err == nil {
				for _, r := range rows {
					src := fmt.Sprintf("%v", r["source"])
					dst := fmt.Sprintf("%v", r["destination"])
					p := r["to_port"]
					cnt := parseDuckDBNumber(r["cnt"])
					details := fmt.Sprintf("警報：來源 [%s] 對 [%s:Port %v] 發起 %d 次密集連線嘗試", src, dst, p, cnt)
					recordSecurityAlert(db, src, dst, "密碼暴力破解猜測", "HIGH", details)
				}
			}

			// ── 威脅 5: 異常巨量資料外洩 (LAN ➔ WAN) ──
			sqlExfil := fmt.Sprintf(`
				SELECT source, destination, round(SUM(bytes)/1048576.0, 2) as mb_size
				FROM read_parquet('%s')
				WHERE timestamp >= '%s' AND from_zone = 'LAN' AND to_zone = 'WAN'
				GROUP BY source, destination HAVING mb_size >= %d
			`, trafficPattern, timeThreshold, cfg.DataExfilThreshold)
			if rows, err := runDuckDBQuery(sqlExfil); err == nil {
				for _, r := range rows {
					src := fmt.Sprintf("%v", r["source"])
					dst := fmt.Sprintf("%v", r["destination"])
					details := fmt.Sprintf("警報：內網主機 [%s] 向外部 IP [%s] 上傳了 %v MB 巨量資料", src, dst, r["mb_size"])
					recordSecurityAlert(db, src, dst, "異常巨量資料外洩", "HIGH", details)
				}
			}

			// ── 威脅 6: 內網橫向擴散移動 ──
			sqlLateral := fmt.Sprintf(`
				SELECT source, COUNT(DISTINCT destination) as target_cnt
				FROM read_parquet('%s')
				WHERE timestamp >= '%s' AND from_zone = 'LAN' AND to_zone = 'LAN' AND to_port IN (445, 135, 3389, 5985)
				GROUP BY source HAVING target_cnt >= %d
			`, trafficPattern, timeThreshold, cfg.LateralSpreadThreshold)
			if rows, err := runDuckDBQuery(sqlLateral); err == nil {
				for _, r := range rows {
					src := fmt.Sprintf("%v", r["source"])
					cnt := parseDuckDBNumber(r["target_cnt"])
					details := fmt.Sprintf("警報：內網主機 [%s] 於 %d 分鐘內對內部 %d 台設備發動橫向高危埠探測", src, cfg.WindowMins, cnt)
					recordSecurityAlert(db, src, "LAN 內部多主機", "內網橫向擴散移動", "HIGH", details)
				}
			}

			// ── 威脅 7: 採礦木馬 (連線外部礦池) ──
			sqlMining := fmt.Sprintf(`
				SELECT source, destination, to_port, COUNT(*) as cnt
				FROM read_parquet('%s')
				WHERE timestamp >= '%s' AND (to_port IN (3333, 5555, 7777, 9999, 14444, 4444, 8333, 18080) OR application ILIKE '%%miner%%' OR application ILIKE '%%stratum%%')
				GROUP BY source, destination, to_port HAVING cnt >= %d
			`, trafficPattern, timeThreshold, cfg.MiningPoolThreshold)
			if rows, err := runDuckDBQuery(sqlMining); err == nil {
				for _, r := range rows {
					src := fmt.Sprintf("%v", r["source"])
					dst := fmt.Sprintf("%v", r["destination"])
					p := r["to_port"]
					cnt := parseDuckDBNumber(r["cnt"])
					details := fmt.Sprintf("警報：內網主機 [%s] 疑似連線至外部礦池 [%s:Port %v] 達 %d 次", src, dst, p, cnt)
					recordSecurityAlert(db, src, dst, "疑似採礦木馬連線", "HIGH", details)
				}
			}
		}
	}()
}

// 寫入預警防重複機制 (帶有日誌真實時間戳記)
func recordSecurityAlertWithTime(db *sql.DB, logTime, src, dst, attackType, severity, details string) {
	var count int
	_ = db.QueryRow(`
		SELECT COUNT(*) FROM flow_security_events 
		WHERE timestamp = ? AND src_ip = ? AND attack_type = ?
	`, logTime, src, attackType).Scan(&count)

	if count == 0 {
		_, _ = db.Exec(`
			INSERT INTO flow_security_events (timestamp, src_ip, dst_ip, attack_type, severity, details)
			VALUES (?, ?, ?, ?, ?, ?)
		`, logTime, src, dst, attackType, severity, details)
	}
}

// 寫入預警防重複機制 (5 分鐘內同 IP、同攻擊型態不重複推播)
func recordSecurityAlert(db *sql.DB, src, dst, attackType, severity, details string) {
	var count int
	_ = db.QueryRow(`
		SELECT COUNT(*) FROM flow_security_events 
		WHERE src_ip = ? AND attack_type = ? AND timestamp >= datetime('now', '-5 minutes')
	`, src, attackType).Scan(&count)

	if count == 0 {
		_, _ = db.Exec(`
			INSERT INTO flow_security_events (src_ip, dst_ip, attack_type, severity, details)
			VALUES (?, ?, ?, ?, ?)
		`, src, dst, attackType, severity, details)
	}
}

// 🌟 向 PA-1420 擷取 System 日誌 API (支援過濾)
func fetchPASystemLogsWithFilter(count int, filter string) ([]SystemEntry, error) {
	if count <= 0 { count = 5000 }
	if count > 5000 { count = 5000 }

	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil {
		return nil, err
	}

	var apiURL string
	if filter != "" {
		escapedFilter := strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=system&nlogs=%d&query=%s&key=%s", fwIP, count, escapedFilter, apiKey)
	} else {
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=system&nlogs=%d&key=%s", fwIP, count, apiKey)
	}

	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("發起 System 查詢失敗: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 {
		return nil, errors.New("無法取得 System Log Job ID")
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
		return nil, errors.New("查詢 System 日誌逾時")
	}

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []SystemEntry
	for {
		token, err := decoder.Token()
		if err != nil { break }
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e SystemEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.TimeGenerated), "/", "-")
				if e.TimeGenerated == "" {
					e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-")
				}
				if e.Description == "" && e.Opaque != "" {
					e.Description = e.Opaque
				}
				entries = append(entries, e)
			}
		}
	}
	return entries, nil
}

// 🌟 System API 碎片隔離寫入引擎 (防止自比對誤殺)
func saveSystemLogsToParquet(entries []SystemEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	systemFileMutex.Lock()
	defer systemFileMutex.Unlock()

	var rawRows []RawLogParquetRow
	entriesByDate := make(map[string][]SystemParquetRow)

	for _, e := range entries {
		ts := strings.TrimSpace(e.TimeGenerated)
		if ts == "" { ts = strings.TrimSpace(e.ReceiveTime) }
		ts = strings.ReplaceAll(ts, "/", "-")

		desc := strings.TrimSpace(e.Description)
		if desc == "" { desc = strings.TrimSpace(e.Opaque) }

		row := SystemParquetRow{
			Timestamp:   ts,
			Subtype:     strings.TrimSpace(e.Subtype),
			Severity:    strings.ToLower(strings.TrimSpace(e.Severity)),
			EventID:     strings.TrimSpace(e.EventID),
			Object:      strings.TrimSpace(e.Object),
			Description: desc,
		}

		recordDate := time.Now().Format("2006-01-02")
		if len(row.Timestamp) >= 10 {
			recordDate = row.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], row)

		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  e.EventID,
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
	}

	if len(rawRows) > 0 {
		go func(r []RawLogParquetRow) {
			_ = saveRawLogBatchFast("system", r)
		}(rawRows)
	}

	totalInserted := 0
	totalToday := 0
	todayStr := time.Now().Format("2006-01-02")

	for dateKey, newRows := range entriesByDate {
		if len(newRows) == 0 { continue }

		tmpDir := filepath.Join(systemDir, ".tmp")
		_ = os.MkdirAll(tmpDir, 0755)

		tmpChunkPath := filepath.Join(tmpDir, fmt.Sprintf("check_%s_%d.parquet", dateKey, time.Now().UnixNano()))
		if err := parquet.WriteFile(tmpChunkPath, newRows); err != nil {
			continue
		}

		minT := newRows[0].Timestamp
		maxT := newRows[0].Timestamp
		for _, r := range newRows {
			if r.Timestamp < minT { minT = r.Timestamp }
			if r.Timestamp > maxT { maxT = r.Timestamp }
		}

		existingPattern := filepath.ToSlash(filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", dateKey)))
		allExisting, _ := filepath.Glob(filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", dateKey)))

		var validExisting []string
		for _, f := range allExisting {
			if !strings.HasSuffix(f, ".tmp") && !strings.Contains(f, "check_") {
				validExisting = append(validExisting, f)
			}
		}

		var actualNewCount int = len(newRows)

		if len(validExisting) > 0 {
			checkSQL := fmt.Sprintf(`
				SELECT COUNT(*) as new_cnt 
				FROM read_parquet('%s') t
				WHERE NOT EXISTS (
					SELECT 1 FROM read_parquet('%s', union_by_name=true) m
					WHERE m.timestamp >= '%s' AND m.timestamp <= '%s'
					  AND COALESCE(m.timestamp, '') = COALESCE(t.timestamp, '')
					  AND COALESCE(m.subtype, '') = COALESCE(t.subtype, '')
					  AND COALESCE(m.severity, '') = COALESCE(t.severity, '')
					  AND COALESCE(m.event_id, '') = COALESCE(t.event_id, '')
					  AND COALESCE(m.description, '') = COALESCE(t.description, '')
				)
			`, filepath.ToSlash(tmpChunkPath), existingPattern, minT, maxT)

			if res, err := runDuckDBQuery(checkSQL); err == nil && len(res) > 0 {
				actualNewCount = int(parseDuckDBNumber(res[0]["new_cnt"]))
			}
		}

		if actualNewCount == 0 {
			_ = os.Remove(tmpChunkPath)
		} else {
			finalChunkPath := filepath.Join(systemDir, fmt.Sprintf("system_%s_api_%d.parquet", dateKey, time.Now().UnixNano()))
			_ = os.Rename(tmpChunkPath, finalChunkPath)
			go ConsolidateSystemParquetFiles()
			go ConsolidateRawParquetFiles("system") // 👈 🌟 同步即時整併系統冷資料
		}

		totalInserted += actualNewCount
		if dateKey == todayStr {
			totalToday += actualNewCount
		}
	}

	return totalInserted, totalToday, nil
}

// 🌟 System Parquet 多檔自動去重整併器 (DuckDB 向量化引擎)
func ConsolidateSystemParquetFiles() (int, int, error) {
	systemFileMutex.Lock()
	defer systemFileMutex.Unlock()

	entries, err := os.ReadDir(systemDir)
	if err != nil { return 0, 0, err }

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`system_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") { continue }
		if m := re.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateFiles[m[1]] = append(dateFiles[m[1]], filepath.Join(systemDir, e.Name()))
		}
	}

	totalMergedFiles := 0

	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(systemDir, fmt.Sprintf("system_%s.parquet", dateKey))
		if len(files) == 1 && files[0] == targetMainFile { continue }

		tmpFile := targetMainFile + ".tmp"
		globPath := filepath.ToSlash(filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", dateKey)))
		tmpSlash := filepath.ToSlash(tmpFile)

		copyQuery := fmt.Sprintf(`
			COPY (
				SELECT timestamp, subtype, severity, event_id, object, description
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY timestamp, subtype, severity, event_id, description 
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
		} else {
			_ = os.Remove(tmpFile)
		}
	}

	return totalMergedFiles, 0, nil
}

// 🌟 系統日誌 DuckDB 向量化高速檢索函式
func querySystemAnalytics(queryDate, subtype, severity, eventID, keyword string, page, perPage int, onlyLogs bool) (*SystemAnalyticsResult, error) {
	queryDate = strings.ReplaceAll(strings.TrimSpace(queryDate), "/", "-")
	if queryDate == "" { queryDate = time.Now().Format("2006-01-02") }
	if page < 1 { page = 1 }
	if perPage < 1 { perPage = 50 }

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ {
		emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0}
	}

	pattern := filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", queryDate))
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
		return &SystemAnalyticsResult{
			TotalLogs: 0, ImportantLogs: 0, TopSubtype: "-", TopEvent: "-",
			DbSize: "0 B", Histogram: emptyHistogram, Logs: make([]SystemLogItem, 0), CurrentPage: 1, TotalPages: 1,
		}, nil
	}

	duckdbPattern := filepath.ToSlash(pattern)
	var conds []string
	conds = append(conds, "1=1")
	if subtype != "" && strings.ToLower(subtype) != "all" {
		conds = append(conds, fmt.Sprintf("LOWER(subtype) = '%s'", strings.ToLower(strings.ReplaceAll(subtype, "'", "''"))))
	}
	if severity != "" && strings.ToLower(severity) != "all" {
		s := strings.ToLower(severity)
		if s == "important" {
			// 🌟 點擊卡片時：同時篩選 critical、high 與 medium
			conds = append(conds, "LOWER(severity) IN ('critical', 'high', 'medium')")
		} else {
			conds = append(conds, fmt.Sprintf("LOWER(severity) = '%s'", s))
		}
	}
	if eventID != "" {
		conds = append(conds, fmt.Sprintf("event_id ILIKE '%%%s%%'", strings.ReplaceAll(eventID, "'", "''")))
	}
	if keyword != "" {
		kw := strings.ReplaceAll(keyword, "'", "''")
		conds = append(conds, fmt.Sprintf("(description ILIKE '%%%s%%' OR object ILIKE '%%%s%%')", kw, kw))
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
					COUNT(*) AS total_logs,
					COALESCE(SUM(CASE WHEN LOWER(severity) IN ('critical', 'high', 'medium') THEN 1 ELSE 0 END), 0) AS important_logs,
					MODE(subtype) AS top_subtype,
					MODE(event_id) AS top_event
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

	var totalLogs, importantLogs int
	topSubtype := "-"
	topEvent := "-"

	if !onlyLogs && len(statsRes) > 0 {
		totalLogs = int(parseDuckDBNumber(statsRes[0]["total_logs"]))
		importantLogs = int(parseDuckDBNumber(statsRes[0]["important_logs"]))
		if v, ok := statsRes[0]["top_subtype"].(string); ok && v != "" { topSubtype = v }
		if v, ok := statsRes[0]["top_event"].(string); ok && v != "" { topEvent = v }
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

	safeGet := func(m map[string]interface{}, key string) string {
		if v, ok := m[key]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" { return s }
		}
		return ""
	}

	logs := make([]SystemLogItem, 0, len(logsRes))
	for _, r := range logsRes {
		logs = append(logs, SystemLogItem{
			Timestamp:   safeGet(r, "timestamp"),
			Subtype:     safeGet(r, "subtype"),
			Severity:    strings.ToLower(safeGet(r, "severity")),
			EventID:     safeGet(r, "event_id"),
			Object:      safeGet(r, "object"),
			Description: safeGet(r, "description"),
		})
	}

	totalPages := int(math.Ceil(float64(totalLogs) / float64(perPage)))
	if totalPages == 0 { totalPages = 1 }

	return &SystemAnalyticsResult{
		TotalLogs:     totalLogs,
		ImportantLogs: importantLogs,
		TopSubtype:    topSubtype,
		TopEvent:      topEvent,
		DbSize:        dbSizeStr,
		Histogram:     emptyHistogram,
		Logs:          logs,
		CurrentPage:   page,
		TotalPages:    totalPages,
	}, nil
}

// 🌟 向 PA-1420 擷取 Config 日誌 API (支援過濾)
func fetchPAConfigLogsWithFilter(count int, filter string) ([]ConfigEntry, error) {
	if count <= 0 { count = 5000 }
	if count > 5000 { count = 5000 }

	fwIP, _, apiKey, _, err := getPAConfig()
	if err != nil { return nil, err }

	var apiURL string
	if filter != "" {
		escapedFilter := strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=config&nlogs=%d&query=%s&key=%s", fwIP, count, escapedFilter, apiKey)
	} else {
		apiURL = fmt.Sprintf("https://%s/api/?type=log&log-type=config&nlogs=%d&key=%s", fwIP, count, apiKey)
	}

	resp, err := httpClient.Get(apiURL)
	if err != nil { return nil, fmt.Errorf("發起 Config 查詢失敗: %w", err) }
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reJob := regexp.MustCompile(`<job>(\d+)</job>`)
	mJob := reJob.FindSubmatch(body)
	if len(mJob) < 2 { return nil, errors.New("無法取得 Config Log Job ID") }
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
	if pollBody == nil { return nil, errors.New("查詢 Config 日誌逾時") }

	decoder := xml.NewDecoder(bytes.NewReader(pollBody))
	var entries []ConfigEntry
	for {
		token, err := decoder.Token()
		if err != nil { break }
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
			var e ConfigEntry
			if err := decoder.DecodeElement(&e, &se); err == nil {
				e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.TimeGenerated), "/", "-")
				if e.TimeGenerated == "" { e.TimeGenerated = strings.ReplaceAll(strings.TrimSpace(e.ReceiveTime), "/", "-") }
				entries = append(entries, e)
			}
		}
	}
	return entries, nil
}

// 🌟 Config API 碎片隔離寫入引擎 (雙重標籤 + 正則保險版)
func saveConfigLogsToParquet(entries []ConfigEntry) (int, int, error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}

	configFileMutex.Lock()
	defer configFileMutex.Unlock()

	var rawRows []RawLogParquetRow
	entriesByDate := make(map[string][]ConfigParquetRow)

	for _, e := range entries {
		ts := strings.TrimSpace(e.TimeGenerated)
		if ts == "" {
			ts = strings.TrimSpace(e.ReceiveTime)
		}
		ts = strings.ReplaceAll(ts, "/", "-")

		// 1. 主機 IP (Host) 與 用戶端 (Web/CLI) 對齊
		hostIP := strings.TrimSpace(e.Host)
		if hostIP == "" {
			hostIP = strings.TrimSpace(e.ClientIP)
		}
		clientApp := strings.TrimSpace(e.Client)
		if hostIP == "" && (strings.Contains(clientApp, ".") || strings.Contains(clientApp, ":")) {
			hostIP = clientApp
			clientApp = "Web"
		}

		// 2. FULL PATH 取值
		fullPath := strings.TrimSpace(e.FullPath1)
		if fullPath == "" { fullPath = strings.TrimSpace(e.FullPath2) }
		if fullPath == "" { fullPath = strings.TrimSpace(e.XPath) }

		// 3. 變更前 (Before) 取值：優先 Struct 解析，若為空由 RawXML 正則保底
		beforeChange := strings.TrimSpace(e.Before1)
		if beforeChange == "" { beforeChange = strings.TrimSpace(e.Before2) }
		if beforeChange == "" { beforeChange = strings.TrimSpace(e.Before3) }
		if beforeChange == "" { beforeChange = strings.TrimSpace(e.Before4) }
		if beforeChange == "" {
			beforeChange = extractConfigDiff(e.RawXML, "before")
		}

		// 4. 變更後 (After) 取值：優先 Struct 解析，若為空由 RawXML 正則保底
		afterChange := strings.TrimSpace(e.After1)
		if afterChange == "" { afterChange = strings.TrimSpace(e.After2) }
		if afterChange == "" { afterChange = strings.TrimSpace(e.After3) }
		if afterChange == "" { afterChange = strings.TrimSpace(e.After4) }
		if afterChange == "" {
			afterChange = extractConfigDiff(e.RawXML, "after")
		}

		row := ConfigParquetRow{
			Timestamp:    ts,
			Admin:        strings.TrimSpace(e.Admin),
			Client:       hostIP,
			ClientApp:    clientApp,
			Command:      strings.TrimSpace(e.Command),
			Result:       strings.TrimSpace(e.Result),
			ConfigPath:   strings.TrimSpace(e.Path),
			FullPath:     fullPath,
			BeforeChange: beforeChange,
			AfterChange:  afterChange,
			SequenceNO:   strings.TrimSpace(e.SequenceNO),
		}

		recordDate := time.Now().Format("2006-01-02")
		if len(row.Timestamp) >= 10 {
			recordDate = row.Timestamp[:10]
		}
		entriesByDate[recordDate] = append(entriesByDate[recordDate], row)

		if strings.TrimSpace(e.RawXML) != "" {
			rawRows = append(rawRows, RawLogParquetRow{
				Timestamp:  ts,
				SessionID:  row.SequenceNO,
				RawContent: "<entry>" + e.RawXML + "</entry>",
			})
		}
	}

	if len(rawRows) > 0 {
		go func(r []RawLogParquetRow) {
			_ = saveRawLogBatchFast("config", r)
		}(rawRows)
	}

	totalInserted := 0
	totalToday := 0
	todayStr := time.Now().Format("2006-01-02")

	for dateKey, newRows := range entriesByDate {
		if len(newRows) == 0 {
			continue
		}

		tmpDir := filepath.Join(configDir, ".tmp")
		_ = os.MkdirAll(tmpDir, 0755)
		tmpChunkPath := filepath.Join(tmpDir, fmt.Sprintf("check_%s_%d.parquet", dateKey, time.Now().UnixNano()))
		if err := parquet.WriteFile(tmpChunkPath, newRows); err != nil {
			continue
		}

		minT := newRows[0].Timestamp
		maxT := newRows[0].Timestamp
		for _, r := range newRows {
			if r.Timestamp < minT { minT = r.Timestamp }
			if r.Timestamp > maxT { maxT = r.Timestamp }
		}

		existingPattern := filepath.ToSlash(filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", dateKey)))
		allExisting, _ := filepath.Glob(filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", dateKey)))
		var validExisting []string
		for _, f := range allExisting {
			if !strings.HasSuffix(f, ".tmp") && !strings.Contains(f, "check_") {
				validExisting = append(validExisting, f)
			}
		}

		actualNewCount := len(newRows)
		if len(validExisting) > 0 {
			checkSQL := fmt.Sprintf(`
				SELECT COUNT(*) as new_cnt 
				FROM read_parquet('%s') t
				WHERE NOT EXISTS (
					SELECT 1 FROM read_parquet('%s', union_by_name=true) m
					WHERE m.timestamp >= '%s' AND m.timestamp <= '%s'
					  AND COALESCE(m.timestamp, '') = COALESCE(t.timestamp, '')
					  AND COALESCE(m.admin, '') = COALESCE(t.admin, '')
					  AND COALESCE(m.sequence_no, '') = COALESCE(t.sequence_no, '')
				)
			`, filepath.ToSlash(tmpChunkPath), existingPattern, minT, maxT)
			if res, err := runDuckDBQuery(checkSQL); err == nil && len(res) > 0 {
				actualNewCount = int(parseDuckDBNumber(res[0]["new_cnt"]))
			}
		}

		if actualNewCount == 0 {
			_ = os.Remove(tmpChunkPath)
		} else {
			finalChunkPath := filepath.Join(configDir, fmt.Sprintf("config_%s_api_%d.parquet", dateKey, time.Now().UnixNano()))
			_ = os.Rename(tmpChunkPath, finalChunkPath)
			go ConsolidateConfigParquetFiles()
			go ConsolidateRawParquetFiles("config")
		}

		totalInserted += actualNewCount
		if dateKey == todayStr {
			totalToday += actualNewCount
		}
	}

	return totalInserted, totalToday, nil
}

// 🌟 Config Parquet 自動整併器
func ConsolidateConfigParquetFiles() (int, int, error) {
	configFileMutex.Lock()
	defer configFileMutex.Unlock()

	entries, err := os.ReadDir(configDir)
	if err != nil { return 0, 0, err }

	dateFiles := make(map[string][]string)
	re := regexp.MustCompile(`config_(\d{4}-\d{2}-\d{2})`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") || strings.HasSuffix(e.Name(), ".tmp") { continue }
		if m := re.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateFiles[m[1]] = append(dateFiles[m[1]], filepath.Join(configDir, e.Name()))
		}
	}

	totalMerged := 0
	for dateKey, files := range dateFiles {
		targetMainFile := filepath.Join(configDir, fmt.Sprintf("config_%s.parquet", dateKey))
		if len(files) == 1 && files[0] == targetMainFile { continue }

		tmpFile := targetMainFile + ".tmp"
		globPath := filepath.ToSlash(filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", dateKey)))
		tmpSlash := filepath.ToSlash(tmpFile)

		copyQuery := fmt.Sprintf(`
			COPY (
				SELECT timestamp, admin, client, client_app, command, result, config_path, full_path, before_change, after_change, sequence_no
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY timestamp, admin, sequence_no 
						ORDER BY timestamp DESC
					) as row_num
					FROM read_parquet('%s', union_by_name=true)
					WHERE (COALESCE(admin, '') != '' OR COALESCE(command, '') != '') -- 👈 🌟 物理剔除幽靈行
				) WHERE row_num = 1
				ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, globPath, tmpSlash)

		if _, err := runDuckDBQuery(copyQuery); err != nil {
			_ = os.Remove(tmpFile)
			continue
		}
		_ = os.Remove(targetMainFile)
		if err := os.Rename(tmpFile, targetMainFile); err == nil {
			for _, f := range files {
				if f != targetMainFile { _ = os.Remove(f); totalMerged++ }
			}
		} else { _ = os.Remove(tmpFile) }
	}
	return totalMerged, 0, nil
}

// 🌟 Config DuckDB 檢索函式
func queryConfigAnalytics(queryDate, admin, clientIP, keyword string, page, perPage int) (*ConfigAnalyticsResult, error) {
	queryDate = strings.ReplaceAll(strings.TrimSpace(queryDate), "/", "-")
	if queryDate == "" { queryDate = time.Now().Format("2006-01-02") }
	if page < 1 { page = 1 }
	if perPage < 1 { perPage = 50 }

	emptyHistogram := make([]HistogramBucket, 24)
	for h := 0; h < 24; h++ { emptyHistogram[h] = HistogramBucket{TimeBucket: fmt.Sprintf("%02d:00", h), Count: 0} }

	pattern := filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", queryDate))
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
	if totalFileSize >= 1024*1024*1024 { dbSizeStr = fmt.Sprintf("%.2f GB", float64(totalFileSize)/(1024*1024*1024))
	} else if totalFileSize >= 1024*1024 { dbSizeStr = fmt.Sprintf("%.2f MB", float64(totalFileSize)/(1024*1024))
	} else if totalFileSize >= 1024 { dbSizeStr = fmt.Sprintf("%.1f KB", float64(totalFileSize)/1024)
	} else { dbSizeStr = fmt.Sprintf("%d B", totalFileSize) }

	if !hasFiles {
		return &ConfigAnalyticsResult{
			TotalLogs: 0, TopAdmin: "-", TopCommand: "-",
			DbSize: "0 B", Histogram: emptyHistogram, Logs: make([]ConfigLogItem, 0), CurrentPage: 1, TotalPages: 1,
		}, nil
	}

	duckdbPattern := filepath.ToSlash(pattern)
	var conds []string
	conds = append(conds, "1=1")
	// 🌟 即使舊檔案裡有幽靈行，查詢時也絕不讀出、絕不統計
	conds = append(conds, "(COALESCE(admin, '') != '' OR COALESCE(command, '') != '')")
	
	if admin != "" { conds = append(conds, fmt.Sprintf("admin ILIKE '%%%s%%'", strings.ReplaceAll(admin, "'", "''"))) }
	if clientIP != "" { conds = append(conds, fmt.Sprintf("client ILIKE '%%%s%%'", strings.ReplaceAll(clientIP, "'", "''"))) }
	if keyword != "" {
		kw := strings.ReplaceAll(keyword, "'", "''")
		conds = append(conds, fmt.Sprintf("(config_path ILIKE '%%%s%%' OR before_change ILIKE '%%%s%%' OR after_change ILIKE '%%%s%%' OR command ILIKE '%%%s%%')", kw, kw, kw, kw))
	}
	whereClause := strings.Join(conds, " AND ")

	var statsRes, histRes, logsRes []map[string]interface{}
	var wg sync.WaitGroup

	wg.Add(3)
	go func() {
		defer wg.Done()
		statsQuery := fmt.Sprintf(`
			SELECT 
				COUNT(*) AS total_logs, 
				MODE(NULLIF(admin, '')) AS top_admin, 
				MODE(NULLIF(command, '')) AS top_cmd 
			FROM read_parquet('%s', union_by_name=true) WHERE %s
		`, duckdbPattern, whereClause)
		statsRes, _ = runDuckDBQuery(statsQuery)
	}()
	go func() {
		defer wg.Done()
		histQuery := fmt.Sprintf(`
			SELECT SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS h, COUNT(*) AS c 
			FROM read_parquet('%s', union_by_name=true) WHERE %s GROUP BY h
		`, duckdbPattern, whereClause)
		histRes, _ = runDuckDBQuery(histQuery)
	}()
	go func() {
		defer wg.Done()
		offset := (page - 1) * perPage
		logsQuery := fmt.Sprintf(`
			SELECT timestamp, admin, client, client_app, command, result, config_path, full_path, before_change, after_change, sequence_no 
			FROM read_parquet('%s', union_by_name=true) 
			WHERE %s 
			ORDER BY timestamp DESC 
			LIMIT %d OFFSET %d
		`, duckdbPattern, whereClause, perPage, offset)
		logsRes, _ = runDuckDBQuery(logsQuery)
	}()
	wg.Wait()

	var totalLogs int
	topAdmin, topCmd := "-", "-"
	if len(statsRes) > 0 {
		totalLogs = int(parseDuckDBNumber(statsRes[0]["total_logs"]))
		if v, ok := statsRes[0]["top_admin"].(string); ok && v != "" { topAdmin = v }
		if v, ok := statsRes[0]["top_cmd"].(string); ok && v != "" { topCmd = v }
	}

	histMap := make(map[string]int)
	for _, row := range histRes {
		if h, ok := row["h"].(string); ok {
			if c, ok := row["c"].(float64); ok { histMap[h] = int(c) }
		}
	}
	for h := 0; h < 24; h++ { emptyHistogram[h].Count = histMap[fmt.Sprintf("%02d:00", h)] }

	safeGet := func(m map[string]interface{}, key string) string {
		if v, ok := m[key]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" { return s }
		}
		return ""
	}

	logs := make([]ConfigLogItem, 0, len(logsRes))
	for _, r := range logsRes {
		logs = append(logs, ConfigLogItem{
			Timestamp:    safeGet(r, "timestamp"),
			Admin:        safeGet(r, "admin"),
			Client:       safeGet(r, "client"),
			ClientApp:    safeGet(r, "client_app"),
			Command:      safeGet(r, "command"),
			Result:       safeGet(r, "result"),
			ConfigPath:   safeGet(r, "config_path"),
			FullPath:     safeGet(r, "full_path"),
			BeforeChange: safeGet(r, "before_change"),
			AfterChange:  safeGet(r, "after_change"),
			SequenceNO:   safeGet(r, "sequence_no"),
		})
	}

	totalPages := int(math.Ceil(float64(totalLogs) / float64(perPage)))
	if totalPages == 0 { totalPages = 1 }

	return &ConfigAnalyticsResult{
		TotalLogs:   totalLogs,
		TopAdmin:    topAdmin,
		TopCommand:  topCmd,
		DbSize:      dbSizeStr,
		Histogram:   emptyHistogram,
		Logs:        logs,
		CurrentPage: page,
		TotalPages:  totalPages,
	}, nil
}

// 🌟 獨立主機資產反查引擎：動態驅動相容 + 全路徑探測 + ARP/DHCP/DNS 多表動態掃描
func lookupHostAssetInfo(ip string) (string, string) {
	var hostname, mac string
	hostname = "-"
	mac = "-"
	cleanIP := strings.TrimSpace(ip)
	if cleanIP == "" {
		return "-", "-"
	}

	// 1. 🌟 自動偵測已註冊的 SQLite 驅動名稱 (完美相容 sqlite 與 sqlite3)
	driverName := ""
	for _, d := range sql.Drivers() {
		if d == "sqlite" || d == "sqlite3" {
			driverName = d
			break
		}
	}
	if driverName == "" {
		if len(sql.Drivers()) > 0 {
			driverName = sql.Drivers()[0]
		} else {
			driverName = "sqlite3"
		}
	}

	// 2. 🌟 自動探測 dhcp_records.db 的多個可能位置
	candidates := []string{
		filepath.Join(appDir, "dhcp_records.db"),
		"dhcp_records.db",
		filepath.Join(".", "dhcp_records.db"),
	}
	if exePath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exePath), "dhcp_records.db"))
	}

	var dbPath string
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				dbPath = p
				break
			}
		}
	}

	if dbPath == "" {
		fmt.Printf("[360鑑識反查] ⚠️ 找不到 dhcp_records.db，已搜尋路徑: %v\n", candidates)
		return "-", "-"
	}

	// 3. 連線 SQLite 資料庫
	sqliteDB, err := sql.Open(driverName, dbPath)
	if err != nil {
		fmt.Printf("[360鑑識反查] ❌ 開啟 SQLite 失敗 (%s, 驅動: %s): %v\n", dbPath, driverName, err)
		return "-", "-"
	}
	defer sqliteDB.Close()

	// 設定繁忙重試等待，避免與後台 DNS 解析寫入衝突
	_, _ = sqliteDB.Exec("PRAGMA busy_timeout = 3000;")

	// 4. 🌟 動態探索資料庫中的所有資料表 (優先掃描 arp_records，次為 dhcp_records, dns_cache)
	tRows, err := sqliteDB.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err == nil {
		var tables []string
		for tRows.Next() {
			var tName string
			if err := tRows.Scan(&tName); err == nil {
				tables = append(tables, tName)
			}
		}
		tRows.Close()

		// 排序優先度：包含 arp 的最優先，其次 dhcp，最後 dns
		sort.Slice(tables, func(i, j int) bool {
			priority := func(name string) int {
				nl := strings.ToLower(name)
				if strings.Contains(nl, "arp") { return 1 }
				if strings.Contains(nl, "dhcp") { return 2 }
				if strings.Contains(nl, "dns") { return 3 }
				return 4
			}
			return priority(tables[i]) < priority(tables[j])
		})

		for _, tbl := range tables {
			// 動態檢測各表欄位結構
			cRows, err := sqliteDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tbl))
			if err != nil { continue }

			var ipCol string
			var allCols []string
			for cRows.Next() {
				var cid int
				var cName, cType string
				var notNull, pk int
				var dfltValue interface{}
				if err := cRows.Scan(&cid, &cName, &cType, &notNull, &dfltValue, &pk); err == nil {
					allCols = append(allCols, cName)
					cn := strings.ToLower(cName)
					if (cn == "ip" || cn == "ip_address" || cn == "ipaddr") && ipCol == "" {
						ipCol = cName
					}
				}
			}
			cRows.Close()

			if ipCol == "" { continue }

			// 針對該表執行 IP 查詢
			querySQL := fmt.Sprintf("SELECT * FROM %s WHERE TRIM(%s) = ? LIMIT 1", tbl, ipCol)
			rows, err := sqliteDB.Query(querySQL, cleanIP)
			if err != nil { continue }

			if rows.Next() {
				vals := make([]interface{}, len(allCols))
				ptrs := make([]interface{}, len(allCols))
				for i := range vals { ptrs[i] = &vals[i] }

				if err := rows.Scan(ptrs...); err == nil {
					for i, col := range allCols {
						if vals[i] == nil { continue }
						vStr := strings.TrimSpace(fmt.Sprintf("%v", vals[i]))
						if vStr == "" || vStr == "<nil>" || vStr == "-" || vStr == "待解析" { continue }

						cn := strings.ToLower(col)
						// 提取 MAC
						if strings.Contains(cn, "mac") && (mac == "-" || mac == "") {
							mac = vStr
						}
						// 提取 Hostname
						if (strings.Contains(cn, "host") || strings.Contains(cn, "name") || strings.Contains(cn, "dev")) && (hostname == "-" || hostname == "") {
							hostname = vStr
						}
					}
				}
			}
			rows.Close()

			// 兩者皆已獲取則提前結束
			if mac != "-" && hostname != "-" && hostname != "" {
				break
			}
		}
	}

	// 5. 若仍無 Hostname，自動發起本機反向 DNS (PTR) 解析備援
	if hostname == "-" || hostname == "" || hostname == "待解析" {
		ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer cancel()
		var r net.Resolver
		names, err := r.LookupAddr(ctx, cleanIP)
		if err == nil && len(names) > 0 {
			h := strings.TrimSpace(names[0])
			h = strings.TrimSuffix(h, ".")
			parts := strings.Split(h, ".")
			if len(parts) > 0 && parts[0] != "" {
				hostname = strings.ToUpper(parts[0])
			} else {
				hostname = h
			}
		}
	}

	// 加上 🌐 圖示保持介面風格一致
	if hostname != "-" && hostname != "" && !strings.HasPrefix(hostname, "🌐") {
		hostname = "🌐 " + hostname
	}

	// 終端即時印出診斷訊息
	fmt.Printf("[360鑑識反查] 🎯 IP: %s ➔ 主機名稱: %s | MAC: %s\n", cleanIP, hostname, mac)
	return hostname, mac
}

func queryHostTimeline(ip, targetDate string) (*Host360Profile, error) {
	targetDate = strings.ReplaceAll(strings.TrimSpace(targetDate), "/", "-")
	
	// 🌟 核心防護：若未帶日期，優先探測湖倉中最新有日誌的日期 (避免跨日變成 0 筆)
	if targetDate == "" {
		targetDate = time.Now().Format("2006-01-02")
		if files, _ := filepath.Glob(filepath.Join(trafficDir, "traffic_*.parquet")); len(files) > 0 {
			sort.Strings(files)
			base := filepath.Base(files[len(files)-1]) // 例如 traffic_2026-10-30.parquet
			parts := strings.Split(base, "_")
			if len(parts) >= 2 {
				dStr := strings.Split(parts[1], ".")[0]
				if len(dStr) == 10 {
					targetDate = dStr
				}
			}
		}
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, errors.New("請輸入欲鑑識的主機 IP 位址")
	}
	safeIP := strings.ReplaceAll(ip, "'", "''")

	// 🌟 核心修正 1：主動向 SQLite ARP/DHCP 靜態資產庫精準反查 Hostname 與 MAC
	hostVal, macVal := lookupHostAssetInfo(ip)

	profile := &Host360Profile{
		IP:          ip,
		Hostname:    hostVal,
		MAC:         macVal,
		Events:      make([]TimelineEvent, 0),
	}

	var events []TimelineEvent
	var mu sync.Mutex
	var wg sync.WaitGroup

	reMAC := regexp.MustCompile(`mac\s+([0-9a-fA-F:]{17})`)
	reHost := regexp.MustCompile(`hostname\s+([^,\s]+)`)

	// 1. 查詢 System (放寬至 2000 筆)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pattern := filepath.ToSlash(filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", targetDate)))
		files, _ := filepath.Glob(filepath.Join(systemDir, fmt.Sprintf("system_%s*.parquet", targetDate)))
		if len(files) == 0 { return }

		q := fmt.Sprintf(`
			SELECT timestamp, subtype, event_id, severity, description 
			FROM read_parquet('%s', union_by_name=true) 
			WHERE description ILIKE '%%%s%%' OR object ILIKE '%%%s%%'
			ORDER BY timestamp DESC LIMIT 2000
		`, pattern, safeIP, safeIP)
		res, err := runDuckDBQuery(q)
		if err == nil {
			mu.Lock()
			for _, r := range res {
				sev := strings.ToLower(fmt.Sprintf("%v", r["severity"]))
				lvl := "info"
				icon := "bi-hdd-network"
				sub := fmt.Sprintf("%v", r["subtype"])
				desc := fmt.Sprintf("%v", r["description"])

				if sub == "dhcp" || strings.Contains(desc, "DHCP") {
					icon = "bi-router-fill"
					if profile.MAC == "-" {
						if m := reMAC.FindStringSubmatch(desc); len(m) > 1 {
							profile.MAC = m[1]
						}
					}
					if profile.Hostname == "-" {
						if m := reHost.FindStringSubmatch(desc); len(m) > 1 {
							profile.Hostname = m[1]
						}
					}
				}

				if sev == "high" || sev == "critical" { lvl = "danger" } else if sev == "medium" { lvl = "warning" }

				events = append(events, TimelineEvent{
					Timestamp:   fmt.Sprintf("%v", r["timestamp"]),
					Category:    "system",
					Level:       lvl,
					Icon:        icon,
					Title:       fmt.Sprintf("系統 [%s] - %v", sub, r["event_id"]),
					Description: desc,
				})
			}
			mu.Unlock()
		}
	}()

	// 2. 查詢 Threat (放寬至 2000 筆)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pattern := filepath.ToSlash(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", targetDate)))
		files, _ := filepath.Glob(filepath.Join(threatDir, fmt.Sprintf("threat_%s*.parquet", targetDate)))
		if len(files) == 0 { return }

		q := fmt.Sprintf(`
			SELECT timestamp, threat_name, severity, action, application, destination, to_port
			FROM read_parquet('%s', union_by_name=true) 
			WHERE source = '%s' OR destination = '%s'
			ORDER BY timestamp DESC LIMIT 2000
		`, pattern, safeIP, safeIP)
		res, err := runDuckDBQuery(q)
		if err == nil {
			mu.Lock()
			for _, r := range res {
				sev := strings.ToLower(fmt.Sprintf("%v", r["severity"]))
				lvl := "warning"
				if sev == "high" || sev == "critical" { lvl = "danger" }
				events = append(events, TimelineEvent{
					Timestamp:   fmt.Sprintf("%v", r["timestamp"]),
					Category:    "threat",
					Level:       lvl,
					Icon:        "bi-shield-slash-fill",
					Title:       fmt.Sprintf("威脅攔截: %v (%v)", r["threat_name"], r["severity"]),
					Description: fmt.Sprintf("動作: %v | 應用: %v | 目標: %v:%v", r["action"], r["application"], r["destination"], r["to_port"]),
				})
			}
			mu.Unlock()
		}
	}()

	// 3. 查詢 Config (放寬至 1000 筆)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pattern := filepath.ToSlash(filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", targetDate)))
		files, _ := filepath.Glob(filepath.Join(configDir, fmt.Sprintf("config_%s*.parquet", targetDate)))
		if len(files) == 0 { return }

		q := fmt.Sprintf(`
			SELECT timestamp, admin, command, result, config_path, full_path, before_change, after_change 
			FROM read_parquet('%s', union_by_name=true) 
			WHERE client = '%s' OR before_change ILIKE '%%%s%%' OR after_change ILIKE '%%%s%%'
			ORDER BY timestamp DESC LIMIT 1000
		`, pattern, safeIP, safeIP, safeIP)
		res, err := runDuckDBQuery(q)
		if err == nil {
			mu.Lock()
			for _, r := range res {
				diff := ""
				if fmt.Sprintf("%v", r["after_change"]) != "" && fmt.Sprintf("%v", r["after_change"]) != "-" {
					diff = fmt.Sprintf(" ➔ 異動: %v", r["after_change"])
				}
				events = append(events, TimelineEvent{
					Timestamp:   fmt.Sprintf("%v", r["timestamp"]),
					Category:    "config",
					Level:       "success",
					Icon:        "bi-gear-fill",
					Title:       fmt.Sprintf("管理操作: %v 執行 %v (%v)", r["admin"], r["command"], r["result"]),
					Description: fmt.Sprintf("路徑: %v%s", r["config_path"], diff),
				})
			}
			mu.Unlock()
		}
	}()

	// 4. 查詢 Traffic (🌟 核心修正：從原本的 LIMIT 100 大幅解放至 5000 筆！)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", targetDate)))
		files, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", targetDate)))
		if len(files) == 0 { return }

		q := fmt.Sprintf(`
			SELECT timestamp, action, application, destination, to_port, bytes
			FROM read_parquet('%s', union_by_name=true) 
			WHERE source = '%s' OR destination = '%s'
			ORDER BY timestamp DESC LIMIT 5000
		`, pattern, safeIP, safeIP)
		res, err := runDuckDBQuery(q)
		if err == nil {
			mu.Lock()
			for _, r := range res {
				act := strings.ToLower(fmt.Sprintf("%v", r["action"]))
				lvl := "info"
				icon := "bi-arrow-left-right"
				title := fmt.Sprintf("網路連線: %v", r["application"])

				// 阻擋事件以紅色強調，巨量傳輸以黃色提醒，正常連線以藍色呈現
				if act == "deny" || act == "drop" || strings.HasPrefix(act, "reset") {
					lvl = "danger"
					icon = "bi-x-circle-fill"
					title = fmt.Sprintf("連線阻擋: %v (Action: %s)", r["application"], r["action"])
				} else if parseDuckDBNumber(r["bytes"]) > 20971520 {
					lvl = "warning"
					title = fmt.Sprintf("巨量連線: %v", r["application"])
				}

				bytesVal := parseDuckDBNumber(r["bytes"])
				bytesStr := fmt.Sprintf("%.2f MB", float64(bytesVal)/(1024*1024))
				if bytesVal < 1024*1024 {
					bytesStr = fmt.Sprintf("%.1f KB", float64(bytesVal)/1024)
				}

				events = append(events, TimelineEvent{
					Timestamp:   fmt.Sprintf("%v", r["timestamp"]),
					Category:    "traffic",
					Level:       lvl,
					Icon:        icon,
					Title:       title,
					Description: fmt.Sprintf("目標端: %v:%v | 傳輸: %s", r["destination"], r["to_port"], bytesStr),
				})
			}
			mu.Unlock()
		}
	}()

	wg.Wait()

	// 統計指標
	for _, e := range events {
		if e.Category == "threat" { profile.ThreatCount++ }
		if e.Category == "traffic" && e.Level == "danger" { profile.BlockCount++ }
	}
	profile.TotalEvents = len(events)

	// 全景按時間倒序排序 (最新在最上)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp > events[j].Timestamp
	})
	profile.Events = events

	return profile, nil
}

// 🌟 將 PA-1420 擷取到的 DHCP 主機名稱與租約非同步推送至 netmon
func pushDHCPToNetmon(entries []DHCPEntry) {
	if len(entries) == 0 {
		return
	}

	type DeviceObservation struct {
		Timestamp  time.Time `json:"timestamp"`
		Source     string    `json:"source"`
		MACAddress string    `json:"mac_address"`
		IPAddress  string    `json:"ip_address"`
		Hostname   string    `json:"hostname"`
		SwitchIP   string    `json:"switch_ip"`
		SwitchPort string    `json:"switch_port"`
		VLANID     int       `json:"vlan_id"`
		IsUplink   bool      `json:"is_uplink"`
	}

	var list []DeviceObservation
	now := time.Now()

	for _, e := range entries {
		cleanMAC := strings.ToUpper(strings.TrimSpace(e.MAC))
		cleanHost := strings.TrimSpace(e.Hostname)
		cleanIP := strings.TrimSpace(e.IP)

		if cleanMAC == "" || cleanMAC == "-" || cleanHost == "" || cleanHost == "-" {
			continue
		}

		list = append(list, DeviceObservation{
			Timestamp:  now,
			Source:     "DHCP",
			MACAddress: cleanMAC,
			IPAddress:  cleanIP,
			Hostname:   cleanHost,
		})
	}

	if len(list) == 0 {
		return
	}

	payload, err := json.Marshal(list)
	if err != nil {
		return
	}

	// 批次推送至 netmon (Port 8000)
	netmonURL := "http://192.50.1.59:8000/api/v1/observations/batch"
	resp, err := httpClient.Post(netmonURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("[Netmon 聯動] ⚠️ 連線至 netmon (Port 8000) 失敗: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("🎯 [PA-1420 聯動] 成功推送 %d 筆 DHCP 主機名稱至 netmon！\n", len(list))

		// 觸發 netmon 自動對帳更新設備名稱
		reconcileURL := "http://192.50.1.59:8000/api/v1/devices/reconcile"
		rResp, rErr := httpClient.Post(reconcileURL, "application/json", nil)
		if rErr == nil {
			_ = rResp.Body.Close()
		}
	}
}

// 🌟 解析並匯入外部 devices.csv 設備清冊 (支援 BOM 剔除與中英文表頭相容)
func importDevicesCSV(r io.Reader) (total int, updated int, inserted int, err error) {
	db, err := initDB()
	if err != nil {
		return 0, 0, 0, err
	}

	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	headers, err := reader.Read()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("讀取 CSV 表頭失敗: %w", err)
	}

	// 🌟 核心防護 1：標準化欄位名稱，抹除 UTF-8 BOM (\ufeff)、空白與底線
	cleanColName := func(s string) string {
		s = strings.TrimPrefix(s, "\ufeff") // 👈 消除 Excel BOM 大魔王！
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, "_", "")
		s = strings.ReplaceAll(s, "-", "")
		return s
	}

	colMap := make(map[string]int)
	for i, h := range headers {
		colMap[cleanColName(h)] = i
	}

	// 🌟 核心防護 2：支援中英雙語欄位別名
	findColIndex := func(aliases ...string) int {
		for _, alias := range aliases {
			key := cleanColName(alias)
			if idx, ok := colMap[key]; ok {
				return idx
			}
		}
		return -1
	}

	// 搜尋 IP 欄位 (相容: ip, ip位址, ipaddress, ip_address, 設備ip)
	ipIdx := findColIndex("ip", "ip位址", "ipaddress", "ip_address", "ip地址", "設備ip")
	if ipIdx == -1 {
		return 0, 0, 0, fmt.Errorf("CSV 缺少必要的 'ip' 或 'IP 位址' 欄位")
	}

	nameIdx := findColIndex("name", "hostname", "設備名稱", "設備名稱(hostname)", "主機名稱")
	locIdx := findColIndex("location", "實體位置", "位置", "機房", "地點")
	typeIdx := findColIndex("device_type", "type", "設備性質", "設備種類", "類型")
	brandIdx := findColIndex("brand", "廠牌", "品牌")
	modelIdx := findColIndex("model", "型號")
	descIdx := findColIndex("sys_descr", "sysdescr", "description", "描述")

	getValByIdx := func(row []string, idx int) string {
		if idx != -1 && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO external_devices (ip, name, location, device_type, brand, model, sys_descr, imported_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET
			name = CASE WHEN excluded.name != '' THEN excluded.name ELSE external_devices.name END,
			location = CASE WHEN excluded.location != '' THEN excluded.location ELSE external_devices.location END,
			device_type = CASE WHEN excluded.device_type != '' THEN excluded.device_type ELSE external_devices.device_type END,
			brand = CASE WHEN excluded.brand != '' THEN excluded.brand ELSE external_devices.brand END,
			model = CASE WHEN excluded.model != '' THEN excluded.model ELSE external_devices.model END,
			sys_descr = CASE WHEN excluded.sys_descr != '' THEN excluded.sys_descr ELSE external_devices.sys_descr END,
			imported_at = CURRENT_TIMESTAMP
	`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer stmt.Close()

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(row) <= ipIdx {
			continue
		}

		rawIP := strings.TrimSpace(row[ipIdx])
		if net.ParseIP(rawIP) == nil {
			continue // 忽略空值或無效 IP 列
		}

		name := getValByIdx(row, nameIdx)
		loc := getValByIdx(row, locIdx)
		dtype := getValByIdx(row, typeIdx)
		brand := getValByIdx(row, brandIdx)
		model := getValByIdx(row, modelIdx)
		sysDescr := getValByIdx(row, descIdx)

		var exists int
		_ = tx.QueryRow("SELECT 1 FROM external_devices WHERE ip = ?", rawIP).Scan(&exists)

		_, err = stmt.Exec(rawIP, name, loc, dtype, brand, model, sysDescr)
		if err == nil {
			total++
			if exists == 1 {
				updated++
			} else {
				inserted++
			}

			// 同步更新目前已存在的 ARP 記錄主機名
			if name != "" {
				_, _ = tx.Exec(`
					UPDATE arp_records 
					SET hostname = ? 
					WHERE ip = ? AND (hostname = '' OR hostname = '-' OR hostname LIKE '%待解析%' OR hostname LIKE '%(無主機名)%')
				`, name, rawIP)
			}
		}
	}

	_ = tx.Commit()
	return total, updated, inserted, nil
}

// 🌟 啟動非同步 DNS PTR 背景反查 Worker (支援前台進度條與快取入庫)
func triggerAsyncDNSResolve(ips []string) {
	if len(ips) == 0 {
		return
	}

	dnsMutex.Lock()
	if dnsWorkerStatus.IsRunning {
		dnsMutex.Unlock()
		return
	}
	dnsWorkerStatus.IsRunning = true
	dnsWorkerStatus.Total = len(ips)
	dnsWorkerStatus.Done = 0
	dnsMutex.Unlock()

	go func(targetIPs []string) {
		defer func() {
			dnsMutex.Lock()
			dnsWorkerStatus.IsRunning = false
			dnsMutex.Unlock()
		}()

		db, err := initDB()
		if err != nil {
			return
		}

		for _, ip := range targetIPs {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				hostname := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
				if hostname != "" {
					_, _ = db.Exec(`
						INSERT INTO ip_hostname_cache (ip, hostname, updated_at) 
						VALUES (?, ?, CURRENT_TIMESTAMP)
						ON CONFLICT(ip) DO UPDATE SET hostname = excluded.hostname, updated_at = CURRENT_TIMESTAMP
					`, ip, hostname)
				}
			}

			dnsMutex.Lock()
			dnsWorkerStatus.Done++
			dnsMutex.Unlock()

			time.Sleep(30 * time.Millisecond) // 避免短時間密集查詢衝擊 DNS 伺服器
		}
	}(ips)
}

// 🌟 獨立執行 Chunk 聚合函式
func doRollupChunksNow() {
	todayStr := time.Now().Format("2006-01-02")
	dayDir := filepath.Join(trafficDir, todayStr)
	pattern := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_chunk_*.parquet", todayStr))
	files, err := filepath.Glob(pattern)
	
	if err != nil || len(files) < 5 {
		return
	}

	mergedChunk := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_rollup_%d.parquet", todayStr, time.Now().Unix()))
	tmpMerged := mergedChunk + ".tmp"

	copySQL := fmt.Sprintf(`
		COPY (
			SELECT * FROM read_parquet('%s')
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, filepath.ToSlash(pattern), filepath.ToSlash(tmpMerged))

	_, err = runDuckDBQuery(copySQL)
	if err == nil {
		if err := os.Rename(tmpMerged, mergedChunk); err == nil {
			for _, f := range files {
				_ = os.Remove(f)
			}
			fmt.Printf("[%s] 📦 [Chunk 聚合成功] 已將 %d 個 Chunk 檔整合成單一 Rollup: %s\n",
				time.Now().Format("15:04:05"), len(files), filepath.Base(mergedChunk))
		} else {
			_ = os.Remove(tmpMerged)
		}
	} else {
		_ = os.Remove(tmpMerged)
	}
}

// 🌟 嚴格對齊時鐘整點與半點 (:00 / :30) 的 Rollup 排程器
func startChunkConsolidatorWorker() {
	go func() {
		// 1. 開機暖機 15 秒後先自檢一次（若目錄下已積累小檔立即清理）
		time.Sleep(15 * time.Second)
		doRollupChunksNow()

		for {
			now := time.Now()
			// 2. 精準計算距離下一個「:00」或「:30」的剩餘時間
			var nextRun time.Time
			if now.Minute() < 30 {
				nextRun = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 30, 0, 0, now.Location())
			} else {
				nextRun = time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 0, 0, now.Location())
			}

			sleepDuration := time.Until(nextRun)
			if sleepDuration <= 0 {
				sleepDuration = 30 * time.Minute
			}

			time.Sleep(sleepDuration)

			// 3. 準點觸發聚合
			doRollupChunksNow()
		}
	}()
}

// 🌟 每日凌晨 00:05 跨日低峰期，對「前一日」的完整日誌做唯一一次全量封存，內部的重複邏輯簡化為呼叫 consolidateDailyTraffic
func startMidnightDailyArchiver() {
    go func() {
        for {
            now := time.Now()
            nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 5, 0, 0, now.Location())
            time.Sleep(time.Until(nextMidnight))

            yesterdayStr := time.Now().Add(-24 * time.Hour).Format("2006-01-02")
            fmt.Printf("[%s] 🌙 [夜間封存] 開始對前一日 (%s) 執行全量去重整併...\n", time.Now().Format("15:04:05"), yesterdayStr)
            _ = consolidateDailyTraffic(yesterdayStr)
        }
    }()
}

// 🌟 1. 自動判斷是否為高階旗艦機種 (PA-5200 / PA-5400 / PA-7000 / PA-3400 等)
func isHighEndFirewall() bool {
	m := strings.ToUpper(getFWModelName())
	// 命中 5250、5200、5450、7000 等高階處理器型號
	if strings.Contains(m, "5250") || strings.Contains(m, "5200") ||
		strings.Contains(m, "5220") || strings.Contains(m, "5260") ||
		strings.Contains(m, "5450") || strings.Contains(m, "5400") ||
		strings.Contains(m, "7000") || strings.Contains(m, "7050") ||
		strings.Contains(m, "7080") || strings.Contains(m, "3400") {
		return true
	}
	return false
}

// 🌟 2. 依據設備硬體能力，動態回傳最佳「Job 輪詢間隔」與「輪與輪冷卻時間」
func getAdaptiveBackfillTimings() (pollInterval time.Duration, roundSleep time.Duration) {
	if isHighEndFirewall() {
		// 🚀 PA-5250 旗艦極速模式：
		// Job 輪詢間隔縮減至 200ms (PA-5250 產日誌次秒完成)，輪次冷卻縮減至 200ms
		return 200 * time.Millisecond, 200 * time.Millisecond
	}
	// 🛡️ PA-1420 / 其它中低階安全保護模式：
	// Job 輪詢維持 600ms，每輪回補間隔休息 1.5 秒，保護 CPU 不過載
	return 600 * time.Millisecond, 1500 * time.Millisecond
}

func consolidateDailyTraffic(dateStr string) error {
	parquetFileMutex.Lock()
	defer parquetFileMutex.Unlock()

	dayDir := filepath.Join(trafficDir, dateStr)
	_ = os.MkdirAll(dayDir, 0755)

	// 1. 若根目錄有該日期的舊碎片或舊主檔，先統一歸位至日期子目錄
	if rootItems, err := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", dateStr))); err == nil {
		for _, rf := range rootItems {
			if !strings.HasSuffix(rf, ".tmp") {
				_ = os.Rename(rf, filepath.Join(dayDir, filepath.Base(rf)))
			}
		}
	}

	// 2. 搜尋日期子目錄內所有碎片檔案 (包含 live, chunk, rollup, nas, api)
	patternAllFragments := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_*_*.parquet", dateStr))
	rawFragments, err := filepath.Glob(patternAllFragments)
	var fragments []string
	for _, f := range rawFragments {
		if !strings.HasSuffix(f, ".tmp") {
			fragments = append(fragments, f)
		}
	}
	if err != nil || len(fragments) == 0 {
		return nil // 無碎片需要整併
	}

	// 3. 檢查該日是否已有分時主檔 (traffic_YYYY-MM-DD_00.parquet ~ _23.parquet)
	hourlyFiles, _ := filepath.Glob(filepath.Join(dayDir, fmt.Sprintf("traffic_%s_[0-2][0-9].parquet", dateStr)))
	hasHourlyMainFiles := len(hourlyFiles) > 0

	var targetMainFile string
	var inputPaths []string

	if hasHourlyMainFiles {
		// 🌟 PA-5250 分時主檔模式：保留 24 個分時主檔不動（避免重寫數十 GB 檔案），僅將零碎分塊合併為單一 syslog 歸檔
		targetMainFile = filepath.Join(dayDir, fmt.Sprintf("traffic_%s_syslog.parquet", dateStr))
		if _, err := os.Stat(targetMainFile); err == nil {
			inputPaths = append(inputPaths, filepath.ToSlash(targetMainFile))
		}
		for _, f := range fragments {
			inputPaths = append(inputPaths, filepath.ToSlash(f))
		}
		fmt.Printf("[每日湖倉整併] 📦 偵測到 %s 具備分時主檔，僅將 %d 個 Syslog 碎片整合為單一歸檔...\n",
			dateStr, len(fragments))
	} else {
		// 🌟 PA-1420 單日主檔模式：將該日所有資料融合為單一 ZSTD 主檔
		targetMainFile = filepath.Join(dayDir, fmt.Sprintf("traffic_%s.parquet", dateStr))
		if _, err := os.Stat(targetMainFile); err == nil {
			inputPaths = append(inputPaths, filepath.ToSlash(targetMainFile))
		}
		for _, f := range fragments {
			inputPaths = append(inputPaths, filepath.ToSlash(f))
		}
		fmt.Printf("[每日湖倉整併] 📦 偵測到 %s 共有 %d 個碎片分塊，啟動全量去重整合...\n",
			dateStr, len(fragments))
	}

	quotedInputs := make([]string, len(inputPaths))
	for i, p := range inputPaths {
		quotedInputs[i] = fmt.Sprintf("'%s'", p)
	}
	sourceListExpr := fmt.Sprintf("[%s]", strings.Join(quotedInputs, ", "))

	tmpMerged := filepath.Join(dayDir, fmt.Sprintf("traffic_%s_consolidating_%d.parquet.tmp", dateStr, time.Now().UnixNano()))
	tempSpillDir := filepath.Join(appDir, "duckdb_temp", fmt.Sprintf("consolidate_%s_%d", dateStr, time.Now().UnixNano()))
	_ = os.MkdirAll(tempSpillDir, 0755)
	defer os.RemoveAll(tempSpillDir)

	duckOutput := filepath.ToSlash(tmpMerged)
	duckSpill := filepath.ToSlash(tempSpillDir)

	duckCmd := fmt.Sprintf(
		"SET max_memory='16GB'; SET preserve_insertion_order=false; SET temp_directory='%s'; "+
			"COPY (SELECT * EXCLUDE (row_num) FROM ("+
			"  SELECT *, ROW_NUMBER() OVER ("+
			"    PARTITION BY timestamp, source, destination, to_port, session_id, action, bytes "+
			"    ORDER BY timestamp DESC"+
			"  ) as row_num "+
			"  FROM read_parquet(%s, union_by_name=true)"+
			") WHERE row_num = 1 ORDER BY timestamp DESC) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
		duckSpill, sourceListExpr, duckOutput,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()

	duckdbExe := getDuckDBExePath()
	cmd := exec.CommandContext(ctx, duckdbExe, "-c", duckCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpMerged)
		fmt.Printf("[每日湖倉整併] ❌ DuckDB 整合失敗: %v, Output: %s\n", err, string(out))
		return err
	}

	_ = os.Remove(targetMainFile)
	if err := os.Rename(tmpMerged, targetMainFile); err != nil {
		_ = os.Remove(tmpMerged)
		fmt.Printf("[每日湖倉整併] ❌ 檔案替換失敗: %v\n", err)
		return err
	}

	for _, f := range fragments {
		_ = os.Remove(f)
	}

	fmt.Printf("[每日湖倉整併] ✅ %s 碎片整併完成，已清除 %d 個零碎分塊！\n", dateStr, len(fragments))
	return nil
}


