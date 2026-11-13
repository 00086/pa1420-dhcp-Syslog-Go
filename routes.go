package main

import (
	"bytes"
	"context" // 👈 🌟 補上這行，解決 undefined: context
	"database/sql"
	"encoding/json" // 👈 🌟 補上這行 (解決 undefined: json)
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec" // 👈 🌟 補上此行 (解決 undefined: exec)
	"path/filepath" // 👈 補上：供 route 16 組合 Parquet 檔案路徑
	"regexp" // 🌟 補上這行，解決 undefined: regexp
	"runtime" // 🌟 跨平台作業系統判定 (Windows / Linux)
	"sort"
	"strconv"
	"strings"
	"sync"        // 👈 🌟 補上此行 (解決 undefined: sync，供 WaitGroup 使用)
	"sync/atomic" // 👈 🌟 必須是 sync/atomic（包含子目錄路徑）
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/parquet-go/parquet-go" // 👈 補上：供 route 16 讀取目前最舊連線紀錄
)

// -------------------------------------------------------------
// 🌟 Palo Alto HTTP Webhook JSON 結構定義
// -------------------------------------------------------------
type PAWebhookTrafficPayload struct {
	Type             string `json:"type"`
	TimeGenerated    string `json:"time_generated"`
	FromZone         string `json:"from"`
	ToZone           string `json:"to"`
	Source           string `json:"src"`
	NatSourceIP      string `json:"natsrc"`
	Destination      string `json:"dst"`
	NatDestIP        string `json:"natdst"`
	ToPort           string `json:"dport"`
	Application      string `json:"app"`
	Action           string `json:"action"`
	Rule             string `json:"rule"`
	SessionEndReason string `json:"session_end_reason"`
	Bytes            string `json:"bytes"`
	SessionID        string `json:"sessionid"`
}

type PAWebhookThreatPayload struct {
	Subtype       string `json:"subtype"`
	TimeGenerated string `json:"time_generated"`
	ThreatID      string `json:"threatid"`
	ThreatName    string `json:"threat_name"`
	FromZone      string `json:"from"`
	ToZone        string `json:"to"`
	Source        string `json:"src"`
	Destination   string `json:"dst"`
	ToPort        string `json:"dport"`
	Application   string `json:"app"`
	Action        string `json:"action"`
	Severity      string `json:"severity"`
	URL           string `json:"url"`
	SessionID     string `json:"sessionid"`
}

func renderPongo(c *gin.Context, tplName string, ctx pongo2.Context) {
	if ctx == nil {
		ctx = pongo2.Context{}
	}
	// 🌟 自動為所有網頁樣板注入防火牆真實型號 (如 PA-5250)
	ctx["fw_model"] = getFWModelName()

	tpl, err := pongoSet.FromFile(tplName)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template load error: %v", err)
		return
	}
	out, err := tpl.Execute(ctx)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template render error: %v", err)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(out))
}

func registerRoutes(r *gin.Engine) {
	// 1. 頁面主路由 (透過 active_page 保持導覽列高亮)
	r.GET("/", func(c *gin.Context) {
		renderPongo(c, "dhcp.html", pongo2.Context{"active_page": "dhcp"})
	})

	r.GET("/traffic", func(c *gin.Context) {
		renderPongo(c, "traffic.html", pongo2.Context{"active_page": "traffic"})
	})
	
	// 🌟 資安威脅分析頁面 (改用系統標準 renderPongo 渲染)
	r.GET("/threat", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "threat.html", pongo2.Context{
			"active_page": "threat",
			"today":       time.Now().Format("2006-01-02"),
		})
	})

	// 🌟 湖倉切分與整併稽核主頁面
	r.GET("/audit", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "audit.html", pongo2.Context{
			"active_page": "audit",
			"today":       time.Now().Format("2006-01-02"),
		})
	})

	// 🌟 湖倉稽核查詢 API
	r.GET("/api/audit-query", func(c *gin.Context) {
		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		status := c.DefaultQuery("status", "all")
		model := c.DefaultQuery("model", "all")
		category := c.DefaultQuery("category", "all")
		keyword := strings.TrimSpace(c.DefaultQuery("keyword", ""))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))

		result, err := QueryAuditLogs(date, status, model, category, keyword, page, perPage)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":       "success",
			"total_events": result.TotalEvents,
			"success_cnt":  result.SuccessCnt,
			"failed_cnt":   result.FailedCnt,
			"total_rows":   result.TotalRows,
			"total_mb":     result.TotalMB,
			"current_page": result.CurrentPage,
			"total_pages":  result.TotalPages,
			"logs":         result.Logs,
		})
	})

	// 🌟 手動加入重試排程 API
	r.POST("/api/audit/retry", func(c *gin.Context) {
		date := strings.TrimSpace(c.PostForm("date"))
		slot := strings.TrimSpace(c.PostForm("slot"))
		model := strings.TrimSpace(c.PostForm("model"))
		category := strings.TrimSpace(c.PostForm("category"))
		if date == "" || slot == "" {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "缺少必要參數 (需具備 date 與 slot)"})
			return
		}
		if model == "" {
			model = getFWModelName()
		}
		if category == "" {
			category = "chunk切片"
		}

		count, err := TriggerTaskRetry(date, slot, model, category)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":      "success",
			"retry_count": count,
			"message":     fmt.Sprintf("已成功將 %s %s 任務加入重試佇列 (已重試 %d 次)", date, slot, count),
		})
	})

	// 🌟 手動停止重試 API
	r.POST("/api/audit/stop-retry", func(c *gin.Context) {
		date := strings.TrimSpace(c.PostForm("date"))
		slot := strings.TrimSpace(c.PostForm("slot"))
		model := strings.TrimSpace(c.PostForm("model"))
		category := strings.TrimSpace(c.PostForm("category"))
		if date == "" || slot == "" {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "缺少必要參數 (需具備 date 與 slot)"})
			return
		}
		if model == "" {
			model = getFWModelName()
		}
		if category == "" {
			category = "chunk切片"
		}

		StopTaskRetry(date, slot, model, category)
		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("已成功停止 %s %s 的重試任務", date, slot),
		})
	})

	// 🌟 手動一鍵清空所有待處理佇列 API
	r.POST("/api/audit/purge-queue", func(c *gin.Context) {
		count := PurgeSliceTaskQueue()
		c.JSON(http.StatusOK, gin.H{
			"status":       "success",
			"purged_count": count,
			"message":      fmt.Sprintf("已成功清空佇列！取消了 %d 個排隊中的切片任務。", count),
		})
	})

	// 🌟 手動觸發缺漏切片自動對賬補償 API (支援傳入 hours 參數)
	r.POST("/api/audit/reconcile", func(c *gin.Context) {
		hours, _ := strconv.Atoi(c.DefaultPostForm("hours", "0"))
		go func() {
			logger := func(format string, a ...any) {
				fmt.Printf("[手動對賬 %s] "+format, append([]any{time.Now().Format("15:04:05")}, a...)...)
			}
			ReconcileMissingSlices(logger, hours)
		}()

		rangeDesc := "今日 00:00 至今全量"
		if hours > 0 {
			rangeDesc = fmt.Sprintf("最近 %d 小時", hours)
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("已啟動背景缺漏對賬檢查 (%s)，若有未落盤切片將自動排入佇列補齊！", rangeDesc),
		})
	})


	// 2. 設定檔狀態檢測 API
	r.GET("/api/config-status", func(c *gin.Context) {
		if _, err := os.Stat(paConfigFile); os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{
				"status":  "missing",
				"message": fmt.Sprintf("找不到設定檔案！系統已建立範本檔，請填寫：%s", paConfigFile),
				"path":    paConfigFile,
			})
			return
		}
		fwIP, iface, _, _, err := getPAConfig()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"status":  "invalid",
				"message": err.Error(),
				"path":    paConfigFile,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"message":   "設定檔配置正確",
			"fw_ip":     fwIP,
			"interface": iface,
		})
	})

	// 3. 立即抓取 DHCP 租約
	r.POST("/api/fetch-now", func(c *gin.Context) {
		info := fetchPADhcpJob("manual")
		c.JSON(http.StatusOK, info)
	})

	// 4. 最新排程狀態
	r.GET("/api/latest-status", func(c *gin.Context) {
		jobMutex.RLock()
		info := lastJobInfo
		jobMutex.RUnlock()
		c.JSON(http.StatusOK, info)
	})

	// 5. 即時硬體狀態
	r.GET("/api/system-health", func(c *gin.Context) {
		data, err := fetchPAHealthData()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	// 6. 硬體歷史折線圖數據 (最末 180 筆)
	r.GET("/api/health-history", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		rows, err := db.Query(`
			SELECT record_time, mp_cpu, dp_cpu, mem_usage_pct, active_sessions, disk_usage_pct
			FROM system_health_log
			ORDER BY id DESC LIMIT 180
		`)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		defer rows.Close()

		type HealthHistoryItem struct {
			RecordTime     string  `json:"record_time"`
			MpCPU          float64 `json:"mp_cpu"`
			DpCPU          float64 `json:"dp_cpu"`
			MemUsagePct    float64 `json:"mem_usage_pct"`
			ActiveSessions int     `json:"active_sessions"`
			DiskUsagePct   float64 `json:"disk_usage_pct"`
		}

		var items []HealthHistoryItem
		for rows.Next() {
			var it HealthHistoryItem
			_ = rows.Scan(&it.RecordTime, &it.MpCPU, &it.DpCPU, &it.MemUsagePct, &it.ActiveSessions, &it.DiskUsagePct)
			items = append(items, it)
		}

		// 反轉為時間正序
		for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
			items[i], items[j] = items[j], items[i]
		}

		c.JSON(http.StatusOK, gin.H{"status": "success", "history": items})
	})

	// 7. 租約表格分頁檢索
	r.GET("/api/leases", func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
		queryDate := c.DefaultQuery("date", time.Now().Format("2006-01-02"))

		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		var totalRecords int
		_ = db.QueryRow("SELECT COUNT(*) FROM dhcp_leases WHERE record_date = ?", queryDate).Scan(&totalRecords)
		totalPages := int(math.Ceil(float64(totalRecords) / float64(perPage)))
		if totalPages == 0 {
			totalPages = 1
		}
		offset := (page - 1) * perPage

		// 數值化 IP 排序
		rows, err := db.Query(`
			SELECT ip, mac, hostname, state, duration, leasetime, record_date
			FROM dhcp_leases
			WHERE record_date = ?
			ORDER BY 
			  CAST(substr(ip, 1, instr(ip, '.') - 1) AS INT),
			  CAST(substr(substr(ip, instr(ip, '.') + 1), 1, instr(substr(ip, instr(ip, '.') + 1), '.') - 1) AS INT),
			  CAST(substr(substr(substr(ip, instr(ip, '.') + 1), instr(substr(ip, instr(ip, '.') + 1), '.') + 1), 1, instr(substr(substr(ip, instr(ip, '.') + 1), instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.') - 1) AS INT),
			  CAST(substr(substr(substr(ip, instr(ip, '.') + 1), instr(substr(ip, instr(ip, '.') + 1), '.') + 1), instr(substr(substr(ip, instr(ip, '.') + 1), instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.') + 1) AS INT),
			  id ASC
			LIMIT ? OFFSET ?
		`, queryDate, perPage, offset)

		type LeaseItem struct {
			IP         string `json:"ip"`
			MAC        string `json:"mac"`
			Hostname   string `json:"hostname"`
			State      string `json:"state"`
			Duration   int    `json:"duration"`
			Leasetime  string `json:"leasetime"`
			RecordDate string `json:"record_date"`
		}

		var dataList []LeaseItem
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var it LeaseItem
				var hn sql.NullString
				_ = rows.Scan(&it.IP, &it.MAC, &hn, &it.State, &it.Duration, &it.Leasetime, &it.RecordDate)
				it.Hostname = hn.String
				dataList = append(dataList, it)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"data":          dataList,
			"current_page":  page,
			"total_pages":   totalPages,
			"total_records": totalRecords,
			"selected_date": queryDate,
		})
	})

	// 8. XML 檔案上傳匯入
	r.POST("/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": "沒有收到檔案"})
			return
		}

		uploadDate := c.DefaultPostForm("record_date", time.Now().Format("2006-01-02"))
		f, err := file.Open()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		defer f.Close()

		bytesData, err := io.ReadAll(f)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		success, duplicate, multiLease, uniqueCount, err := parseAndInsertXML(bytesData, uploadDate)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":            "success",
			"message":           fmt.Sprintf("檔案已成功匯入至【%s】！", uploadDate),
			"success_count":     success,
			"duplicate_count":   duplicate,
			"multi_lease_count": multiLease,
			"unique_ip_count":   uniqueCount,
			"record_date":       uploadDate,
		})
	})

	// 9. 資安威脅排行分析
	r.GET("/api/threat-analytics", func(c *gin.Context) {
		entries, err := fetchPAThreatLogs(150)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		todayStr := time.Now().Format("2006-01-02")
		db, _ := initDB()
		dhcpMap := make(map[string]map[string]string)
		if db != nil {
			rows, err := db.Query("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", todayStr)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var ip, mac, hn string
					_ = rows.Scan(&ip, &mac, &hn)
					dhcpMap[ip] = map[string]string{"mac": mac, "hostname": hn}
				}
			}
		}

		severityDist := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
		sourceCounter := make(map[string]int)
		threatCounter := make(map[string]int)

		type ThreatLogRecord struct {
			Time       string `json:"time"`
			Src        string `json:"src"`
			Hostname   string `json:"hostname"`
			MAC        string `json:"mac"`
			IsInternal bool   `json:"is_internal"`
			Dst        string `json:"dst"`
			ThreatName string `json:"threat_name"`
			Subtype    string `json:"subtype"`
			Severity   string `json:"severity"`
			Action     string `json:"action"`
			App        string `json:"app"`
		}

		var records []ThreatLogRecord
		for _, e := range entries {
			src := strings.TrimSpace(e.Src)
			dst := strings.TrimSpace(e.Dst)
			threatName := strings.TrimSpace(e.ThreatID)
			if threatName == "" {
				threatName = strings.TrimSpace(e.ThreatName)
			}
			if threatName == "" {
				threatName = "未知威脅"
			}
			subtype := strings.TrimSpace(e.Subtype)
			sev := strings.ToLower(strings.TrimSpace(e.Severity))
			if sev == "" {
				sev = "low"
			}
			action := strings.TrimSpace(e.Action)
			logTime := strings.TrimSpace(e.TimeGenerated)
			if logTime == "" {
				logTime = strings.TrimSpace(e.ReceiveTime)
			}
			app := strings.TrimSpace(e.App)

			if _, ok := severityDist[sev]; ok {
				severityDist[sev]++
			} else {
				severityDist["low"]++
			}

			sourceCounter[src]++
			threatCounter[threatName]++

			dhcpInfo := dhcpMap[src]
			hn := "-"
			mac := "-"
			isInternal := false
			if dhcpInfo != nil {
				hn = dhcpInfo["hostname"]
				mac = dhcpInfo["mac"]
				isInternal = true
			}

			records = append(records, ThreatLogRecord{
				Time:       logTime,
				Src:        src,
				Hostname:   hn,
				MAC:        mac,
				IsInternal: isInternal,
				Dst:        dst,
				ThreatName: threatName,
				Subtype:    subtype,
				Severity:   sev,
				Action:     action,
				App:        app,
			})
		}

		type Pair struct {
			Key   string
			Count int
		}
		var srcPairs []Pair
		for k, v := range sourceCounter {
			srcPairs = append(srcPairs, Pair{k, v})
		}
		sort.Slice(srcPairs, func(i, j int) bool { return srcPairs[i].Count > srcPairs[j].Count })

		type TopSource struct {
			IP       string `json:"ip"`
			Count    int    `json:"count"`
			Hostname string `json:"hostname"`
			MAC      string `json:"mac"`
		}
		var topSources []TopSource
		for i := 0; i < len(srcPairs) && i < 5; i++ {
			hn := "外部/非DHCP"
			mac := "-"
			if dhcpMap[srcPairs[i].Key] != nil {
				hn = dhcpMap[srcPairs[i].Key]["hostname"]
				mac = dhcpMap[srcPairs[i].Key]["mac"]
			}
			topSources = append(topSources, TopSource{
				IP:       srcPairs[i].Key,
				Count:    srcPairs[i].Count,
				Hostname: hn,
				MAC:      mac,
			})
		}

		var threatPairs []Pair
		for k, v := range threatCounter {
			threatPairs = append(threatPairs, Pair{k, v})
		}
		sort.Slice(threatPairs, func(i, j int) bool { return threatPairs[i].Count > threatPairs[j].Count })

		type TopThreat struct {
			ThreatName string `json:"threat_name"`
			Count      int    `json:"count"`
		}
		var topThreats []TopThreat
		for i := 0; i < len(threatPairs) && i < 5; i++ {
			topThreats = append(topThreats, TopThreat{ThreatName: threatPairs[i].Key, Count: threatPairs[i].Count})
		}

		maxLogs := len(records)
		if maxLogs > 50 {
			maxLogs = 50
		}

		c.JSON(http.StatusOK, gin.H{
			"status":        "success",
			"total_threats": len(records),
			"severity_dist": severityDist,
			"top_sources":   topSources,
			"top_threats":   topThreats,
			"logs":          records[:maxLogs],
		})
	})

	// 10. 🌟 PA-1420 ARP 即時比對分析 API (口徑對齊：固定 IP 統一為 185，消除跨日誤判，優先採用手動/歷史 MAC)
	r.GET("/api/arp-analysis", func(c *gin.Context) {
		_ = c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		pingRange := strings.TrimSpace(c.DefaultQuery("ping_range", ""))

		db, _ := initDB()

		if db != nil {
			_, _ = db.Exec(`
				CREATE TABLE IF NOT EXISTS arp_records (
					ip TEXT PRIMARY KEY,
					mac TEXT,
					interface TEXT DEFAULT 'Windows ARP',
					hostname TEXT DEFAULT '',
					dev_type TEXT DEFAULT '🚨 疑似私設 (未列管)',
					updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
				);
			`)
			_, _ = db.Exec("ALTER TABLE external_devices ADD COLUMN mac TEXT DEFAULT '';")
			_, _ = db.Exec("ALTER TABLE external_devices ADD COLUMN manual_state TEXT DEFAULT '';")
		}

		// 🌟 1. 執行 Windows Ping 掃描與 arp -a 提取
		winArpFoundCount := 0
		if pingRange != "" {
			scanIPs, err := parseIPRangeString(pingRange)
			if err == nil && len(scanIPs) > 0 {
				winMap, err := scanIPRangeAndGetWindowsARP(scanIPs)
				if err == nil && db != nil {
					winArpFoundCount = len(winMap)
					tx, _ := db.Begin()
					arpIfaceLabel := "Windows ARP"
					if runtime.GOOS != "windows" {
						arpIfaceLabel = "Linux ARP"
					}

					stmt, _ := tx.Prepare(fmt.Sprintf(`
						INSERT INTO arp_records (ip, mac, interface, updated_at) 
						VALUES (?, ?, '%s', CURRENT_TIMESTAMP)
						ON CONFLICT(ip) DO UPDATE SET 
							mac = excluded.mac, 
							interface = CASE WHEN arp_records.interface IS NULL OR arp_records.interface = '' OR arp_records.interface = '-' THEN '%s' ELSE arp_records.interface END,
							updated_at = CURRENT_TIMESTAMP
					`, arpIfaceLabel, arpIfaceLabel))
					for wIP, wMAC := range winMap {
						if stmt != nil {
							_, _ = stmt.Exec(wIP, wMAC)
						}
					}
					if stmt != nil {
						stmt.Close()
					}
					_ = tx.Commit()
				}
			}
		}

		// 🌟 2. 抓取 PA-1420 防火牆在線 ARP
		cmds := []string{
			"<show><arp><all/></show>",
			"<show><arp><entry name='all'/></arp></show>",
		}

		var livePAEntries []ARPEntry
		for _, cmd := range cmds {
			body, err := runPACommand(cmd)
			if err != nil {
				continue
			}
			decoder := xml.NewDecoder(bytes.NewReader(body))
			for {
				token, err := decoder.Token()
				if err != nil {
					break
				}
				if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
					var e ARPEntry
					if err := decoder.DecodeElement(&e, &se); err == nil {
						if strings.TrimSpace(e.IP) != "" && strings.TrimSpace(e.MAC) != "" {
							livePAEntries = append(livePAEntries, e)
						}
					}
				}
			}
			if len(livePAEntries) > 0 {
				break
			}
		}

		// 🌟 3. 將 PA-1420 即時 ARP 也存入 arp_records 永久保存
		if db != nil && len(livePAEntries) > 0 {
			tx, _ := db.Begin()
			stmt, _ := tx.Prepare(`
				INSERT INTO arp_records (ip, mac, interface, updated_at) 
				VALUES (?, ?, ?, CURRENT_TIMESTAMP)
				ON CONFLICT(ip) DO UPDATE SET 
					mac = excluded.mac, 
					interface = excluded.interface,
					updated_at = CURRENT_TIMESTAMP
			`)
			for _, e := range livePAEntries {
				cleanIP := strings.TrimSpace(e.IP)
				cleanMAC := strings.ToLower(strings.TrimSpace(e.MAC))
				if cleanIP != "" && cleanMAC != "" && cleanMAC != "(incomplete)" {
					if stmt != nil {
						_, _ = stmt.Exec(cleanIP, cleanMAC, strings.TrimSpace(e.Interface))
					}
				}
			}
			if stmt != nil {
				stmt.Close()
			}
			_ = tx.Commit()
		}

		// 🌟 4. 由資料庫中讀出歷史與本機掃描到的所有 ARP 記錄
		type MergedARPItem struct {
			IP        string
			MAC       string
			Interface string
		}
		mergedMap := make(map[string]MergedARPItem)

		if db != nil {
			rows, err := db.Query("SELECT ip, mac, COALESCE(interface, 'Windows ARP') FROM arp_records")
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var ip, mac, iface string
					_ = rows.Scan(&ip, &mac, &iface)
					ip = strings.TrimSpace(ip)
					mac = strings.ToLower(strings.TrimSpace(mac))
					if ip != "" && mac != "" && mac != "(incomplete)" {
						mergedMap[ip] = MergedARPItem{
							IP:        ip,
							MAC:       mac,
							Interface: iface,
						}
					}
				}
			}
		}

		for _, e := range livePAEntries {
			ip := strings.TrimSpace(e.IP)
			mac := strings.ToLower(strings.TrimSpace(e.MAC))
			if ip != "" && mac != "" && mac != "(incomplete)" {
				mergedMap[ip] = MergedARPItem{
					IP:        ip,
					MAC:       mac,
					Interface: strings.TrimSpace(e.Interface),
				}
			}
		}

		// 🌟 5. 撈取全量最新 DHCP 租約、歷史快取與已列管設備清冊
		dhcpRecords := make(map[string]map[string]string)
		historicalMACMap := make(map[string]string)
		dnsCacheMap := make(map[string]string)
		knownIPToMACMap := make(map[string]string)

		type ExtAsset struct {
			MAC         string
			Name        string
			DeviceType  string
			Brand       string
			Model       string
			Location    string
			ManualState string
		}
		externalMap := make(map[string]ExtAsset)

		if db != nil {
			// (A) 從 dhcp_leases 讀取所有 IP 曾出現過的最新 MAC
			rMAC1, err := db.Query("SELECT ip, mac FROM dhcp_leases WHERE mac != '' AND mac != '-' GROUP BY ip")
			if err == nil {
				defer rMAC1.Close()
				for rMAC1.Next() {
					var ip, mac string
					_ = rMAC1.Scan(&ip, &mac)
					cleanIP := strings.TrimSpace(ip)
					cleanMAC := strings.ToLower(strings.TrimSpace(mac))
					if cleanIP != "" && cleanMAC != "" {
						knownIPToMACMap[cleanIP] = cleanMAC
					}
				}
			}

			// (B) 從 arp_records 補足 Windows Ping 掃描或歷史 ARP 曾取得過的 MAC
			rMAC2, err := db.Query("SELECT ip, mac FROM arp_records WHERE mac != '' AND mac != '-' AND mac != '(incomplete)'")
			if err == nil {
				defer rMAC2.Close()
				for rMAC2.Next() {
					var ip, mac string
					_ = rMAC2.Scan(&ip, &mac)
					cleanIP := strings.TrimSpace(ip)
					cleanMAC := strings.ToLower(strings.TrimSpace(mac))
					if cleanIP != "" && cleanMAC != "" {
						knownIPToMACMap[cleanIP] = cleanMAC
					}
				}
			}

			// (C) 全量最新 DHCP 租約 (不限單日，口徑與資產清冊一致)
			r1, err := db.Query("SELECT ip, mac, hostname FROM dhcp_leases GROUP BY ip")
			if err == nil {
				defer r1.Close()
				for r1.Next() {
					var ip, mac, hn string
					_ = r1.Scan(&ip, &mac, &hn)
					dhcpRecords[ip] = map[string]string{"mac": strings.ToLower(mac), "hostname": hn}
				}
			}

			// (D) 歷史 DHCP 租約主機名
			r2, err := db.Query("SELECT mac, hostname FROM dhcp_leases WHERE hostname != '' AND hostname IS NOT NULL ORDER BY id ASC")
			if err == nil {
				defer r2.Close()
				for r2.Next() {
					var mac, hn string
					_ = r2.Scan(&mac, &hn)
					historicalMACMap[strings.ToLower(mac)] = hn
				}
			}

			// (E) DNS 反解 PTR 快取
			r3, err := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
			if err == nil {
				defer r3.Close()
				for r3.Next() {
					var ip, hn string
					_ = r3.Scan(&ip, &hn)
					dnsCacheMap[ip] = hn
				}
			}

			// (F) 撈取 external_devices 中包含手動輸入的 mac
			r4, err := db.Query("SELECT ip, COALESCE(mac, ''), name, device_type, brand, model, location, COALESCE(manual_state, '') FROM external_devices")
			if err == nil {
				defer r4.Close()
				for r4.Next() {
					var ip, mac, name, dtype, brand, model, loc, mstate string
					_ = r4.Scan(&ip, &mac, &name, &dtype, &brand, &model, &loc, &mstate)
					cleanIP := strings.TrimSpace(ip)
					cleanMAC := strings.ToLower(strings.TrimSpace(mac))
					if cleanIP != "" {
						externalMap[cleanIP] = ExtAsset{
							MAC:         cleanMAC,
							Name:        strings.TrimSpace(name),
							DeviceType:  strings.TrimSpace(dtype),
							Brand:       strings.TrimSpace(brand),
							Model:       strings.TrimSpace(model),
							Location:    strings.TrimSpace(loc),
							ManualState: strings.TrimSpace(mstate),
						}
						// 手動輸入的 MAC 亦自動注入反查快取
						if cleanMAC != "" && cleanMAC != "-" {
							knownIPToMACMap[cleanIP] = cleanMAC
						}
					}
				}
			}
		}

		// 🌟 6. 定義回傳前端之結構體 (含 Category 欄位宣告)
		type ARPResult struct {
			IP        string `json:"ip"`
			MAC       string `json:"mac"`
			Interface string `json:"interface"`
			Hostname  string `json:"hostname"`
			DevType   string `json:"dev_type"`
			TagClass  string `json:"tag_class"`
			Category  string `json:"category"`
		}

		var results []ARPResult
		managedStaticCount, rogueCount, normalCount, conflictCount := 0, 0, 0, 0

		// 🌟 7. 遍歷在線 ARP 設備清單
		for _, it := range mergedMap {
			ip := it.IP
			mac := it.MAC

			ext, hasExt := externalMap[ip]
			d, hasDHCP := dhcpRecords[ip]

			// 🌟 【地點一】現場若未抓到 MAC，優先取用管理員手動維護的 ext.MAC
			if (mac == "" || mac == "-" || mac == "(incomplete)") && hasExt && ext.MAC != "" && ext.MAC != "-" {
				mac = ext.MAC
			}

			var hostname string
			var hasValidName bool

			if hasExt && ext.Name != "" && ext.Name != "-" && ext.Name != "待解析" {
				metaDesc := ""
				if ext.Brand != "" || ext.Model != "" {
					metaDesc = fmt.Sprintf(" (%s %s)", ext.Brand, ext.Model)
				} else if ext.DeviceType != "" && ext.DeviceType != "-" {
					metaDesc = fmt.Sprintf(" (%s)", ext.DeviceType)
				}
				hostname = fmt.Sprintf("<span class='text-primary fw-bold'><i class='bi bi-hdd-network-fill me-1'></i>%s</span><small class='text-muted font-monospace'>%s</small>", ext.Name, metaDesc)
				hasValidName = true
			} else if hasDHCP && d["hostname"] != "" && d["hostname"] != "-" && d["hostname"] != "(無主機名)" {
				hostname = fmt.Sprintf("<span class='fw-bold text-dark'>%s</span>", d["hostname"])
				hasValidName = true
			} else if h, ok := dnsCacheMap[ip]; ok && h != "" {
				hostname = fmt.Sprintf("<span class='text-primary fw-bold'><i class='bi bi-globe me-1'></i>%s</span>", h)
				hasValidName = true
			} else if h, ok := historicalMACMap[mac]; ok && h != "" {
				hostname = fmt.Sprintf("<span class='text-secondary'><i class='bi bi-clock-history me-1'></i>%s (歷史)</span>", h)
				hasValidName = true
			}

			if !hasValidName {
				hostname = "<span class='text-muted'>待解析</span>"
			}

			var devType, tagClass, category string
			if hasDHCP && d["mac"] != mac {
				devType = "⚠️ IP 衝突/MAC變更"
				tagClass = "danger"
				category = "CONFLICT"
				conflictCount++
			} else if (hasExt && ext.ManualState == "STATIC") || (hasExt && ext.Name != "" && ext.Name != "-" && !hasDHCP) {
				devLabel := ext.DeviceType
				if devLabel == "" || devLabel == "-" {
					devLabel = "固定 IP"
				}
				devType = fmt.Sprintf("🔵 已列管固定 IP (%s)", devLabel)
				tagClass = "primary"
				category = "STATIC"
				managedStaticCount++
			} else if hasDHCP && (hasExt && ext.ManualState == "DHCP" || !hasExt) {
				devType = "🟢 DHCP 動態配發"
				tagClass = "success"
				category = "DHCP"
				normalCount++
			} else if hasExt && ext.ManualState == "ROGUE" {
				devType = "🚨 私設 IP (未列管)"
				tagClass = "danger"
				category = "ROGUE"
				rogueCount++
			} else {
				devType = "🚨 疑似私設 (未列管)"
				tagClass = "warning"
				category = "ROGUE"
				rogueCount++
			}

			results = append(results, ARPResult{
				IP:        ip,
				MAC:       mac,
				Interface: it.Interface,
				Hostname:  hostname,
				DevType:   devType,
				TagClass:  tagClass,
				Category:  category,
			})
		}

		// 🌟 8. 【核心對齊】：將 external_devices 中列管但離線的固定 IP 一併加入
		for extIP, ext := range externalMap {
			if _, exists := mergedMap[extIP]; !exists {
				if ext.ManualState == "STATIC" || (ext.Name != "" && ext.Name != "-" && ext.ManualState != "ROGUE" && ext.ManualState != "DHCP") {
					// 🌟 【地點二】優先使用手動輸入的 ext.MAC，次之歷史快取，最後租約
					macVal := "-"
					if ext.MAC != "" && ext.MAC != "-" {
						macVal = ext.MAC
					} else if m, ok := knownIPToMACMap[extIP]; ok && m != "" && m != "-" {
						macVal = m
					} else if d, ok := dhcpRecords[extIP]; ok && d["mac"] != "" && d["mac"] != "-" {
						macVal = d["mac"]
					}

					results = append(results, ARPResult{
						IP:        extIP,
						MAC:       macVal,
						Interface: "未在線 (離線)",
						Hostname:  fmt.Sprintf("<span class='text-secondary'><i class='bi bi-hdd-network me-1'></i>%s (未在線)</span>", ext.Name),
						DevType:   fmt.Sprintf("⚪ 已列管固定 IP (%s / 未在線)", ext.DeviceType),
						TagClass:  "secondary",
						Category:  "STATIC",
					})
					managedStaticCount++
				}
			}
		}

		// 依照 IP 數值大小自然排序
		sort.Slice(results, func(i, j int) bool {
			ipA := net.ParseIP(results[i].IP).To4()
			ipB := net.ParseIP(results[j].IP).To4()
			if ipA != nil && ipB != nil {
				return ipToUint32(ipA) < ipToUint32(ipB)
			}
			return results[i].IP < results[j].IP
		})

		c.JSON(http.StatusOK, gin.H{
			"status":               "success",
			"total_arp":            len(results),
			"normal_dhcp_count":    normalCount,
			"managed_static_count": managedStaticCount,
			"rogue_ip_count":       rogueCount,
			"conflict_count":       conflictCount,
			"windows_arp_found":    winArpFoundCount,
			"data":                 results,
		})
	})
	
	// 11. 流量日誌檢索與直方圖數據 API
	r.GET("/api/traffic-query", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		date = strings.ReplaceAll(strings.TrimSpace(date), "/", "-")
		src := strings.TrimSpace(c.DefaultQuery("src", ""))
		dst := strings.TrimSpace(c.DefaultQuery("dst", ""))
		app := strings.TrimSpace(c.DefaultQuery("app", ""))
		action := strings.TrimSpace(c.DefaultQuery("action", "all"))
		zone := strings.TrimSpace(c.DefaultQuery("zone", "all"))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
		onlyLogs := c.DefaultQuery("only_logs", "false") == "true"
		order := strings.ToUpper(strings.TrimSpace(c.DefaultQuery("order", "DESC")))
		if order != "ASC" && order != "DESC" {
			order = "DESC"
		}
		totalCount, _ := strconv.ParseInt(c.DefaultQuery("total_count", "0"), 10, 64)

		// 🌟 接收首屏秒開與背景計數參數
		firstLoad := c.DefaultQuery("first_load", "false") == "true"
		countOnly := c.DefaultQuery("count_only", "false") == "true"

		result, err := queryTrafficAnalytics(date, src, dst, app, action, zone, page, perPage, onlyLogs, order, totalCount, firstLoad, countOnly)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		// 🌟 若僅為背景彙算總數 (count_only)，僅回傳統計數據以節省網路頻寬
		if countOnly {
			c.JSON(http.StatusOK, gin.H{
				"status":      "success",
				"total_flows": result.TotalFlows,
				"total_bytes": result.TotalBytes,
				"top_app":     result.TopApp,
				"deny_flows":  result.DenyFlows,
				"db_size":     result.DbSize,
				"histogram":   result.Histogram,
				"total_pages": result.TotalPages,
			})
			return
		}

		// 🌟 正常回傳（包含首屏 50/100/200 筆明細）
		c.JSON(http.StatusOK, gin.H{
			"status":       "success",
			"total_flows":  result.TotalFlows,
			"total_bytes":  result.TotalBytes,
			"top_app":      result.TopApp,
			"deny_flows":   result.DenyFlows,
			"db_size":      result.DbSize,
			"histogram":    result.Histogram,
			"logs":         result.Logs,
			"current_page": result.CurrentPage,
			"total_pages":  result.TotalPages,
		})
	})
	
	// 12. 立即手動自 PA-1420 擷取最新流量 (預設 2500 筆，最高支援 5000 筆)
	r.POST("/api/traffic-fetch-now", func(c *gin.Context) {
		count, _ := strconv.Atoi(c.DefaultPostForm("count", "2500"))
		if count <= 0 {
			count = 2500
		}
		if count > 5000 {
			count = 5000
		}

		entries, err := fetchPATrafficLogs(count)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		success, total, err := saveTrafficLogsToParquet(entries)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("成功自 %s 擷取 %d 筆流量紀錄！新增至當日 Parquet：%d 筆，今日累計：%d 筆", getFWModelName(), len(entries), success, total),
		})
	})
	
	// 12-2. 🌟 立即手動自 PA-1420 擷取最新資安威脅日誌 (預設 2500 筆，最高 5000 筆)
	r.POST("/api/threat-fetch-now", func(c *gin.Context) {
		countStr := strings.TrimSpace(c.Query("count"))
		if countStr == "" {
			countStr = strings.TrimSpace(c.PostForm("count"))
		}
		if countStr == "" {
			countStr = strings.TrimSpace(c.Request.FormValue("count"))
		}

		count, _ := strconv.Atoi(countStr)
		if count <= 0 {
			count = 2500
		}
		if count > 5000 {
			count = 5000
		}

		// 呼叫過濾器函式 (filter="" 代表無條件抓取當前最新日誌，且時間戳記已自動轉為標準格式)
		entries, err := fetchPAThreatLogsWithFilter(count, "")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		success, total, err := saveThreatLogsToParquet(entries)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("成功自 %s 擷取 %d 筆威脅紀錄！新增入庫：%d 筆，該檔案累計：%d 筆", getFWModelName(), len(entries), success, total),
		})
	})

	// 13. 查詢後端流量排程器狀態 (供前端載入或 F5 時同步狀態)
	r.GET("/api/traffic-scheduler", func(c *gin.Context) {
		status := GetTrafficSchedulerStatus()
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   status,
		})
	})

	// 14. 設定後端流量排程器頻率 (10s, 30s, 60s, 0=手動)
	r.POST("/api/traffic-scheduler", func(c *gin.Context) {
		interval, _ := strconv.Atoi(c.DefaultPostForm("interval", "0"))
		SetTrafficSchedulerInterval(interval)
		status := GetTrafficSchedulerStatus()
		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": "後端排程頻率已更新",
			"data":    status,
		})
	})

	// 15. 查詢 Syslog 即時接收與 Flush 狀態 (強制禁用瀏覽器快取)
	r.GET("/api/syslog-status", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		status := GetSyslogStatus()
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   status,
		})
	})

	// 16. 🌟 智慧接力回溯 (即時分輪串流輸出)：支援當日智慧斷點續傳與指定時間回溯
	r.POST("/api/traffic-backfill", func(c *gin.Context) {
		// 🌟 1. 優先讀取所有傳入參數 (同時相容 URL Query 與 POST 表單)
		customBefore := strings.TrimSpace(c.Query("before"))
		if customBefore == "" { customBefore = strings.TrimSpace(c.PostForm("before")) }
		if customBefore == "" { customBefore = strings.TrimSpace(c.Request.FormValue("before")) }
		customBefore = strings.ReplaceAll(customBefore, "/", "-")

		// 🌟 核心防呆：如果傳入的時間只有 "23:59:59" (長度 <= 8)，自動補上今日日期
		if len(customBefore) > 0 && len(customBefore) <= 8 {
			customBefore = time.Now().Format("2006-01-02") + " " + customBefore
		}

		targetDate := strings.TrimSpace(c.Query("date"))
		if targetDate == "" { targetDate = strings.TrimSpace(c.PostForm("date")) }
		if targetDate == "" { targetDate = strings.TrimSpace(c.Request.FormValue("date")) }
		targetDate = strings.ReplaceAll(targetDate, "/", "-")

		isLimit := c.DefaultQuery("limit", "false") == "true" || c.DefaultPostForm("limit", "false") == "true"

		roundsStr := strings.TrimSpace(c.Query("rounds"))
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.PostForm("rounds")) }
		rounds, _ := strconv.Atoi(roundsStr)
		if rounds <= 0 { rounds = 5 }
		if rounds > 10 {
			rounds = 10
		}

		// 🌟 2. 啟用 HTTP 分塊串流 (停用緩衝)
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		// 定義即時輸出小函式
		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush()
		}

		lastTime := customBefore

		// 🌟 3. 當日斷點續傳探測 (00:00:00 邊界防護)
		if lastTime == "" && targetDate != "" {
			dayFile := filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", targetDate))
			rows, err := parquet.ReadFile[TrafficParquetRow](dayFile)
			if err == nil && len(rows) > 0 {
				oldestInDay := rows[len(rows)-1].Timestamp

				// 🛑 邊界防線：若最舊紀錄已小於等於 00:00:00，代表該日已回補到底
				if oldestInDay <= targetDate+" 00:00:00" {
					sendMsg("[流量回補] 🎯 %s 本地記錄已涵蓋至當日 00:00:00 (最舊連線：%s)，該日回溯已達標，無需向前回補！\n", targetDate, oldestInDay)
					_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
					return
				}

				t, err := time.Parse("2006-01-02 15:04:05", oldestInDay)
				if err == nil {
					lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
					sendMsg("[流量回補] 🎯 偵測到 %s 已有歷史資料，自動從最舊連線 %s 接力往前回溯！\n", targetDate, oldestInDay)
				}
			} else {
				lastTime = targetDate + " 23:59:59"
				sendMsg("[流量回補] 🎯 %s 尚無歷史日誌，自動自當日 23:59:59 起跑\n", targetDate)
			}
		}

		// 🌟 4. 全庫最舊時間搜尋
		if lastTime == "" {
			files, _ := filepath.Glob(filepath.Join(trafficDir, "traffic_*.parquet"))
			sort.Strings(files)
			for _, f := range files {
				if strings.HasSuffix(f, ".tmp") {
					continue
				}
				rows, err := parquet.ReadFile[TrafficParquetRow](f)
				if err == nil && len(rows) > 0 {
					oldestInDB := rows[len(rows)-1].Timestamp
					t, err := time.Parse("2006-01-02 15:04:05", oldestInDB)
					if err == nil {
						lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
						sendMsg("[流量回補] 🎯 鎖定資料庫最舊連線 %s，接續向前回溯\n", oldestInDB)
						break
					}
				}
			}
		} else {
			if targetDate != "" {
				sendMsg("[流量回補] 🎯 收到指定時間點：%s (邊界目標：%s 00:00:00)\n", lastTime, targetDate)
			} else {
				sendMsg("[流量回補] 🎯 收到指定時間點：%s，將以此為起點向前回溯\n", lastTime)
			}
		}

		// 🌟 【在此處插入】依據防火牆型號自動判斷並印出性能模式
		modelName := getFWModelName()
		if isHighEndFirewall() {
			sendMsg("[流量回補] 🚀 偵測到旗艦機型 [%s]：啟用極速回溯模式 (輪詢: 200ms / 間隔: 200ms)\n", modelName)
		} else {
			sendMsg("[流量回補] 🛡️ 偵測到標準機型 [%s]：啟用防護回溯模式 (輪詢: 600ms / 間隔: 1.5s)\n", modelName)
		}

		sendMsg("[流量回補] 🚀 啟動回溯作業，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		totalRaw := 0           // 👈 🌟 補上：冷資料累計計數器
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			// 原本：sendMsg("[流量回補] ⏳ [%d/%d] 正在向 PA-1420 請求資料 (過濾條件: %s)...\n", r+1, rounds, filter)
			sendMsg("[流量回補] ⏳ [%d/%d] 正在向 %s 請求資料 (過濾條件: %s)...\n", r+1, rounds, getFWModelName(), filter)

			entries, err := fetchPATrafficLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[流量回補] ⚠️ 第 %d 輪擷取逾時或失敗：%v (提前結束)\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[流量回補] ℹ️ 第 %d 輪已無更早的歷史日誌 (已達極限)\n", r+1)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			ins, _, err := saveTrafficLogsToParquet(entries)
			if err != nil {
				sendMsg("[流量回補] ❌ 存入磁碟發生錯誤：%v\n", err)
			} else {
				totalNew += ins
				totalRaw += len(entries)
				successfulRounds++
			}

			oldest := entries[0].Timestamp
			for _, e := range entries {
				if e.Timestamp < oldest {
					oldest = e.Timestamp
				}
			}

			dupCount := len(entries) - ins
			sendMsg("[流量回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，真實新增: %d 筆 (略過重複: %d 筆)，時間推進至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, dupCount, oldest)
				
		    // 🌟 向批次檔視窗推送冷資料落盤戰報
			//sendMsg("   ↳ ❄️ [Raw Log 備份] 原始 XML 已落盤: %d 筆 ➔ traffic_raw_logs/\n", len(entries))

			// 🌟 無論此輪新增多少，時間嚴格往前推 1 秒，確保持續穿越已記錄區間去抓前面的缺漏
			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			// 🌟 僅在「非 Limit 模式」下才在跨越 00:00 時終止；Limit 模式下持續跨日深挖
			if !isLimit && targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[Raw 取回] 🎯 已達成當日 00:00:00 邊界！\n")
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			if r < rounds-1 {
				_, roundSleep := getAdaptiveBackfillTimings()
				time.Sleep(roundSleep) // 🌟 5250 自動改為 0.2 秒，1420 自動維持 1.5 秒
			}
		}

		sendMsg("🏁 [流量回補] 完成！共執行 %d 輪，熱檔新增: %d 筆，歷史時間已向前推進至 %s。\n", 
			successfulRounds, totalNew, lastTime)
	})

	// 17. 🌟 智慧接力回溯：向 PA-1420 擷取歷史資安威脅 (即時分輪串流輸出)
	r.POST("/api/threat-backfill", func(c *gin.Context) {
		// 🌟 1. 優先讀取所有傳入參數
		customBefore := strings.TrimSpace(c.Query("before"))
		if customBefore == "" {
			customBefore = strings.TrimSpace(c.PostForm("before"))
		}
		if customBefore == "" {
			customBefore = strings.TrimSpace(c.Request.FormValue("before"))
		}
		customBefore = strings.ReplaceAll(customBefore, "/", "-")

		targetDate := strings.TrimSpace(c.Query("date"))
		if targetDate == "" {
			targetDate = strings.TrimSpace(c.PostForm("date"))
		}
		if targetDate == "" {
			targetDate = strings.TrimSpace(c.Request.FormValue("date"))
		}
		targetDate = strings.ReplaceAll(targetDate, "/", "-")

		// 🌟 自動萃取日期邊界
		if targetDate == "" && len(customBefore) >= 10 {
			targetDate = customBefore[:10]
		}

		roundsStr := strings.TrimSpace(c.Query("rounds"))
		if roundsStr == "" {
			roundsStr = strings.TrimSpace(c.PostForm("rounds"))
		}
		if roundsStr == "" {
			roundsStr = strings.TrimSpace(c.Request.FormValue("rounds"))
		}
		rounds, _ := strconv.Atoi(roundsStr)
		if rounds <= 0 {
			rounds = 5
		}
		if rounds > 10 {
			rounds = 10
		}

		// 🌟 2. 啟用 HTTP 分塊串流
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush()
		}

		lastTime := customBefore

		// 🌟 3. 當日斷點續傳探測 (補齊 00:00:00 邊界防護)
		if lastTime == "" && targetDate != "" {
			dayFile := filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", targetDate))
			rows, err := parquet.ReadFile[ThreatParquetRow](dayFile)
			if err == nil && len(rows) > 0 {
				oldestInDay := rows[len(rows)-1].Timestamp

				// 🛑 補上 Threat 邊界防線
				if oldestInDay <= targetDate+" 00:00:00" {
					sendMsg("[Threat 回補] 🎯 %s 本地威脅已涵蓋至當日 00:00:00 (最舊紀錄：%s)，該日回溯已達標，無需向前回補！\n", targetDate, oldestInDay)
					_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
					return
				}

				t, err := time.Parse("2006-01-02 15:04:05", oldestInDay)
				if err == nil {
					lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
					sendMsg("[Threat 回補] 🎯 偵測到 %s 已有威脅資料，自動從最舊事件 %s 接力往前回溯！\n", targetDate, oldestInDay)
				}
			} else {
				lastTime = targetDate + " 23:59:59"
				sendMsg("[Threat 回補] 🎯 %s 尚無威脅日誌，自動自當日 23:59:59 起跑\n", targetDate)
			}
		}

		// 🌟 4. 全庫最舊時間搜尋
		if lastTime == "" {
			files, _ := filepath.Glob(filepath.Join(threatDir, "threat_*.parquet"))
			sort.Strings(files)
			for _, f := range files {
				if strings.HasSuffix(f, ".tmp") {
					continue
				}
				rows, err := parquet.ReadFile[ThreatParquetRow](f)
				if err == nil && len(rows) > 0 {
					oldestInDB := rows[len(rows)-1].Timestamp
					t, err := time.Parse("2006-01-02 15:04:05", oldestInDB)
					if err == nil {
						lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
						sendMsg("[Threat 回補] 🎯 鎖定資料庫最舊威脅 %s，接續向前回溯\n", oldestInDB)
						break
					}
				}
			}
		} else {
			// 修正提示文字判斷
			if targetDate != "" {
				sendMsg("[Threat 回補] 🎯 收到指定時間點：%s (邊界目標：%s 00:00:00)\n", lastTime, targetDate)
			} else {
				sendMsg("[Threat 回補] 🎯 收到指定時間點：%s，將以此為起點向前回溯\n", lastTime)
			}
		}

		sendMsg("[Threat 回補] 🚀 啟動資安威脅回溯，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		totalRaw := 0           // 👈 🌟 補上：威脅冷資料累計計數器
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[Threat 回補] ⏳ [%d/%d] 正在向 %s 擷取威脅日誌 (條件: %s)...\n", r+1, rounds, getFWModelName(), filter)

			entries, err := fetchPAThreatLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[Threat 回補] ⚠️ 第 %d 輪擷取失敗：%v\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[Threat 回補] ℹ️ 第 %d 輪已無更早的威脅日誌\n", r+1)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			ins, tot, err := saveThreatLogsToParquet(entries)
			if err != nil {
				// 修正錯誤標籤
				sendMsg("[Threat 回補] ❌ 存入磁碟發生錯誤：%v\n", err)
			} else {
				totalNew += ins
				totalRaw += len(entries) // 👈 🌟 累加筆數
				successfulRounds++
			}

			oldest := entries[0].TimeGenerated
			for _, e := range entries {
				if e.TimeGenerated < oldest {
					oldest = e.TimeGenerated
				}
			}

			sendMsg("[Threat 回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (累計: %d 筆)，時間推至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, tot, oldest)
				
			// 🌟 核心新增：向批次檔視窗推送威脅冷資料進度
			sendMsg("   ↳ ❄️ [Raw Log 備份] 原始 XML 已落盤: %d 筆 ➔ threat_raw_logs/\n", len(entries))

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			// 🛑 迴圈內部關鍵煞車機制
			if targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[Threat 回補] 🎯 已成功回溯至當日 00:00:00 邊界 (時間至: %s)，任務圓滿達成！\n", lastTime)
				break
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [Threat 回補] 完成！共執行 %d 輪，熱檔新增: %d 筆，冷資料 (Raw Log) 備份: %d 筆，時間已推進至 %s。\n", 
			successfulRounds, totalNew, totalRaw, lastTime)
	})
	
	// 🌟 17-2. 智慧接力回溯：向 PA-1420 擷取歷史系統紀錄 (即時分輪串流輸出)
	r.POST("/api/system-backfill", func(c *gin.Context) {
		customBefore := strings.TrimSpace(c.Query("before"))
		if customBefore == "" { customBefore = strings.TrimSpace(c.PostForm("before")) }
		if customBefore == "" { customBefore = strings.TrimSpace(c.Request.FormValue("before")) }
		customBefore = strings.ReplaceAll(customBefore, "/", "-")

		targetDate := strings.TrimSpace(c.Query("date"))
		if targetDate == "" { targetDate = strings.TrimSpace(c.PostForm("date")) }
		if targetDate == "" { targetDate = strings.TrimSpace(c.Request.FormValue("date")) }
		targetDate = strings.ReplaceAll(targetDate, "/", "-")

		if targetDate == "" && len(customBefore) >= 10 {
			targetDate = customBefore[:10]
		}

		roundsStr := strings.TrimSpace(c.Query("rounds"))
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.PostForm("rounds")) }
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.Request.FormValue("rounds")) }
		rounds, _ := strconv.Atoi(roundsStr)
		if rounds <= 0 { rounds = 5 }
		if rounds > 10 { rounds = 10 }

		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush()
		}

		lastTime := customBefore

		if lastTime == "" && targetDate != "" {
			dayFile := filepath.Join(systemDir, fmt.Sprintf("system_%s.parquet", targetDate))
			rows, err := parquet.ReadFile[SystemParquetRow](dayFile)
			if err == nil && len(rows) > 0 {
				oldestInDay := rows[len(rows)-1].Timestamp
				if oldestInDay <= targetDate+" 00:00:00" {
					sendMsg("[System 回補] 🎯 %s 本地系統日誌已涵蓋至當日 00:00:00 (最舊紀錄：%s)，該日回溯已達標，無需向前回補！\n", targetDate, oldestInDay)
					_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
					return
				}

				t, err := time.Parse("2006-01-02 15:04:05", oldestInDay)
				if err == nil {
					lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
					sendMsg("[System 回補] 🎯 偵測到 %s 已有歷史資料，自動從最舊事件 %s 接力往前回溯！\n", targetDate, oldestInDay)
				}
			} else {
				lastTime = targetDate + " 23:59:59"
				sendMsg("[System 回補] 🎯 %s 尚無系統日誌，自動自當日 23:59:59 起跑\n", targetDate)
			}
		}

		if lastTime == "" {
			files, _ := filepath.Glob(filepath.Join(systemDir, "system_*.parquet"))
			sort.Strings(files)
			for _, f := range files {
				if strings.HasSuffix(f, ".tmp") { continue }
				rows, err := parquet.ReadFile[SystemParquetRow](f)
				if err == nil && len(rows) > 0 {
					oldestInDB := rows[len(rows)-1].Timestamp
					t, err := time.Parse("2006-01-02 15:04:05", oldestInDB)
					if err == nil {
						lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
						sendMsg("[System 回補] 🎯 鎖定資料庫最舊事件 %s，接續向前回溯\n", oldestInDB)
						break
					}
				}
			}
		} else {
			if targetDate != "" {
				sendMsg("[System 回補] 🎯 收到指定時間點：%s (邊界目標：%s 00:00:00)\n", lastTime, targetDate)
			} else {
				sendMsg("[System 回補] 🎯 收到指定時間點：%s，將以此為起點向前回溯\n", lastTime)
			}
		}

		sendMsg("[System 回補] 🚀 啟動系統日誌回溯，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		totalRaw := 0
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[System 回補] ⏳ [%d/%d] 正在向 %s 擷取系統日誌 (條件: %s)...\n", r+1, rounds, getFWModelName(), filter)

			entries, err := fetchPASystemLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[System 回補] ⚠️ 第 %d 輪擷取失敗：%v\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[System 回補] ℹ️ 第 %d 輪已無更早的系統日誌\n", r+1)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			ins, _, err := saveSystemLogsToParquet(entries)
			if err != nil {
				sendMsg("[System 回補] ❌ 存入磁碟發生錯誤：%v\n", err)
			} else {
				totalNew += ins
				totalRaw += len(entries)
				successfulRounds++
			}

			oldest := entries[0].TimeGenerated
			for _, e := range entries {
				if e.TimeGenerated < oldest {
					oldest = e.TimeGenerated
				}
			}

			dupCount := len(entries) - ins
			sendMsg("[System 回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (略過重複: %d 筆)，時間推至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, dupCount, oldest)
				
			sendMsg("   ↳ ❄️ [Raw Log 備份] 原始 XML 已落盤: %d 筆 ➔ system_raw_logs/\n", len(entries))

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			if targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[System 回補] 🎯 已成功回溯至當日 00:00:00 邊界 (時間至: %s)，任務圓滿達成！\n", lastTime)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [System 回補] 完成！共執行 %d 輪，熱檔新增: %d 筆，冷資料 (Raw Log) 備份: %d 筆，時間已推進至 %s。\n", 
			successfulRounds, totalNew, totalRaw, lastTime)
	})

	// 🌟 17-3. 智慧接力回溯：向 PA-1420 擷取歷史組態日誌 (即時分輪串流輸出)
	r.POST("/api/config-backfill", func(c *gin.Context) {
		customBefore := strings.TrimSpace(c.Query("before"))
		if customBefore == "" { customBefore = strings.TrimSpace(c.PostForm("before")) }
		if customBefore == "" { customBefore = strings.TrimSpace(c.Request.FormValue("before")) }
		customBefore = strings.ReplaceAll(customBefore, "/", "-")

		targetDate := strings.TrimSpace(c.Query("date"))
		if targetDate == "" { targetDate = strings.TrimSpace(c.PostForm("date")) }
		if targetDate == "" { targetDate = strings.TrimSpace(c.Request.FormValue("date")) }
		targetDate = strings.ReplaceAll(targetDate, "/", "-")

		if targetDate == "" && len(customBefore) >= 10 {
			targetDate = customBefore[:10]
		}

		roundsStr := strings.TrimSpace(c.Query("rounds"))
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.PostForm("rounds")) }
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.Request.FormValue("rounds")) }
		rounds, _ := strconv.Atoi(roundsStr)
		if rounds <= 0 { rounds = 5 }
		if rounds > 10 { rounds = 10 }

		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush()
		}

		lastTime := customBefore

		if lastTime == "" && targetDate != "" {
			dayFile := filepath.Join(configDir, fmt.Sprintf("config_%s.parquet", targetDate))
			rows, err := parquet.ReadFile[ConfigParquetRow](dayFile)
			if err == nil && len(rows) > 0 {
				oldestInDay := rows[len(rows)-1].Timestamp
				if oldestInDay <= targetDate+" 00:00:00" {
					sendMsg("[Config 回補] 🎯 %s 本地組態紀錄已涵蓋至當日 00:00:00 (最舊紀錄：%s)，該日回溯已達標，無需向前回補！\n", targetDate, oldestInDay)
					_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
					return
				}

				t, err := time.Parse("2006-01-02 15:04:05", oldestInDay)
				if err == nil {
					lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
					sendMsg("[Config 回補] 🎯 偵測到 %s 已有歷史資料，自動從最舊事件 %s 接力往前回溯！\n", targetDate, oldestInDay)
				}
			} else {
				lastTime = targetDate + " 23:59:59"
				sendMsg("[Config 回補] 🎯 %s 尚無組態日誌，自動自當日 23:59:59 起跑\n", targetDate)
			}
		}

		if lastTime == "" {
			files, _ := filepath.Glob(filepath.Join(configDir, "config_*.parquet"))
			sort.Strings(files)
			for _, f := range files {
				if strings.HasSuffix(f, ".tmp") { continue }
				rows, err := parquet.ReadFile[ConfigParquetRow](f)
				if err == nil && len(rows) > 0 {
					oldestInDB := rows[len(rows)-1].Timestamp
					t, err := time.Parse("2006-01-02 15:04:05", oldestInDB)
					if err == nil {
						lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
						sendMsg("[Config 回補] 🎯 鎖定資料庫最舊事件 %s，接續向前回溯\n", oldestInDB)
						break
					}
				}
			}
		} else {
			if targetDate != "" {
				sendMsg("[Config 回補] 🎯 收到指定時間點：%s (邊界目標：%s 00:00:00)\n", lastTime, targetDate)
			} else {
				sendMsg("[Config 回補] 🎯 收到指定時間點：%s，將以此為起點向前回溯\n", lastTime)
			}
		}

		sendMsg("[Config 回補] 🚀 啟動組態日誌回溯，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		totalRaw := 0
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[Config 回補] ⏳ [%d/%d] 正在向 %s 擷取組態日誌 (條件: %s)...\n", r+1, rounds, getFWModelName(), filter)

			entries, err := fetchPAConfigLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[Config 回補] ⚠️ 第 %d 輪擷取失敗：%v\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[Config 回補] ℹ️ 第 %d 輪已無更早的組態日誌\n", r+1)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			ins, _, err := saveConfigLogsToParquet(entries)
			if err != nil {
				sendMsg("[Config 回補] ❌ 存入磁碟發生錯誤：%v\n", err)
			} else {
				totalNew += ins
				totalRaw += len(entries)
				successfulRounds++
			}

			oldest := entries[0].TimeGenerated
			for _, e := range entries {
				if e.TimeGenerated < oldest {
					oldest = e.TimeGenerated
				}
			}

			dupCount := len(entries) - ins
			sendMsg("[Config 回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (略過重複: %d 筆)，時間推至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, dupCount, oldest)
				
			sendMsg("   ↳ ❄️ [Raw Log 備份] 原始 XML 已落盤: %d 筆 ➔ config_raw_logs/\n", len(entries))

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			if targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[Config 回補] 🎯 已成功回溯至當日 00:00:00 邊界 (時間至: %s)，任務圓滿達成！\n", lastTime)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [Config 回補] 完成！共執行 %d 輪，熱檔新增: %d 筆，冷資料 (Raw Log) 備份: %d 筆，時間已推進至 %s。\n", 
			successfulRounds, totalNew, totalRaw, lastTime)
	})
	
	// 🌟 18. Palo Alto 原生 HTTP/JSON Webhook 接收端點 (Traffic)
	r.POST("/api/webhook/traffic", func(c *gin.Context) {
		// 讀取 Raw Body 供冷資料備份
		rawBytes, err := io.ReadAll(c.Request.Body)
		if err != nil || len(rawBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
			return
		}

		var payload PAWebhookTrafficPayload
		if err := json.Unmarshal(rawBytes, &payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}

		// 格式正規化 (日期斜線轉橫線、型別轉換)
		ts := strings.ReplaceAll(strings.TrimSpace(payload.TimeGenerated), "/", "-")
		portVal, _ := strconv.Atoi(payload.ToPort)
		bytesVal, _ := strconv.ParseInt(payload.Bytes, 10, 64)

		row := TrafficParquetRow{
			Timestamp:        ts,
			Type:             payload.Type,
			FromZone:         payload.FromZone,
			ToZone:           payload.ToZone,
			Source:           payload.Source,
			NatSourceIP:      payload.NatSourceIP,
			Destination:      payload.Destination,
			NatDestIP:        payload.NatDestIP,
			ToPort:           int32(portVal),
			Application:      payload.Application,
			Action:           payload.Action,
			Rule:             payload.Rule,
			SessionEndReason: payload.SessionEndReason,
			Bytes:            bytesVal,
			SessionID:        payload.SessionID,
		}

		// 1. 推入熱資料寫入佇列
		select {
		case syslogQueue <- row:
			atomic.AddInt64(&syslogReceivedCount, 1)
		default:
		}

		// 2. 推入冷資料寫入佇列 (備份原始 JSON 內容)
		select {
		case rawTrafficQueue <- RawLogParquetRow{
			Timestamp:  ts,
			SessionID:  payload.SessionID,
			RawContent: string(rawBytes),
		}:
		default:
		}

		// 即時秒回 HTTP 200，避免 PA 防火牆等待導致佇列堵塞
		c.Status(http.StatusOK)
	})

	// 🌟 19. Palo Alto 原生 HTTP/JSON Webhook 接收端點 (Threat)
	r.POST("/api/webhook/threat", func(c *gin.Context) {
		rawBytes, err := io.ReadAll(c.Request.Body)
		if err != nil || len(rawBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "empty body"})
			return
		}

		var payload PAWebhookThreatPayload
		if err := json.Unmarshal(rawBytes, &payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}

		ts := strings.ReplaceAll(strings.TrimSpace(payload.TimeGenerated), "/", "-")
		portVal, _ := strconv.Atoi(payload.ToPort)
		tName := payload.ThreatName
		if tName == "" {
			tName = payload.ThreatID
		}

		row := ThreatParquetRow{
			Timestamp:   ts,
			Subtype:     payload.Subtype,
			ThreatID:    payload.ThreatID,
			ThreatName:  tName,
			FromZone:    payload.FromZone,
			ToZone:      payload.ToZone,
			Src:         payload.Source,
			Dst:         payload.Destination,
			ToPort:      int32(portVal),
			Application: payload.Application,
			Action:      payload.Action,
			Severity:    strings.ToLower(payload.Severity),
			URL:         payload.URL,
			SessionID:   payload.SessionID,
		}

		select {
		case threatSyslogQueue <- row:
			atomic.AddInt64(&threatSyslogReceivedCount, 1)
		default:
		}

		select {
		case rawThreatQueue <- RawLogParquetRow{
			Timestamp:  ts,
			SessionID:  payload.SessionID,
			RawContent: string(rawBytes),
		}:
		default:
		}

		c.Status(http.StatusOK)
	})
	
	// 🌟 20. CLI 高速匯出自動化 API (支援 CMD 每一秒即時動態串流，免傳帳密)
	r.POST("/api/cli-export", func(c *gin.Context) {
		var req CLIExportRequest
		if err := c.ShouldBind(&req); err != nil {
			c.String(http.StatusBadRequest, "❌ 參數解析失敗: %v\n", err)
			return
		}

		if req.Date == "" {
			c.String(http.StatusBadRequest, "❌ 缺少必要參數 (需具備 date)\n")
			return
		}

		// 🌟 讀取 ftpparaw.bat 傳入的 raw_only、hour 與 slot 旗標
		rawOnly := c.PostForm("raw_only") == "true" || c.Query("raw_only") == "true"
		hour := strings.TrimSpace(c.PostForm("hour"))
		if hour == "" { hour = strings.TrimSpace(c.Query("hour")) }

		slot := strings.TrimSpace(c.PostForm("slot"))
		if slot == "" { slot = strings.TrimSpace(c.Query("slot")) }

		interval := strings.TrimSpace(c.PostForm("interval"))
		if interval == "" { interval = strings.TrimSpace(c.Query("interval")) }

		req.RawOnly = rawOnly
		req.Hour = hour
		req.Slot = slot
		req.Interval = interval

		// 🌟 定位目錄
		ftpBaseDir := filepath.Join(appDir, "ftp_data")
		targetDayDir := filepath.Join(ftpBaseDir, req.Date)
		_ = os.MkdirAll(targetDayDir, 0755)

		// 1. 若先前已有該日的 CSV 遺留在根目錄，先移入當日子資料夾
		datePatternUnderscore := strings.ReplaceAll(req.Date, "-", "_")
		if rootCsvs, err := filepath.Glob(filepath.Join(ftpBaseDir, fmt.Sprintf("*%s*.csv*", datePatternUnderscore))); err == nil {
			for _, srcFile := range rootCsvs {
				destFile := filepath.Join(targetDayDir, filepath.Base(srcFile))
				_ = os.Rename(srcFile, destFile)
			}
		}

		// 🌟 2. 【核心修復「顯示 0 個」之關鍵】：
		// 防火牆連線匯出時固定寫入 ftp_data 根目錄，因此傳輸時監控 ftpBaseDir 才能即時看到檔案與 MB 數跳動！
		// 若為純轉檔模式 (ConvertOnly)，才直接對準 targetDayDir
		if req.ConvertOnly {
			req.FTPFolder = targetDayDir
		} else {
			req.FTPFolder = ftpBaseDir
		}

		if req.LogType != "threat" {
			req.LogType = "traffic"
		}
		
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		var logStreamMutex sync.Mutex
		logStream := func(format string, a ...any) {
			logStreamMutex.Lock()
			defer logStreamMutex.Unlock()
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = fmt.Fprint(c.Writer, msg)
			c.Writer.Flush()
		}

		// 🌟 呼叫原生成熟核心引擎
		err := performCLIExportAndConvert(req, logStream)
		if err != nil {
			logStream("\n❌ 任務失敗: %v\n", err)
			return
		}

		// 🌟 3. 傳輸轉檔完畢後，將根目錄剛接收到的 CSV 歸檔至當日子資料夾，保持 ftp_data 根目錄乾淨
		if rootCsvs, err := filepath.Glob(filepath.Join(ftpBaseDir, fmt.Sprintf("*%s*.csv*", datePatternUnderscore))); err == nil {
			for _, srcFile := range rootCsvs {
				destFile := filepath.Join(targetDayDir, filepath.Base(srcFile))
				_ = os.Rename(srcFile, destFile)
			}
		}

		// 🌟 4. 若為 ftpparaw.bat 觸發之 RAW 模式，自動將 Parquet 備份至 raw_archives/
		/*
		if rawOnly {
			archiveDir := filepath.Join(appDir, "raw_archives")
			_ = os.MkdirAll(archiveDir, 0755)

			var sourceParquet string
			if req.LogType == "threat" {
				sourceParquet = filepath.Join(appDir, "threat_logs", fmt.Sprintf("threat_%s.parquet", req.Date))
			} else {
				sourceParquet = filepath.Join(appDir, "traffic_logs", fmt.Sprintf("traffic_%s.parquet", req.Date))
			}

			destParquet := filepath.Join(archiveDir, fmt.Sprintf("%s_raw_%s.parquet", req.LogType, req.Date))
			if data, rErr := os.ReadFile(sourceParquet); rErr == nil {
				_ = os.WriteFile(destParquet, data, 0644)
				logStream("\n📦 [RAW 歸檔] 原始資料已獨立封裝至冷倉: raw_archives/%s_raw_%s.parquet\n", req.LogType, req.Date)
			}
		}
		*/
	})
	
	// 🌟 21. NAS 歷史日誌匯入 API (支援單檔或多檔案批次上傳)
	r.POST("/api/import-nas", func(c *gin.Context) {
		form, err := c.MultipartForm()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "解析上傳檔案失敗：" + err.Error()})
			return
		}

		// 同時相容 nas_files 與 nas_file 欄位名稱
		files := form.File["nas_files"]
		if len(files) == 0 {
			files = form.File["nas_file"]
		}
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "未收到任何上傳檔案"})
			return
		}

		logType := c.PostForm("log_type")
		if logType != "threat" && logType != "traffic" {
			logType = "all"
		}

		tmpDir := filepath.Join(os.TempDir(), "pa_nas_import")
		_ = os.MkdirAll(tmpDir, 0755)

		var tmpFilePaths []string
		for i, file := range files {
			tmpPath := filepath.Join(tmpDir, fmt.Sprintf("nas_%d_%d_%s", time.Now().Unix(), i, file.Filename))
			if err := c.SaveUploadedFile(file, tmpPath); err == nil {
				tmpFilePaths = append(tmpFilePaths, tmpPath)
			}
		}

		if len(tmpFilePaths) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "暫存檔案儲存失敗"})
			return
		}

		// 背景執行多檔案串流掃描與 DuckDB 轉換
		go processNASImport(tmpFilePaths, logType)

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("成功接收 %d 個日誌檔案！系統正在背景自動依日誌內容逐日分流與建立湖倉。", len(tmpFilePaths)),
		})
	})
	
	// 🌟 21-A. 單檔循序匯入 API：匯入一個、處理一個、立即釋放空間
	r.POST("/api/import-nas-single", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "未收到檔案內容: " + err.Error()})
			return
		}

		logType := c.DefaultPostForm("log_type", "all")
		fileIndex, _ := strconv.Atoi(c.DefaultPostForm("file_index", "1"))
		totalFiles, _ := strconv.Atoi(c.DefaultPostForm("total_files", "1"))

		tmpDir := filepath.Join(os.TempDir(), "pa_nas_import_single")
		_ = os.MkdirAll(tmpDir, 0755)

		tmpPath := filepath.Join(tmpDir, fmt.Sprintf("single_%d_%s", time.Now().UnixNano(), file.Filename))
		if err := c.SaveUploadedFile(file, tmpPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "暫存檔案儲存失敗: " + err.Error()})
			return
		}
		defer os.Remove(tmpPath) // 處理完立即清除暫存檔，磁碟零累積

		// 同步執行單一檔案之串流掃描、分類切分與 DuckDB 湖倉轉檔
		lines, valids, dates, err := processSingleNASImport(tmpPath, file.Filename, fileIndex, totalFiles, logType)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":      "success",
			"file_lines":  lines,
			"file_valids": valids,
			"dates":       dates,
		})
	})

	// 🌟 21-B. 佇列全數完成後的全域去重整併 API
	r.GET("/api/nas-consolidate-all", func(c *gin.Context) {
		ConsolidateParquetFiles()
		ConsolidateThreatParquetFiles()
		ConsolidateSystemParquetFiles() // 👈 補上
		ConsolidateConfigParquetFiles() // 👈 補上
		ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")
		ConsolidateRawParquetFiles("system") // 👈 補上
		ConsolidateRawParquetFiles("config") // 👈 補上
				ConsolidateAuditLogs() // 👈 補上：全域整合時一併整併稽核紀錄碎片
		c.JSON(http.StatusOK, gin.H{"status": "success", "message": "全域整合完成"})
	})
	
	// 🌟 22. NAS 匯入即時狀態與進度查詢 API
	r.GET("/api/nas-import-status", func(c *gin.Context) {
		globalNASProgress.RLock()
		defer globalNASProgress.RUnlock()

		c.JSON(http.StatusOK, gin.H{
			"status":         "success",
			"is_running":     globalNASProgress.IsRunning,
			"stage":          globalNASProgress.Stage,
			"file_name":      globalNASProgress.FileName,
			"total_lines":    globalNASProgress.TotalLines,
			"valid_lines":    globalNASProgress.ValidLines,
			"current_date":   globalNASProgress.CurrentDate,
			"processed_days": globalNASProgress.ProcessedDays,
			"total_days":     globalNASProgress.TotalDays,
			"percent":        globalNASProgress.Percent,
			"logs":           globalNASProgress.Logs,
			"error":          globalNASProgress.Error,
		})
	})
	
	// 🌟 23. 獲取資料庫已存在的有效日期列表 (供前端下拉選單自動產生)
	r.GET("/api/available-dates", func(c *gin.Context) {
		logType := c.DefaultQuery("type", "traffic")
		var targetDir string
		var prefix string
		
		if logType == "threat" {
			targetDir = threatDir
			prefix = "threat_"
		} else if logType == "system" {
			targetDir = systemDir
			prefix = "system_"
		} else if logType == "config" { // 👈 🌟 補上此分支
			targetDir = configDir
			prefix = "config_"
		} else {
			targetDir = trafficDir
			prefix = "traffic_"
		}

		dateSet := make(map[string]bool)
		dateRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

		// 🌟 修改：使用 WalkDir 同步相容根目錄舊扁平檔與日期子目錄新檔案
		_ = filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// (A) 若為子資料夾，檢查資料夾名稱是否直接為 YYYY-MM-DD 格式
			if d.IsDir() {
				if d.Name() != filepath.Base(targetDir) {
					if dateStr := dateRegex.FindString(d.Name()); dateStr != "" {
						dateSet[dateStr] = true
					}
				}
				return nil
			}

			// (B) 若為 Parquet 檔案 (排除 .tmp)，從檔名或路徑中提取日期
			if strings.HasSuffix(d.Name(), ".parquet") && !strings.HasSuffix(d.Name(), ".tmp") {
				if strings.HasPrefix(d.Name(), prefix) || strings.Contains(path, prefix) {
					if dateStr := dateRegex.FindString(d.Name()); dateStr != "" {
						dateSet[dateStr] = true
					} else if dateStr := dateRegex.FindString(path); dateStr != "" {
						dateSet[dateStr] = true
					}
				}
			}
			return nil
		})

		var dates []string
		for d := range dateSet {
			dates = append(dates, d)
		}
		// 日期由新到舊排序
		sort.Slice(dates, func(i, j int) bool {
			return dates[i] > dates[j]
		})

		// 若資料夾是空的，預設給予今天日期
		todayStr := time.Now().Format("2006-01-02")
		if len(dates) == 0 {
			dates = append(dates, todayStr)
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"dates":  dates,
		})
	})
	
	// =============================================================
	// 🌟 全網 IP 資產與取得管理模組 (整合 ARP、DHCP 與 devices.csv)
	// =============================================================

	// 1. 管理取得 IP 頁面路由
	r.GET("/devices", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "devices.html", pongo2.Context{
			"active_page": "devices",
			"today":       time.Now().Format("2006-01-02"),
		})
	})

	// 2. 外部 devices.csv 匯入 API
	r.POST("/api/devices/import-csv", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "未收到上傳的 CSV 檔案"})
			return
		}

		f, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "開啟檔案失敗: " + err.Error()})
			return
		}
		defer f.Close()

		total, updated, inserted, err := importDevicesCSV(f)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "匯入解析失敗: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"message":  fmt.Sprintf("成功比對匯入！處理 %d 筆（更新既有: %d 筆，新增列管: %d 筆）", total, updated, inserted),
			"total":    total,
			"updated":  updated,
			"inserted": inserted,
		})
	})

	// 3. 獲取整合比對後的全網 IP 資產清冊 (支援手動狀態覆寫、手動輸入 MAC 與自癒)
	r.GET("/api/devices/managed-ips", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		// 🌟 自動自癒：確保 manual_state 與 mac 欄位存在
		_, _ = db.Exec(`
			CREATE TABLE IF NOT EXISTS external_devices (
				ip TEXT PRIMARY KEY,
				mac TEXT DEFAULT '',
				name TEXT NOT NULL DEFAULT '',
				location TEXT DEFAULT '',
				device_type TEXT DEFAULT '',
				brand TEXT DEFAULT '',
				model TEXT DEFAULT '',
				sys_descr TEXT DEFAULT '',
				manual_state TEXT DEFAULT '',
				imported_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
		`)
		_, _ = db.Exec("ALTER TABLE external_devices ADD COLUMN manual_state TEXT DEFAULT '';")
		_, _ = db.Exec("ALTER TABLE external_devices ADD COLUMN mac TEXT DEFAULT '';")

		// 🌟 關鍵補回：被意外刪除的 statusFilter 與 keyword 宣告 (解決 undefined 報錯)
		statusFilter := strings.ToUpper(strings.TrimSpace(c.DefaultQuery("status", "ALL")))
		keyword := strings.TrimSpace(c.DefaultQuery("keyword", ""))

		// 🌟 MAC 優先順序：手動輸入的 ext.mac > ARP 實體網卡 > DHCP 租約
		query := `
			WITH all_ips AS (
				SELECT ip FROM arp_records
				UNION
				SELECT ip FROM dhcp_leases WHERE ip != '' AND ip != '-'
				UNION
				SELECT ip FROM external_devices
			)
			SELECT 
				a.ip,
				COALESCE(NULLIF(ext.mac, ''), arp.mac, dhcp.mac, '-') AS mac,
				COALESCE(NULLIF(ext.name, ''), NULLIF(arp.hostname, ''), NULLIF(dhcp.hostname, ''), '') AS device_name,
				COALESCE(NULLIF(ext.location, ''), '') AS location,
				COALESCE(NULLIF(ext.device_type, ''), '桌上電腦') AS device_type,
				COALESCE(NULLIF(ext.brand, ''), '') AS brand,
				COALESCE(NULLIF(ext.model, ''), '') AS model,
				COALESCE(NULLIF(arp.interface, ''), '-') AS interface,
				CASE 
					WHEN ext.manual_state = 'STATIC' THEN 
						CASE WHEN arp.ip IS NOT NULL THEN 'STATIC' ELSE 'OFFLINE_STATIC' END
					WHEN ext.manual_state = 'ROGUE' THEN 'ROGUE'
					WHEN ext.manual_state = 'DHCP' THEN 'DHCP'
					WHEN dhcp.ip IS NOT NULL AND (arp.mac IS NULL OR LOWER(arp.mac) = LOWER(dhcp.mac)) THEN 'DHCP'
					WHEN ext.ip IS NOT NULL AND arp.ip IS NOT NULL THEN 'STATIC'
					WHEN ext.ip IS NOT NULL AND arp.ip IS NULL THEN 'OFFLINE_STATIC'
					WHEN dhcp.ip IS NOT NULL AND arp.mac IS NOT NULL AND LOWER(arp.mac) != LOWER(dhcp.mac) THEN 'CONFLICT'
					ELSE 'ROGUE'
				END AS ip_source_state,
				COALESCE(NULLIF(ext.manual_state, ''), '') AS manual_state,
				COALESCE(arp.updated_at, dhcp.record_date, ext.imported_at) AS last_seen
			FROM all_ips a
			LEFT JOIN arp_records arp ON a.ip = arp.ip
			LEFT JOIN (SELECT ip, mac, hostname, MAX(record_date) as record_date FROM dhcp_leases GROUP BY ip) dhcp ON a.ip = dhcp.ip
			LEFT JOIN external_devices ext ON a.ip = ext.ip
			ORDER BY 
				CAST(substr(a.ip, 1, instr(a.ip, '.') - 1) AS INT),
				CAST(substr(substr(a.ip, instr(a.ip, '.') + 1), 1, instr(substr(a.ip, instr(a.ip, '.') + 1), '.') - 1) AS INT),
				CAST(substr(substr(substr(a.ip, instr(a.ip, '.') + 1), instr(substr(a.ip, instr(a.ip, '.') + 1), '.') + 1), 1, instr(substr(substr(a.ip, instr(a.ip, '.') + 1), instr(substr(a.ip, instr(a.ip, '.') + 1), '.') + 1), '.') - 1) AS INT),
				CAST(substr(substr(substr(a.ip, instr(a.ip, '.') + 1), instr(substr(a.ip, instr(a.ip, '.') + 1), '.') + 1), instr(substr(substr(a.ip, instr(a.ip, '.') + 1), instr(substr(a.ip, instr(a.ip, '.') + 1), '.') + 1), '.') + 1) AS INT)
		`

		rows, err := db.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}
		defer rows.Close()

		type ManagedIPItem struct {
			IP          string `json:"ip"`
			MAC         string `json:"mac"`
			DeviceName  string `json:"device_name"`
			Location    string `json:"location"`
			DeviceType  string `json:"device_type"`
			Brand       string `json:"brand"`
			Model       string `json:"model"`
			Interface   string `json:"interface"`
			SourceState string `json:"source_state"`
			ManualState string `json:"manual_state"`
			LastSeen    string `json:"last_seen"`
		}

		var list []ManagedIPItem
		statTotal, statDHCP, statStatic, statRogue := 0, 0, 0, 0

		cleanRegex := regexp.MustCompile(`<[^>]*>`)

		for rows.Next() {
			var it ManagedIPItem
			_ = rows.Scan(&it.IP, &it.MAC, &it.DeviceName, &it.Location, &it.DeviceType, &it.Brand, &it.Model, 
				&it.Interface, &it.SourceState, &it.ManualState, &it.LastSeen)

			if strings.Contains(it.DeviceName, "<") {
				it.DeviceName = cleanRegex.ReplaceAllString(it.DeviceName, "")
			}

			switch it.SourceState {
			case "DHCP":
				statDHCP++
			case "STATIC", "OFFLINE_STATIC":
				statStatic++
			default:
				statRogue++
			}
			statTotal++

			if statusFilter != "ALL" {
				if statusFilter == "STATIC" && it.SourceState != "STATIC" && it.SourceState != "OFFLINE_STATIC" {
					continue
				} else if statusFilter == "ROGUE" && it.SourceState != "ROGUE" && it.SourceState != "CONFLICT" {
					continue
				} else if statusFilter == "DHCP" && it.SourceState != "DHCP" {
					continue
				}
			}

			if keyword != "" {
				kw := strings.ToLower(keyword)
				if !strings.Contains(strings.ToLower(it.IP), kw) &&
					!strings.Contains(strings.ToLower(it.MAC), kw) &&
					!strings.Contains(strings.ToLower(it.DeviceName), kw) &&
					!strings.Contains(strings.ToLower(it.Brand), kw) &&
					!strings.Contains(strings.ToLower(it.Model), kw) &&
					!strings.Contains(strings.ToLower(it.Location), kw) {
					continue
				}
			}

			list = append(list, it)
		}

		c.JSON(http.StatusOK, gin.H{
			"status":      "success",
			"total":       statTotal,
			"stat_dhcp":   statDHCP,
			"stat_static": statStatic,
			"stat_rogue":  statRogue,
			"data":        list,
		})
	})

	// 4. 🌟 Excel 編輯確認儲存 API (完整修復 tx 與 MAC 儲存，解決 undefined: tx 與 := 報錯)
	r.POST("/api/devices/batch-save", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		type DeviceSaveItem struct {
			IP          string `json:"ip"`
			MAC         string `json:"mac"`
			Name        string `json:"name"`
			Location    string `json:"location"`
			DeviceType  string `json:"device_type"`
			Brand       string `json:"brand"`
			Model       string `json:"model"`
			ManualState string `json:"manual_state"`
		}

		var list []DeviceSaveItem
		if err := c.ShouldBindJSON(&list); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "資料解析失敗: " + err.Error()})
			return
		}

		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare(`
			INSERT INTO external_devices (ip, mac, name, location, device_type, brand, model, manual_state, imported_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(ip) DO UPDATE SET
				mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE external_devices.mac END,
				name = excluded.name,
				location = excluded.location,
				device_type = excluded.device_type,
				brand = excluded.brand,
				model = excluded.model,
				manual_state = excluded.manual_state,
				imported_at = CURRENT_TIMESTAMP
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}
		defer stmt.Close()

		savedCount := 0
		for _, it := range list {
			cleanIP := strings.TrimSpace(it.IP)
			if cleanIP == "" || net.ParseIP(cleanIP) == nil {
				continue
			}
			cleanMAC := strings.ToLower(strings.TrimSpace(it.MAC))
			cleanMAC = strings.ReplaceAll(cleanMAC, "-", ":")
			if cleanMAC == "-" {
				cleanMAC = ""
			}

			_, err := stmt.Exec(cleanIP, cleanMAC, it.Name, it.Location, it.DeviceType, it.Brand, it.Model, it.ManualState)
			if err == nil {
				savedCount++

				// 若有輸入 MAC，同步寫入 arp_records 標記為「手動列管」
				if cleanMAC != "" {
					_, _ = tx.Exec(`
						INSERT INTO arp_records (ip, mac, interface, updated_at) 
						VALUES (?, ?, '手動列管', CURRENT_TIMESTAMP)
						ON CONFLICT(ip) DO UPDATE SET 
							mac = excluded.mac,
							updated_at = CURRENT_TIMESTAMP
					`, cleanIP, cleanMAC)
				}

				if it.ManualState == "STATIC" {
					_, _ = tx.Exec("UPDATE arp_records SET dev_type = '固定 IP (已列管)' WHERE ip = ?", cleanIP)
				} else if it.ManualState == "DHCP" {
					_, _ = tx.Exec("UPDATE arp_records SET dev_type = 'DHCP 動態配發' WHERE ip = ?", cleanIP)
				} else if it.ManualState == "ROGUE" {
					_, _ = tx.Exec("UPDATE arp_records SET dev_type = '🚨 私設 IP (未列管)' WHERE ip = ?", cleanIP)
				}

				if strings.TrimSpace(it.Name) != "" {
					_, _ = tx.Exec("UPDATE arp_records SET hostname = ? WHERE ip = ?", it.Name, cleanIP)
				}
			}
		}

		if err := tx.Commit(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("成功儲存 %d 筆設備資產與狀態更新！", savedCount),
			"saved":   savedCount,
		})
	})
	
	// 🌟 系統日誌分析主頁面
	r.GET("/system", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "system.html", pongo2.Context{
			"active_page": "system",
			"today":       time.Now().Format("2006-01-02"),
			"today_fmt":   time.Now().Format("2006/01/02"),
		})
	})

	// 🌟 系統日誌 DuckDB 檢索 API
	r.GET("/api/system-query", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		subtype := strings.TrimSpace(c.DefaultQuery("subtype", "all")) // 👈 🌟 確保這行是 subtype，不是 src
		severity := strings.TrimSpace(c.DefaultQuery("severity", "all"))
		eventID := strings.TrimSpace(c.DefaultQuery("event_id", ""))
		keyword := strings.TrimSpace(c.DefaultQuery("keyword", ""))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
		onlyLogs := c.DefaultQuery("only_logs", "false") == "true"

		res, err := querySystemAnalytics(date, subtype, severity, eventID, keyword, page, perPage, onlyLogs)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":         "success",
			"total_logs":     res.TotalLogs,
			"important_logs": res.ImportantLogs,
			"top_subtype":    res.TopSubtype,
			"top_event":      res.TopEvent,
			"db_size":        res.DbSize,
			"histogram":      res.Histogram,
			"logs":           res.Logs,
			"current_page":   res.CurrentPage,
			"total_pages":    res.TotalPages,
		})
	})
	
	// 🌟 立即手動自 PA-1420 擷取最新系統日誌
	r.POST("/api/system-fetch-now", func(c *gin.Context) {
		countStr := strings.TrimSpace(c.Query("count"))
		if countStr == "" { countStr = strings.TrimSpace(c.PostForm("count")) }
		if countStr == "" { countStr = strings.TrimSpace(c.Request.FormValue("count")) }

		count, _ := strconv.Atoi(countStr)
		if count <= 0 { count = 2500 }
		if count > 5000 { count = 5000 }

		entries, err := fetchPASystemLogsWithFilter(count, "")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		success, total, err := saveSystemLogsToParquet(entries)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "success",
			"message": fmt.Sprintf("成功自 %s 擷取 %d 筆系統紀錄！新增入庫：%d 筆，該檔案累計：%d 筆", getFWModelName(), len(entries), success, total),
		})
	})
	
	// 🌟 單一主機 360° 全景鑑識頁面
	r.GET("/timeline", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "timeline.html", pongo2.Context{
			"active_page": "timeline",
		})
	})

	// 🌟 單一主機 360° 全景鑑識 API
	r.GET("/api/host-timeline", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		ip := strings.TrimSpace(c.Query("ip"))
		date := strings.TrimSpace(c.Query("date"))
		if ip == "" {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": "請輸入欲鑑識的主機 IP 位址"})
			return
		}
		profile, err := queryHostTimeline(ip, date)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "data": profile})
	})
	
	// 🌟 組態日誌分析主頁面
	r.GET("/config", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "config.html", pongo2.Context{
			"active_page": "config",
		})
	})

	// 🌟 組態日誌 DuckDB 檢索 API
	r.GET("/api/config-query", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		admin := strings.TrimSpace(c.DefaultQuery("admin", ""))
		clientIP := strings.TrimSpace(c.DefaultQuery("client_ip", ""))
		keyword := strings.TrimSpace(c.DefaultQuery("keyword", ""))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))

		res, err := queryConfigAnalytics(date, admin, clientIP, keyword, page, perPage)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":       "success",
			"total_logs":   res.TotalLogs,
			"top_admin":    res.TopAdmin,
			"top_command":  res.TopCommand,
			"db_size":      res.DbSize,
			"histogram":    res.Histogram,
			"logs":         res.Logs,
			"current_page": res.CurrentPage,
			"total_pages":  res.TotalPages,
		})
	})

	// 🌟 立即手動自 PA-1420 擷取最新組態日誌
	r.POST("/api/config-fetch-now", func(c *gin.Context) {
		count, _ := strconv.Atoi(c.DefaultPostForm("count", "2500"))
		if count <= 0 { count = 2500 }
		entries, err := fetchPAConfigLogsWithFilter(count, "")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		success, total, err := saveConfigLogsToParquet(entries)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"message": fmt.Sprintf("成功自 %s 擷取 %d 筆組態紀錄！新增入庫：%d 筆，當日累計：%d 筆", getFWModelName(), len(entries), success, total),
		})
	})
	
	// 威脅日誌 DuckDB 檢索 API
	r.GET("/api/threat-query", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		src := strings.TrimSpace(c.DefaultQuery("src", ""))
		dst := strings.TrimSpace(c.DefaultQuery("dst", ""))
		severity := strings.TrimSpace(c.DefaultQuery("severity", "all"))
		action := strings.TrimSpace(c.DefaultQuery("action", "all"))
		threatName := strings.TrimSpace(c.DefaultQuery("threat_name", ""))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
		onlyLogs := c.DefaultQuery("only_logs", "false") == "true"

		res, err := queryThreatAnalytics(date, src, dst, severity, action, threatName, page, perPage, onlyLogs)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":          "success",
			"total_threats":   res.TotalThreats,
			"critical_high":   res.CriticalHigh,
			"top_threat":      res.TopThreat,
			"top_victim_ip":   res.TopVictimIP,
			"top_victim_host": res.TopVictimHost,
			"db_size":         res.DbSize,
			"histogram":       res.Histogram,
			"logs":            res.Logs,
			"current_page":    res.CurrentPage,
			"total_pages":     res.TotalPages,
		})
	})
	
	// ==========================================
	// 🌟 全新移植：流量明細檢索與三向統計頁面
	// 1. 流量通訊軌跡明細檢索頁面
	// ==========================================
	r.GET("/search", func(c *gin.Context) {
		renderPongo(c, "search.html", pongo2.Context{
			"active_page": "search",
			"today":       time.Now().Format("2006-01-02"),
		})
	})

	// 流量進階檢索 API (時間基準錨定 + 頁碼超界防護 + 完整分頁)
	r.POST("/api/flow/search", func(c *gin.Context) {
		var req struct {
			Date      string `json:"date"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			SrcIP     string `json:"src_ip"`
			DstIP     string `json:"dst_ip"`
			Port      string `json:"port"`
			App       string `json:"app"`  // 🌟 新增：支援 L7 應用服務過濾
			Zone      string `json:"zone"` // download, upload, internal
			Page      int    `json:"page"`
			PerPage   int    `json:"per_page"`
		}
		_ = c.ShouldBindJSON(&req)

		queryDate := strings.ReplaceAll(strings.TrimSpace(req.Date), "/", "-")
		if queryDate == "" {
			queryDate = time.Now().Format("2006-01-02")
		}
		if req.Page < 1 { req.Page = 1 }
		if req.PerPage < 1 { req.PerPage = 50 }

		// 🌟 1. DuckDB 查詢路徑：改為 ** 遞迴萬用字元，自動橫跨歷史扁平檔與日期子目錄
		pattern := filepath.ToSlash(filepath.Join(trafficDir, "**", fmt.Sprintf("traffic*%s*.parquet", queryDate)))

		// 🌟 2. Go 前置檢查：同時檢查根目錄舊檔與日期子目錄新檔
		tFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))
		if len(tFiles) == 0 {
			subFiles, _ := filepath.Glob(filepath.Join(trafficDir, queryDate, fmt.Sprintf("traffic*%s*.parquet", queryDate)))
			tFiles = append(tFiles, subFiles...)
		}

		if len(tFiles) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"status":        "success",
				"total_records": 0,
				"total_pages":   1,
				"current_page":  1,
				"fixed_end_time": "",
				"sum_download":  0.0,
				"sum_upload":    0.0,
				"sum_internal":  0.0,
				"data":          []interface{}{},
			})
			return
		}

		// 🌟 1. 時間錨定：若前端在分頁過程中有帶入前次查詢的固定 end_time，直接鎖定該時間
		var fixedEndTime string
		var baseTime time.Time

		if req.EndTime != "" && req.StartTime != "custom" && !strings.Contains(req.StartTime, " ") {
			if pt, err := time.Parse("2006-01-02 15:04:05", strings.ReplaceAll(req.EndTime, "T", " ")); err == nil {
				baseTime = pt
				fixedEndTime = baseTime.Format("2006-01-02 15:04:05")
			}
		}

		// 初次點擊查詢：以 Parquet 檔案中最新一筆紀錄（或目前時間）作為時間窗錨點
		if baseTime.IsZero() {
			maxTimeSQL := fmt.Sprintf(`SELECT MAX(timestamp) AS max_t FROM read_parquet('%s')`, pattern)
			if maxRes, err := runDuckDBQuery(maxTimeSQL); err == nil && len(maxRes) > 0 && maxRes[0]["max_t"] != nil {
				if tStr, ok := maxRes[0]["max_t"].(string); ok && len(tStr) >= 19 {
					if pt, err := time.Parse("2006-01-02 15:04:05", tStr[:19]); err == nil {
						baseTime = pt
					}
				}
			}
			if baseTime.IsZero() {
				baseTime = time.Now()
			}
			fixedEndTime = baseTime.Format("2006-01-02 15:04:05")
		}

		// 🌟 2. 構建時間條件
		var baseConds []string
		baseConds = append(baseConds, "1=1")

		if req.StartTime != "" && req.StartTime != "-24h" {
			if req.StartTime == "custom" || strings.Contains(req.StartTime, " ") || strings.Contains(req.StartTime, "T") {
				st := strings.ReplaceAll(strings.TrimSpace(req.StartTime), "T", " ")
				et := strings.ReplaceAll(strings.TrimSpace(req.EndTime), "T", " ")
				if len(st) == 16 { st += ":00" }
				if len(et) == 16 { et += ":59" }
				if st != "" && et != "" {
					baseConds = append(baseConds, fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'", st, et))
				} else if st != "" {
					baseConds = append(baseConds, fmt.Sprintf("timestamp >= '%s'", st))
				}
			} else {
				mins := 5
				switch req.StartTime {
				case "-5m": mins = 5
				case "-15m": mins = 15
				case "-30m": mins = 30
				case "-1h": mins = 60
				case "-6h": mins = 360
				default: mins = 5
				}
				stThres := baseTime.Add(-time.Duration(mins) * time.Minute).Format("2006-01-02 15:04:05")
				etThres := fixedEndTime
				baseConds = append(baseConds, fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'", stThres, etThres))
			}
		}

		if req.SrcIP != "" { baseConds = append(baseConds, fmt.Sprintf("source ILIKE '%%%s%%'", strings.ReplaceAll(req.SrcIP, "'", "''"))) }
		if req.DstIP != "" { baseConds = append(baseConds, fmt.Sprintf("destination ILIKE '%%%s%%'", strings.ReplaceAll(req.DstIP, "'", "''"))) }
		if req.Port != "" { baseConds = append(baseConds, fmt.Sprintf("to_port = %s", req.Port)) }
		// 🌟 新增：L7 應用 (application) 模糊比對過濾
		if req.App != "" {
			baseConds = append(baseConds, fmt.Sprintf("application ILIKE '%%%s%%'", strings.ReplaceAll(req.App, "'", "''")))
		}
		baseWhereClause := strings.Join(baseConds, " AND ")

		safeFloat := func(val interface{}) float64 {
			if val == nil { return 0.0 }
			switch v := val.(type) {
			case float64: return v
			case int64:   return float64(v)
			case int:     return float64(v)
			case string:
				if f, err := strconv.ParseFloat(v, 64); err == nil { return f }
			}
			return 0.0
		}

		// 🌟 3. 三向卡片統計
		threeWaySQL := fmt.Sprintf(`
			SELECT 
				CAST(round(COALESCE(SUM(CASE WHEN from_zone = 'LAN' AND to_zone = 'WAN' THEN bytes END), 0)/1048576.0, 2) AS DOUBLE) AS lan_wan_mb,
				CAST(round(COALESCE(SUM(CASE WHEN from_zone = 'WAN' AND to_zone = 'LAN' THEN bytes END), 0)/1048576.0, 2) AS DOUBLE) AS wan_lan_mb,
				CAST(round(COALESCE(SUM(CASE WHEN from_zone = 'LAN' AND to_zone = 'LAN' THEN bytes END), 0)/1048576.0, 2) AS DOUBLE) AS lan_lan_mb
			FROM read_parquet('%s')
			WHERE %s
		`, pattern, baseWhereClause)

		var sumLanWan, sumWanLan, sumLanLan float64
		if threeWayRes, err := runDuckDBQuery(threeWaySQL); err == nil && len(threeWayRes) > 0 {
			sumLanWan = safeFloat(threeWayRes[0]["lan_wan_mb"])
			sumWanLan = safeFloat(threeWayRes[0]["wan_lan_mb"])
			sumLanLan = safeFloat(threeWayRes[0]["lan_lan_mb"])
		}

		// 🌟 4. 表格過濾條件 (Zone)
		tableConds := append([]string{}, baseConds...)
		if req.Zone == "download" {
			tableConds = append(tableConds, "from_zone = 'LAN' AND to_zone = 'WAN'")
		} else if req.Zone == "upload" {
			tableConds = append(tableConds, "from_zone = 'WAN' AND to_zone = 'LAN'")
		} else if req.Zone == "internal" {
			tableConds = append(tableConds, "from_zone = 'LAN' AND to_zone = 'LAN'")
		}
		tableWhereClause := strings.Join(tableConds, " AND ")

		// 🌟 5. 真實總筆數查詢
		countSQL := fmt.Sprintf(`SELECT COUNT(*) AS total_count FROM read_parquet('%s') WHERE %s`, pattern, tableWhereClause)
		var totalRecords int64 = 0
		if countRes, err := runDuckDBQuery(countSQL); err == nil && len(countRes) > 0 {
			totalRecords = parseDuckDBNumber(countRes[0]["total_count"])
		}
		totalPages := int(math.Ceil(float64(totalRecords) / float64(req.PerPage)))
		if totalPages == 0 { totalPages = 1 }

		// 🌟 6. 核心保護：頁碼超界保護 (防止翻到最後一頁時 Offset 超出資料集)
		targetPage := req.Page
		if targetPage > totalPages {
			targetPage = totalPages
		}
		offset := (targetPage - 1) * req.PerPage
		if offset < 0 { offset = 0 }

		searchSQL := fmt.Sprintf(`
			SELECT 
				timestamp as time, source as src_ip, destination as dst_ip, 
				0 as src_port, to_port as dst_port, application as protocol, 
				round(bytes/1048576.0, 3) as traffic_mb,
				from_zone, to_zone
			FROM read_parquet('%s')
			WHERE %s
			ORDER BY timestamp DESC 
			LIMIT %d OFFSET %d
		`, pattern, tableWhereClause, req.PerPage, offset)

		logsRes, err := runDuckDBQuery(searchSQL)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":         "success",
			"total_records":  totalRecords,
			"total_pages":    totalPages,
			"current_page":   targetPage,
			"fixed_end_time": fixedEndTime,
			"sum_download":   sumLanWan,
			"sum_upload":     sumWanLan,
			"sum_internal":   sumLanLan,
			"data":           logsRes,
		})
	})
	
	// 🌟 全量圖表分析 API (時間基準精準雙向錨定 + DuckDB 向量高速聚合)
	r.POST("/api/flow/chart-data", func(c *gin.Context) {
		var req struct {
			Date      string `json:"date"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			SrcIP     string `json:"src_ip"`
			DstIP     string `json:"dst_ip"`
			Port      string `json:"port"`
			App       string `json:"app"`
			Zone      string `json:"zone"`
		}
		_ = c.ShouldBindJSON(&req)

		queryDate := strings.ReplaceAll(strings.TrimSpace(req.Date), "/", "-")
		if queryDate == "" { queryDate = time.Now().Format("2006-01-02") }

		// 🌟 改為 ** 遞迴萬用字元
		pattern := filepath.ToSlash(filepath.Join(trafficDir, "**", fmt.Sprintf("traffic*%s*.parquet", queryDate)))

		// 🌟 1. 時間基準雙向錨定：優先使用前端凍結的結束時間 (req.EndTime) 作為 baseTime
		var fixedEndTime string
		var baseTime time.Time

		if req.EndTime != "" && req.StartTime != "custom" && !strings.Contains(req.StartTime, " ") {
			if pt, err := time.Parse("2006-01-02 15:04:05", strings.ReplaceAll(req.EndTime, "T", " ")); err == nil {
				baseTime = pt
				fixedEndTime = baseTime.Format("2006-01-02 15:04:05")
			}
		}

		// 若無凍結錨點 (例如未檢索前點開圖表)，才動態取資料庫最新紀錄時間
		if baseTime.IsZero() {
			maxTimeSQL := fmt.Sprintf(`SELECT MAX(timestamp) AS max_t FROM read_parquet('%s')`, pattern)
			if maxRes, err := runDuckDBQuery(maxTimeSQL); err == nil && len(maxRes) > 0 && maxRes[0]["max_t"] != nil {
				if tStr, ok := maxRes[0]["max_t"].(string); ok && len(tStr) >= 19 {
					if pt, err := time.Parse("2006-01-02 15:04:05", tStr[:19]); err == nil {
						baseTime = pt
					}
				}
			}
			if baseTime.IsZero() {
				baseTime = time.Now()
			}
			fixedEndTime = baseTime.Format("2006-01-02 15:04:05")
		}

		// 🌟 2. 構建過濾條件 (確保起始與結束時間均源自同一個 baseTime，杜絕時間反轉)
		var conds []string
		conds = append(conds, "1=1")

		isMinuteGrain := true
		if req.StartTime != "" && req.StartTime != "-24h" {
			if req.StartTime == "custom" || strings.Contains(req.StartTime, " ") || strings.Contains(req.StartTime, "T") {
				st := strings.ReplaceAll(strings.TrimSpace(req.StartTime), "T", " ")
				et := strings.ReplaceAll(strings.TrimSpace(req.EndTime), "T", " ")
				if len(st) == 16 { st += ":00" }
				if len(et) == 16 { et += ":59" }
				if st != "" && et != "" {
					conds = append(conds, fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'", st, et))
				} else if st != "" {
					conds = append(conds, fmt.Sprintf("timestamp >= '%s'", st))
				}
				isMinuteGrain = false
			} else {
				mins := 5
				switch req.StartTime {
				case "-5m": mins = 5
				case "-15m": mins = 15
				case "-30m": mins = 30
				case "-1h": mins = 60
				case "-6h": mins = 360; isMinuteGrain = false
				default: mins = 5
				}

				// 關鍵：起始時間與結束時間一律由同一個 baseTime 計算，保證永遠合法
				stThres := baseTime.Add(-time.Duration(mins) * time.Minute).Format("2006-01-02 15:04:05")
				etThres := fixedEndTime
				conds = append(conds, fmt.Sprintf("timestamp >= '%s' AND timestamp <= '%s'", stThres, etThres))
			}
		} else {
			isMinuteGrain = false
		}

		if req.Zone == "download" {
			conds = append(conds, "from_zone = 'LAN' AND to_zone = 'WAN'")
		} else if req.Zone == "upload" {
			conds = append(conds, "from_zone = 'WAN' AND to_zone = 'LAN'")
		} else if req.Zone == "internal" {
			conds = append(conds, "from_zone = 'LAN' AND to_zone = 'LAN'")
		}

		if req.SrcIP != "" { conds = append(conds, fmt.Sprintf("source ILIKE '%%%s%%'", strings.ReplaceAll(req.SrcIP, "'", "''"))) }
		if req.DstIP != "" { conds = append(conds, fmt.Sprintf("destination ILIKE '%%%s%%'", strings.ReplaceAll(req.DstIP, "'", "''"))) }
		if req.Port != "" {
			if p, err := strconv.Atoi(strings.TrimSpace(req.Port)); err == nil {
				conds = append(conds, fmt.Sprintf("to_port = %d", p))
			}
		}
		if req.App != "" {
			conds = append(conds, fmt.Sprintf("application ILIKE '%%%s%%'", strings.ReplaceAll(req.App, "'", "''")))
		}
		whereClause := strings.Join(conds, " AND ")

		// 1. 時序趨勢查詢 (分 / 時)
		var trendSQL string
		if isMinuteGrain {
			trendSQL = fmt.Sprintf(`
				SELECT SUBSTRING(timestamp FROM 12 FOR 5) AS t, round(COALESCE(SUM(bytes),0)/1048576.0, 2) AS mb
				FROM read_parquet('%s') WHERE %s
				GROUP BY t ORDER BY t ASC
			`, pattern, whereClause)
		} else {
			trendSQL = fmt.Sprintf(`
				SELECT SUBSTRING(timestamp FROM 12 FOR 2) || ':00' AS t, round(COALESCE(SUM(bytes),0)/1048576.0, 2) AS mb
				FROM read_parquet('%s') WHERE %s
				GROUP BY t ORDER BY t ASC
			`, pattern, whereClause)
		}

		// 2. 全域 Top 6 應用協定佔比
		appSQL := fmt.Sprintf(`
			SELECT application AS app, round(COALESCE(SUM(bytes),0)/1048576.0, 2) AS mb
			FROM read_parquet('%s') WHERE %s
			GROUP BY app ORDER BY mb DESC LIMIT 6
		`, pattern, whereClause)

		// 3. 全域 Top 8 通訊埠分佈
		portSQL := fmt.Sprintf(`
			SELECT to_port AS port, round(COALESCE(SUM(bytes),0)/1048576.0, 2) AS mb
			FROM read_parquet('%s') WHERE %s
			GROUP BY port ORDER BY mb DESC LIMIT 8
		`, pattern, whereClause)

		trendRes, _ := runDuckDBQuery(trendSQL)
		appRes, _ := runDuckDBQuery(appSQL)
		portRes, _ := runDuckDBQuery(portSQL)

		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"trend":  trendRes,
			"apps":   appRes,
			"ports":  portRes,
		})
	})
	
	// 應用程式能見度與 QoE 品質評分 API
	r.GET("/api/flow/qoe-summary", func(c *gin.Context) {
		queryDate := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		// 🌟 改為 ** 遞迴萬用字元
		pattern := filepath.ToSlash(filepath.Join(trafficDir, "**", fmt.Sprintf("traffic*%s*.parquet", queryDate)))

		sql := fmt.Sprintf(`
			SELECT 
				application as app_name,
				to_port as port,
				COUNT(*) as connections,
				round(SUM(bytes)/1048576.0, 2) as traffic_mb,
				COUNT(CASE WHEN session_end_reason = 'tcp-rst' OR action = 'deny' THEN 1 END) as fail_cnt
			FROM read_parquet('%s')
			GROUP BY app_name, port
			ORDER BY traffic_mb DESC LIMIT 20
		`, pattern)

		rows, err := runDuckDBQuery(sql)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "data": []interface{}{}})
			return
		}

		type QoEItem struct {
			AppName     string  `json:"app_name"`
			Port        string  `json:"port"`
			Connections int64   `json:"connections"`
			TrafficMB   float64 `json:"traffic_mb"`
			Percentage  string  `json:"percentage"`
			QoEScore    int     `json:"qoe_score"`
		}

		var totalMB float64 = 0
		for _, r := range rows {
			if v, ok := r["traffic_mb"].(float64); ok { totalMB += v }
		}

		var list []QoEItem
		for _, r := range rows {
			connCnt := parseDuckDBNumber(r["connections"])
			failCnt := parseDuckDBNumber(r["fail_cnt"])
			mbVal := 0.0
			if v, ok := r["traffic_mb"].(float64); ok { mbVal = v }

			score := 96
			if connCnt > 0 {
				failRate := float64(failCnt) / float64(connCnt)
				score = int(100 - (failRate * 100) * 1.5)
				if score < 55 { score = 55 }
			}

			pct := "0.0"
			if totalMB > 0 {
				pct = fmt.Sprintf("%.1f", (mbVal / totalMB) * 100)
			}

			list = append(list, QoEItem{
				AppName:     fmt.Sprintf("%v", r["app_name"]),
				Port:        fmt.Sprintf("%v", r["port"]),
				Connections: connCnt,
				TrafficMB:   mbVal,
				Percentage:  pct,
				QoEScore:    score,
			})
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": list})
	})
	
	// 🌟 取得資安預警靈敏度閥值設定 API
	r.GET("/api/flow/security-settings", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
		settings := getSecuritySettings(db)
		c.JSON(http.StatusOK, gin.H{"success": true, "settings": settings})
	})

	// 🌟 儲存資安預警靈敏度閥值設定 API (寫入 SQLite 持久儲存)
	r.POST("/api/flow/security-settings", func(c *gin.Context) {
		var req SecuritySettings
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "參數解析失敗: " + err.Error()})
			return
		}

		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}

		if err := saveSecuritySettings(db, req); err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": "儲存至資料庫失敗: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "預警靈敏度閥值已成功儲存並即時套用！"})
	})

	// ==========================================
	// 🛡️ 全新移植：流量資安預警與防禦中心
	// 2. 資安威脅預警中心頁面
	// ==========================================
	r.GET("/security", func(c *gin.Context) {
		renderPongo(c, "security.html", pongo2.Context{
			"active_page": "security",
		})
	})

	// 預警事件列表查詢 API
	r.GET("/api/flow/security-alerts", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
			return
		}
		rows, err := db.Query(`
			SELECT id, strftime('%Y-%m-%d %H:%M:%S', timestamp, 'localtime') as ts,
			       src_ip, dst_ip, attack_type, severity, details, status
			FROM flow_security_events ORDER BY id DESC LIMIT 200
		`)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"success": false, "data": []interface{}{}})
			return
		}
		defer rows.Close()

		type AlertItem struct {
			ID         int    `json:"id"`
			TS         string `json:"ts"`
			SrcIP      string `json:"src_ip"`
			DstIP      string `json:"dst_ip"`
			AttackType string `json:"attack_type"`
			Severity   string `json:"severity"`
			Details    string `json:"details"`
			Status     string `json:"status"`
		}
		var list []AlertItem
		for rows.Next() {
			var it AlertItem
			_ = rows.Scan(&it.ID, &it.TS, &it.SrcIP, &it.DstIP, &it.AttackType, &it.Severity, &it.Details, &it.Status)
			list = append(list, it)
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": list})
	})

	// 清除預警紀錄 API
	r.POST("/api/flow/security-alerts/clear", func(c *gin.Context) {
		db, err := initDB()
		if err == nil {
			_, _ = db.Exec("DELETE FROM flow_security_events")
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "已清空所有資安威脅預警紀錄！"})
	})

	// 外部嫌疑 IP 攻擊 Port 調閱 API
	r.POST("/api/flow/security-single-ip-details", func(c *gin.Context) {
		var req struct {
			SrcIP string `json:"src_ip"`
			Date  string `json:"date"`
		}
		_ = c.ShouldBindJSON(&req)
		if req.Date == "" { req.Date = time.Now().Format("2006-01-02") }

		// 🌟 改為 ** 遞迴萬用字元
		pattern := filepath.ToSlash(filepath.Join(trafficDir, "**", fmt.Sprintf("traffic*%s*.parquet", req.Date)))
		sql := fmt.Sprintf(`
			SELECT destination as dst_ip, to_port as dst_port, round(SUM(bytes)/1048576.0, 3) as traffic_mb
			FROM read_parquet('%s')
			WHERE source = '%s'
			GROUP BY dst_ip, dst_port
			ORDER BY SUM(bytes) DESC LIMIT 100
		`, pattern, strings.ReplaceAll(req.SrcIP, "'", "''"))

		rows, _ := runDuckDBQuery(sql)
		c.JSON(http.StatusOK, gin.H{"success": true, "details": rows})
	})

	// 🌟 內網/外網 IP 智能反解 API (DHCP + ARP + 公網 rDNS PTR 與機構識別)
	r.GET("/api/tools/ip-lookup/:ip", func(c *gin.Context) {
		targetIP := strings.TrimSpace(c.Param("ip"))
		db, _ := initDB()

		hostname := "-"
		mac := "-"
		macSource := ""
		orgDesc := ""
		isInternal := false

		// 🌟 1. 標準私有 IP 判定 (RFC 1918)
		parsedIP := net.ParseIP(targetIP)
		if parsedIP != nil && parsedIP.IsPrivate() {
			isInternal = true
		}

		// 🌟 2. 若非標準私有網段，檢查是否已記錄於本地 ARP / DHCP 資產庫中 (動態識別，零硬編碼)
		if !isInternal && db != nil {
			var exists int
			_ = db.QueryRow("SELECT 1 FROM arp_records WHERE ip = ? UNION SELECT 1 FROM dhcp_leases WHERE ip = ? LIMIT 1", targetIP, targetIP).Scan(&exists)
			if exists == 1 {
				isInternal = true
			}
		}

		if db != nil {
			// 1. 若為內網 IP，優先查詢 DHCP 租約與 ARP 紀錄
			if isInternal {
				var dHn, dMac sql.NullString
				_ = db.QueryRow("SELECT hostname, mac FROM dhcp_leases WHERE ip = ? ORDER BY id DESC LIMIT 1", targetIP).Scan(&dHn, &dMac)
				if dMac.Valid && dMac.String != "" && dMac.String != "-" {
					mac = dMac.String
					macSource = "DHCP 租約"
					if dHn.Valid && dHn.String != "" {
						hostname = dHn.String
					}
				}

				if mac == "-" || mac == "" {
					var aMac, aHn sql.NullString
					_ = db.QueryRow("SELECT mac, hostname FROM arp_records WHERE ip = ?", targetIP).Scan(&aMac, &aHn)
					if aMac.Valid && aMac.String != "" && aMac.String != "-" {
						mac = aMac.String
						macSource = "ARP 靜態紀錄"
						if (hostname == "-" || hostname == "") && aHn.Valid && aHn.String != "" {
							hostname = aHn.String
						}
					}
				}
			}

			// 2. 查詢本地已儲存的 DNS 快取庫
			if hostname == "" || hostname == "-" {
				var cacheHn sql.NullString
				_ = db.QueryRow("SELECT hostname FROM ip_hostname_cache WHERE ip = ?", targetIP).Scan(&cacheHn)
				if cacheHn.Valid && cacheHn.String != "" {
					hostname = cacheHn.String
				}
			}
		}

		// 3. 🌟 外部公網 IP 發動 rDNS 反查 (加入 1.5 秒超時保護，避免阻塞)
		if hostname == "" || hostname == "-" {
			if !strings.Contains(targetIP, "WAN") && !strings.Contains(targetIP, "LAN") && net.ParseIP(targetIP) != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
				defer cancel()
				names, err := net.DefaultResolver.LookupAddr(ctx, targetIP)
				if err == nil && len(names) > 0 {
					hostname = strings.TrimSuffix(names[0], ".")
					if db != nil {
						_, _ = db.Exec("INSERT OR REPLACE INTO ip_hostname_cache (ip, hostname) VALUES (?, ?)", targetIP, hostname)
					}
				}
			}
		}

		// 4. 🌟 外部公網 IP 之知名單位與機構智能識別 (結合 IP 網段特徵與 DNS 域名)
		if !isInternal {
			hnLower := strings.ToLower(hostname)

			// 1. 臺灣教育與學術網路 (TANet / 各縣市教育局 / 學校)
			if strings.HasPrefix(targetIP, "163.21.") {
				orgDesc = "臺北市教育網路中心 (臺北市各級學校/教育局)"
			} else if strings.HasPrefix(targetIP, "163.20.") {
				orgDesc = "新北市教育網路中心 (新北市各級學校)"
			} else if strings.HasPrefix(targetIP, "140.111.") || strings.HasPrefix(targetIP, "163.28.") {
				orgDesc = "教育部 / 臺灣學術網路 (TANet)"
			} else if strings.HasPrefix(targetIP, "163.") || strings.HasPrefix(targetIP, "140.") || strings.Contains(hnLower, "edu.tw") || strings.Contains(hnLower, "tanet") {
				orgDesc = "臺灣學術網路 (TANet / 各縣市教網與大專院校)"

			// 2. 臺灣政府網路 (GSN / 公務機關)
			} else if strings.HasPrefix(targetIP, "210.69.") || strings.HasPrefix(targetIP, "210.70.") || strings.HasPrefix(targetIP, "210.71.") || strings.Contains(hnLower, "gov.tw") {
				orgDesc = "臺灣政府網際網路 (GSN / 政府與公務機關)"

			// 3. 中華電信 HiNet 數據網路
			} else if strings.HasPrefix(targetIP, "168.95.") || strings.HasPrefix(targetIP, "139.175.") || strings.Contains(hnLower, "hinet.net") {
				orgDesc = "中華電信 HiNet 數據網路"

			// 4. Google 服務 (搜尋 / YouTube / 8.8.8.8 / 142.251.* / 172.217.* 等)
			} else if strings.HasPrefix(targetIP, "8.8.8.") || strings.HasPrefix(targetIP, "8.8.4.") || strings.HasPrefix(targetIP, "142.250.") || strings.HasPrefix(targetIP, "142.251.") || strings.HasPrefix(targetIP, "172.217.") || strings.HasPrefix(targetIP, "108.177.") || strings.Contains(hnLower, "1e100.net") || strings.Contains(hnLower, "google") {
				orgDesc = "Google LLC (搜尋/YouTube/雲端服務)"

			// 5. Cloudflare CDN / Public DNS (1.1.1.1 等)
			} else if strings.HasPrefix(targetIP, "1.1.1.") || strings.HasPrefix(targetIP, "1.0.0.") || strings.Contains(hnLower, "cloudflare") {
				orgDesc = "Cloudflare CDN 網路加速節點 / DNS"

			// 6. Microsoft Corporation (Windows Update / Azure)
			} else if strings.Contains(hnLower, "microsoft") || strings.Contains(hnLower, "msn") || strings.Contains(hnLower, "azure") {
				orgDesc = "Microsoft Corporation (微軟/Windows Update/Azure)"

			// 7. Apple Inc. (App Store / iCloud)
			} else if strings.Contains(hnLower, "apple.com") || strings.Contains(hnLower, "icloud") || strings.Contains(hnLower, "aaplimg") {
				orgDesc = "Apple Inc. (蘋果服務/App Store/iCloud)"

			// 8. 其他公網服務
			} else if strings.Contains(hnLower, "facebook") || strings.Contains(hnLower, "fbcdn") {
				orgDesc = "Meta / Facebook 平台"
			} else if strings.Contains(hnLower, "amazon") || strings.Contains(hnLower, "aws") || strings.Contains(hnLower, "cloudfront") {
				orgDesc = "Amazon AWS / 雲端託管服務"
			} else {
				orgDesc = "網際網路外部公網主機"
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"ip":          targetIP,
			"hostname":    hostname,
			"mac_address": mac,
			"mac_source":  macSource,
			"org_desc":    orgDesc,
			"is_internal": isInternal,
		})
	})
	
	// 🌟 全網設備 IP / MAC / Hostname 整合資產清冊匯出 API (支援 CSV 匯出)
	r.GET("/api/tools/export-network-devices", func(c *gin.Context) {
		db, err := initDB()
		if err != nil {
			c.String(http.StatusInternalServerError, "資料庫讀取失敗")
			return
		}

		// 整合 ARP 與 DHCP 全量不重複設備清冊
		query := `
			SELECT 
				COALESCE(a.ip, d.ip) AS ip,
				COALESCE(NULLIF(a.mac, ''), d.mac) AS mac,
				COALESCE(NULLIF(a.hostname, ''), NULLIF(d.hostname, ''), c.hostname, '-') AS hostname,
				COALESCE(a.dev_type, 'DHCP 動態配發') AS dev_type,
				COALESCE(a.updated_at, d.record_date) AS last_seen
			FROM arp_records a
			FULL OUTER JOIN (
				SELECT ip, mac, hostname, record_date FROM dhcp_leases GROUP BY ip
			) d ON a.ip = d.ip
			LEFT JOIN ip_hostname_cache c ON COALESCE(a.ip, d.ip) = c.ip
			ORDER BY 
				CAST(substr(COALESCE(a.ip, d.ip), 1, instr(COALESCE(a.ip, d.ip), '.') - 1) AS INT),
				CAST(substr(substr(COALESCE(a.ip, d.ip), instr(COALESCE(a.ip, d.ip), '.') + 1), 1, instr(substr(COALESCE(a.ip, d.ip), instr(COALESCE(a.ip, d.ip), '.') + 1), '.') - 1) AS INT)
		`
		rows, err := db.Query(query)
		if err != nil {
			// 若 SQLite 版本不支援 FULL OUTER JOIN，以 UNION 容錯查詢
			queryFallback := `
				SELECT ip, mac, hostname, dev_type, updated_at FROM arp_records
				UNION
				SELECT ip, mac, hostname, 'DHCP 動態配發', record_date FROM dhcp_leases
			`
			rows, _ = db.Query(queryFallback)
		}
		defer rows.Close()

		csvData := "IP 位址,實體網卡 MAC,設備名稱 (Hostname),設備性質,最後發現時間\n"
		for rows.Next() {
			var ip, mac, hn, dtype, seen string
			_ = rows.Scan(&ip, &mac, &hn, &dtype, &seen)
			csvData += fmt.Sprintf("%s,%s,%s,%s,%s\n", ip, mac, hn, dtype, seen)
		}

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=Network_Devices_%s.csv", time.Now().Format("20060102_150405")))
		c.Data(http.StatusOK, "text/csv; charset=utf-8", []byte("\xEF\xBB\xBF"+csvData)) // 加上 UTF-8 BOM 避免 Excel 亂碼
	})
	
	// 🌟 獨立 Raw Log 歷史取回 API (支援單日與 Limit 極限跨日回溯)
	r.POST("/api/raw-traffic-download", func(c *gin.Context) {
		customBefore := strings.TrimSpace(c.Query("before"))
		if customBefore == "" { customBefore = strings.TrimSpace(c.PostForm("before")) }
		if customBefore == "" { customBefore = strings.TrimSpace(c.Request.FormValue("before")) }
		customBefore = strings.ReplaceAll(customBefore, "/", "-")

		targetDate := strings.TrimSpace(c.Query("date"))
		if targetDate == "" { targetDate = strings.TrimSpace(c.PostForm("date")) }
		if targetDate == "" { targetDate = strings.TrimSpace(c.Request.FormValue("date")) }
		targetDate = strings.ReplaceAll(targetDate, "/", "-")

		// 判斷是否為 Limit 模式 (不以 00:00:00 停機，深挖到底)
		isLimit := c.DefaultQuery("limit", "false") == "true" || c.DefaultPostForm("limit", "false") == "true"
		_ = isLimit // 👈 🌟 加上這行，消除 declared and not used 錯誤

		roundsStr := strings.TrimSpace(c.Query("rounds"))
		if roundsStr == "" { roundsStr = strings.TrimSpace(c.PostForm("rounds")) }
		rounds, _ := strconv.Atoi(roundsStr)
		if rounds <= 0 { rounds = 5 }

		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush()
		}

		lastTime := customBefore
		if lastTime == "" {
			if targetDate != "" {
				lastTime = targetDate + " 23:59:59"
			} else {
				lastTime = time.Now().Format("2006-01-02 15:04:05")
			}
		}

		if isLimit {
			sendMsg("[Raw Limit 回溯] 🚀 啟動歷史極限 Raw Log 取回 (起點: %s，目標: 直至硬體極限)...\n", lastTime)
		} else {
			sendMsg("[Raw 取回] 🚀 啟動單日 Raw Log 取回 (目標日期: %s，起點: %s)...\n", targetDate, lastTime)
		}

		successfulRounds := 0
		totalCount := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[Raw 取回] ⏳ [%d/%d] 正在向 %s 請求原始日誌 (條件: %s)...\n", r+1, rounds, getFWModelName(), filter)

			entries, err := fetchPATrafficLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[Raw 取回] ⚠️ 第 %d 輪擷取失敗: %v\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[Raw 取回] ℹ️ 已無更早的歷史日誌 (已抵達防火牆硬體極限！)\n")
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			// 🌟 跨日自適應分流：依據每筆日誌真實日期歸入 raw_archives/<日期>/
			entriesByDate := make(map[string][]TrafficParquetRow)
			for _, e := range entries {
				dKey := time.Now().Format("2006-01-02")
				if len(e.Timestamp) >= 10 {
					dKey = e.Timestamp[:10]
				}

				entriesByDate[dKey] = append(entriesByDate[dKey], TrafficParquetRow{
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

			for dKey, dRows := range entriesByDate {
				dDir := filepath.Join(appDir, "raw_archives", dKey)
				_ = os.MkdirAll(dDir, 0755)
				chunkFile := filepath.Join(dDir, fmt.Sprintf("chunk_%s_%d.parquet", dKey, time.Now().UnixNano()))
				_ = parquet.WriteFile(chunkFile, dRows)
			}

			totalCount += len(entries)
			successfulRounds++

			oldest := entries[0].Timestamp
			for _, e := range entries {
				if e.Timestamp < oldest {
					oldest = e.Timestamp
				}
			}

			sendMsg("[Raw 取回] ✅ [%d/%d] 成功落盤: %d 筆 (耗時: %.1fs)，推進至: %s\n",
				r+1, rounds, len(entries), time.Since(startT).Seconds(), oldest)

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			// 🛑 僅在「非 Limit 模式」下才在跨越 00:00:00 時終止；Limit 模式下持續深挖
			if !isLimit && targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[Raw 取回] 🎯 已達成當日 00:00:00 邊界 (推進至: %s)！\n", lastTime)
				_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte("LIMIT"), 0644)
				break
			}

			if r < rounds-1 {
				_, roundSleep := getAdaptiveBackfillTimings()
				time.Sleep(roundSleep)
			}
		}

		sendMsg("🏁 [Raw 取回] 本批次完成！共執行 %d 輪，累積儲存: %d 筆，歷史時間推進至 %s。\n",
			successfulRounds, totalCount, lastTime)
	})	
	
	// 🌟 OS 跨平台冷資料根目錄解析器 (自動判斷 Windows 與 Linux 路徑、工作目錄及軟連結)
	getColdArchiveScanRoots := func() []struct {
		label string
		path  string
	} {
		type rootEntry struct {
			label string
			path  string
		}
		var candidates []rootEntry
		wd, _ := os.Getwd()

		if runtime.GOOS == "windows" {
			// 🪟 Windows 路徑候選清單
			if trafficRawDir != "" {
				candidates = append(candidates, rootEntry{"traffic_raw_logs", trafficRawDir})
			}
			candidates = append(candidates,
				rootEntry{"traffic_raw_logs", filepath.Join(appDir, "traffic_raw_logs")},
				rootEntry{"raw_archives", filepath.Join(appDir, "raw_archives")},
			)
			if wd != "" {
				candidates = append(candidates,
					rootEntry{"traffic_raw_logs", filepath.Join(wd, "traffic_raw_logs")},
					rootEntry{"raw_archives", filepath.Join(wd, "raw_archives")},
				)
			}
		} else {
			// 🐧 Linux / Unix 路徑候選清單 (相容執行檔目錄、當前工作目錄與標準 /opt/pa_monitor)
			baseDirs := []string{appDir, wd, "/opt/pa_monitor"}
			if trafficRawDir != "" {
				candidates = append(candidates, rootEntry{"traffic_raw_logs", trafficRawDir})
			}
			for _, base := range baseDirs {
				if base == "" {
					continue
				}
				candidates = append(candidates,
					rootEntry{"traffic_raw_logs", filepath.Join(base, "traffic_raw_logs")},
					rootEntry{"raw_archives", filepath.Join(base, "raw_archives")},
				)
			}
		}

		// 去除重複路徑並解析真實實體路徑 (處理 Linux Symlink)
		seen := make(map[string]bool)
		var validRoots []struct {
			label string
			path  string
		}
		for _, c := range candidates {
			cleanPath := filepath.Clean(c.path)
			if resolved, err := filepath.EvalSymlinks(cleanPath); err == nil {
				cleanPath = resolved
			}
			dedupKey := cleanPath
			if runtime.GOOS == "windows" {
				dedupKey = strings.ToLower(cleanPath)
			}
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			validRoots = append(validRoots, struct {
				label string
				path  string
			}{label: c.label, path: cleanPath})
		}
		return validRoots
	}

	// 🌟 支援 Linux 軟連結子目錄的 Parquet 檔案遞迴掃描器
	walkParquetFilesOS := func(rootDir string, onFile func(fullPath, fileName string, info os.FileInfo)) {
		visitedDirs := make(map[string]bool)
		var walkFn func(currDir string)
		walkFn = func(currDir string) {
			realDir := currDir
			if r, err := filepath.EvalSymlinks(currDir); err == nil {
				realDir = r
			}
			key := realDir
			if runtime.GOOS == "windows" {
				key = strings.ToLower(realDir)
			}
			if visitedDirs[key] {
				return
			}
			visitedDirs[key] = true

			entries, err := os.ReadDir(currDir)
			if err != nil {
				return
			}
			for _, entry := range entries {
				fullPath := filepath.Join(currDir, entry.Name())
				// 使用 os.Stat 取代 entry.Info()，確保 Linux 軟連結目錄能被正確識別為資料夾
				info, statErr := os.Stat(fullPath)
				if statErr != nil {
					continue
				}
				if info.IsDir() {
					walkFn(fullPath)
					continue
				}
				name := entry.Name()
				if strings.HasSuffix(strings.ToLower(name), ".parquet") && !strings.HasSuffix(strings.ToLower(name), ".tmp") && info.Size() > 0 {
					onFile(fullPath, name, info)
				}
			}
		}
		walkFn(rootDir)
	}

	// 🌟 24-A. 自動掃描冷資料目錄與分時檔案明細 API (跨平台 OS 路徑相容版)
	r.GET("/api/cold-archives/list", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")

		type ColdFileDetail struct {
			FileName  string  `json:"file_name"`
			FullPath  string  `json:"full_path"`
			HourLabel string  `json:"hour_label"`
			SizeMB    float64 `json:"size_mb"`
			HotExists bool    `json:"hot_exists"`
		}

		type ColdArchiveSummary struct {
			Date         string           `json:"date"`
			FileCount    int              `json:"file_count"`
			TotalSizeMB  float64          `json:"total_size_mb"`
			HotExists    bool             `json:"hot_exists"`
			HotFileCount int              `json:"hot_file_count"`
			HotSizeMB    float64          `json:"hot_size_mb"`
			SourceDirs   []string         `json:"source_dirs"`
			Files        []ColdFileDetail `json:"files"`
		}

		dateMap := make(map[string]*ColdArchiveSummary)
		dirSetMap := make(map[string]map[string]bool)
		seenFileMap := make(map[string]bool)
		dateRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
		hourSlotRegex := regexp.MustCompile(`_(\d{2})(?:_(\d{2}))?\.parquet$`)

		scanRoots := getColdArchiveScanRoots()
		var scannedPaths []string

		for _, root := range scanRoots {
			scannedPaths = append(scannedPaths, root.path)
			if _, err := os.Stat(root.path); os.IsNotExist(err) {
				continue
			}

			walkParquetFilesOS(root.path, func(fullPath, name string, info os.FileInfo) {
				normKey := fullPath
				if runtime.GOOS == "windows" {
					normKey = strings.ToLower(fullPath)
				}
				if seenFileMap[normKey] {
					return
				}
				seenFileMap[normKey] = true

				dateStr := dateRegex.FindString(name)
				if dateStr == "" {
					dateStr = dateRegex.FindString(fullPath)
				}
				if dateStr == "" {
					return
				}

				if _, exists := dateMap[dateStr]; !exists {
					dateMap[dateStr] = &ColdArchiveSummary{
						Date:  dateStr,
						Files: make([]ColdFileDetail, 0),
					}
					dirSetMap[dateStr] = make(map[string]bool)
				}

				hourLabel := "全日主檔"
				hourHotExists := false
				if m := hourSlotRegex.FindStringSubmatch(name); len(m) >= 2 {
					hh := m[1]
					if len(m) >= 3 && m[2] != "" {
						hourLabel = fmt.Sprintf("%s:%s 切片", hh, m[2])
					} else {
						hourLabel = fmt.Sprintf("%s:00", hh)
					}
					hotHourPath := filepath.Join(trafficDir, dateStr, fmt.Sprintf("traffic_%s_%s.parquet", dateStr, hh))
					if fi, err := os.Stat(hotHourPath); err == nil && fi.Size() > 0 {
						hourHotExists = true
					}
				} else {
					hotDayPath := filepath.Join(trafficDir, dateStr, fmt.Sprintf("traffic_%s.parquet", dateStr))
					if fi, err := os.Stat(hotDayPath); err == nil && fi.Size() > 0 {
						hourHotExists = true
					}
				}

				sizeMB := float64(info.Size()) / 1024 / 1024
				item := dateMap[dateStr]
				item.FileCount++
				item.TotalSizeMB += sizeMB
				item.Files = append(item.Files, ColdFileDetail{
					FileName:  name,
					FullPath:  filepath.ToSlash(fullPath),
					HourLabel: hourLabel,
					SizeMB:    sizeMB,
					HotExists: hourHotExists,
				})
				dirSetMap[dateStr][root.label] = true
			})
		}

		var results []*ColdArchiveSummary
		for dateStr, item := range dateMap {
			for dirLabel := range dirSetMap[dateStr] {
				item.SourceDirs = append(item.SourceDirs, dirLabel)
			}
			sort.Strings(item.SourceDirs)

			sort.Slice(item.Files, func(i, j int) bool {
				return item.Files[i].FileName < item.Files[j].FileName
			})

			hotSubFiles, _ := filepath.Glob(filepath.Join(trafficDir, dateStr, "*.parquet"))
			hotFlatFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", dateStr)))
			allHot := append(hotSubFiles, hotFlatFiles...)
			for _, hf := range allHot {
				if strings.HasSuffix(hf, ".tmp") {
					continue
				}
				if fi, err := os.Stat(hf); err == nil && fi.Size() > 0 {
					item.HotExists = true
					item.HotFileCount++
					item.HotSizeMB += float64(fi.Size()) / 1024 / 1024
				}
			}

			results = append(results, item)
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].Date > results[j].Date
		})

		c.JSON(http.StatusOK, gin.H{
			"status":        "success",
			"os":            runtime.GOOS,
			"scanned_paths": scannedPaths,
			"items":         results,
		})
	})

	// 🌟 24-B. 冷資料轉熱資料 API (OS 跨平台路徑正規化 + 指定分時轉換 + 清除舊熱檔與碎片)
	r.POST("/api/cold-to-hot", func(c *gin.Context) {
		targetDate := strings.TrimSpace(c.DefaultPostForm("date", c.Query("date")))
		targetDate = strings.ReplaceAll(targetDate, "/", "-")
		if targetDate == "" {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "請指定日期 (YYYY-MM-DD)"})
			return
		}

		var requestedFiles []string
		if filesJSON := strings.TrimSpace(c.PostForm("files")); filesJSON != "" {
			_ = json.Unmarshal([]byte(filesJSON), &requestedFiles)
		}

		// 取得當前作業系統下所有合法的冷資料根目錄
		scanRoots := getColdArchiveScanRoots()
		isPathInAllowedRoots := func(targetPath string) bool {
			cleanTarget := filepath.Clean(targetPath)
			if r, err := filepath.EvalSymlinks(cleanTarget); err == nil {
				cleanTarget = r
			}
			for _, root := range scanRoots {
				rootClean := filepath.Clean(root.path)
				if runtime.GOOS == "windows" {
					if strings.HasPrefix(strings.ToLower(cleanTarget), strings.ToLower(rootClean)) {
						return true
					}
				} else {
					if strings.HasPrefix(cleanTarget, rootClean) {
						return true
					}
				}
			}
			return false
		}

		var coldFiles []string
		if len(requestedFiles) > 0 {
			for _, rf := range requestedFiles {
				var osNativePath string
				if runtime.GOOS == "windows" {
					osNativePath = filepath.Clean(strings.ReplaceAll(strings.TrimSpace(rf), "/", `\`))
				} else {
					osNativePath = filepath.Clean(strings.ReplaceAll(strings.TrimSpace(rf), `\`, "/"))
				}

				if !isPathInAllowedRoots(osNativePath) {
					continue
				}
				if fi, err := os.Stat(osNativePath); err == nil && !fi.IsDir() && fi.Size() > 0 {
					coldFiles = append(coldFiles, filepath.ToSlash(osNativePath))
				}
			}
		} else {
			dateRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
			for _, root := range scanRoots {
				if _, err := os.Stat(root.path); os.IsNotExist(err) {
					continue
				}
				walkParquetFilesOS(root.path, func(fullPath, name string, info os.FileInfo) {
					dStr := dateRegex.FindString(name)
					if dStr == "" {
						dStr = dateRegex.FindString(fullPath)
					}
					if dStr == targetDate {
						coldFiles = append(coldFiles, filepath.ToSlash(fullPath))
					}
				})
			}
		}

		if len(coldFiles) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": fmt.Sprintf("在 %s 系統下找不到 %s 可轉換的冷資料檔案", runtime.GOOS, targetDate)})
			return
		}

		startT := time.Now()
		hourSlotRegex := regexp.MustCompile(`_(\d{2})(?:_(\d{2}))?\.parquet$`)

		hourlyGroups := make(map[string][]string)
		var dailyGroup []string
		for _, cf := range coldFiles {
			base := filepath.Base(cf)
			if m := hourSlotRegex.FindStringSubmatch(base); len(m) >= 2 {
				hourlyGroups[m[1]] = append(hourlyGroups[m[1]], cf)
			} else {
				dailyGroup = append(dailyGroup, cf)
			}
		}

		hotDir := filepath.Join(trafficDir, targetDate)
		_ = os.MkdirAll(hotDir, 0755)
		tempSpillDir := filepath.ToSlash(filepath.Join(appDir, "duckdb_temp"))
		_ = os.MkdirAll(filepath.Join(appDir, "duckdb_temp"), 0755)

		convertGroupToHot := func(srcFiles []string, timeFilterPrefix string, outHotFile string) (int64, int64, float64, error) {
			quoted := make([]string, len(srcFiles))
			for i, f := range srcFiles {
				quoted[i] = fmt.Sprintf("'%s'", f)
			}
			arrayExpr := fmt.Sprintf("[%s]", strings.Join(quoted, ", "))

			var grpRaw int64
			if res, err := runDuckDBQuery(fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata(%s);", arrayExpr)); err == nil && len(res) > 0 {
				grpRaw = parseDuckDBNumber(res[0]["cnt"])
			}

			colSet := make(map[string]bool)
			if descRows, err := runDuckDBQuery(fmt.Sprintf("DESCRIBE SELECT * FROM read_parquet(%s, union_by_name=true);", arrayExpr)); err == nil {
				for _, r := range descRows {
					colSet[fmt.Sprintf("%v", r["column_name"])] = true
				}
			}

			pickVarchar := func(defaultExpr string, candidates ...string) string {
				var valid []string
				for _, col := range candidates {
					if colSet[col] {
						valid = append(valid, fmt.Sprintf(`NULLIF(TRY_CAST("%s" AS VARCHAR), '')`, col))
					}
				}
				if len(valid) == 0 {
					return defaultExpr
				}
				if defaultExpr != "" {
					valid = append(valid, defaultExpr)
				}
				return fmt.Sprintf("COALESCE(%s)", strings.Join(valid, ", "))
			}

			pickInt := func(candidates ...string) string {
				var valid []string
				for _, col := range candidates {
					if colSet[col] {
						valid = append(valid, fmt.Sprintf(`TRY_CAST("%s" AS INT)`, col))
					}
				}
				if len(valid) == 0 {
					return "0"
				}
				return fmt.Sprintf("COALESCE(%s, 0)", strings.Join(valid, ", "))
			}

			pickBigInt := func(candidates ...string) string {
				var valid []string
				for _, col := range candidates {
					if colSet[col] {
						valid = append(valid, fmt.Sprintf(`TRY_CAST("%s" AS BIGINT)`, col))
					}
				}
				if len(valid) == 0 {
					return "0"
				}
				return fmt.Sprintf("COALESCE(%s, 0)", strings.Join(valid, ", "))
			}

			tsExpr := pickVarchar("''", "Generate Time", "Receive Time", "column6", "timestamp")
			typeExpr := pickVarchar("'end'", "Threat/Content Type", "Type", "column4", "type")
			fromZoneExpr := pickVarchar("''", "Source Zone", "column16", "from_zone")
			toZoneExpr := pickVarchar("''", "Destination Zone", "column17", "to_zone")
			srcExpr := pickVarchar("''", "Source address", "column7", "source")
			natSrcExpr := pickVarchar("''", "NAT Source IP", "column9", "nat_source_ip")
			dstExpr := pickVarchar("''", "Destination address", "column8", "destination")
			natDstExpr := pickVarchar("''", "NAT Destination IP", "column10", "nat_dest_ip")
			portExpr := pickInt("Destination Port", "column25", "to_port")
			appExpr := pickVarchar("'unknown'", "Application", "column14", "application")
			actionExpr := pickVarchar("'allow'", "Action", "column30", "action")
			ruleExpr := pickVarchar("''", "Rule", "column11", "rule")
			endReasonExpr := pickVarchar("''", "Session End Reason", "column46", "session_end_reason")
			bytesExpr := pickBigInt("Bytes", "column31", "bytes")
			sidExpr := pickVarchar("''", "Session ID", "column22", "session_id")

			tmpFile := fmt.Sprintf("%s.%d.tmp", outHotFile, time.Now().UnixNano())
			sql := fmt.Sprintf(`
				SET max_memory = '32GB'; SET threads = 12; SET preserve_insertion_order = false; SET temp_directory = '%s';
				COPY (
					SELECT * EXCLUDE (rn) FROM (
						SELECT *, ROW_NUMBER() OVER (
							PARTITION BY timestamp, source, destination, to_port, session_id, action, bytes
							ORDER BY timestamp DESC
						) AS rn
						FROM (
							SELECT
								REPLACE(REPLACE(%s, '/', '-'), '  ', ' ') AS timestamp,
								%s AS type, %s AS from_zone, %s AS to_zone,
								%s AS source, %s AS nat_source_ip, %s AS destination, %s AS nat_dest_ip,
								%s AS to_port, %s AS application, %s AS action, %s AS rule,
								%s AS session_end_reason, %s AS bytes, %s AS session_id
							FROM read_parquet(%s, union_by_name=true)
						)
						WHERE timestamp LIKE '%s%%' AND source != '' AND destination != ''
					) WHERE rn = 1
					ORDER BY timestamp DESC
				) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
			`, tempSpillDir,
				tsExpr, typeExpr, fromZoneExpr, toZoneExpr,
				srcExpr, natSrcExpr, dstExpr, natDstExpr,
				portExpr, appExpr, actionExpr, ruleExpr,
				endReasonExpr, bytesExpr, sidExpr,
				arrayExpr, timeFilterPrefix, filepath.ToSlash(tmpFile))

			if _, err := runDuckDBQuery(sql); err != nil {
				_ = os.Remove(tmpFile)
				return grpRaw, 0, 0, err
			}

			_ = os.Remove(outHotFile)
			if err := os.Rename(tmpFile, outHotFile); err != nil {
				_ = os.Remove(tmpFile)
				return grpRaw, 0, 0, err
			}

			var grpValid int64
			if res, err := runDuckDBQuery(fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');", filepath.ToSlash(outHotFile))); err == nil && len(res) > 0 {
				grpValid = parseDuckDBNumber(res[0]["cnt"])
			}
			var grpMB float64
			if fi, err := os.Stat(outHotFile); err == nil {
				grpMB = float64(fi.Size()) / 1024 / 1024
			}
			return grpRaw, grpValid, grpMB, nil
		}

		var totalRawCount, totalValidCount int64
		var totalOutputMB float64
		removedHotFiles := 0
		var outputNames []string

		var hours []string
		for h := range hourlyGroups {
			hours = append(hours, h)
		}
		sort.Strings(hours)

		for _, hh := range hours {
			targetHourHot := filepath.Join(hotDir, fmt.Sprintf("traffic_%s_%s.parquet", targetDate, hh))
			oldHourMatches, _ := filepath.Glob(filepath.Join(hotDir, fmt.Sprintf("traffic_%s_%s*.parquet", targetDate, hh)))
			for _, oldF := range oldHourMatches {
				if !strings.HasSuffix(oldF, ".tmp") {
					if err := os.Remove(oldF); err == nil {
						removedHotFiles++
					}
				}
			}

			rCnt, vCnt, mb, err := convertGroupToHot(hourlyGroups[hh], fmt.Sprintf("%s %s:", targetDate, hh), targetHourHot)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("第 %s 時轉換失敗: %v", hh, err)})
				return
			}
			totalRawCount += rCnt
			totalValidCount += vCnt
			totalOutputMB += mb
			outputNames = append(outputNames, filepath.Base(targetHourHot))
		}

		if len(hours) > 0 {
			flatMatches, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", targetDate)))
			for _, ff := range flatMatches {
				if err := os.Remove(ff); err == nil {
					removedHotFiles++
				}
			}
			fragMatches, _ := filepath.Glob(filepath.Join(hotDir, fmt.Sprintf("traffic_%s_*.parquet", targetDate)))
			for _, fm := range fragMatches {
				base := filepath.Base(fm)
				if strings.Contains(base, "_live_") || strings.Contains(base, "_chunk_") || strings.Contains(base, "_rollup_") || strings.Contains(base, "_nas_") {
					if err := os.Remove(fm); err == nil {
						removedHotFiles++
					}
				}
			}
			if len(hours) >= 24 {
				oldSingleDay := filepath.Join(hotDir, fmt.Sprintf("traffic_%s.parquet", targetDate))
				if err := os.Remove(oldSingleDay); err == nil {
					removedHotFiles++
				}
			}
		}

		if len(dailyGroup) > 0 {
			targetDayHot := filepath.Join(hotDir, fmt.Sprintf("traffic_%s.parquet", targetDate))
			oldSubFiles, _ := filepath.Glob(filepath.Join(hotDir, "*.parquet"))
			for _, f := range oldSubFiles {
				if !strings.HasSuffix(f, ".tmp") {
					if err := os.Remove(f); err == nil {
						removedHotFiles++
					}
				}
			}
			oldFlatFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", targetDate)))
			for _, f := range oldFlatFiles {
				if err := os.Remove(f); err == nil {
					removedHotFiles++
				}
			}

			rCnt, vCnt, mb, err := convertGroupToHot(dailyGroup, targetDate, targetDayHot)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "全日熱資料轉換失敗: " + err.Error()})
				return
			}
			totalRawCount += rCnt
			totalValidCount += vCnt
			totalOutputMB += mb
			outputNames = append(outputNames, filepath.Base(targetDayHot))
		}

		durationSec := time.Since(startT).Seconds()
		outDesc := strings.Join(outputNames, ", ")
		if len(outputNames) > 3 {
			outDesc = fmt.Sprintf("%s 等 %d 個分時熱檔", outputNames[0], len(outputNames))
		}

		RecordAuditLog(AuditLogRecord{
			FWModel:     getFWModelName(),
			LogType:     "traffic",
			Category:    "14欄熱資料",
			TargetDate:  targetDate,
			TargetSlot:  fmt.Sprintf("已選 %d 檔", len(coldFiles)),
			Status:      "SUCCESS",
			RecordCount: totalValidCount,
			FileSizeMB:  totalOutputMB,
			DurationSec: durationSec,
			OutputFile:  outDesc,
			Details:     fmt.Sprintf("[%s] 冷資料轉熱資料完成 (選定 %d 檔)｜原始: %d 筆 ➔ 有效: %d 筆 (移除 %d 個舊檔/碎片)", runtime.GOOS, len(coldFiles), totalRawCount, totalValidCount, removedHotFiles),
			Operator:    "MANUAL_RECOVER",
		})

		c.JSON(http.StatusOK, gin.H{
			"status":            "success",
			"date":              targetDate,
			"selected_files":    len(coldFiles),
			"raw_count":         totalRawCount,
			"valid_count":       totalValidCount,
			"removed_hot_files": removedHotFiles,
			"file_size_mb":      totalOutputMB,
			"duration":          fmt.Sprintf("%.2f 秒", durationSec),
			"file":              outDesc,
		})
	})
	
}

// 🌟 動態取得連線至目標主機時所使用的本機網路卡 IP (零寫死、隨插即用)
func getOutboundIPToFirewall(targetIP string) string {
	if targetIP == "" {
		return "127.0.0.1"
	}
	conn, err := net.Dial("udp", targetIP+":80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// 🌟 1. 解析 IP 範圍格式 (支援 192.168.1.1-254, 192.168.1.1-192.168.1.254, 192.168.1.0/24)
func parseIPRangeString(rangeStr string) ([]string, error) {
	s := strings.TrimSpace(rangeStr)
	if s == "" {
		return nil, fmt.Errorf("IP 範圍不能為空")
	}

	var ips []string
	if strings.Contains(s, "/") {
		// CIDR 格式
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		for curr := ip.Mask(ipNet.Mask); ipNet.Contains(curr); incIP(curr) {
			ips = append(ips, curr.String())
		}
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1] // 去除網路位址與廣播位址
		}
	} else if strings.Contains(s, "-") {
		// 區間格式: 192.50.1.1-254 或 192.50.1.1-192.50.1.254
		parts := strings.Split(s, "-")
		startStr := strings.TrimSpace(parts[0])
		endStr := strings.TrimSpace(parts[1])

		startIP := net.ParseIP(startStr).To4()
		if startIP == nil {
			return nil, fmt.Errorf("無效的起始 IP: %s", startStr)
		}

		var endIP net.IP
		if strings.Contains(endStr, ".") {
			endIP = net.ParseIP(endStr).To4()
		} else {
			lastDot := strings.LastIndex(startStr, ".")
			endIP = net.ParseIP(startStr[:lastDot+1] + endStr).To4()
		}
		if endIP == nil {
			return nil, fmt.Errorf("無效的結束 IP: %s", endStr)
		}

		startInt := ipToUint32(startIP)
		endInt := ipToUint32(endIP)
		if startInt > endInt {
			startInt, endInt = endInt, startInt
		}
		if endInt-startInt > 1024 {
			endInt = startInt + 1024 // 安全上限，一次最多 1024 個 IP
		}

		for i := startInt; i <= endInt; i++ {
			ips = append(ips, uint32ToIP(i).String())
		}
	} else {
		// 單一 IP
		if net.ParseIP(s) != nil {
			ips = append(ips, s)
		}
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// 🌟 跨平台並行高速 Ping 區網並提取本機 ARP 對應表 (Windows/Linux 雙相容)
func scanIPRangeAndGetWindowsARP(ips []string) (map[string]string, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("沒有要掃描的 IP")
	}

	// 1. 建立 40 個 Worker 並行發送 Ping 喚醒鄰居 ARP
	jobs := make(chan string, len(ips))
	var wg sync.WaitGroup
	workers := 40
	if len(ips) < workers {
		workers = len(ips)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetIP := range jobs {
				var cmd *exec.Cmd
				if runtime.GOOS == "windows" {
					cmd = exec.Command("ping", "-n", "1", "-w", "200", targetIP)
				} else {
					// Linux iputils: -c 1 (1次), -W 1 (等待1秒)
					cmd = exec.Command("ping", "-c", "1", "-W", "1", targetIP)
				}
				_ = cmd.Run()
			}
		}()
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()

	arpMap := make(map[string]string)

	// 🌟 2-A. Linux 原生：直接讀取核心 /proc/net/arp (毫秒級提取，零外部工具依賴)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/net/arp"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines[1:] { // 略過第一行表頭
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					ip := strings.TrimSpace(fields[0])
					flags := strings.TrimSpace(fields[2])
					mac := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fields[3]), "-", ":"))

					// flags == 0x2 代表已完成解析的有效 MAC，排除未完成 (00:00:00:00:00:00) 與廣播
					if flags == "0x2" && mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff" &&
						!strings.HasPrefix(ip, "224.") && !strings.HasPrefix(ip, "239.") && !strings.HasSuffix(ip, ".255") {
						arpMap[ip] = mac
					}
				}
			}
			return arpMap, nil
		}
	}

	// 🌟 2-B. Windows 或 Linux 備援：執行命令列 arp -a / ip neigh
	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = exec.Command("arp", "-a").Output()
	} else {
		out, err = exec.Command("ip", "neigh").Output()
		if err != nil {
			out, err = exec.Command("arp", "-an").Output()
		}
	}

	if err != nil {
		return nil, fmt.Errorf("取得系統 ARP 表失敗: %v", err)
	}

	// 3. 正則提取 IP 與實體 MAC (相容 Windows 與 Linux 輸出格式)
	re := regexp.MustCompile(`([0-9]{1,3}(?:\.[0-9]{1,3}){3})[\s\S]*?([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})`)
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			ip := strings.TrimSpace(matches[1])
			mac := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(matches[2]), "-", ":"))

			if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") || strings.HasSuffix(ip, ".255") ||
				mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e:") || mac == "00:00:00:00:00:00" {
				continue
			}

			arpMap[ip] = mac
		}
	}

	return arpMap, nil
}


