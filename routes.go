package main

import (
	"bytes"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath" // 👈 補上：供 route 16 組合 Parquet 檔案路徑
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/parquet-go/parquet-go" // 👈 補上：供 route 16 讀取目前最舊連線紀錄
)

func renderPongo(c *gin.Context, tplName string, ctx pongo2.Context) {
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

	// 10. ARP 即時比對與固定 IP 分析
	r.GET("/api/arp-analysis", func(c *gin.Context) {
		queryDate := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		body, err := runPACommand("<show><arp><entry name='all'/></arp></show>")
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		decoder := xml.NewDecoder(bytes.NewReader(body))
		var arpEntries []ARPEntry
		for {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			if se, ok := token.(xml.StartElement); ok && se.Name.Local == "entry" {
				var e ARPEntry
				if err := decoder.DecodeElement(&e, &se); err == nil {
					arpEntries = append(arpEntries, e)
				}
			}
		}

		db, _ := initDB()
		dhcpRecords := make(map[string]map[string]string)
		historicalMACMap := make(map[string]string)
		dnsCacheMap := make(map[string]string)

		if db != nil {
			r1, err := db.Query("SELECT ip, mac, hostname FROM dhcp_leases WHERE record_date = ?", queryDate)
			if err == nil {
				defer r1.Close()
				for r1.Next() {
					var ip, mac, hn string
					_ = r1.Scan(&ip, &mac, &hn)
					dhcpRecords[ip] = map[string]string{"mac": strings.ToLower(mac), "hostname": hn}
				}
			}
			r2, err := db.Query("SELECT mac, hostname FROM dhcp_leases WHERE hostname != '' AND hostname IS NOT NULL ORDER BY id ASC")
			if err == nil {
				defer r2.Close()
				for r2.Next() {
					var mac, hn string
					_ = r2.Scan(&mac, &hn)
					historicalMACMap[strings.ToLower(mac)] = hn
				}
			}
			r3, err := db.Query("SELECT ip, hostname FROM ip_hostname_cache")
			if err == nil {
				defer r3.Close()
				for r3.Next() {
					var ip, hn string
					_ = r3.Scan(&ip, &hn)
					dnsCacheMap[ip] = hn
				}
			}
		}

		type ARPResult struct {
			IP        string `json:"ip"`
			MAC       string `json:"mac"`
			Interface string `json:"interface"`
			Hostname  string `json:"hostname"`
			DevType   string `json:"dev_type"`
			TagClass  string `json:"tag_class"`
		}

		var results []ARPResult
		staticCount, normalCount, conflictCount := 0, 0, 0
		var uncachedStaticIPs []string

		dnsMutex.RLock()
		isDNSRunning := dnsWorkerStatus.IsRunning
		dnsMutex.RUnlock()

		for _, e := range arpEntries {
			ip := strings.TrimSpace(e.IP)
			mac := strings.ToLower(strings.TrimSpace(e.MAC))
			if ip == "" || mac == "" || mac == "(incomplete)" || e.Status == "i" {
				continue
			}

			var devType, tagClass, hostname string
			if d, ok := dhcpRecords[ip]; ok {
				if d["mac"] == mac {
					devType = "DHCP 動態配發"
					tagClass = "success"
					normalCount++
					hostname = d["hostname"]
					if hostname == "" {
						hostname = "(無主機名)"
					}
				} else {
					devType = "⚠️ IP 衝突/MAC變更"
					tagClass = "danger"
					conflictCount++
					hostname = d["hostname"]
					if hostname == "" {
						hostname = "(無主機名)"
					}
				}
			} else {
				devType = "🚨 私設/固定 IP (Static IP)"
				tagClass = "warning"
				staticCount++

				if h, ok := dnsCacheMap[ip]; ok {
					hostname = fmt.Sprintf("<span class='text-primary fw-bold'><i class='bi bi-globe me-1'></i>%s</span>", h)
				} else if h, ok := historicalMACMap[mac]; ok {
					hostname = fmt.Sprintf("<span class='text-secondary'><i class='bi bi-clock-history me-1'></i>%s (歷史)</span>", h)
					uncachedStaticIPs = append(uncachedStaticIPs, ip)
				} else {
					if isDNSRunning {
						hostname = "<span class='text-muted'><div class='spinner-grow spinner-grow-sm text-secondary me-1'></div>解析中...</span>"
					} else {
						hostname = "<span class='text-muted'>待解析</span>"
					}
					uncachedStaticIPs = append(uncachedStaticIPs, ip)
				}
			}

			results = append(results, ARPResult{
				IP:        ip,
				MAC:       mac,
				Interface: e.Interface,
				Hostname:  hostname,
				DevType:   devType,
				TagClass:  tagClass,
			})
		}

		if len(uncachedStaticIPs) > 0 && !isDNSRunning {
			backgroundDNSWorker(uncachedStaticIPs)
		}

		// IP 排序
		sort.Slice(results, func(i, j int) bool {
			ip1 := net.ParseIP(results[i].IP)
			ip2 := net.ParseIP(results[j].IP)
			if ip1 != nil && ip2 != nil {
				return bytes.Compare(ip1.To4(), ip2.To4()) < 0
			}
			return results[i].IP < results[j].IP
		})

		dnsMutex.RLock()
		progress := dnsWorkerStatus
		dnsMutex.RUnlock()

		c.JSON(http.StatusOK, gin.H{
			"status":            "success",
			"date":              queryDate,
			"total_arp":         len(results),
			"static_ip_count":   staticCount,
			"normal_dhcp_count": normalCount,
			"conflict_count":    conflictCount,
			"dns_progress":      progress,
			"data":              results,
		})
	})

	// 11. 流量日誌檢索與直方圖數據 API (強制禁用瀏覽器快取)
	r.GET("/api/traffic-query", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		date := c.DefaultQuery("date", time.Now().Format("2006-01-02"))
		src := strings.TrimSpace(c.DefaultQuery("src", ""))
		dst := strings.TrimSpace(c.DefaultQuery("dst", ""))
		app := strings.TrimSpace(c.DefaultQuery("app", ""))
		action := strings.TrimSpace(c.DefaultQuery("action", "all"))
		zone := strings.TrimSpace(c.DefaultQuery("zone", "all"))
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))

		result, err := queryTrafficAnalytics(date, src, dst, app, action, zone, page, perPage)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":       "success",
			"total_flows":  result.TotalFlows,
			"total_bytes":  result.TotalBytes,
			"top_app":      result.TopApp,
			"deny_flows":   result.DenyFlows,
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
			"message": fmt.Sprintf("成功自 PA-1420 擷取 %d 筆流量紀錄！新增至當日 Parquet：%d 筆，今日累計：%d 筆", len(entries), success, total),
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

	// 16. 🌟 智慧接力回溯 (即時分輪串流輸出)：每輪即時回傳給終端機，不再等待全部跑完
	r.POST("/api/traffic-backfill", func(c *gin.Context) {
		// 設定 HTTP 分塊串流標頭 (停用緩衝)
		c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		// 定義即時輸出小函式 (同時輸出至伺服器 Console 與客戶端 curl)
		sendMsg := func(format string, a ...interface{}) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = c.Writer.Write([]byte(msg))
			c.Writer.Flush() // 👈 關鍵：強制立刻將封包送出到網路上
		}

		rounds, _ := strconv.Atoi(c.DefaultPostForm("rounds", "5"))
		if rounds <= 0 {
			rounds = 5
		}
		if rounds > 10 {
			rounds = 10
		}

		customBefore := strings.TrimSpace(c.DefaultPostForm("before", ""))
		lastTime := customBefore

		// 跨日全庫搜尋最早時間
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
		}

		sendMsg("[流量回補] 🚀 啟動回溯作業，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[流量回補] ⏳ [%d/%d] 正在向 PA-1420 請求資料 (過濾條件: %s)...\n", r+1, rounds, filter)

			entries, err := fetchPATrafficLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[流量回補] ⚠️ 第 %d 輪擷取逾時或失敗：%v (提前結束)\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[流量回補] ℹ️ 第 %d 輪已無更早的歷史日誌 (已達極限)\n", r+1)
				break
			}

			ins, tot, _ := saveTrafficLogsToParquet(entries)
			totalNew += ins
			successfulRounds++

			oldest := entries[0].Timestamp
			for _, e := range entries {
				if e.Timestamp < oldest {
					oldest = e.Timestamp
				}
			}

			// 👈 每跑完一輪，客戶端會立刻跳出此行
			sendMsg("[流量回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (當日累計: %d 筆)，時間推進至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, tot, oldest)

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [流量回補] 完成！共執行 %d 輪，補入 %d 筆紀錄，歷史時間已向前推進至 %s。\n", successfulRounds, totalNew, lastTime)
	})

	// 17. 🌟 智慧接力回溯：向 PA-1420 擷取歷史資安威脅 (即時分輪串流輸出)
	r.POST("/api/threat-backfill", func(c *gin.Context) {
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

		rounds, _ := strconv.Atoi(c.DefaultPostForm("rounds", "5"))
		if rounds <= 0 {
			rounds = 5
		}
		if rounds > 10 {
			rounds = 10
		}

		customBefore := strings.TrimSpace(c.DefaultPostForm("before", ""))
		lastTime := customBefore

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
		}

		sendMsg("[Threat 回補] 🚀 啟動資安威脅回溯，預計回溯 %d 輪 (目標: %d 筆)...\n", rounds, rounds*5000)

		totalNew := 0
		successfulRounds := 0

		for r := 0; r < rounds; r++ {
			var filter string
			if lastTime != "" {
				paTime := strings.ReplaceAll(lastTime, "-", "/")
				filter = fmt.Sprintf("(time_generated leq '%s')", paTime)
			}

			startT := time.Now()
			sendMsg("[Threat 回補] ⏳ [%d/%d] 正在向 PA-1420 擷取威脅日誌 (條件: %s)...\n", r+1, rounds, filter)

			entries, err := fetchPAThreatLogsWithFilter(5000, filter)
			if err != nil {
				sendMsg("[Threat 回補] ⚠️ 第 %d 輪擷取失敗：%v\n", r+1, err)
				break
			}
			if len(entries) == 0 {
				sendMsg("[Threat 回補] ℹ️ 第 %d 輪已無更早的威脅日誌\n", r+1)
				break
			}

			ins, tot, _ := saveThreatLogsToParquet(entries)
			totalNew += ins
			successfulRounds++

			oldest := entries[0].TimeGenerated
			for _, e := range entries {
				if e.TimeGenerated < oldest {
					oldest = e.TimeGenerated
				}
			}

			// 👈 每跑完一輪，客戶端立刻印出
			sendMsg("[Threat 回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (累計: %d 筆)，時間推至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, tot, oldest)

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [Threat 回補] 完成！共執行 %d 輪，補入 %d 筆紀錄，時間已推進至 %s。\n", successfulRounds, totalNew, lastTime)
	})
	
}