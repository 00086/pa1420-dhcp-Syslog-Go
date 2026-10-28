package main

import (
	"bytes"
	"database/sql"
	"encoding/json" // 👈 🌟 補上這行 (解決 undefined: json)
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath" // 👈 補上：供 route 16 組合 Parquet 檔案路徑
	"regexp" // 🌟 補上這行，解決 undefined: regexp
	"sort"
	"strconv"
	"strings"
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

	// 10. ARP 即時比對與固定 IP 分析 (加入 PAN-OS 11 相容與 SQLite 自動落盤)
	r.GET("/api/arp-analysis", func(c *gin.Context) {
		queryDate := strings.ReplaceAll(c.DefaultQuery("date", time.Now().Format("2006-01-02")), "/", "-")

		// 🌟 雙重相容性指令：相容 PAN-OS 10/11 的 <all/> 與舊版 entry 標籤
		cmds := []string{
			"<show><arp><all/></show>",
			"<show><arp><entry name='all'/></arp></show>",
		}

		var arpEntries []ARPEntry
		var lastErr error

		for _, cmd := range cmds {
			body, err := runPACommand(cmd)
			if err != nil {
				lastErr = err
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
							arpEntries = append(arpEntries, e)
						}
					}
				}
			}

			if len(arpEntries) > 0 {
				break
			}
		}

		if len(arpEntries) == 0 && lastErr != nil {
			c.JSON(http.StatusOK, gin.H{"status": "error", "message": fmt.Sprintf("無法取得防火牆 ARP 紀錄: %v", lastErr)})
			return
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
			if ip == "" || mac == "" || mac == "(incomplete)" || strings.ToLower(strings.TrimSpace(e.Status)) == "i" {
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

		// =========================================================================
		// 🌟 核心落盤位置：在 sort.Slice 之後、回傳 c.JSON 之前自動寫入 SQLite
		// =========================================================================
		if db != nil && len(results) > 0 {
			go func(entries []ARPResult) {
				tx, err := db.Begin()
				if err == nil {
					stmt, sErr := tx.Prepare(`
						INSERT INTO arp_records (ip, mac, interface, hostname, dev_type, updated_at)
						VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
						ON CONFLICT(ip) DO UPDATE SET
							mac = excluded.mac,
							interface = excluded.interface,
							hostname = CASE WHEN excluded.hostname != '' AND excluded.hostname != '-' THEN excluded.hostname ELSE arp_records.hostname END,
							dev_type = excluded.dev_type,
							updated_at = CURRENT_TIMESTAMP
					`)
					if sErr == nil {
						defer stmt.Close()
						cleanRegex := regexp.MustCompile(`<[^>]*>`)
						for _, r := range entries {
							cleanHn := r.Hostname
							if strings.Contains(cleanHn, "<") {
								cleanHn = strings.TrimSpace(cleanRegex.ReplaceAllString(cleanHn, ""))
							}
							_, _ = stmt.Exec(r.IP, r.MAC, r.Interface, cleanHn, r.DevType)
						}
						_ = tx.Commit()
					}
				}
			}(results)
		}

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
		
		// 🌟 判斷是否為純翻頁模式
		onlyLogs := c.DefaultQuery("only_logs", "false") == "true"

		result, err := queryTrafficAnalytics(date, src, dst, app, action, zone, page, perPage, onlyLogs)
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
			"message": fmt.Sprintf("成功自 PA-1420 擷取 %d 筆流量紀錄！新增至當日 Parquet：%d 筆，今日累計：%d 筆", len(entries), success, total),
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
			"message": fmt.Sprintf("成功自 PA-1420 擷取 %d 筆威脅紀錄！新增入庫：%d 筆，該檔案累計：%d 筆", len(entries), success, total),
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

		// 🌟 核心防護：若有指定時間但未給 date，自動萃取前 10 碼為邊界日期
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
			sendMsg("[流量回補] ⏳ [%d/%d] 正在向 PA-1420 請求資料 (過濾條件: %s)...\n", r+1, rounds, filter)

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

			ins, tot, err := saveTrafficLogsToParquet(entries)
			if err != nil {
				sendMsg("[流量回補] ❌ 存入磁碟發生錯誤：%v\n", err)
			} else {
				totalNew += ins
				totalRaw += len(entries) // 👈 🌟 累加冷資料筆數
				successfulRounds++
			}

			oldest := entries[0].Timestamp
			for _, e := range entries {
				if e.Timestamp < oldest {
					oldest = e.Timestamp
				}
			}

			sendMsg("[流量回補] ✅ [%d/%d] 完成！耗時: %.1fs，抓取: %d 筆，新增: %d 筆 (當日累計: %d 筆)，時間推進至: %s\n",
				r+1, rounds, time.Since(startT).Seconds(), len(entries), ins, tot, oldest)
				
		    // 🌟 核心新增：向批次檔視窗 (curl) 推送冷資料落盤戰報
			sendMsg("   ↳ ❄️ [Raw Log 備份] 原始 XML 已落盤: %d 筆 ➔ traffic_raw_logs/\n", len(entries))

			t, err := time.Parse("2006-01-02 15:04:05", oldest)
			if err == nil {
				lastTime = t.Add(-1 * time.Second).Format("2006-01-02 15:04:05")
			} else {
				lastTime = oldest
			}

			_ = os.WriteFile(filepath.Join(appDir, "backfill_status.txt"), []byte(lastTime), 0644)

			// 🛑 迴圈內部關鍵煞車機制
			if targetDate != "" && lastTime <= targetDate+" 00:00:00" {
				sendMsg("[流量回補] 🎯 已成功回溯至當日 00:00:00 邊界 (推進至: %s)，任務圓滿達成！\n", lastTime)
				break
			}

			if r < rounds-1 {
				time.Sleep(1500 * time.Millisecond)
			}
		}

		sendMsg("🏁 [流量回補] 完成！共執行 %d 輪，熱檔新增: %d 筆，冷資料 (Raw Log) 備份: %d 筆，歷史時間已向前推進至 %s。\n", 
			successfulRounds, totalNew, totalRaw, lastTime)
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
			sendMsg("[Threat 回補] ⏳ [%d/%d] 正在向 PA-1420 擷取威脅日誌 (條件: %s)...\n", r+1, rounds, filter)

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

		// 🌟 1. 改為專案目錄下的相對路徑 ftp_data/<日期>，不再寫死任何磁碟代號
		if req.FTPFolder == "" {
			req.FTPFolder = filepath.Join("ftp_data", req.Date)
		}
		if !filepath.IsAbs(req.FTPFolder) {
			req.FTPFolder = filepath.Join(appDir, req.FTPFolder)
		}

		// 🌟 2. 自動檢查並建立 ftp_data 及當前日期子目錄
		if err := os.MkdirAll(req.FTPFolder, 0755); err != nil {
			c.String(http.StatusInternalServerError, "❌ 建立 FTP 匯出目錄失敗: %v\n", err)
			return
		}

		if req.LogType != "threat" {
			req.LogType = "traffic"
		}

		// 🌟 若不是純轉換模式，自動從 pa1420key.txt 讀出 FTP 帳密
		if !req.ConvertOnly {
			ftpUser := "ftpuser"
			ftpPass := "ftppass"
			if content, err := os.ReadFile(paConfigFile); err == nil {
				var lines []string
				for _, l := range strings.Split(string(content), "\n") {
					trimmed := strings.TrimSpace(l)
					if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
						lines = append(lines, trimmed)
					}
				}
				if len(lines) >= 7 {
					ftpUser = lines[5]
					ftpPass = lines[6]
				}
			}
			// 自動將本機 IP (192.50.1.55) 寫死或由設定檔擴展
			req.FTPHost = fmt.Sprintf("%s:%s@192.50.1.55", ftpUser, ftpPass)
		}

		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Status(http.StatusOK)
		c.Writer.Flush()

		logStream := func(format string, a ...any) {
			msg := fmt.Sprintf(format, a...)
			fmt.Print(msg)
			_, _ = fmt.Fprint(c.Writer, msg)
			c.Writer.Flush()
		}

		err := performCLIExportAndConvert(req, logStream)
		if err != nil {
			logStream("\n❌ 任務失敗: %v\n", err)
			return
		}
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
		ConsolidateRawParquetFiles("traffic")
		ConsolidateRawParquetFiles("threat")
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
		logType := c.DefaultQuery("type", "traffic") // 接收 "traffic" 或 "threat"
		var targetDir string
		var prefix string
		
		if logType == "threat" {
			targetDir = threatDir
			prefix = "threat_"
		} else {
			targetDir = trafficDir
			prefix = "traffic_"
		}

		dateSet := make(map[string]bool)
		entries, err := os.ReadDir(targetDir)
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if !e.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".parquet") && !strings.HasSuffix(name, ".tmp") {
					// 從檔名萃取日期 (例如 traffic_2026-10-10_nas_123.parquet)
					part := strings.TrimPrefix(name, prefix)
					if len(part) >= 10 {
						dateStr := part[:10]
						// 簡易 Regex 確保格式為 YYYY-MM-DD
						if matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, dateStr); matched {
							dateSet[dateStr] = true
						}
					}
				}
			}
		}

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
	
	// 威脅日誌分析主頁面
	r.GET("/threat", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		renderPongo(c, "threat.html", pongo2.Context{
			"page":       "threat",
			"today":      time.Now().Format("2006-01-02"),
			"today_fmt":  time.Now().Format("2006/01/02"),
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

		pattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))

		tFiles, _ := filepath.Glob(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))
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

		pattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))

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
		pattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", queryDate)))

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

		pattern := filepath.ToSlash(filepath.Join(trafficDir, fmt.Sprintf("traffic_%s*.parquet", req.Date)))
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

	// 🌟 內網 MAC / 主機名秒級反解 API (DHCP + ARP 靜態庫雙軌聯防)
	r.GET("/api/tools/ip-lookup/:ip", func(c *gin.Context) {
		targetIP := c.Param("ip")
		db, _ := initDB()

		hostname := "-"
		mac := "-"
		macSource := ""
		isInternal := false

		if strings.HasPrefix(targetIP, "192.168.") || strings.HasPrefix(targetIP, "10.") || strings.HasPrefix(targetIP, "172.") || strings.HasPrefix(targetIP, "192.50.") {
			isInternal = true
		}

		if db != nil {
			// 1. 優先查詢 DHCP 租約
			var dHn, dMac sql.NullString
			_ = db.QueryRow("SELECT hostname, mac FROM dhcp_leases WHERE ip = ? ORDER BY id DESC LIMIT 1", targetIP).Scan(&dHn, &dMac)
			if dMac.Valid && dMac.String != "" && dMac.String != "-" {
				mac = dMac.String
				macSource = "DHCP 租約"
				if dHn.Valid && dHn.String != "" {
					hostname = dHn.String
				}
			}

			// 2. 若 DHCP 無紀錄 (如 192.50.1.25 固定 IP)，立即穿透查詢 ARP 靜態資料庫
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

			// 3. 主機名補強：查詢本機 DNS 快取表
			if hostname == "" || hostname == "-" {
				var cacheHn sql.NullString
				_ = db.QueryRow("SELECT hostname FROM ip_hostname_cache WHERE ip = ?", targetIP).Scan(&cacheHn)
				if cacheHn.Valid && cacheHn.String != "" {
					hostname = cacheHn.String
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"ip":          targetIP,
			"hostname":    hostname,
			"mac_address": mac,
			"mac_source":  macSource,
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
		
}