package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

// 🌟 14 欄位不可變稽核日誌結構體
type AuditLogRecord struct {
	Timestamp   string  `parquet:"timestamp"`    // 1. 紀錄時間 (YYYY-MM-DD HH:mm:ss)
	FWModel     string  `parquet:"fw_model"`     // 2. 設備型號 (PA-5250 / PA-1420)
	LogType     string  `parquet:"log_type"`     // 3. 日誌類型 (traffic / threat / system / config)
	Category    string  `parquet:"category"`     // 4. 分類 (chunk切片 / 分時parquet / rollup整併 / raw_log歸檔 / 14欄熱資料 / NAS切分)
	TargetDate  string  `parquet:"target_date"`  // 5. 目標日誌日期 (YYYY-MM-DD)
	TargetSlot  string  `parquet:"target_slot"`  // 6. 目標時段 (14:00-14:10 / 14:00整點 / 全日)
	Status      string  `parquet:"status"`       // 7. 狀態 (SUCCESS / FAILED / QUEUED / CANCELLED)
	RecordCount int64   `parquet:"record_count"` // 8. 處理筆數
	FileSizeMB  float64 `parquet:"file_size_mb"` // 9. 產出大小 (MB)
	DurationSec float64 `parquet:"duration_sec"` // 10. 耗時 (秒)
	OutputFile  string  `parquet:"output_file"`  // 11. 產出檔案路徑
	Details     string  `parquet:"details"`      // 12. 任務說明
	ErrorReason string  `parquet:"error_reason"` // 13. 失敗原因 (若成功則為空)
	Operator    string  `parquet:"operator"`     // 14. 觸發來源 (AUTO_SCHEDULER / MANUAL / NAS_SPLITTER)
}

var (
	auditLock             sync.Mutex
	auditConsolidateMutex sync.Mutex
	retryTrackerLock      sync.RWMutex
	retryCounts           = make(map[string]int)  // key: "date_slot" -> 重試次數
	retryActive           = make(map[string]bool) // key: "date_slot" -> 是否正在佇列中重試
	retryCancelled        = make(map[string]bool) // key: "date_slot" -> 管理員是否已手動停止重試
)

// 🌟 取得稽核日誌根目錄
func getAuditBaseDir() string {
	return filepath.Join(appDir, "audit_logs")
}

// 🌟 核心記錄入口：依日期歸入 audit_logs/YYYY-MM-DD/ 子目錄，達 25 個碎片自動背景整併
func RecordAuditLog(rec AuditLogRecord) {
	auditLock.Lock()

	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}
	if rec.TargetDate == "" && len(rec.Timestamp) >= 10 {
		rec.TargetDate = rec.Timestamp[:10]
	}
	rec.TargetDate = strings.ReplaceAll(strings.TrimSpace(rec.TargetDate), "/", "-")
	if rec.TargetDate == "" {
		rec.TargetDate = time.Now().Format("2006-01-02")
	}

	dayDir := filepath.Join(getAuditBaseDir(), rec.TargetDate)
	_ = os.MkdirAll(dayDir, 0755)

	chunkPath := filepath.Join(dayDir, fmt.Sprintf("audit_%s_chunk_%d.parquet", rec.TargetDate, time.Now().UnixNano()))
	_ = parquet.WriteFile(chunkPath, []AuditLogRecord{rec})

	// 檢查該日碎片數量，若累積 >= 25 個即在背景自動微整併，防止單日產生數百個小檔
	chunks, _ := filepath.Glob(filepath.Join(dayDir, fmt.Sprintf("audit_%s_chunk_*.parquet", rec.TargetDate)))
	needCompact := len(chunks) >= 25
	targetDate := rec.TargetDate
	auditLock.Unlock()

	if needCompact {
		go ConsolidateAuditLogsForDate(targetDate)
	}
}

// 🌟 手動觸發重試：加入 FIFO 佇列排隊執行並記錄次數
func TriggerTaskRetry(date, slot, model, category string) (int, error) {
	key := fmt.Sprintf("%s_%s", date, slot)
	retryTrackerLock.Lock()
	retryCounts[key]++
	count := retryCounts[key]
	retryActive[key] = true
	delete(retryCancelled, key)
	retryTrackerLock.Unlock()

	hour := ""
	cleanSlot := ""
	if strings.Contains(slot, ":") {
		parts := strings.Split(slot, ":")
		hour = parts[0]
		cleanSlot = strings.TrimSuffix(parts[1], "整點")
	}

	task := ExportSliceTask{
		Date:          date,
		Hour:          hour,
		Slot:          cleanSlot,
		Interval:      "10",
		IsHourRolling: strings.Contains(slot, "整點"),
	}

	select {
	case sliceTaskQueue <- task:
		RecordAuditLog(AuditLogRecord{
			FWModel:     model,
			LogType:     "traffic",
			Category:    category,
			TargetDate:  date,
			TargetSlot:  slot,
			Status:      "QUEUED",
			Details:     fmt.Sprintf("管理員手動觸發重試 (第 %d 次，已進入 FIFO 佇列排隊)", count),
			Operator:    "MANUAL_RETRY",
		})
		return count, nil
	default:
		retryTrackerLock.Lock()
		retryActive[key] = false
		retryTrackerLock.Unlock()
		return count, fmt.Errorf("佇列已滿 (288 個上限)，暫時無法加入重試")
	}
}

// 🌟 停止重試：標記取消，佇列抽到時自動略過
func StopTaskRetry(date, slot, model, category string) {
	key := fmt.Sprintf("%s_%s", date, slot)
	retryTrackerLock.Lock()
	retryCancelled[key] = true
	delete(retryActive, key)
	count := retryCounts[key]
	retryTrackerLock.Unlock()

	RecordAuditLog(AuditLogRecord{
		FWModel:     model,
		LogType:     "traffic",
		Category:    category,
		TargetDate:  date,
		TargetSlot:  slot,
		Status:      "CANCELLED",
		Details:     fmt.Sprintf("管理員已手動停止重試 (累計重試 %d 次)", count),
		Operator:    "MANUAL_STOP",
	})
}

// 🌟 查詢結果包裝結構體
type AuditQueryResult struct {
	TotalEvents int64                    `json:"total_events"`
	SuccessCnt  int64                    `json:"success_cnt"`
	FailedCnt   int64                    `json:"failed_cnt"`
	TotalRows   int64                    `json:"total_rows"`
	TotalMB     float64                  `json:"total_mb"`
	CurrentPage int                      `json:"current_page"`
	TotalPages  int                      `json:"total_pages"`
	Logs        []map[string]interface{} `json:"logs"`
}

// 🌟 蒐集指定日期的所有有效稽核 Parquet 檔案 (同時相容 YYYY-MM-DD 子目錄與舊版根目錄扁平檔)
func collectValidAuditFilesForDate(cleanDate string) []string {
	auditBase := getAuditBaseDir()
	dayDir := filepath.Join(auditBase, cleanDate)

	subFiles, _ := filepath.Glob(filepath.Join(dayDir, fmt.Sprintf("audit_%s*.parquet", cleanDate)))
	rootFiles, _ := filepath.Glob(filepath.Join(auditBase, fmt.Sprintf("audit_%s*.parquet", cleanDate)))
	candidates := append(subFiles, rootFiles...)

	var validPaths []string
	for _, f := range candidates {
		if strings.HasSuffix(f, ".tmp") {
			continue
		}
		if fi, err := os.Stat(f); err == nil && !fi.IsDir() && fi.Size() > 0 {
			validPaths = append(validPaths, filepath.ToSlash(f))
		}
	}
	return validPaths
}

// 🌟 DuckDB 向量化多條件檢索引擎 (含背景整併自動重讀容錯)
func QueryAuditLogs(date, status, model, category, keyword string, page, perPage int) (AuditQueryResult, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		res, err := queryAuditLogsOnce(date, status, model, category, keyword, page, perPage)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if isTransientParquetCompactionError(err) && attempt < 3 {
			time.Sleep(time.Duration(60*(attempt+1)) * time.Millisecond)
			continue
		}
		break
	}
	return AuditQueryResult{CurrentPage: page, TotalPages: 1, Logs: []map[string]interface{}{}}, lastErr
}

func queryAuditLogsOnce(date, status, model, category, keyword string, page, perPage int) (AuditQueryResult, error) {
	res := AuditQueryResult{CurrentPage: page, TotalPages: 1}
	if perPage <= 0 {
		perPage = 50
	}
	if page <= 0 {
		page = 1
	}

	cleanDate := strings.ReplaceAll(strings.TrimSpace(date), "/", "-")
	if cleanDate == "" {
		cleanDate = time.Now().Format("2006-01-02")
	}

	validPaths := collectValidAuditFilesForDate(cleanDate)
	if len(validPaths) == 0 {
		res.Logs = []map[string]interface{}{}
		return res, nil
	}

	var sourceExpr string
	if len(validPaths) == 1 {
		sourceExpr = fmt.Sprintf("'%s'", validPaths[0])
	} else {
		quoted := make([]string, len(validPaths))
		for i, p := range validPaths {
			quoted[i] = fmt.Sprintf("'%s'", p)
		}
		sourceExpr = fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
	}

	var conds []string
	conds = append(conds, "1=1")

	if status != "" && status != "all" {
		conds = append(conds, fmt.Sprintf("status = '%s'", strings.ToUpper(strings.ReplaceAll(status, "'", "''"))))
	}
	if model != "" && model != "all" {
		conds = append(conds, fmt.Sprintf("fw_model = '%s'", strings.ReplaceAll(model, "'", "''")))
	}
	if category != "" && category != "all" {
		conds = append(conds, fmt.Sprintf("category = '%s'", strings.ReplaceAll(category, "'", "''")))
	}
	if keyword != "" {
		kw := strings.ReplaceAll(keyword, "'", "''")
		conds = append(conds, fmt.Sprintf("(output_file ILIKE '%%%s%%' OR details ILIKE '%%%s%%' OR error_reason ILIKE '%%%s%%' OR target_slot ILIKE '%%%s%%')", kw, kw, kw, kw))
	}
	whereClause := strings.Join(conds, " AND ")

	statsSQL := fmt.Sprintf(`
		SELECT 
			COUNT(*) AS total_events,
			COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) AS success_cnt,
			COUNT(CASE WHEN status = 'FAILED' THEN 1 END) AS failed_cnt,
			COALESCE(SUM(record_count), 0) AS total_rows,
			round(COALESCE(SUM(file_size_mb), 0), 2) AS total_mb
		FROM read_parquet(%s, union_by_name=true)
		WHERE %s
	`, sourceExpr, whereClause)

	statRows, err := runDuckDBQuery(statsSQL)
	if err != nil {
		return res, err
	}
	if len(statRows) > 0 {
		res.TotalEvents = parseDuckDBNumber(statRows[0]["total_events"])
		res.SuccessCnt = parseDuckDBNumber(statRows[0]["success_cnt"])
		res.FailedCnt = parseDuckDBNumber(statRows[0]["failed_cnt"])
		res.TotalRows = parseDuckDBNumber(statRows[0]["total_rows"])
		if mbVal, ok := statRows[0]["total_mb"].(float64); ok {
			res.TotalMB = mbVal
		}
	}

	res.TotalPages = int(math.Ceil(float64(res.TotalEvents) / float64(perPage)))
	if res.TotalPages == 0 {
		res.TotalPages = 1
	}
	if page > res.TotalPages {
		page = res.TotalPages
		res.CurrentPage = page
	}
	offset := (page - 1) * perPage
	if offset < 0 {
		offset = 0
	}

	// 🌟 透過 DuckDB 視窗函式 (COUNT(*) OVER (...) - 1) 動態計算歷史重試次數
	listSQL := fmt.Sprintf(`
		SELECT 
			timestamp, fw_model, log_type, category, target_date, target_slot,
			status, record_count, file_size_mb, duration_sec, output_file,
			details, error_reason, operator,
			CAST(COUNT(*) OVER (PARTITION BY target_date, target_slot, category) - 1 AS BIGINT) AS hist_retries
		FROM read_parquet(%s, union_by_name=true)
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d
	`, sourceExpr, whereClause, perPage, offset)

	logs, err := runDuckDBQuery(listSQL)
	if err != nil {
		return res, err
	}

	// 🌟 疊加即時記憶體狀態與重試次數
	for _, row := range logs {
		d, _ := row["target_date"].(string)
		s, _ := row["target_slot"].(string)
		key := fmt.Sprintf("%s_%s", d, s)

		histCount := parseDuckDBNumber(row["hist_retries"])

		retryTrackerLock.RLock()
		memCount := retryCounts[key]
		active := retryActive[key]
		cancelled := retryCancelled[key]
		retryTrackerLock.RUnlock()

		finalCount := histCount
		if int64(memCount) > finalCount {
			finalCount = int64(memCount)
		}
		if finalCount < 0 {
			finalCount = 0
		}

		row["retry_count"] = finalCount
		row["is_retrying"] = active
		row["is_cancelled"] = cancelled
	}

	res.Logs = logs
	return res, nil
}

// 🌟 將 audit_logs 根目錄下的舊版扁平檔自動搬移歸位至 audit_logs/YYYY-MM-DD/ 子目錄
func migrateFlatAuditFilesToDailyDirs() int {
	auditBase := getAuditBaseDir()
	entries, err := os.ReadDir(auditBase)
	if err != nil {
		return 0
	}

	dateRe := regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`)
	moved := 0

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") {
			continue
		}
		srcPath := filepath.Join(auditBase, e.Name())
		if strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(srcPath)
			continue
		}
		if m := dateRe.FindStringSubmatch(e.Name()); len(m) > 1 {
			dateStr := m[1]
			dayDir := filepath.Join(auditBase, dateStr)
			_ = os.MkdirAll(dayDir, 0755)

			dstPath := filepath.Join(dayDir, e.Name())
			if _, err := os.Stat(dstPath); err == nil {
				// 若子目錄已存在同名主檔，先改名為碎片檔供整併融合，避免覆蓋遺失資料
				dstPath = filepath.Join(dayDir, fmt.Sprintf("audit_%s_chunk_migrated_%d.parquet", dateStr, time.Now().UnixNano()))
			}
			if err := os.Rename(srcPath, dstPath); err == nil {
				moved++
			}
		}
	}
	return moved
}

// 🌟 針對單一日期目錄執行稽核日誌去重整併 -> audit_logs/YYYY-MM-DD/audit_YYYY-MM-DD.parquet
func ConsolidateAuditLogsForDate(dateStr string) {
	auditConsolidateMutex.Lock()
	defer auditConsolidateMutex.Unlock()

	_ = migrateFlatAuditFilesToDailyDirs()
	consolidateAuditDateUnlocked(dateStr)
}

func consolidateAuditDateUnlocked(dateStr string) {
	dateStr = strings.ReplaceAll(strings.TrimSpace(dateStr), "/", "-")
	if dateStr == "" {
		return
	}

	dayDir := filepath.Join(getAuditBaseDir(), dateStr)
	entries, err := os.ReadDir(dayDir)
	if err != nil {
		return
	}

	targetFile := filepath.Join(dayDir, fmt.Sprintf("audit_%s.parquet", dateStr))
	var validFiles []string
	var chunkFiles []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".parquet") {
			continue
		}
		fullPath := filepath.Join(dayDir, e.Name())
		if strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(fullPath)
			continue
		}
		if fi, statErr := os.Stat(fullPath); statErr == nil && fi.Size() > 0 {
			validFiles = append(validFiles, filepath.ToSlash(fullPath))
			if fullPath != targetFile {
				chunkFiles = append(chunkFiles, fullPath)
			}
		}
	}

	// 若目錄裡只剩下唯一的單一主檔 audit_YYYY-MM-DD.parquet，無需重做
	if len(chunkFiles) == 0 {
		return
	}

	quoted := make([]string, len(validFiles))
	for i, p := range validFiles {
		quoted[i] = fmt.Sprintf("'%s'", p)
	}
	sourceListExpr := fmt.Sprintf("[%s]", strings.Join(quoted, ", "))

	tmpFile := filepath.Join(dayDir, fmt.Sprintf("audit_%s_consolidating_%d.parquet.tmp", dateStr, time.Now().UnixNano()))
	tmpSlash := filepath.ToSlash(tmpFile)

	// 透過 ROW_NUMBER 去重並依時間倒序壓縮為單一 ZSTD 主檔
	sqlCmd := fmt.Sprintf(
		"COPY (SELECT * EXCLUDE (rn) FROM ("+
			"  SELECT *, ROW_NUMBER() OVER ("+
			"    PARTITION BY timestamp, fw_model, log_type, category, target_date, target_slot, status, output_file, details "+
			"    ORDER BY timestamp DESC"+
			"  ) AS rn "+
			"  FROM read_parquet(%s, union_by_name=true)"+
			") WHERE rn = 1 ORDER BY timestamp DESC) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
		sourceListExpr, tmpSlash,
	)

	if _, err := runDuckDBQuery(sqlCmd); err == nil {
		_ = os.Remove(targetFile)
		if err := os.Rename(tmpFile, targetFile); err == nil {
			for _, f := range chunkFiles {
				_ = os.Remove(f)
			}
			fmt.Printf("📦 [稽核日誌整併] %s 已歸檔至 audit_logs/%s/，成功合併 %d 個碎片為單一主檔！\n",
				dateStr, dateStr, len(chunkFiles))
		} else {
			_ = os.Remove(tmpFile)
		}
	} else {
		_ = os.Remove(tmpFile)
	}
}

// 🌟 全量整併所有日期的稽核日誌 (含舊版扁平檔自動遷移至 YYYY-MM-DD 子目錄)
func ConsolidateAuditLogs() {
	auditConsolidateMutex.Lock()
	defer auditConsolidateMutex.Unlock()

	auditBase := getAuditBaseDir()
	_ = os.MkdirAll(auditBase, 0755)

	if moved := migrateFlatAuditFilesToDailyDirs(); moved > 0 {
		fmt.Printf("📂 [稽核目錄整理] 已將 %d 個舊版扁平稽核檔歸位至 YYYY-MM-DD 日期子目錄\n", moved)
	}

	entries, err := os.ReadDir(auditBase)
	if err != nil {
		return
	}

	dateRe := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	for _, e := range entries {
		if e.IsDir() && dateRe.MatchString(e.Name()) {
			consolidateAuditDateUnlocked(e.Name())
		}
	}
}
