package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
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
	auditLock        sync.Mutex
	retryTrackerLock sync.RWMutex
	retryCounts      = make(map[string]int)  // key: "date_slot" -> 重試次數
	retryActive      = make(map[string]bool) // key: "date_slot" -> 是否正在佇列中重試
	retryCancelled   = make(map[string]bool) // key: "date_slot" -> 管理員是否已手動停止重試
)

// 🌟 核心記錄入口：毫秒級寫入獨立不可變 Parquet 區塊
func RecordAuditLog(rec AuditLogRecord) {
	auditLock.Lock()
	defer auditLock.Unlock()

	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}
	if rec.TargetDate == "" && len(rec.Timestamp) >= 10 {
		rec.TargetDate = rec.Timestamp[:10]
	}

	auditDir := filepath.Join(appDir, "audit_logs")
	_ = os.MkdirAll(auditDir, 0755)

	chunkPath := filepath.Join(auditDir, fmt.Sprintf("audit_%s_chunk_%d.parquet", rec.TargetDate, time.Now().UnixNano()))
	_ = parquet.WriteFile(chunkPath, []AuditLogRecord{rec})
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

// 🌟 DuckDB 向量化多條件檢索引擎 (支援計算累計重試次數與重試狀態)
func QueryAuditLogs(date, status, model, category, keyword string, page, perPage int) (AuditQueryResult, error) {
	res := AuditQueryResult{CurrentPage: page, TotalPages: 1}
	if perPage <= 0 {
		perPage = 50
	}
	if page <= 0 {
		page = 1
	}

	cleanDate := strings.ReplaceAll(strings.TrimSpace(date), "/", "-")
	pattern := filepath.ToSlash(filepath.Join(appDir, "audit_logs", fmt.Sprintf("audit_%s*.parquet", cleanDate)))

	matches, _ := filepath.Glob(filepath.Join(appDir, "audit_logs", fmt.Sprintf("audit_%s*.parquet", cleanDate)))
	if len(matches) == 0 {
		res.Logs = []map[string]interface{}{}
		return res, nil
	}

	var conds []string
	conds = append(conds, "1=1")

	if status != "" && status != "all" {
		conds = append(conds, fmt.Sprintf("status = '%s'", strings.ToUpper(status)))
	}
	if model != "" && model != "all" {
		conds = append(conds, fmt.Sprintf("fw_model = '%s'", model))
	}
	if category != "" && category != "all" {
		conds = append(conds, fmt.Sprintf("category = '%s'", category))
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
		FROM read_parquet('%s', union_by_name=true)
		WHERE %s
	`, pattern, whereClause)

	if statRows, err := runDuckDBQuery(statsSQL); err == nil && len(statRows) > 0 {
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
		FROM read_parquet('%s', union_by_name=true)
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d
	`, pattern, whereClause, perPage, offset)

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

// 🌟 每日全量整併：將當日所有 audit chunk 碎片整合為一個單一的 Parquet 主檔
func ConsolidateAuditLogs() {
	auditDir := filepath.Join(appDir, "audit_logs")
	
	matches, err := filepath.Glob(filepath.Join(auditDir, "audit_*_chunk_*.parquet"))
	if err != nil || len(matches) == 0 {
		return
	}

	dateMap := make(map[string][]string)
	for _, m := range matches {
		base := filepath.Base(m)
		parts := strings.Split(base, "_")
		if len(parts) >= 2 {
			dateStr := parts[1]
			dateMap[dateStr] = append(dateMap[dateStr], m)
		}
	}

	duckdbExe := getDuckDBExePath()
	if _, err := os.Stat(duckdbExe); os.IsNotExist(err) {
		return
	}

	for dateStr, frags := range dateMap {
		if len(frags) == 0 {
			continue
		}
		
		targetFile := filepath.Join(auditDir, fmt.Sprintf("audit_%s.parquet", dateStr))
		tmpFile := targetFile + ".tmp"
		
		pattern := filepath.ToSlash(filepath.Join(auditDir, fmt.Sprintf("audit_%s*.parquet", dateStr)))
		tmpSlash := filepath.ToSlash(tmpFile)

		sqlCmd := fmt.Sprintf(
			"SET max_memory='4GB'; SET preserve_insertion_order=false; " +
			"COPY (SELECT * FROM read_parquet('%s', union_by_name=true) ORDER BY timestamp DESC) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
			pattern, tmpSlash,
		)

		if _, err := runDuckDBQuery(sqlCmd); err == nil {
			_ = os.Remove(targetFile)
			_ = os.Rename(tmpFile, targetFile)
			
			for _, f := range frags {
				_ = os.Remove(f)
			}
			fmt.Printf("📦 [稽核日誌整併] %s 日期已成功整併 %d 個碎片！\n", dateStr, len(frags))
		} else {
			_ = os.Remove(tmpFile)
		}
	}
}