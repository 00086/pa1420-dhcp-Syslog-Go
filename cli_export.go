package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type CLIExportRequest struct {
	Date          string `json:"date" form:"date"`
	PAAdmin       string `json:"pa_admin" form:"pa_admin"`
	PAPassword    string `json:"pa_pass" form:"pa_pass"`
	FTPHost       string `json:"ftp_host" form:"ftp_host"`
	FTPFolder     string `json:"ftp_folder" form:"ftp_folder"`
	LogType       string `json:"log_type" form:"log_type"`
	ConvertOnly   bool   `json:"convert_only" form:"convert_only"`
	SkipCold      bool   `json:"skip_cold" form:"skip_cold"`
	RawOnly       bool   `json:"raw_only" form:"raw_only"`
	Hour          string `json:"hour" form:"hour"`
	Slot          string `json:"slot" form:"slot"`
	Interval      string `json:"interval" form:"interval"`
	TriggerSource string `json:"trigger_source"` // AUTO_SCHEDULER, AUTO_RECONCILER, MANUAL_RETRY 等
	TriggerReason string `json:"trigger_reason"` // 具體觸發動機 (例如: 30分鐘常規排程, 磁碟無檔案自動回補)
}

func init() {
	StartAutoExportScheduler()
}

type StreamLogger func(format string, a ...any)

// =========================================================================
// 🌟 核心模組：完成狀態標註庫 (支援 PA-5250 288 切片 / PA-1420 2 天全域登記)
// =========================================================================
var (
	checkpointLock        sync.RWMutex
	checkpointMemoryCache = make(map[string]bool) // key: task_key -> true
)

// 🌟 初始化標註庫：建立 SQLite 資料表、載入近 3 天紀錄並主動盤點磁碟補登
func InitExportCheckpoints() {
	db, err := initDB()
	if err != nil {
		return
	}

	// 1. 建立持久化資料表與日期索引
	_, _ = db.Exec(`
		CREATE TABLE IF NOT EXISTS export_checkpoints (
			task_key TEXT PRIMARY KEY,
			fw_model TEXT NOT NULL,
			category TEXT NOT NULL,
			target_date TEXT NOT NULL,
			target_hour TEXT DEFAULT '',
			target_slot TEXT DEFAULT '',
			status TEXT NOT NULL DEFAULT 'COMPLETED',
			file_path TEXT DEFAULT '',
			file_size_mb REAL DEFAULT 0,
			completed_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_chk_date ON export_checkpoints(target_date);
	`)

	// 2. 載入過去 72 小時 (涵蓋 288 切片與 2 天) 標註至記憶體快取
	now := time.Now()
	cutoffDate := now.Add(-72 * time.Hour).Format("2006-01-02")
	rows, err := db.Query("SELECT task_key FROM export_checkpoints WHERE target_date >= ?", cutoffDate)
	if err == nil {
		checkpointLock.Lock()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err == nil && k != "" {
				checkpointMemoryCache[k] = true
			}
		}
		rows.Close()
		checkpointLock.Unlock()
	}

	// 3. 🌟 主動磁碟盤點（對賬補登）：若磁碟已有歷史檔案，自動補登入庫
	rawDir := filepath.Join(appDir, "traffic_raw_logs")
	discovered := 0

	// 盤點 PA-5250 過去 48 小時 (288 個切片)
	for h := 0; h <= 48; h++ {
		tTime := now.Add(-time.Duration(h) * time.Hour)
		dStr := tTime.Format("2006-01-02")
		hStr := tTime.Format("15")

		hourFileInSub := filepath.Join(rawDir, dStr, fmt.Sprintf("traffic_raw_%s_%s.parquet", dStr, hStr))
		hourFileFlat := filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s_%s.parquet", dStr, hStr))
		hourDone := false

		if fi, err := os.Stat(hourFileInSub); err == nil && fi.Size() > 0 {
			MarkHourMergeCompleted(dStr, hStr, hourFileInSub, float64(fi.Size())/1024/1024)
			hourDone = true
			discovered++
		} else if fi, err := os.Stat(hourFileFlat); err == nil && fi.Size() > 0 {
			MarkHourMergeCompleted(dStr, hStr, hourFileFlat, float64(fi.Size())/1024/1024)
			hourDone = true
			discovered++
		}

		// 若小時尚未整併，檢查 6 個獨立 10 分鐘切片
		if !hourDone {
			for _, mStr := range []string{"00", "10", "20", "30", "40", "50"} {
				sFileInSub := filepath.Join(rawDir, dStr, fmt.Sprintf("traffic_raw_%s_%s_%s.parquet", dStr, hStr, mStr))
				sFileFlat := filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s_%s_%s.parquet", dStr, hStr, mStr))

				if fi, err := os.Stat(sFileInSub); err == nil && fi.Size() > 0 {
					MarkSliceCompleted("PA-5250", dStr, hStr, mStr, sFileInSub, float64(fi.Size())/1024/1024)
					discovered++
				} else if fi, err := os.Stat(sFileFlat); err == nil && fi.Size() > 0 {
					MarkSliceCompleted("PA-5250", dStr, hStr, mStr, sFileFlat, float64(fi.Size())/1024/1024)
					discovered++
				}
			}
		}
	}

	// 盤點 PA-1420 過去 2 天全日檔
	for d := 0; d <= 2; d++ {
		tTime := now.AddDate(0, 0, -d)
		dStr := tTime.Format("2006-01-02")
		dFileInSub := filepath.Join(rawDir, dStr, fmt.Sprintf("traffic_raw_%s.parquet", dStr))
		dFileFlat := filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s.parquet", dStr))

		if fi, err := os.Stat(dFileInSub); err == nil && fi.Size() > 0 {
			MarkDayRollupCompleted(dStr, dFileInSub, float64(fi.Size())/1024/1024)
			discovered++
		} else if fi, err := os.Stat(dFileFlat); err == nil && fi.Size() > 0 {
			MarkDayRollupCompleted(dStr, dFileFlat, float64(fi.Size())/1024/1024)
			discovered++
		}
	}

	checkpointLock.RLock()
	totalCached := len(checkpointMemoryCache)
	checkpointLock.RUnlock()

	fmt.Printf("🏷️ [標註庫就緒] 已鎖定過去 48 小時 (288 切片範圍) 標註紀錄：目前累計 %d 個已完成標記 (啟動自檢補登: %d 個)\n", totalCached, discovered)
}

// 🌟 登記標註項目至 SQLite 與快取
func SaveTaskCheckpoint(taskKey, fwModel, category, targetDate, targetHour, targetSlot, filePath string, sizeMB float64) {
	checkpointLock.Lock()
	checkpointMemoryCache[taskKey] = true
	checkpointLock.Unlock()

	db, err := initDB()
	if err != nil {
		return
	}

	query := `
		INSERT INTO export_checkpoints (task_key, fw_model, category, target_date, target_hour, target_slot, status, file_path, file_size_mb, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, 'COMPLETED', ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(task_key) DO UPDATE SET 
			status='COMPLETED', 
			file_path=excluded.file_path, 
			file_size_mb=excluded.file_size_mb, 
			completed_at=CURRENT_TIMESTAMP;
	`
	_, _ = db.Exec(query, taskKey, fwModel, category, targetDate, targetHour, targetSlot, filePath, sizeMB)
}

// 🌟 1. 標註 PA-5250 10分鐘切片完成
func MarkSliceCompleted(fwModel, date, hour, slot, filePath string, sizeMB float64) {
	key := fmt.Sprintf("PA-5250_SLICE_%s_%s_%s", date, hour, slot)
	SaveTaskCheckpoint(key, fwModel, "10M_SLICE", date, hour, slot, filePath, sizeMB)
}

// 🌟 2. 標註 PA-5250 1小時整合完畢 (同時覆蓋標記該小時 6 個切片)
func MarkHourMergeCompleted(date, hour, filePath string, sizeMB float64) {
	hourKey := fmt.Sprintf("PA-5250_HOUR_%s_%s", date, hour)
	SaveTaskCheckpoint(hourKey, "PA-5250", "HOUR_MERGE", date, hour, "00", filePath, sizeMB)

	// 一旦小時整併完畢，將 6 個切片也一併標註完畢，絕不重複執行
	for _, s := range []string{"00", "10", "20", "30", "40", "50"} {
		sliceKey := fmt.Sprintf("PA-5250_SLICE_%s_%s_%s", date, hour, s)
		checkpointLock.Lock()
		checkpointMemoryCache[sliceKey] = true
		checkpointLock.Unlock()
	}
}

// 🌟 3. 標註 PA-1420 每日整合完畢
func MarkDayRollupCompleted(date, filePath string, sizeMB float64) {
	dayKey := fmt.Sprintf("PA-1420_DAY_%s", date)
	SaveTaskCheckpoint(dayKey, "PA-1420", "DAILY_ROLLUP", date, "", "全日", filePath, sizeMB)
}

// 🌟 核心判定：該切片是否已經完成標註 (包含小時主檔覆蓋檢查與實體磁碟相容檢查)
func isSliceAlreadyCompleted(date, hour, slot string) bool {
	// (A) 優先檢查快取：所屬小時主檔是否已整併？
	hourKey := fmt.Sprintf("PA-5250_HOUR_%s_%s", date, hour)
	checkpointLock.RLock()
	if checkpointMemoryCache[hourKey] {
		checkpointLock.RUnlock()
		return true
	}
	// (B) 檢查快取：此獨立 10 分鐘切片是否已登記完成？
	sliceKey := fmt.Sprintf("PA-5250_SLICE_%s_%s_%s", date, hour, slot)
	if checkpointMemoryCache[sliceKey] {
		checkpointLock.RUnlock()
		return true
	}
	checkpointLock.RUnlock()

	// (C) 實體磁碟備援檢查 (相容離線產出的檔案)
	rawDir := filepath.Join(appDir, "traffic_raw_logs")
	if fi, err := os.Stat(filepath.Join(rawDir, date, fmt.Sprintf("traffic_raw_%s_%s.parquet", date, hour))); err == nil && fi.Size() > 0 {
		return true
	}
	if fi, err := os.Stat(filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s_%s.parquet", date, hour))); err == nil && fi.Size() > 0 {
		return true
	}
	if fi, err := os.Stat(filepath.Join(rawDir, date, fmt.Sprintf("traffic_raw_%s_%s_%s.parquet", date, hour, slot))); err == nil && fi.Size() > 0 {
		return true
	}
	if fi, err := os.Stat(filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s_%s_%s.parquet", date, hour, slot))); err == nil && fi.Size() > 0 {
		return true
	}

	return false
}

// 🌟 Linux 專屬：核心判定該小時主檔是否已完成 (SQLite 標註庫 + 實體磁碟雙重校驗)
func isHourAlreadyCompleted(date, hour string) bool {
	// (A) 優先檢查快取：此小時主檔是否已登記完成？
	hourKey := fmt.Sprintf("PA-5250_HOUR_%s_%s", date, hour)
	checkpointLock.RLock()
	if checkpointMemoryCache[hourKey] {
		checkpointLock.RUnlock()
		return true
	}
	checkpointLock.RUnlock()

	// (B) 實體磁碟檢查：避免離線手動匯入或先前生成的檔案未登記入庫
	rawDir := filepath.Join(appDir, "traffic_raw_logs")

	// 檢查日期子資料夾：traffic_raw_logs/2026-11-11/traffic_raw_2026-11-11_10.parquet
	if fi, err := os.Stat(filepath.Join(rawDir, date, fmt.Sprintf("traffic_raw_%s_%s.parquet", date, hour))); err == nil && fi.Size() > 0 {
		return true
	}
	// 檢查根目錄扁平路徑：traffic_raw_logs/traffic_raw_2026-11-11_10.parquet
	if fi, err := os.Stat(filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s_%s.parquet", date, hour))); err == nil && fi.Size() > 0 {
		return true
	}

	return false
}

// 🌟 核心判定：PA-1420 全日導出是否已完成標註
func isDayRollupAlreadyCompleted(date string) bool {
	dayKey := fmt.Sprintf("PA-1420_DAY_%s", date)
	checkpointLock.RLock()
	if checkpointMemoryCache[dayKey] {
		checkpointLock.RUnlock()
		return true
	}
	checkpointLock.RUnlock()

	rawDir := filepath.Join(appDir, "traffic_raw_logs")
	if fi, err := os.Stat(filepath.Join(rawDir, date, fmt.Sprintf("traffic_raw_%s.parquet", date))); err == nil && fi.Size() > 0 {
		return true
	}
	if fi, err := os.Stat(filepath.Join(rawDir, fmt.Sprintf("traffic_raw_%s.parquet", date))); err == nil && fi.Size() > 0 {
		return true
	}
	return false
}

// 🌟 毫秒級讀取剛產出的 Parquet 總筆數 (< 10ms，僅讀檔尾 Metadata，不重掃 CSV)
func getParquetExactRowCount(parquetPath string) int64 {
	cleanPath := filepath.ToSlash(parquetPath)
	sql := fmt.Sprintf("SELECT COALESCE(SUM(num_rows), 0) AS cnt FROM parquet_file_metadata('%s');",
		strings.ReplaceAll(cleanPath, "'", "''"))
	res, err := runDuckDBQuery(sql)
	if err != nil {
		fmt.Printf("[筆數讀取異常] ⚠️ 讀取 %s Metadata 失敗: %v\n", filepath.Base(parquetPath), err)
		return 0
	}
	if len(res) == 0 {
		return 0
	}
	return parseDuckDBNumber(res[0]["cnt"])
}

// =========================================================================
// 業務核心：執行匯出、轉檔與整併
// =========================================================================

func performCLIExportAndConvert(req CLIExportRequest, log StreamLogger) error {
	totalStart := time.Now()
	currentModel := getFWModelName()

	slotDesc := "全日"
	auditCategory := "rollup整併"
	if req.Hour != "" && req.Slot != "" {
		slotDesc = fmt.Sprintf("%s:%s", req.Hour, req.Slot)
		auditCategory = "chunk切片"
	} else if req.Hour != "" {
		slotDesc = fmt.Sprintf("%s:00整點", req.Hour)
		auditCategory = "分時parquet"
	}

	// 🌟 提升作用域：記錄 FTP 傳輸狀態與耗時 (供後續 DuckDB 轉檔與稽核使用)
	ftpExitReason := "略過 FTP 傳輸 (ConvertOnly 模式)"
	isTruncated := false
	var transferDuration time.Duration

	if !req.ConvertOnly {
		_ = os.MkdirAll(req.FTPFolder, 0755)
		oldCSVs, _ := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv*"))
		if len(oldCSVs) > 0 {
			log("🧹 [前置清理] 偵測到 %d 個歷史殘留檔案，先行強制排空...\n", len(oldCSVs))
			for _, f := range oldCSVs {
				_ = os.Remove(f)
			}
		}
	}

	if !req.ConvertOnly {
		fwIP, _, _, _, err := getPAConfig()
		if err != nil {
			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(totalStart).Seconds(),
				Details:     "讀取防火牆設定檔失敗",
				ErrorReason: err.Error(),
				Operator:    "CLI_EXPORT",
			})
			return err
		}

		sshUser := req.PAAdmin
		sshPass := req.PAPassword

		if content, err := os.ReadFile(paConfigFile); err == nil {
			var lines []string
			for _, l := range strings.Split(string(content), "\n") {
				trimmed := strings.TrimSpace(l)
				if trimmed != "" {
					lines = append(lines, trimmed)
				}
			}
			if len(lines) >= 5 {
				sshUser = strings.Trim(lines[3], "\"' \r\t")
				sshPass = strings.Trim(lines[4], "\"' \r\t")
			}
		}

		if sshUser == "" || sshPass == "" {
			errStr := "未提供防火牆 SSH 帳密，且 pa1420key.txt 中未設定"

			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(totalStart).Seconds(),
				Details:     "身分驗證憑證缺失",
				ErrorReason: errStr,
				Operator:    "CLI_EXPORT",
			})
			return fmt.Errorf(errStr)
		}

		log("[1/4 連線驗證] 🔄 正在連線至防火牆 %s:22 (帳號: [%s])...\n", fwIP, sshUser)

		var authMethods []ssh.AuthMethod
		authMethods = append(authMethods, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
			if len(questions) == 0 {
				return []string{}, nil
			}
			answers = make([]string, len(questions))
			for i, q := range questions {
				if !echos[i] || strings.Contains(strings.ToLower(q), "password") {
					answers[i] = sshPass
				} else if strings.Contains(strings.ToLower(q), "login as") || strings.EqualFold(strings.TrimSpace(q), "username:") {
					answers[i] = sshUser
				} else {
					answers[i] = sshPass
				}
			}
			return answers, nil
		}))
		authMethods = append(authMethods, ssh.Password(sshPass))

		config := &ssh.ClientConfig{
			User:            sshUser,
			Auth:            authMethods,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			ClientVersion:   "SSH-2.0-OpenSSH_8.9p1",
			Timeout:         20 * time.Second,
		}

		client, err := ssh.Dial("tcp", fwIP+":22", config)
		if err != nil {
			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(totalStart).Seconds(),
				Details:     "SSH 連線防火牆失敗",
				ErrorReason: err.Error(),
				Operator:    "CLI_EXPORT",
			})
			return fmt.Errorf("SSH 連線失敗: %w", err)
		}
		defer client.Close()

		localTCPAddr := client.LocalAddr().String()
		localIP := strings.Split(localTCPAddr, ":")[0]

		ftpUser := "ftpuser"
		ftpPass := "ftppass"
		if content, err := os.ReadFile(paConfigFile); err == nil {
			var rawLines []string
			for _, l := range strings.Split(string(content), "\n") {
				trimmed := strings.TrimSpace(l)
				if trimmed != "" {
					rawLines = append(rawLines, trimmed)
				}
			}
			if len(rawLines) >= 7 {
				ftpUser = strings.Trim(rawLines[5], "\"' \r\t")
				ftpPass = strings.Trim(rawLines[6], "\"' \r\t")
			}
		}

		if req.FTPHost == "" || !strings.Contains(req.FTPHost, "@") {
			req.FTPHost = fmt.Sprintf("%s:%s@%s", ftpUser, ftpPass, localIP)
		}

		session, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("建立 SSH 會話失敗: %w", err)
		}
		defer session.Close()

		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
			return fmt.Errorf("請求 PTY 終端失敗: %w", err)
		}

		stdoutPipe, err := session.StdoutPipe()
		if err != nil {
			return fmt.Errorf("取得 Stdout 失敗: %w", err)
		}
		stdinPipe, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("取得 Stdin 失敗: %w", err)
		}

		if err := session.Shell(); err != nil {
			return fmt.Errorf("啟動 Shell 失敗: %w", err)
		}

		readChan := make(chan string, 100)
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := stdoutPipe.Read(buf)
				if n > 0 {
					chunk := string(buf[:n])
					log("%s", chunk)
					readChan <- chunk
				}
				if err != nil {
					close(readChan)
					return
				}
			}
		}()

		waitForPrompt := func(prompt string, timeout time.Duration) error {
			var accumulated strings.Builder
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			for {
				select {
				case chunk, ok := <-readChan:
					if !ok {
						return fmt.Errorf("連線中斷")
					}
					accumulated.WriteString(chunk)
					if strings.Contains(accumulated.String(), prompt) {
						return nil
					}
				case <-timer.C:
					return fmt.Errorf("等待逾時 (%v)", timeout)
				}
			}
		}

		log("[1/4 連線驗證] ⏳ 等待防火牆就緒提示字元 (>)...\n")
		if err := waitForPrompt(">", 15*time.Second); err != nil {
			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(totalStart).Seconds(),
				Details:     "等待提示字元逾時",
				ErrorReason: err.Error(),
				Operator:    "CLI_EXPORT",
			})
			return fmt.Errorf("登入逾時: %w", err)
		}

		for len(readChan) > 0 {
			<-readChan
		}

		cleanDate := strings.Trim(strings.TrimSpace(req.Date), ".\"' \r\t")
		cleanDate = strings.ReplaceAll(cleanDate, "-", "/")
		cleanDate = strings.TrimRight(cleanDate, ".")

		cleanHour := strings.Trim(strings.TrimSpace(req.Hour), ".\"' \r\t")
		if len(cleanHour) == 1 {
			cleanHour = "0" + cleanHour
		}

		cleanSlot := strings.Trim(strings.TrimSpace(req.Slot), ".\"' \r\t")
		if cleanSlot == "0" {
			cleanSlot = "00"
		}

		var cmd string
		isFullDay := false

		if cleanHour != "" && cleanSlot != "" {
			hInt := 0
			fmt.Sscanf(cleanHour, "%d", &hInt)
			nextHour := fmt.Sprintf("%02d", hInt+1)
			mInt := 0
			fmt.Sscanf(cleanSlot, "%d", &mInt)

			step := 10
			if req.Interval != "" {
				fmt.Sscanf(req.Interval, "%d", &step)
			}
			if step <= 0 {
				step = 10
			}

			nextMin := mInt + step
			startT := fmt.Sprintf("%s@%s:%02d:00", cleanDate, cleanHour, mInt)
			var endT string
			if nextMin >= 60 {
				if hInt == 23 {
					endT = fmt.Sprintf("%s@23:59:59", cleanDate)
				} else {
					endT = fmt.Sprintf("%s@%s:00:00", cleanDate, nextHour)
				}
			} else {
				endT = fmt.Sprintf("%s@%s:%02d:00", cleanDate, cleanHour, nextMin)
			}
			cmd = fmt.Sprintf("ftp export log %s start-time equal %s end-time equal %s to %s\n",
				req.LogType, startT, endT, req.FTPHost)
		} else if cleanHour != "" {
			hInt := 0
			fmt.Sscanf(cleanHour, "%d", &hInt)
			nextHour := fmt.Sprintf("%02d", hInt+1)
			if hInt == 23 {
				cmd = fmt.Sprintf("ftp export log %s start-time equal %s@23:00:00 end-time equal %s@23:59:59 to %s\n",
					req.LogType, cleanDate, cleanDate, req.FTPHost)
			} else {
				cmd = fmt.Sprintf("ftp export log %s start-time equal %s@%s:00:00 end-time equal %s@%s:00:00 to %s\n",
					req.LogType, cleanDate, cleanHour, cleanDate, nextHour, req.FTPHost)
			}
		} else {
			isFullDay = true
			cmd = fmt.Sprintf("ftp export log %s start-time equal %s@00:00:00 end-time equal %s@23:59:59 to %s\n",
				req.LogType, cleanDate, cleanDate, req.FTPHost)
		}

		log("[2/4 串流傳輸] 🚀 發送匯出指令: %s", cmd)
		if _, err := stdinPipe.Write([]byte(cmd)); err != nil {
			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(totalStart).Seconds(),
				Details:     "發送 FTP 匯出指令失敗",
				ErrorReason: err.Error(),
				Operator:    "CLI_EXPORT",
			})
			return fmt.Errorf("發送指令失敗: %w", err)
		}

		stopTicker := make(chan struct{})
		transferDone := make(chan struct{})

		// 🌟 核心修復：精準依據任務類型與切片間隔 (Interval) 分配超時時間
		var maxIdleSec int
		var maxWaitTime time.Duration

		if isFullDay {
			// ☀️ 全日 24 小時任務
			maxIdleSec = 60
			maxWaitTime = 120 * time.Minute
		} else if (cleanHour != "" && cleanSlot == "") || req.Interval == "60" {
			// 🐧 1 小時整檔 (60 分鐘區間)
			maxIdleSec = 60
			maxWaitTime = 90 * time.Minute
		} else if req.Interval == "30" || runtime.GOOS == "linux" {
			// ⏱️ 30 分鐘切片 (Linux 模式)：PA-5250 吐檔需 22~25 分鐘，給予充裕保護
			maxIdleSec = 30
			maxWaitTime = 60 * time.Minute
		} else {
			// ⏱️ 10 分鐘切片 (Windows 模式)
			maxIdleSec = 25
			maxWaitTime = 35 * time.Minute
		}

		ftpStartTime := time.Now()

		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			var lastBytes int64 = -1
			idleSeconds := 0

			for {
				select {
				case <-ticker.C:
					csvs, _ := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv*"))
					var totalBytes int64
					for _, f := range csvs {
						if fi, err := os.Stat(f); err == nil {
							totalBytes += fi.Size()
						}
					}
					elapsed := int(time.Since(ftpStartTime).Seconds())
					mb := float64(totalBytes) / 1024 / 1024
					log("    ⏱️ [%02d秒] FTP 接收中 (Gzip 邊收邊壓): 已生成 %d 個檔案 (累計 %.1f MB)...\n", elapsed, len(csvs), mb)

					if len(csvs) > 0 && totalBytes > 0 && totalBytes == lastBytes {
						idleSeconds++
						if idleSeconds >= maxIdleSec {
							log("    ⚡ [傳輸靜默偵測] 連續 %d 秒無新數據流入，主動觸發中斷！\n", maxIdleSec)
							close(transferDone)
							return
						}
					} else {
						idleSeconds = 0
						lastBytes = totalBytes
					}
				case <-stopTicker:
					return
				}
			}
		}()

		time.Sleep(2 * time.Second)
		promptChan := make(chan error, 1)
		go func() {
			promptChan <- waitForPrompt(">", maxWaitTime)
		}()

		select {
		case err := <-promptChan:
			if err != nil {
				isTruncated = true
				ftpExitReason = fmt.Sprintf("⚠️ 等待逾時強制截斷 (%v)，資料可能缺漏", maxWaitTime)
				log("    ⚠️ 等待提示字元逾時或斷線: %v\n", err)
			} else {
				ftpExitReason = "✅ 防火牆正常傳輸完畢 (提示字元 > 就緒)"
			}
		case <-transferDone:
			ftpExitReason = fmt.Sprintf("✅ 靜默收斂正常結束 (連續 %d 秒無新數據流入)", maxIdleSec)
			log("    🛑 正在向防火牆發送中斷訊號 (Ctrl+C) 回收後台工作...\n")
			_, _ = stdinPipe.Write([]byte{0x03})
			time.Sleep(500 * time.Millisecond)
		}
		close(stopTicker)
		transferDuration = time.Since(ftpStartTime)

		log("    🧹 [連線清理] 正在清除 %s 歷史連線並正常登出...\n", sshUser)
		_, _ = stdinPipe.Write([]byte(fmt.Sprintf("clear admin-sessions username %s\n", sshUser)))
		time.Sleep(150 * time.Millisecond)
		_, _ = stdinPipe.Write([]byte("exit\n"))
		time.Sleep(150 * time.Millisecond)

		_ = stdinPipe.Close()
		_ = session.Close()

		time.Sleep(300 * time.Millisecond)
		log("[2/4 串流傳輸] ✅ 防火牆資料推送完成！\n")
	}

	// ==========================================
	// 階段 B：DuckDB 湖倉轉換
	// ==========================================
	matches, _ := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv*"))
	if len(matches) == 0 {
		baseFTP := filepath.Dir(req.FTPFolder)
		if filepath.Base(req.FTPFolder) == "ftp_data" {
			baseFTP = req.FTPFolder
		}
		rootMatches, _ := filepath.Glob(filepath.Join(baseFTP, "*.csv*"))
		if len(rootMatches) > 0 {
			matches = rootMatches
			req.FTPFolder = baseFTP
		}
	}

	if len(matches) == 0 {
		errStr := fmt.Sprintf("在目錄 %s 下未找到任何 CSV/GZ 檔案", req.FTPFolder)
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     req.LogType,
			Category:    auditCategory,
			TargetDate:  req.Date,
			TargetSlot:  slotDesc,
			Status:      "FAILED",
			DurationSec: time.Since(totalStart).Seconds(),
			Details:     "未接收到任何日誌碎片",
			ErrorReason: errStr,
			Operator:    "CLI_EXPORT",
		})
		return fmt.Errorf(errStr)
	}

	log("[3/4 湖倉轉換] 📁 偵測到 %d 個分塊壓縮檔案 (Gzip/CSV)，啟動 DuckDB 向量化引擎...\n", len(matches))

	if req.RawOnly {
		log("    📦 [RAW 專屬通道] 略過熱資料解析，直接將 CSV/GZ 壓縮至 traffic_raw_logs/...\n")

		archiveDir := filepath.Join(appDir, "traffic_raw_logs", req.Date)
		if req.LogType == "threat" {
			archiveDir = filepath.Join(appDir, "threat_raw_logs", req.Date)
		}
		_ = os.MkdirAll(archiveDir, 0755)

		var destParquet string
		if req.Hour != "" && req.Slot != "" {
			destParquet = filepath.Join(archiveDir, fmt.Sprintf("%s_raw_%s_%s_%s.parquet", req.LogType, req.Date, req.Hour, req.Slot))
		} else if req.Hour != "" {
			destParquet = filepath.Join(archiveDir, fmt.Sprintf("%s_raw_%s_%s.parquet", req.LogType, req.Date, req.Hour))
		} else {
			destParquet = filepath.Join(archiveDir, fmt.Sprintf("%s_raw_%s.parquet", req.LogType, req.Date))
		}

		tmpDestParquet := destParquet + ".tmp"
		csvPattern := filepath.ToSlash(filepath.Join(req.FTPFolder, "*.csv*"))
		tmpDestSlash := filepath.ToSlash(tmpDestParquet)

		// 🌟 32 vCPU / 64GB 配置：配置 16 核心向量解析、45GB 記憶體天花板與磁碟溢位保護
		tempSpillDir := filepath.ToSlash(filepath.Join(appDir, "duckdb_temp"))
		_ = os.MkdirAll(filepath.Join(appDir, "duckdb_temp"), 0755)

		duckCmd := fmt.Sprintf(
			"SET max_memory='45GB'; SET threads=16; SET preserve_insertion_order=false; SET temp_directory='%s'; "+
				"COPY (SELECT * FROM read_csv_auto('%s', all_varchar=true, union_by_name=true, quote='\"', escape='\"', null_padding=true, ignore_errors=true)) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
			tempSpillDir, csvPattern, tmpDestSlash,
		)

		rawStart := time.Now()
		if _, err := runDuckDBQuery(duckCmd); err != nil {
			_ = os.Remove(tmpDestParquet)
			RecordAuditLog(AuditLogRecord{
				FWModel:     currentModel,
				LogType:     req.LogType,
				Category:    auditCategory,
				TargetDate:  req.Date,
				TargetSlot:  slotDesc,
				Status:      "FAILED",
				DurationSec: time.Since(rawStart).Seconds(),
				OutputFile:  filepath.Base(destParquet),
				Details:     "RAW Parquet 壓縮轉檔失敗",
				ErrorReason: err.Error(),
				Operator:    "CLI_EXPORT",
			})
			return fmt.Errorf("RAW 資料轉換失敗: %w", err)
		}

		_ = os.Remove(destParquet)
		_ = os.Rename(tmpDestParquet, destParquet)

		var rawMB float64
		if fi, err := os.Stat(destParquet); err == nil {
			rawMB = float64(fi.Size()) / 1024 / 1024
		}
		rawRowCount := getParquetExactRowCount(destParquet)
		log("    ✅ RAW 歸檔完成！(耗時: %.1f 秒，共 %d 筆) ➔ %s\n", time.Since(rawStart).Seconds(), rawRowCount, filepath.Base(destParquet))

		// 🌟 1. 登記標註項目至標註庫 (PA-5250 切片 或 PA-1420 全日)
		if req.Hour != "" && req.Slot != "" {
			MarkSliceCompleted(currentModel, req.Date, req.Hour, req.Slot, destParquet, rawMB)
		} else if req.Hour != "" {
			MarkHourMergeCompleted(req.Date, req.Hour, destParquet, rawMB)
		} else {
			MarkDayRollupCompleted(req.Date, destParquet, rawMB)
		}

		// 🌟 核心升級：依任務粒度分流雙軌反哺
		if req.Hour != "" && req.Slot == "" {
			// PA-5250 完整小時 RAW 主檔 ➔ 反哺至小時熱主檔
			log("    🛡️ [雙軌反哺] 正在從第 %s 時 RAW 主檔萃取 14 欄熱資料，整合至小時熱庫...\n", req.Hour)
			go reconcileSyslogMissingRecords(req.LogType, req.Date, req.Hour, destParquet)
		} else if req.Hour == "" {
			// PA-1420 全日 RAW 主檔 ➔ 萃取 14 欄熱資料、與現有熱資料去重融合，並清除當日零碎檔
			log("    🛡️ [PA-1420 雙軌反哺] 正在從 %s 全日 RAW 主檔萃取熱資料、去重整合並清理零碎檔...\n", req.Date)
			go reconcileDailySyslogAndCleanup(req.LogType, req.Date, destParquet)
		}

		// =========================================================================
		// 🌟 步驟 3：組裝全維度稽核 Details，並寫入不可變日誌（含實際處理筆數）
		// =========================================================================
		trigSource := req.TriggerSource
		if trigSource == "" {
			trigSource = "AUTO_SCHEDULER"
		}
		trigReason := req.TriggerReason
		if trigReason == "" {
			if req.Interval == "30" {
				trigReason = "30分鐘切片例行傾印"
			} else if req.Interval == "60" || (req.Hour != "" && req.Slot == "") {
				trigReason = "1小時整檔例行傾印"
			} else {
				trigReason = "PA-1420 全日日誌例行傾印"
			}
		}

		finalStatus := "SUCCESS"
		if isTruncated {
			finalStatus = "WARNING"
		}

		transferSec := transferDuration.Seconds()
		avgRateMBs := 0.0
		if transferSec > 0 {
			avgRateMBs = rawMB / transferSec
		}

		auditDetails := fmt.Sprintf(
			"【進入整併原因】觸發: %s (%s) | 傳輸狀態: %s | 來源: %d 個 GZ (耗時 %.1f秒, 均速 %.1f MB/s) | 產出 RAW: %s (%d 筆, %.1f MB)",
			trigSource,
			trigReason,
			ftpExitReason,
			len(matches),
			transferSec,
			avgRateMBs,
			filepath.Base(destParquet),
			rawRowCount,
			rawMB,
		)

		if req.Hour != "" && req.Slot == "" {
			auditDetails += " | 後續: 啟動 DuckDB 雙軌反哺整合 14 欄小時熱庫"
		} else if req.Hour == "" {
			auditDetails += " | 後續: 啟動 PA-1420 全日熱資料萃取、去重融合與碎片清理"
		} else {
			auditDetails += " | 後續: 等待整點切片整併為小時主檔後統一反哺熱庫"
		}

		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     req.LogType,
			Category:    auditCategory,
			TargetDate:  req.Date,
			TargetSlot:  slotDesc,
			Status:      finalStatus,
			RecordCount: rawRowCount,
			FileSizeMB:  rawMB,
			DurationSec: time.Since(totalStart).Seconds(),
			OutputFile:  filepath.Base(destParquet),
			Details:     auditDetails,
			ErrorReason: func() string {
				if isTruncated {
					return "傳輸達到最大等待上限，強制截斷進入轉檔"
				}
				return ""
			}(),
			Operator: trigSource,
		})

		log("[4/4 空間清理] 🧹 正在清理臨時壓縮檔案...")
		for _, f := range matches {
			_ = os.Remove(f)
		}
		log(" 清理完成！\n")

		log("🎉 [RAW 任務完成] 總耗時: %s\n", time.Since(totalStart).Round(time.Second))
		return nil
	}

	// ==========================================
	// ⚡ 核心升級：先轉出 119 欄 RAW 冷主檔，再從中萃取 14 欄熱資料補漏
	// ==========================================
	safeSuffix := fmt.Sprintf("_nas_%d.parquet", time.Now().UnixNano())
	txtPattern := filepath.ToSlash(filepath.Join(req.FTPFolder, "*.csv*"))

	var coldParquetPath, hotParquetPath string
	if req.LogType == "threat" {
		coldParquetPath = filepath.Join(threatRawDir, fmt.Sprintf("threat_raw_%s%s", req.Date, safeSuffix))
		hotParquetPath = filepath.Join(threatDir, fmt.Sprintf("threat_%s%s", req.Date, safeSuffix))
	} else {
		coldParquetPath = filepath.Join(trafficRawDir, fmt.Sprintf("traffic_raw_%s%s", req.Date, safeSuffix))
		hotParquetPath = filepath.Join(trafficDir, fmt.Sprintf("traffic_%s%s", req.Date, safeSuffix))
	}

	tmpCold := filepath.ToSlash(coldParquetPath + ".tmp")

	// ------------------------------------------
	// 步驟 1：巨量 CSV ➔ RAW 冷資料 Parquet (多核心極速解析與 ZSTD 壓縮)
	// ------------------------------------------
	coldStart := time.Now()
	log("    🧊 [1/2] 正在將 %d 個碎片 CSV 轉換為全量無損冷資料 (RAW Parquet)...\n", len(matches))

	tempSpillDir := filepath.ToSlash(filepath.Join(appDir, "duckdb_temp"))
	_ = os.MkdirAll(filepath.Join(appDir, "duckdb_temp"), 0755)

	coldQuery := fmt.Sprintf(
		"SET max_memory='16GB'; SET threads=16; SET preserve_insertion_order=false; SET temp_directory='%s'; "+
			"COPY (SELECT * FROM read_csv_auto('%s', all_varchar=true, union_by_name=true, quote='\"', escape='\"', null_padding=true, ignore_errors=true) ORDER BY \"Generate Time\" DESC) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
		tempSpillDir, txtPattern, tmpCold,
	)

	if _, err := runDuckDBQuery(coldQuery); err != nil {
		_ = os.Remove(coldParquetPath + ".tmp")
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     req.LogType,
			Category:    auditCategory,
			TargetDate:  req.Date,
			TargetSlot:  slotDesc,
			Status:      "FAILED",
			DurationSec: time.Since(coldStart).Seconds(),
			Details:     "冷主檔 RAW Parquet 轉換失敗",
			ErrorReason: err.Error(),
			Operator:    "CLI_EXPORT",
		})
		return fmt.Errorf("冷主檔轉換失敗: %w", err)
	}

	_ = os.Remove(coldParquetPath)
	_ = os.Rename(coldParquetPath+".tmp", coldParquetPath)

	var coldMB float64
	if fi, err := os.Stat(coldParquetPath); err == nil {
		coldMB = float64(fi.Size()) / 1024 / 1024
	}
	coldRowCount := getParquetExactRowCount(coldParquetPath)
	log("      ✅ 冷資料轉換完成！(耗時: %.1f 秒，共 %d 筆，產生大小: %.1f MB)\n", time.Since(coldStart).Seconds(), coldRowCount, coldMB)

	// ------------------------------------------
	// 步驟 2：從 RAW 冷資料中萃取 14 欄熱資料，並進行去重 (ANTI JOIN 概念)
	// ------------------------------------------
	hotStart := time.Now()
	log("    ⚡ [2/2] 正在從冷資料庫萃取 14 欄強型別熱資料，準備補齊至主檔...\n")

	tmpHot := filepath.ToSlash(hotParquetPath + ".tmp")
	coldSlashPath := filepath.ToSlash(coldParquetPath)

	var hotQuery string
	if req.LogType == "threat" {
		hotQuery = fmt.Sprintf(`
			SET max_memory='16GB'; SET threads=16; SET preserve_insertion_order=false; SET temp_directory='%s';
			COPY (
				SELECT
					REPLACE(REPLACE(COALESCE(TRY_CAST("Generate Time" AS VARCHAR), TRY_CAST("Receive Time" AS VARCHAR)), '/', '-'), ' ', ' ') AS timestamp,
					TRY_CAST("Threat/Content Type" AS VARCHAR) AS subtype,
					COALESCE(NULLIF(TRY_CAST("Threat/Content Name" AS VARCHAR), ''), TRY_CAST("Threat/Content Type" AS VARCHAR)) AS threat_name,
					TRY_CAST("Threat/Content Type" AS VARCHAR) AS threat_id,
					TRY_CAST("Source Zone" AS VARCHAR) AS from_zone,
					TRY_CAST("Destination Zone" AS VARCHAR) AS to_zone,
					TRY_CAST("Source address" AS VARCHAR) AS src,
					TRY_CAST("Destination address" AS VARCHAR) AS dst,
					TRY_CAST("Destination Port" AS INT) AS to_port,
					TRY_CAST("Application" AS VARCHAR) AS application,
					TRY_CAST("Action" AS VARCHAR) AS action,
					LOWER(TRY_CAST("Severity" AS VARCHAR)) AS severity,
					TRY_CAST("Misc" AS VARCHAR) AS url,
					TRY_CAST("Session ID" AS VARCHAR) AS session_id
				FROM read_parquet('%s')
				WHERE "Type" = 'THREAT'
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, tempSpillDir, coldSlashPath, tmpHot)
	} else {
		hotQuery = fmt.Sprintf(`
			SET max_memory='16GB'; SET threads=16; SET preserve_insertion_order=false; SET temp_directory='%s';
			COPY (
				SELECT
					REPLACE(REPLACE(COALESCE(TRY_CAST("Generate Time" AS VARCHAR), TRY_CAST("Receive Time" AS VARCHAR)), '/', '-'), ' ', ' ') AS timestamp,
					TRY_CAST("Type" AS VARCHAR) AS type,
					TRY_CAST("Source Zone" AS VARCHAR) AS from_zone,
					TRY_CAST("Destination Zone" AS VARCHAR) AS to_zone,
					TRY_CAST("Source address" AS VARCHAR) AS source,
					TRY_CAST("NAT Source IP" AS VARCHAR) AS nat_source_ip,
					TRY_CAST("Destination address" AS VARCHAR) AS destination,
					TRY_CAST("NAT Destination IP" AS VARCHAR) AS nat_dest_ip,
					TRY_CAST("Destination Port" AS INT) AS to_port,
					TRY_CAST("Application" AS VARCHAR) AS application,
					TRY_CAST("Action" AS VARCHAR) AS action,
					TRY_CAST("Rule" AS VARCHAR) AS rule,
					TRY_CAST("Session End Reason" AS VARCHAR) AS session_end_reason,
					TRY_CAST("Bytes" AS BIGINT) AS bytes,
					TRY_CAST("Session ID" AS VARCHAR) AS session_id
				FROM read_parquet('%s')
				WHERE "Type" = 'TRAFFIC'
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, tempSpillDir, coldSlashPath, tmpHot)
	}

	if _, err := runDuckDBQuery(hotQuery); err != nil {
		_ = os.Remove(hotParquetPath + ".tmp")
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     req.LogType,
			Category:    "14欄熱資料",
			TargetDate:  req.Date,
			TargetSlot:  slotDesc,
			Status:      "FAILED",
			DurationSec: time.Since(hotStart).Seconds(),
			Details:     "熱資料萃取失敗",
			ErrorReason: err.Error(),
			Operator:    "CLI_EXPORT",
		})
		return fmt.Errorf("熱資料轉換失敗: %w", err)
	}

	_ = os.Remove(hotParquetPath)
	_ = os.Rename(hotParquetPath+".tmp", hotParquetPath)

	var hotMB float64
	if fi, err := os.Stat(hotParquetPath); err == nil {
		hotMB = float64(fi.Size()) / 1024 / 1024
	}
	hotRowCount := getParquetExactRowCount(hotParquetPath)
	log("      ✅ 萃取完成！(耗時: %.1f 秒，冷檔: %d 筆 / 熱檔: %d 筆，大小: %.1f MB)\n", time.Since(hotStart).Seconds(), coldRowCount, hotRowCount, hotMB)

	mergeReason := ""
	if req.Hour != "" && req.Slot == "" {
		mergeReason = " (原因：Linux 排程觸發 1 小時整檔傾印與碎片整併)"
	} else if req.Hour != "" && req.Slot != "" {
		mergeReason = fmt.Sprintf(" (原因：Windows 排程觸發 %s 分鐘切片傾印與碎片整併)", req.Interval)
	} else {
		mergeReason = " (原因：PA-1420 全日傾印與碎片整併)"
	}

	RecordAuditLog(AuditLogRecord{
		FWModel:     currentModel,
		LogType:     req.LogType,
		Category:    auditCategory,
		TargetDate:  req.Date,
		TargetSlot:  slotDesc,
		Status:      "SUCCESS",
		RecordCount: coldRowCount,
		FileSizeMB:  coldMB,
		DurationSec: time.Since(coldStart).Seconds(),
		OutputFile:  filepath.Base(coldParquetPath),
		Details:     fmt.Sprintf("RAW 冷主檔 (%d 筆) 與 14 欄熱資料 (%d 筆) 萃取成功 (來源: %d 個 CSV 碎片)%s", coldRowCount, hotRowCount, len(matches), mergeReason),
		Operator:    "CLI_EXPORT",
	})

	log("[4/4 空間清理] 🧹 正在清理臨時檔案...")
	for _, f := range matches {
		_ = os.Remove(f)
	}
	log(" 清理完成！\n")

	log("[5/5 資料整併] 🔄 正在由 DuckDB 自動執行去重整併...\n")
	if req.LogType == "threat" {
		ConsolidateThreatParquetFiles()
		ConsolidateRawParquetFiles("threat")
	} else {
		ConsolidateParquetFiles()
		ConsolidateRawParquetFiles("traffic")
	}
	ConsolidateAuditLogs()

	log("✅ 去重整併完成，已清除碎片！\n")

	log("🎉 全部流程順利完成！總耗時: %s\n", time.Since(totalStart).Round(time.Second))
	return nil
}

func isHighEndFirewallModel(model string) bool {
	m := strings.ToUpper(model)
	highEndKeys := []string{"5250", "5200", "5220", "5260", "5450", "5400", "7000", "7050", "7080", "3400"}
	for _, k := range highEndKeys {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

var (
	hourlyMergeMapLock sync.Mutex
	hourlyMergeLocks   = make(map[string]*sync.Mutex)
)

func getHourMergeLock(date, hour string) *sync.Mutex {
	key := date + "_" + hour
	hourlyMergeMapLock.Lock()
	defer hourlyMergeMapLock.Unlock()
	if l, ok := hourlyMergeLocks[key]; ok {
		return l
	}
	l := &sync.Mutex{}
	hourlyMergeLocks[key] = l
	return l
}

func consolidateHourlyRawParquet(logType, targetDate, targetHour string) error {
	mergeLock := getHourMergeLock(targetDate, targetHour)
	mergeLock.Lock()
	defer mergeLock.Unlock()

	rawDir := filepath.Join(appDir, "traffic_raw_logs")
	if logType == "threat" {
		rawDir = filepath.Join(appDir, "threat_raw_logs")
	}

	dayDir := filepath.Join(rawDir, targetDate)
	pattern := filepath.Join(dayDir, fmt.Sprintf("%s_raw_%s_%s_*.parquet", logType, targetDate, targetHour))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	targetHourlyFile := filepath.Join(dayDir, fmt.Sprintf("%s_raw_%s_%s.parquet", logType, targetDate, targetHour))
	tmpHourlyFile := targetHourlyFile + ".tmp"

	sqlCmd := fmt.Sprintf(
		"SET max_memory='16GB'; SET threads=16; SET preserve_insertion_order=false; "+
			"COPY (SELECT * FROM read_parquet('%s', union_by_name=true)) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);",
		filepath.ToSlash(pattern), filepath.ToSlash(tmpHourlyFile),
	)

	consStart := time.Now()
	currentModel := getFWModelName()
	if _, err := runDuckDBQuery(sqlCmd); err != nil {
		_ = os.Remove(tmpHourlyFile)
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     logType,
			Category:    "分時parquet",
			TargetDate:  targetDate,
			TargetSlot:  fmt.Sprintf("%s:00整點", targetHour),
			Status:      "FAILED",
			DurationSec: time.Since(consStart).Seconds(),
			OutputFile:  filepath.Base(targetHourlyFile),
			Details:     fmt.Sprintf("第 %s 小時切片整合失敗 (碎片數: %d)", targetHour, len(matches)),
			ErrorReason: err.Error(),
			Operator:    "AUTO_SCHEDULER",
		})
		return fmt.Errorf("小時整併失敗: %w", err)
	}

	_ = os.Remove(targetHourlyFile)
	if err := os.Rename(tmpHourlyFile, targetHourlyFile); err != nil {
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     logType,
			Category:    "分時parquet",
			TargetDate:  targetDate,
			TargetSlot:  fmt.Sprintf("%s:00整點", targetHour),
			Status:      "FAILED",
			DurationSec: time.Since(consStart).Seconds(),
			OutputFile:  filepath.Base(targetHourlyFile),
			Details:     fmt.Sprintf("第 %s 小時主檔命名替換失敗", targetHour),
			ErrorReason: err.Error(),
			Operator:    "AUTO_SCHEDULER",
		})
		return fmt.Errorf("命名小時主檔失敗: %w", err)
	}

	for _, f := range matches {
		_ = os.Remove(f)
	}

	var hourlyMB float64
	if fi, err := os.Stat(targetHourlyFile); err == nil {
		hourlyMB = float64(fi.Size()) / 1024 / 1024
	}
	hourlyRowCount := getParquetExactRowCount(targetHourlyFile)

	// 🌟 核心：登記 PA-5250 小時整併完成標註
	MarkHourMergeCompleted(targetDate, targetHour, targetHourlyFile, hourlyMB)

	RecordAuditLog(AuditLogRecord{
		FWModel:     currentModel,
		LogType:     logType,
		Category:    "分時parquet",
		TargetDate:  targetDate,
		TargetSlot:  fmt.Sprintf("%s:00整點", targetHour),
		Status:      "SUCCESS",
		RecordCount: hourlyRowCount,
		FileSizeMB:  hourlyMB,
		DurationSec: time.Since(consStart).Seconds(),
		OutputFile:  filepath.Base(targetHourlyFile),
		Details:     fmt.Sprintf("第 %s 時的 %d 個切片已整合成小時主檔 (共 %d 筆)", targetHour, len(matches), hourlyRowCount),
		Operator:    "AUTO_SCHEDULER",
	})

	fmt.Printf("📦 [每小時整併成功] %s %s 時的 %d 個切片已整合成: %s (共 %d 筆)\n",
		targetDate, targetHour, len(matches), filepath.Base(targetHourlyFile), hourlyRowCount)

	// 🌟 啟動背景非同步雙軌反哺：自動將整點冷資料反哺成 14 欄熱資料並去重融合
	if logType == "traffic" {
		go reconcileSyslogMissingRecords(logType, targetDate, targetHour, targetHourlyFile)
	}

	return nil
}

var (
	autoExportLock   sync.Mutex
	currentTaskName  string
	currentTaskStart time.Time
	taskMetaLock     sync.Mutex
	schedulerOnce    sync.Once
)

func tryLockWithTask(taskName string) bool {
	if autoExportLock.TryLock() {
		taskMetaLock.Lock()
		currentTaskName = taskName
		currentTaskStart = time.Now()
		taskMetaLock.Unlock()
		return true
	}
	return false
}

func unlockTask() {
	taskMetaLock.Lock()
	currentTaskName = ""
	taskMetaLock.Unlock()
	autoExportLock.Unlock()
}

type ExportSliceTask struct {
	Date          string
	Hour          string
	Slot          string
	Interval      string
	IsHourRolling bool
}

var (
	sliceTaskQueue  = make(chan ExportSliceTask, 288)
	queueWorkerOnce sync.Once
	inQueueSetLock  sync.Mutex
	inQueueTaskSet  = make(map[string]bool)
)

// 🌟 緊急清空佇列：瞬間排空所有正在等候的任務
func PurgeSliceTaskQueue() int {
	inQueueSetLock.Lock()
	defer inQueueSetLock.Unlock()

	purged := 0
	for {
		select {
		case task := <-sliceTaskQueue:
			purged++
			key := fmt.Sprintf("%s_%s_%s", task.Date, task.Hour, task.Slot)
			delete(inQueueTaskSet, key)

			RecordAuditLog(AuditLogRecord{
				FWModel:    getFWModelName(),
				LogType:    "traffic",
				Category:   "chunk切片",
				TargetDate: task.Date,
				TargetSlot: fmt.Sprintf("%s:%s", task.Hour, task.Slot),
				Status:     "CANCELLED",
				Details:    "管理員執行【緊急清空佇列】，已取消此排隊任務",
				Operator:   "MANUAL_PURGE",
			})
		default:
			return purged
		}
	}
}

// 🌟 核心消費者 Worker
func initSliceQueueWorker() {
	queueWorkerOnce.Do(func() {
		go func() {
			logger := func(format string, a ...any) {
				msg := fmt.Sprintf("[切片佇列 %s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, a...)
				fmt.Print(msg)
			}

			for task := range sliceTaskQueue {
				slotLabel := fmt.Sprintf("%s:%s", task.Hour, task.Slot)
				if task.Slot == "" {
					slotLabel = fmt.Sprintf("%s:00整點(1小時整檔)", task.Hour)
				}
				key := fmt.Sprintf("%s_%s_%s", task.Date, task.Hour, task.Slot)
				taskName := fmt.Sprintf("PA-5250 自動傾印 (%s %s)", task.Date, slotLabel)

				inQueueSetLock.Lock()
				delete(inQueueTaskSet, key)
				inQueueSetLock.Unlock()

				// 🌟 只略過 10 分鐘的歷史舊切片，完整放行 30 分鐘切片 (Interval == "30")
				if runtime.GOOS == "linux" && task.Interval == "10" {
					logger("⏭️ [Linux 略過舊切片] 略過 10 分鐘舊切片任務 (%s %s:%s)\n", task.Date, task.Hour, task.Slot)
					continue
				}

				// 🛑 防禦 1：檢查此任務是否已被管理員點擊停止
				retryTrackerLock.RLock()
				isCancelled := retryCancelled[fmt.Sprintf("%s_%s", task.Date, slotLabel)]
				retryTrackerLock.RUnlock()
				if isCancelled {
					logger("🛑 [任務取消] %s 已由管理員停止，略過執行！\n", taskName)
					continue
				}

				// 🛑 防禦 2【核心標註檢查】：若標註庫或小時主檔已標記完成，0 毫秒跳過，絕不連線 FTP！
				if isSliceAlreadyCompleted(task.Date, task.Hour, task.Slot) {
					logger("⏭️ [已標註完成] 任務 %s 經檢查已於標註庫登記完成，0毫秒略過，絕不連線 FTP！\n", taskName)
					continue
				}

				// 搶鎖準備執行
				waitSec := 0
				for !tryLockWithTask(taskName) {
					if waitSec == 0 {
						taskMetaLock.Lock()
						runningTask := currentTaskName
						runningSec := int(time.Since(currentTaskStart).Seconds())
						taskMetaLock.Unlock()
						logger("⚠️ 資源佔用中，任務 %s 於佇列等待... [執行中: %s，已耗時: %d 秒]\n", taskName, runningTask, runningSec)
					}
					time.Sleep(3 * time.Second)
					waitSec += 3
				}

				logger("⏱️ [佇列啟動] 任務 %s 開始執行 (待處理佇列: %d 個)...\n", taskName, len(sliceTaskQueue))

				req := CLIExportRequest{
					Date:        task.Date,
					Hour:        task.Hour,
					Slot:        task.Slot,
					Interval:    task.Interval,
					FTPFolder:   filepath.Join(appDir, "ftp_data"),
					LogType:     "traffic",
					RawOnly:     true,
					ConvertOnly: false,
				}

				if err := performCLIExportAndConvert(req, logger); err != nil {
					logger("❌ [PA-5250] 切片失敗 (%s %s:%s): %v\n", task.Date, task.Hour, task.Slot, err)
				} else {
					logger("✅ [PA-5250] 切片已存為 traffic_raw_%s_%s_%s.parquet\n", task.Date, task.Hour, task.Slot)

					// 🌟 檢查該小時所有切片是否已齊全 (Linux 30分模式需齊備 00 與 30 兩檔；Windows 10分模式需齊備 6 檔)
					dayRawDir := filepath.Join(appDir, "traffic_raw_logs", task.Date)
					slicePattern := filepath.Join(dayRawDir, fmt.Sprintf("traffic_raw_%s_%s_*.parquet", task.Date, task.Hour))
					existingSlices, _ := filepath.Glob(slicePattern)

					expectedSlices := 6
					if runtime.GOOS == "linux" || task.Interval == "30" {
						expectedSlices = 2
					}

					if len(existingSlices) >= expectedSlices {
						logger("📦 [PA-5250 每小時打包] %s 第 %s 時已集齊 %d 個切片，開始整合成小時主檔並反哺熱庫...\n",
							task.Date, task.Hour, len(existingSlices))
						_ = consolidateHourlyRawParquet("traffic", task.Date, task.Hour)
					} else {
						logger("⏳ [等待整點齊全] %s 第 %s 時目前已有 %d/%d 個切片，待全數齊備後再進行小時整併與熱資料反哺。\n",
							task.Date, task.Hour, len(existingSlices), expectedSlices)
					}
				}

				unlockTask()
			}
		}()
	})
}

// 🌟 安全的入隊函式 (內建重複過濾)
func EnqueueSliceTask(task ExportSliceTask, log StreamLogger) bool {
	key := fmt.Sprintf("%s_%s_%s", task.Date, task.Hour, task.Slot)

	inQueueSetLock.Lock()
	defer inQueueSetLock.Unlock()

	if inQueueTaskSet[key] {
		return false
	}

	select {
	case sliceTaskQueue <- task:
		inQueueTaskSet[key] = true
		return true
	default:
		log("🚨 [佇列已滿] 嚴重警告：切片佇列已達 288 個上限！\n")
		return false
	}
}

// 🌟 缺漏巡檢：支援指定回溯小時數 (0 = 今日 00:00:00 起全天對賬；> 0 = 回溯過去 N 個小時並對齊整點)
func ReconcileMissingSlices(log StreamLogger, hoursBack int) int {
	if !isHighEndFirewall() {
		return 0
	}

	// 🌟 核心修正：Linux 環境下點擊「手動對賬」時，自動切換至 30 分鐘巡檢函式
	if runtime.GOOS == "linux" {
		return ReconcileMissingHours(log, hoursBack)
	}

	now := time.Now()
	currentSlot := now.Truncate(10 * time.Minute)
	lastCompletedSlot := currentSlot.Add(-10 * time.Minute)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var windowStart time.Time
	if hoursBack <= 0 {
		windowStart = startOfToday
	} else {
		windowStart = currentSlot.Add(-time.Duration(hoursBack) * time.Hour).Truncate(time.Hour)
		if windowStart.Before(startOfToday) {
			windowStart = startOfToday
		}
	}

	if lastCompletedSlot.Before(windowStart) {
		return 0
	}

	missingCount := 0

	for slotTime := windowStart; !slotTime.After(lastCompletedSlot); slotTime = slotTime.Add(10 * time.Minute) {
		dStr := slotTime.Format("2006-01-02")
		hStr := slotTime.Format("15")
		mStr := slotTime.Format("04")

		if isSliceAlreadyCompleted(dStr, hStr, mStr) {
			continue
		}

		task := ExportSliceTask{
			Date:          dStr,
			Hour:          hStr,
			Slot:          mStr,
			Interval:      "10",
			IsHourRolling: (mStr == "50"),
		}

		if EnqueueSliceTask(task, log) {
			missingCount++
			log("🩹 [自檢修復] 偵測到缺失時段 (%s %s:%s)，已自動推入佇列！\n", dStr, hStr, mStr)

			RecordAuditLog(AuditLogRecord{
				FWModel:    getFWModelName(),
				LogType:    "traffic",
				Category:   "chunk切片",
				TargetDate: dStr,
				TargetSlot: fmt.Sprintf("%s:%s", hStr, mStr),
				Status:     "QUEUED",
				Details:    fmt.Sprintf("自檢巡檢對賬：偵測到磁碟無此時段日誌，自動排隊補抓"),
				Operator:   "AUTO_RECONCILER",
			})
		}
	}

	if missingCount > 0 {
		log("🏁 [對賬完成] 共發現並排入 %d 個缺失切片，佇列正在背景依序追趕回補中...\n", missingCount)
	} else {
		log("✅ [對賬完成] %s ~ %s 無任何缺失切片，全數日誌完整！\n",
			windowStart.Format("15:04"), lastCompletedSlot.Format("15:04"))
	}

	return missingCount
}

// 🌟 Linux 專屬：檢查過去 N 小時缺漏，以 30 分鐘為單位切片自動回補，並自動補合延遲整點與缺失熱資料
func ReconcileMissingHours(log StreamLogger, hoursBack int) int {
	if !isHighEndFirewall() {
		return 0
	}

	now := time.Now()
	currentSlot := now.Truncate(30 * time.Minute)
	lastCompletedSlot := currentSlot.Add(-30 * time.Minute)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	var windowStart time.Time
	if hoursBack <= 0 {
		windowStart = startOfToday
	} else {
		windowStart = currentSlot.Add(-time.Duration(hoursBack) * time.Hour)
		if windowStart.Before(startOfToday) {
			windowStart = startOfToday
		}
	}

	if lastCompletedSlot.Before(windowStart) {
		return 0
	}

	missingCount := 0

	// 1. 以 30 分鐘步進巡檢缺失切片
	for sTime := windowStart; !sTime.After(lastCompletedSlot); sTime = sTime.Add(30 * time.Minute) {
		dStr := sTime.Format("2006-01-02")
		hStr := sTime.Format("15")
		mStr := sTime.Format("04") // "00" 或 "30"

		if isHourAlreadyCompleted(dStr, hStr) || isSliceAlreadyCompleted(dStr, hStr, mStr) {
			continue
		}

		task := ExportSliceTask{
			Date:          dStr,
			Hour:          hStr,
			Slot:          mStr,
			Interval:      "30",
			IsHourRolling: (mStr == "30"),
		}

		if EnqueueSliceTask(task, log) {
			missingCount++
			log("🩹 [30分切片自動回補] 偵測到缺失時段 (%s %s:%s)，已排入佇列！\n", dStr, hStr, mStr)

			RecordAuditLog(AuditLogRecord{
				FWModel:    getFWModelName(),
				LogType:    "traffic",
				Category:   "chunk切片",
				TargetDate: dStr,
				TargetSlot: fmt.Sprintf("%s:%s", hStr, mStr),
				Status:     "QUEUED",
				Details:    fmt.Sprintf("Linux 30分鐘切片對賬補登"),
				Operator:   "AUTO_RECONCILER",
			})
		}
	}

	// 2. 🌟 全盤整點補漏：針對已過完的整點小時，自動補合「2 個切片已齊卻未整併」與「已有整點冷檔卻尚未轉熱資料」
	lastCompletedHourStart := now.Truncate(time.Hour).Add(-1 * time.Hour)
	for hTime := windowStart.Truncate(time.Hour); !hTime.After(lastCompletedHourStart); hTime = hTime.Add(1 * time.Hour) {
		dStr := hTime.Format("2006-01-02")
		hStr := hTime.Format("15")

		dayRawDir := filepath.Join(appDir, "traffic_raw_logs", dStr)
		hourlyRawFile := filepath.Join(dayRawDir, fmt.Sprintf("traffic_raw_%s_%s.parquet", dStr, hStr))
		hotHourlyFile := filepath.Join(appDir, "traffic_logs", dStr, fmt.Sprintf("traffic_%s_%s.parquet", dStr, hStr))

		// (A) 若尚未合併成整點冷檔，檢查 00 與 30 兩個切片是否已齊全
		if fi, err := os.Stat(hourlyRawFile); err != nil || fi.Size() == 0 {
			slice00 := filepath.Join(dayRawDir, fmt.Sprintf("traffic_raw_%s_%s_00.parquet", dStr, hStr))
			slice30 := filepath.Join(dayRawDir, fmt.Sprintf("traffic_raw_%s_%s_30.parquet", dStr, hStr))
			if f0, e0 := os.Stat(slice00); e0 == nil && f0.Size() > 0 {
				if f3, e3 := os.Stat(slice30); e3 == nil && f3.Size() > 0 {
					log("🩹 [整點切片自動補合] 偵測到 %s %s 時兩個切片已齊全，立即整併並反哺熱庫...\n", dStr, hStr)
					go func(td, th string) {
						_ = consolidateHourlyRawParquet("traffic", td, th)
					}(dStr, hStr)
				}
			}
			continue
		}

		// (B) 若整點冷檔已存在，但對應的 14 欄熱資料檔尚未產生，立即補跑冷轉熱反哺
		if hFi, hErr := os.Stat(hotHourlyFile); hErr != nil || hFi.Size() == 0 {
			log("🩹 [冷轉熱自動補漏] 偵測到 %s %s 時冷檔已就緒但熱資料缺失，立即啟動雙軌反哺...\n", dStr, hStr)
			go reconcileSyslogMissingRecords("traffic", dStr, hStr, hourlyRawFile)
		}
	}

	if missingCount > 0 {
		log("🏁 [30分對賬完成] 共發現並排入 %d 個缺失 30 分鐘切片，佇列正在背景循序處理...\n", missingCount)
	} else {
		log("✅ [30分對賬完成] %s ~ %s 日誌切片皆完整存在！\n",
			windowStart.Format("15:04"), lastCompletedSlot.Format("15:04"))
	}

	return missingCount
}

func StartAutoExportScheduler() {
	schedulerOnce.Do(func() {
		go func() {
			time.Sleep(6 * time.Second)

			for i := 0; i < 15; i++ {
				m := getFWModelName()
				if m != "" && m != "PA 防火牆" {
					break
				}
				time.Sleep(1 * time.Second)
			}

			fwModel := getFWModelName()
			isHighEnd := isHighEndFirewall()

			modeDesc := "每日 00:00:10 全日傾印"
			if isHighEnd {
				if runtime.GOOS == "linux" {
					modeDesc = "Linux 極速模式：每 30 分鐘切片 + 整點雙檔融合 + 熱資料雙軌反哺"
				} else {
					modeDesc = "Windows 模式：每 10 分鐘切片 + 佇列循序執行 + 50分滾動整併 + 雙軌對賬"
				}
			}
			fmt.Printf("🚀 [%s 自動排程引擎] 守護程序已正式就緒！(運作模式: %s)\n", fwModel, modeDesc)

			// 🌟 啟動時先載入並校驗過去 48 小時標註庫
			InitExportCheckpoints()

			initSliceQueueWorker()

			logger := func(format string, a ...any) {
				msg := fmt.Sprintf("[排程引擎 %s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, a...)
				fmt.Print(msg)
			}

			// 🌟 開機完整性對賬（自動補抓缺漏切片並補合延遲整點與熱資料）
			if isHighEnd {
				if runtime.GOOS == "windows" {
					logger("🔍 正在執行 PA-5250 Windows 開機 10 分鐘切片完整性對賬...\n")
					ReconcileMissingSlices(logger, 4)
				} else {
					logger("🔍 [Linux 開機全盤對賬] 正在檢查過去 24 小時小時主檔與熱資料完整性...\n")
					ReconcileMissingHours(logger, 24)
				}
			}

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			var lastDailyExportDate string
			var lastSlotKey string

			for now := range ticker.C {
				currentHighEnd := isHighEndFirewall()

				// PA-1420 低階機型維持每日 00:00:10 全日傾印
				if !currentHighEnd {
					if now.Hour() == 0 && now.Minute() == 0 && now.Second() >= 10 && now.Second() <= 15 {
						todayStr := now.Format("2006-01-02")
						if lastDailyExportDate != todayStr {
							lastDailyExportDate = todayStr
							yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")

							go func(targetDay string) {
								if isDayRollupAlreadyCompleted(targetDay) {
									logger("⏭️ [PA-1420 略過] 前一日 (%s) 已完成標註，略過傾印！\n", targetDay)
									return
								}

								if !tryLockWithTask("PA-1420 全日傾印 (" + targetDay + ")") {
									taskMetaLock.Lock()
									runningTask := currentTaskName
									runningSec := int(time.Since(currentTaskStart).Seconds())
									taskMetaLock.Unlock()
									logger("⚠️ 鎖被佔用，排程略過本次觸發 [目前正執行: %s，已耗時: %d 秒]\n", runningTask, runningSec)

									RecordAuditLog(AuditLogRecord{
										FWModel:     getFWModelName(),
										LogType:     "traffic",
										Category:    "rollup整併",
										TargetDate:  targetDay,
										TargetSlot:  "全日",
										Status:      "FAILED",
										Details:     "排程觸發時鎖被佔用，略過本次傾印",
										ErrorReason: fmt.Sprintf("資源鎖被佔用 (目前正執行: %s，已耗時: %d 秒)", runningTask, runningSec),
										Operator:    "AUTO_SCHEDULER",
									})
									return
								}
								defer unlockTask()

								logger("⏰ [PA-1420 觸發] 抵達 00:00:10，啟動前一日 (%s) 全日 RAW Log 傾印...\n", targetDay)

								req := CLIExportRequest{
									Date:        targetDay,
									FTPFolder:   filepath.Join(appDir, "ftp_data"),
									LogType:     "traffic",
									RawOnly:     true,
									ConvertOnly: false,
								}
								if err := performCLIExportAndConvert(req, logger); err != nil {
									logger("❌ [PA-1420] 傾印失敗: %v\n", err)
								} else {
									logger("✅ [PA-1420] 前一日 (%s) RAW Log 已封裝進 traffic_raw_logs/！\n", targetDay)
								}
							}(yesterday)
						}
					}
				}

				// ==========================================
				// 🌟 高階機型 (PA-5250) Linux 30 分鐘切片排程架構
				// ==========================================
				if currentHighEnd {
					if runtime.GOOS == "linux" {
						// 🌟 定時巡邏：每小時第 05 分與 35 分巡檢缺漏與補轉熱資料
						if (now.Minute() == 5 || now.Minute() == 35) && now.Second() <= 2 {
							go ReconcileMissingHours(logger, 4)
						}

						// 🌟 30 分鐘正常觸發 (00分 10秒 或 30分 10秒)
						if (now.Minute() == 0 || now.Minute() == 30) && (now.Second() >= 10 && now.Second() <= 15) {
							slotEnd := now.Truncate(30 * time.Minute)
							slotStart := slotEnd.Add(-30 * time.Minute)

							targetDate := slotStart.Format("2006-01-02")
							targetHour := slotStart.Format("15")
							targetSlot := slotStart.Format("04") // "00" 或 "30"
							slotKey := fmt.Sprintf("%s_%s_%s", targetDate, targetHour, targetSlot)

							if lastSlotKey != slotKey {
								lastSlotKey = slotKey

								t := ExportSliceTask{
									Date:          targetDate,
									Hour:          targetHour,
									Slot:          targetSlot,
									Interval:      "30",
									IsHourRolling: (targetSlot == "30"),
								}

								if EnqueueSliceTask(t, logger) {
									queueLen := len(sliceTaskQueue)
									logger("📥 [Linux 30分排程] 已派發切片任務: %s %s:%s (待處理: %d)\n",
										targetDate, targetHour, targetSlot, queueLen)

									RecordAuditLog(AuditLogRecord{
										FWModel:    getFWModelName(),
										LogType:    "traffic",
										Category:   "chunk切片",
										TargetDate: targetDate,
										TargetSlot: fmt.Sprintf("%s:%s", targetHour, targetSlot),
										Status:     "QUEUED",
										Details:    fmt.Sprintf("Linux 30分鐘切片排程派發 (排隊深度: %d)", queueLen),
										Operator:   "AUTO_SCHEDULER",
									})
								}
							}
						}
					} else {
						// 🪟 【Windows 專屬】維持 10 分鐘邊收邊壓切片 + 佇列循序執行 + 50分整併
						if now.Minute() == 5 && now.Second() <= 2 {
							go ReconcileMissingSlices(logger, 4)
						}

						if (now.Minute()%10 == 0) && (now.Second() >= 10 && now.Second() <= 15) {
							slotEnd := now.Truncate(10 * time.Minute)
							slotStart := slotEnd.Add(-10 * time.Minute)

							targetDate := slotStart.Format("2006-01-02")
							targetHour := slotStart.Format("15")
							targetSlot := slotStart.Format("04")
							slotKey := fmt.Sprintf("%s_%s_%s", targetDate, targetHour, targetSlot)

							if lastSlotKey != slotKey {
								lastSlotKey = slotKey

								t := ExportSliceTask{
									Date:          targetDate,
									Hour:          targetHour,
									Slot:          targetSlot,
									Interval:      "10",
									IsHourRolling: slotEnd.Minute() == 0,
								}

								if EnqueueSliceTask(t, logger) {
									queueLen := len(sliceTaskQueue)
									logger("📥 [Windows 排程派送] 已將 10 分鐘切片加入佇列: %s %s:%s (待處理佇列: %d)\n",
										targetDate, targetHour, targetSlot, queueLen)

									RecordAuditLog(AuditLogRecord{
										FWModel:    getFWModelName(),
										LogType:    "traffic",
										Category:   "chunk切片",
										TargetDate: targetDate,
										TargetSlot: fmt.Sprintf("%s:%s", targetHour, targetSlot),
										Status:     "QUEUED",
										Details:    fmt.Sprintf("排程派發任務至佇列等待 (目前排隊深度: %d)", queueLen),
										Operator:   "AUTO_SCHEDULER",
									})
								}
							}
						}
					}
				}
			}
		}()
	})
}

var (
	hotReconcileMapLock  sync.Mutex
	hotReconcileLocks    = make(map[string]*sync.Mutex)
	hotReconcileInFlight = make(map[string]bool)
)

func getHourReconcileLock(date, hour string) *sync.Mutex {
	key := date + "_" + hour
	hotReconcileMapLock.Lock()
	defer hotReconcileMapLock.Unlock()
	if l, ok := hotReconcileLocks[key]; ok {
		return l
	}
	l := &sync.Mutex{}
	hotReconcileLocks[key] = l
	return l
}

// 🌟 雙軌反哺引擎：整點小時 RAW 主檔完成後，動態偵測欄位萃取 14 欄熱資料並與現有熱庫全量去重融合
func reconcileSyslogMissingRecords(logType, targetDate, targetHour, hourlyRawFile string) {
	if logType != "traffic" {
		return
	}

	flightKey := targetDate + "_" + targetHour
	hotReconcileMapLock.Lock()
	if hotReconcileInFlight[flightKey] {
		hotReconcileMapLock.Unlock()
		return
	}
	hotReconcileInFlight[flightKey] = true
	hotReconcileMapLock.Unlock()

	defer func() {
		hotReconcileMapLock.Lock()
		delete(hotReconcileInFlight, flightKey)
		hotReconcileMapLock.Unlock()
	}()

	// 1. 鎖定該「日期_小時」，防止重複觸發造成同時寫入覆蓋
	hourLock := getHourReconcileLock(targetDate, targetHour)
	hourLock.Lock()
	defer hourLock.Unlock()

	if fi, err := os.Stat(hourlyRawFile); err != nil || fi.Size() == 0 {
		return
	}

	startT := time.Now()
	rawSlash := filepath.ToSlash(hourlyRawFile)
	currentModel := getFWModelName()

	// 2. 動態偵測 RAW 檔案欄位（同時相容具名表頭與無表頭 CSV 轉出的 column0~column46）
	colSet := make(map[string]bool)
	if descRows, err := runDuckDBQuery(fmt.Sprintf("DESCRIBE SELECT * FROM read_parquet('%s');", rawSlash)); err == nil {
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

	// 3. 定位目標熱資料目錄與小時主檔路徑
	hotDayDir := filepath.Join(appDir, "traffic_logs", targetDate)
	_ = os.MkdirAll(hotDayDir, 0755)

	hotHourlyFile := filepath.Join(hotDayDir, fmt.Sprintf("traffic_%s_%s.parquet", targetDate, targetHour))
	tmpMergeFile := fmt.Sprintf("%s.%d.tmp", hotHourlyFile, time.Now().UnixNano())
	tempSpillDir := filepath.ToSlash(filepath.Join(appDir, "duckdb_temp"))
	_ = os.MkdirAll(filepath.Join(appDir, "duckdb_temp"), 0755)

	// 4. 盤點現有熱資料檔案（包含既有小時熱主檔、舊小時切片、以及同日 Syslog 碎片）
	var existingHotFiles []string
	allDayParquets, _ := filepath.Glob(filepath.Join(hotDayDir, fmt.Sprintf("traffic*%s*.parquet", targetDate)))
	for _, f := range allDayParquets {
		base := filepath.Base(f)
		if strings.HasSuffix(base, ".tmp") || strings.HasPrefix(base, "patch_") {
			continue
		}
		if fi, err := os.Stat(f); err == nil && fi.Size() > 0 {
			existingHotFiles = append(existingHotFiles, filepath.ToSlash(f))
		}
	}

	hourPrefix := fmt.Sprintf("%s %s:", targetDate, targetHour)
	rawSelectSQL := fmt.Sprintf(`
		SELECT
			REPLACE(REPLACE(%s, '/', '-'), '  ', ' ') AS timestamp,
			%s AS type, %s AS from_zone, %s AS to_zone,
			%s AS source, %s AS nat_source_ip, %s AS destination, %s AS nat_dest_ip,
			%s AS to_port, %s AS application, %s AS action, %s AS rule,
			%s AS session_end_reason, %s AS bytes, %s AS session_id
		FROM read_parquet('%s')
		WHERE REPLACE(%s, '/', '-') LIKE '%s%%'
	`, tsExpr, typeExpr, fromZoneExpr, toZoneExpr,
		srcExpr, natSrcExpr, dstExpr, natDstExpr,
		portExpr, appExpr, actionExpr, ruleExpr,
		endReasonExpr, bytesExpr, sidExpr,
		rawSlash, tsExpr, hourPrefix)

	var unionSourceSQL string
	if len(existingHotFiles) > 0 {
		quotedFiles := make([]string, len(existingHotFiles))
		for i, f := range existingHotFiles {
			quotedFiles[i] = fmt.Sprintf("'%s'", f)
		}
		existingSelectSQL := fmt.Sprintf(`
			SELECT
				TRY_CAST(timestamp AS VARCHAR) AS timestamp,
				TRY_CAST(type AS VARCHAR) AS type,
				TRY_CAST(from_zone AS VARCHAR) AS from_zone,
				TRY_CAST(to_zone AS VARCHAR) AS to_zone,
				TRY_CAST(source AS VARCHAR) AS source,
				TRY_CAST(nat_source_ip AS VARCHAR) AS nat_source_ip,
				TRY_CAST(destination AS VARCHAR) AS destination,
				TRY_CAST(nat_dest_ip AS VARCHAR) AS nat_dest_ip,
				TRY_CAST(to_port AS INT) AS to_port,
				TRY_CAST(application AS VARCHAR) AS application,
				TRY_CAST(action AS VARCHAR) AS action,
				TRY_CAST(rule AS VARCHAR) AS rule,
				TRY_CAST(session_end_reason AS VARCHAR) AS session_end_reason,
				TRY_CAST(bytes AS BIGINT) AS bytes,
				TRY_CAST(session_id AS VARCHAR) AS session_id
			FROM read_parquet([%s], union_by_name=true)
			WHERE TRY_CAST(timestamp AS VARCHAR) LIKE '%s%%'
		`, strings.Join(quotedFiles, ", "), hourPrefix)

		unionSourceSQL = fmt.Sprintf("(%s) UNION ALL (%s)", rawSelectSQL, existingSelectSQL)
	} else {
		unionSourceSQL = rawSelectSQL
	}

	// 5. 全量去重整合並降冪排序寫入
	mergeSQL := fmt.Sprintf(`
		SET max_memory='32GB'; SET threads=12; SET preserve_insertion_order=false; SET temp_directory='%s';
		COPY (
			SELECT * EXCLUDE (rn) FROM (
				SELECT *, ROW_NUMBER() OVER (
					PARTITION BY timestamp, source, destination, to_port, session_id, action, bytes
					ORDER BY timestamp DESC
				) AS rn
				FROM (%s)
			) WHERE rn = 1 AND source != '' AND destination != ''
			ORDER BY timestamp DESC
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, tempSpillDir, unionSourceSQL, filepath.ToSlash(tmpMergeFile))

	if _, err := runDuckDBQuery(mergeSQL); err != nil {
		_ = os.Remove(tmpMergeFile)
		fmt.Printf("❌ [雙軌反哺失敗] %s 第 %s 時熱資料整合失敗: %v\n", targetDate, targetHour, err)
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     logType,
			Category:    "14欄熱資料",
			TargetDate:  targetDate,
			TargetSlot:  fmt.Sprintf("%s:00整點", targetHour),
			Status:      "FAILED",
			DurationSec: time.Since(startT).Seconds(),
			OutputFile:  filepath.Base(hotHourlyFile),
			Details:     fmt.Sprintf("第 %s 時冷資料自動轉熱資料失敗", targetHour),
			ErrorReason: err.Error(),
			Operator:    "AUTO_SCHEDULER",
		})
		return
	}

	// 6. 原子替換為正式小時熱主檔，並清理該小時舊的熱碎片
	_ = os.Remove(hotHourlyFile)
	if err := os.Rename(tmpMergeFile, hotHourlyFile); err != nil {
		_ = os.Remove(tmpMergeFile)
		fmt.Printf("❌ [雙軌反哺失敗] %s 第 %s 時小時熱主檔替換失敗: %v\n", targetDate, targetHour, err)
		return
	}

	oldHourSlices, _ := filepath.Glob(filepath.Join(hotDayDir, fmt.Sprintf("traffic_%s_%s_*.parquet", targetDate, targetHour)))
	for _, f := range oldHourSlices {
		_ = os.Remove(f)
	}

	rollupFrags, _ := filepath.Glob(filepath.Join(hotDayDir, fmt.Sprintf("traffic_%s_*.parquet", targetDate)))
	for _, rf := range rollupFrags {
		base := filepath.Base(rf)
		if strings.Contains(base, "_chunk_") || strings.Contains(base, "_rollup_") {
			trimTmp := rf + ".trim.tmp"
			trimSQL := fmt.Sprintf(`
				SET max_memory='16GB'; SET threads=8; SET preserve_insertion_order=false;
				COPY (
					SELECT * FROM read_parquet('%s')
					WHERE TRY_CAST(timestamp AS VARCHAR) NOT LIKE '%s%%'
				) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
			`, filepath.ToSlash(rf), hourPrefix, filepath.ToSlash(trimTmp))
			if _, err := runDuckDBQuery(trimSQL); err == nil {
				_ = os.Remove(rf)
				_ = os.Rename(trimTmp, rf)
			} else {
				_ = os.Remove(trimTmp)
			}
		}
	}

	var finalMB float64
	if fi, err := os.Stat(hotHourlyFile); err == nil {
		finalMB = float64(fi.Size()) / 1024 / 1024
	}
	hotRowCount := getParquetExactRowCount(hotHourlyFile)
	durationSec := time.Since(startT).Seconds()

	fmt.Printf("🛡️ [雙軌反哺整合完成] %s 第 %s 時已與現有熱資料去重融合 ➔ %s (共 %d 筆，%.1f MB，耗時: %.1f 秒)\n",
		targetDate, targetHour, filepath.Base(hotHourlyFile), hotRowCount, finalMB, durationSec)

	RecordAuditLog(AuditLogRecord{
		FWModel:     currentModel,
		LogType:     logType,
		Category:    "14欄熱資料",
		TargetDate:  targetDate,
		TargetSlot:  fmt.Sprintf("%s:00整點", targetHour),
		Status:      "SUCCESS",
		RecordCount: hotRowCount,
		FileSizeMB:  finalMB,
		DurationSec: durationSec,
		OutputFile:  filepath.Base(hotHourlyFile),
		Details:     fmt.Sprintf("第 %s 時整點冷資料自動反哺 14 欄熱資料並去重融合完成", targetHour),
		Operator:    "AUTO_SCHEDULER",
	})
}

var (
	dailyReconcileMapLock sync.Mutex
	dailyReconcileLocks   = make(map[string]*sync.Mutex)
)

func getDayReconcileLock(date string) *sync.Mutex {
	dailyReconcileMapLock.Lock()
	defer dailyReconcileMapLock.Unlock()
	if l, ok := dailyReconcileLocks[date]; ok {
		return l
	}
	l := &sync.Mutex{}
	dailyReconcileLocks[date] = l
	return l
}

// 🌟 PA-1420 全日雙軌反哺引擎：
// 1. 從每日 RAW 主檔萃取 14 欄熱資料
// 2. 與 traffic_logs/YYYY-MM-DD/ 內現有熱資料 (Syslog _live_ / _chunk_ / _rollup_) 全量去重融合
// 3. 原子替換為單一 traffic_YYYY-MM-DD.parquet 主檔，並清除該日期資料夾下所有零碎檔
func reconcileDailySyslogAndCleanup(logType, targetDate, dailyRawFile string) {
	if logType != "traffic" {
		return
	}

	dayLock := getDayReconcileLock(targetDate)
	dayLock.Lock()
	defer dayLock.Unlock()

	if fi, err := os.Stat(dailyRawFile); err != nil || fi.Size() == 0 {
		return
	}

	startT := time.Now()
	rawSlash := filepath.ToSlash(dailyRawFile)
	currentModel := getFWModelName()

	// 1. 動態偵測 RAW 檔案欄位，防止缺少欄位導致 Binder Error
	hasTypeCol := false
	hasThreatTypeCol := false
	if descRows, err := runDuckDBQuery(fmt.Sprintf("DESCRIBE SELECT * FROM read_parquet('%s');", rawSlash)); err == nil {
		for _, r := range descRows {
			colName := fmt.Sprintf("%v", r["column_name"])
			if colName == "Type" {
				hasTypeCol = true
			} else if colName == "Threat/Content Type" {
				hasThreatTypeCol = true
			}
		}
	}

	typeExpr := "'end'"
	if hasThreatTypeCol && hasTypeCol {
		typeExpr = `COALESCE(NULLIF(TRY_CAST("Threat/Content Type" AS VARCHAR), ''), TRY_CAST("Type" AS VARCHAR), 'end')`
	} else if hasThreatTypeCol {
		typeExpr = `COALESCE(NULLIF(TRY_CAST("Threat/Content Type" AS VARCHAR), ''), 'end')`
	} else if hasTypeCol {
		typeExpr = `COALESCE(NULLIF(TRY_CAST("Type" AS VARCHAR), ''), 'end')`
	}

	// 2. 確保目標日期子目錄存在：traffic_logs/YYYY-MM-DD/
	hotDayDir := filepath.Join(appDir, "traffic_logs", targetDate)
	_ = os.MkdirAll(hotDayDir, 0755)

	hotDailyFile := filepath.Join(hotDayDir, fmt.Sprintf("traffic_%s.parquet", targetDate))
	tmpMergeFile := fmt.Sprintf("%s.%d.tmp", hotDailyFile, time.Now().UnixNano())
	tempSpillDir := filepath.ToSlash(filepath.Join(appDir, "duckdb_temp"))
	_ = os.MkdirAll(filepath.Join(appDir, "duckdb_temp"), 0755)

	// 3. 收集現有熱資料檔案 (包含 traffic_logs/YYYY-MM-DD/ 內所有碎片與主檔，以及根目錄舊扁平檔)
	var existingHotFiles []string
	var legacyFlatFiles []string

	subParquets, _ := filepath.Glob(filepath.Join(hotDayDir, "*.parquet"))
	for _, f := range subParquets {
		base := filepath.Base(f)
		if strings.HasSuffix(base, ".tmp") || strings.HasPrefix(base, "patch_") {
			continue
		}
		if fi, err := os.Stat(f); err == nil && fi.Size() > 0 {
			existingHotFiles = append(existingHotFiles, filepath.ToSlash(f))
		}
	}

	flatParquets, _ := filepath.Glob(filepath.Join(appDir, "traffic_logs", fmt.Sprintf("traffic_%s*.parquet", targetDate)))
	for _, f := range flatParquets {
		base := filepath.Base(f)
		if strings.HasSuffix(base, ".tmp") {
			continue
		}
		if fi, err := os.Stat(f); err == nil && fi.Size() > 0 {
			existingHotFiles = append(existingHotFiles, filepath.ToSlash(f))
			legacyFlatFiles = append(legacyFlatFiles, f)
		}
	}

	// 4. 組合 RAW 萃取與現有熱資料庫 UNION ALL 去重 SQL
	rawSelectSQL := fmt.Sprintf(`
		SELECT
			REPLACE(REPLACE(COALESCE(TRY_CAST("Generate Time" AS VARCHAR), TRY_CAST("Receive Time" AS VARCHAR)), '/', '-'), '  ', ' ') AS timestamp,
			%s AS type,
			TRY_CAST("Source Zone" AS VARCHAR) AS from_zone,
			TRY_CAST("Destination Zone" AS VARCHAR) AS to_zone,
			TRY_CAST("Source address" AS VARCHAR) AS source,
			TRY_CAST("NAT Source IP" AS VARCHAR) AS nat_source_ip,
			TRY_CAST("Destination address" AS VARCHAR) AS destination,
			TRY_CAST("NAT Destination IP" AS VARCHAR) AS nat_dest_ip,
			TRY_CAST("Destination Port" AS INT) AS to_port,
			TRY_CAST("Application" AS VARCHAR) AS application,
			TRY_CAST("Action" AS VARCHAR) AS action,
			TRY_CAST("Rule" AS VARCHAR) AS rule,
			TRY_CAST("Session End Reason" AS VARCHAR) AS session_end_reason,
			TRY_CAST("Bytes" AS BIGINT) AS bytes,
			TRY_CAST("Session ID" AS VARCHAR) AS session_id
		FROM read_parquet('%s')
		WHERE REPLACE(COALESCE(TRY_CAST("Generate Time" AS VARCHAR), TRY_CAST("Receive Time" AS VARCHAR)), '/', '-') LIKE '%s%%'
	`, typeExpr, rawSlash, targetDate)

	var unionSourceSQL string
	if len(existingHotFiles) > 0 {
		quotedFiles := make([]string, len(existingHotFiles))
		for i, f := range existingHotFiles {
			quotedFiles[i] = fmt.Sprintf("'%s'", f)
		}
		existingSelectSQL := fmt.Sprintf(`
			SELECT
				TRY_CAST(timestamp AS VARCHAR) AS timestamp,
				TRY_CAST(type AS VARCHAR) AS type,
				TRY_CAST(from_zone AS VARCHAR) AS from_zone,
				TRY_CAST(to_zone AS VARCHAR) AS to_zone,
				TRY_CAST(source AS VARCHAR) AS source,
				TRY_CAST(nat_source_ip AS VARCHAR) AS nat_source_ip,
				TRY_CAST(destination AS VARCHAR) AS destination,
				TRY_CAST(nat_dest_ip AS VARCHAR) AS nat_dest_ip,
				TRY_CAST(to_port AS INT) AS to_port,
				TRY_CAST(application AS VARCHAR) AS application,
				TRY_CAST(action AS VARCHAR) AS action,
				TRY_CAST(rule AS VARCHAR) AS rule,
				TRY_CAST(session_end_reason AS VARCHAR) AS session_end_reason,
				TRY_CAST(bytes AS BIGINT) AS bytes,
				TRY_CAST(session_id AS VARCHAR) AS session_id
			FROM read_parquet([%s], union_by_name=true)
			WHERE TRY_CAST(timestamp AS VARCHAR) LIKE '%s%%'
		`, strings.Join(quotedFiles, ", "), targetDate)

		unionSourceSQL = fmt.Sprintf("(%s) UNION ALL (%s)", rawSelectSQL, existingSelectSQL)
	} else {
		unionSourceSQL = rawSelectSQL
	}

	mergeSQL := fmt.Sprintf(`
		SET max_memory='16GB'; SET threads=8; SET preserve_insertion_order=false; SET temp_directory='%s';
		COPY (
			SELECT * EXCLUDE (rn) FROM (
				SELECT *, ROW_NUMBER() OVER (
					PARTITION BY timestamp, source, destination, to_port, session_id, action, bytes
					ORDER BY timestamp DESC
				) AS rn
				FROM (%s)
			) WHERE rn = 1
			ORDER BY timestamp DESC
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, tempSpillDir, unionSourceSQL, filepath.ToSlash(tmpMergeFile))

	if _, err := runDuckDBQuery(mergeSQL); err != nil {
		_ = os.Remove(tmpMergeFile)
		fmt.Printf("❌ [PA-1420 雙軌反哺失敗] %s 熱資料萃取整合失敗: %v\n", targetDate, err)
		RecordAuditLog(AuditLogRecord{
			FWModel:     currentModel,
			LogType:     logType,
			Category:    "14欄熱資料",
			TargetDate:  targetDate,
			TargetSlot:  "全日",
			Status:      "FAILED",
			DurationSec: time.Since(startT).Seconds(),
			OutputFile:  filepath.Base(hotDailyFile),
			Details:     "PA-1420 全日熱資料萃取與去重整合失敗",
			ErrorReason: err.Error(),
			Operator:    "AUTO_SCHEDULER",
		})
		return
	}

	// 5. 原子替換為正式全日熱主檔
	_ = os.Remove(hotDailyFile)
	if err := os.Rename(tmpMergeFile, hotDailyFile); err != nil {
		_ = os.Remove(tmpMergeFile)
		fmt.Printf("❌ [PA-1420 雙軌反哺失敗] %s 熱主檔替換失敗: %v\n", targetDate, err)
		return
	}

	// 6. 徹底清除 traffic_logs/YYYY-MM-DD/ 下的所有零碎檔 (_live_, _chunk_, _rollup_, _nas_ 等)
	cleanedCount := 0
	allFilesInDayDir, _ := filepath.Glob(filepath.Join(hotDayDir, "*.parquet"))
	for _, f := range allFilesInDayDir {
		if filepath.Base(f) != filepath.Base(hotDailyFile) {
			if err := os.Remove(f); err == nil {
				cleanedCount++
			}
		}
	}
	for _, lf := range legacyFlatFiles {
		if err := os.Remove(lf); err == nil {
			cleanedCount++
		}
	}

	var finalMB float64
	if fi, err := os.Stat(hotDailyFile); err == nil {
		finalMB = float64(fi.Size()) / 1024 / 1024
	}
	totalRows := getParquetExactRowCount(hotDailyFile)

	durationSec := time.Since(startT).Seconds()
	fmt.Printf("🛡️ [PA-1420 全日熱資料整併完成] %s 已與現有熱庫去重融合 ➔ %s (共 %d 筆, %.1f MB, 清除 %d 個零碎檔, 耗時: %.1f 秒)\n",
		targetDate, filepath.Base(hotDailyFile), totalRows, finalMB, cleanedCount, durationSec)

	RecordAuditLog(AuditLogRecord{
		FWModel:     currentModel,
		LogType:     logType,
		Category:    "14欄熱資料",
		TargetDate:  targetDate,
		TargetSlot:  "全日",
		Status:      "SUCCESS",
		RecordCount: totalRows,
		FileSizeMB:  finalMB,
		DurationSec: durationSec,
		OutputFile:  filepath.Base(hotDailyFile),
		Details:     fmt.Sprintf("PA-1420 全日 RAW 萃取熱資料並與現有熱庫去重融合完成 (已清除 %d 個零碎檔)", cleanedCount),
		Operator:    "AUTO_SCHEDULER",
	})
}