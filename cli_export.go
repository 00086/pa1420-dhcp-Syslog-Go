package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type CLIExportRequest struct {
	Date        string `json:"date" form:"date"`
	PAAdmin     string `json:"pa_admin" form:"pa_admin"`
	PAPassword  string `json:"pa_pass" form:"pa_pass"`
	FTPHost     string `json:"ftp_host" form:"ftp_host"`
	FTPFolder   string `json:"ftp_folder" form:"ftp_folder"`
	LogType     string `json:"log_type" form:"log_type"`
	ConvertOnly bool   `json:"convert_only" form:"convert_only"`
	SkipCold    bool   `json:"skip_cold" form:"skip_cold"` // 🌟 新增：略過耗時的冷資料 JSON 轉檔
}

type StreamLogger func(format string, a ...any)

func performCLIExportAndConvert(req CLIExportRequest, log StreamLogger) error {
	totalStart := time.Now()

	// ==========================================
	// 階段 A：SSH 觸發 PA-1420 匯出
	// ==========================================
	if !req.ConvertOnly {
		fwIP, _, _, _, err := getPAConfig()
		if err != nil {
			return err
		}

		sshUser := req.PAAdmin
		sshPass := req.PAPassword

		// 優先自 pa1420key.txt 讀取帳密
		if content, err := os.ReadFile(paConfigFile); err == nil {
			var lines []string
			for _, l := range strings.Split(string(content), "\n") {
				trimmed := strings.TrimSpace(l)
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					lines = append(lines, trimmed)
				}
			}
			if len(lines) >= 5 {
				sshUser = lines[3]
				sshPass = lines[4]
			}
		}

		if sshUser == "" || sshPass == "" {
			return fmt.Errorf("未提供防火牆 SSH 帳密，且 pa1420key.txt 中未設定第 4、5 行")
		}

		log("[1/4 連線驗證] 🔄 正在連線至防火牆 %s:22 (帳號: %s)...\n", fwIP, sshUser)
		config := &ssh.ClientConfig{
			User:            sshUser,
			Auth:            []ssh.AuthMethod{ssh.Password(sshPass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		}

		client, err := ssh.Dial("tcp", fwIP+":22", config)
		if err != nil {
			return fmt.Errorf("SSH 連線失敗: %w", err)
		}
		defer client.Close()

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
			return fmt.Errorf("取得 Stdout 管道失敗: %w", err)
		}
		stdinPipe, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("取得 Stdin 管道失敗: %w", err)
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
					log("%s", chunk) // 🌟 關鍵：將 PA 的真實回應/報錯即時推到 CMD 視窗
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
			return fmt.Errorf("登入逾時: %w", err)
		}

		paDate := strings.ReplaceAll(req.Date, "-", "/")
		cmd := fmt.Sprintf("ftp export log %s start-time equal %s@00:00:00 end-time equal %s@23:59:59 to %s\n",
			req.LogType, paDate, paDate, req.FTPHost)

		log("[2/4 串流傳輸] 🚀 已發送匯出指令，啟動即時傳輸監控...\n")
		if _, err := stdinPipe.Write([]byte(cmd)); err != nil {
			return fmt.Errorf("發送指令失敗: %w", err)
		}

		// 🌟 每 1 秒即時計算資料夾檔案數與大小，推送到 CMD
		stopTicker := make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			startTime := time.Now()
			for {
				select {
				case <-ticker.C:
					csvs, _ := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv"))
					var totalBytes int64
					for _, f := range csvs {
						if fi, err := os.Stat(f); err == nil {
							totalBytes += fi.Size()
						}
					}
					elapsed := int(time.Since(startTime).Seconds())
					mb := float64(totalBytes) / 1024 / 1024
					log("    ⏱️ [%02d秒] FTP 接收中: 已生成 %d 個 CSV 檔案 (累計 %.1f MB)...\n", elapsed, len(csvs), mb)
				case <-stopTicker:
					return
				}
			}
		}()

		// 等待防火牆完成傳輸並回到提示字元
		_ = waitForPrompt(">", 10*time.Minute)
		close(stopTicker)

		_, _ = stdinPipe.Write([]byte("exit\n"))
		_ = stdinPipe.Close()
		_ = session.Wait()

		log("[2/4 串流傳輸] ✅ 防火牆資料推送完成！\n")
	}

	// ==========================================
	// 階段 B：DuckDB 冷熱湖倉轉換
	// ==========================================
	matches, err := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv"))
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("在目錄 %s 下未找到任何 CSV 檔案，請確認 FTP 接收狀況", req.FTPFolder)
	}

	log("[3/4 湖倉轉換] 📁 偵測到 %d 個分塊 CSV 檔案，啟動 DuckDB 向量化引擎...\n", len(matches))

	csvPattern := filepath.ToSlash(filepath.Join(req.FTPFolder, "*.csv"))
	var hotParquetPath, coldParquetPath string
	// 🌟 關鍵修正：加上 UnixNano 隨機後綴，確保不覆寫現有主檔，改由事後整合器合併
	safeSuffix := fmt.Sprintf("_nas_%d.parquet", time.Now().UnixNano())
	
	if req.LogType == "threat" {
		hotParquetPath = filepath.Join(threatDir, fmt.Sprintf("threat_%s%s", req.Date, safeSuffix))
		coldParquetPath = filepath.Join(threatRawDir, fmt.Sprintf("threat_raw_%s%s", req.Date, safeSuffix))
	} else {
		hotParquetPath = filepath.Join(trafficDir, fmt.Sprintf("traffic_%s%s", req.Date, safeSuffix))
		coldParquetPath = filepath.Join(trafficRawDir, fmt.Sprintf("traffic_raw_%s%s", req.Date, safeSuffix))
	}

	tmpHot := filepath.ToSlash(hotParquetPath + ".tmp")
	tmpCold := filepath.ToSlash(coldParquetPath + ".tmp")

	txtPattern := filepath.ToSlash(filepath.Join(req.FTPFolder, "*.txt"))
	// 若相容原本的 csv 命名，亦可使用:
	if matches, _ := filepath.Glob(filepath.Join(req.FTPFolder, "*.csv")); len(matches) > 0 {
		txtPattern = filepath.ToSlash(filepath.Join(req.FTPFolder, "*.csv"))
	}

	// 🌟 熱資料 SQL：徹底拋棄 read_csv_auto，改採與批次檔 100% 一致的強健 split_part
	var hotQuery string
	if req.LogType == "threat" {
		hotQuery = fmt.Sprintf(`
			COPY (
				SELECT
					REPLACE(REPLACE(split_part(line, ',', 7), '/', '-'), ' ', ' ') AS timestamp,
					split_part(line, ',', 5) AS subtype,
					COALESCE(NULLIF(split_part(line, ',', 33), ''), split_part(line, ',', 5)) AS threat_name,
					split_part(line, ',', 5) AS threat_id,
					split_part(line, ',', 17) AS from_zone,
					split_part(line, ',', 18) AS to_zone,
					split_part(line, ',', 8) AS src,
					split_part(line, ',', 9) AS dst,
					TRY_CAST(split_part(line, ',', 26) AS INT) AS to_port,
					split_part(line, ',', 15) AS application,
					split_part(line, ',', 31) AS action,
					split_part(line, ',', 35) AS severity,
					split_part(line, ',', 32) AS url,
					split_part(line, ',', 23) AS session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY split_part(line, ',', 7), split_part(line, ',', 8), split_part(line, ',', 9), split_part(line, ',', 23)
						ORDER BY split_part(line, ',', 7) DESC
					) as rn
					FROM read_csv('%s', header=false, columns={'line': 'VARCHAR'}, quote='', escape='', auto_detect=false, delim=E'\x1f', strict_mode=false)
					WHERE line LIKE '%%,THREAT,%%'
				) WHERE rn = 1 ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, txtPattern, tmpHot)
	} else {
		hotQuery = fmt.Sprintf(`
			COPY (
				SELECT
					REPLACE(REPLACE(split_part(line, ',', 7), '/', '-'), ' ', ' ') AS timestamp,
					split_part(line, ',', 5) AS type,
					split_part(line, ',', 17) AS from_zone,
					split_part(line, ',', 18) AS to_zone,
					split_part(line, ',', 8) AS source,
					split_part(line, ',', 10) AS nat_source_ip,
					split_part(line, ',', 9) AS destination,
					split_part(line, ',', 11) AS nat_dest_ip,
					TRY_CAST(split_part(line, ',', 26) AS INT) AS to_port,
					split_part(line, ',', 15) AS application,
					split_part(line, ',', 31) AS action,
					split_part(line, ',', 12) AS rule,
					split_part(line, ',', 47) AS session_end_reason,
					TRY_CAST(split_part(line, ',', 32) AS BIGINT) AS bytes,
					split_part(line, ',', 23) AS session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY split_part(line, ',', 7), split_part(line, ',', 8), split_part(line, ',', 9), split_part(line, ',', 23)
						ORDER BY split_part(line, ',', 7) DESC
					) as rn
					FROM read_csv('%s', header=false, columns={'line': 'VARCHAR'}, quote='', escape='', auto_detect=false, delim=E'\x1f', strict_mode=false)
					WHERE line LIKE '%%,TRAFFIC,%%'
				) WHERE rn = 1 ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, txtPattern, tmpHot)
	}

	// 熱資料落盤 (去重、強型別、ZSTD 列式壓縮)
	hotStart := time.Now()
	log("    ⚡ 正在產生熱資料 (多核心去重、強型別、ZSTD 壓縮)...")
	if _, err := runDuckDBQuery(hotQuery); err != nil {
		_ = os.Remove(tmpHot)
		return fmt.Errorf("熱資料轉換失敗: %w", err)
	}
	_ = os.Remove(hotParquetPath)
	_ = os.Rename(tmpHot, hotParquetPath)
	log(" 完成！(耗時: %.1f 秒)\n", time.Since(hotStart).Seconds())

	// 🌟 冷資料落盤：以極速原始行提取 (保留完整 117 欄與去重)，不拼裝 JSON，2 秒內完成！
	if !req.SkipCold {
		coldQuery := fmt.Sprintf(`
			COPY (
				SELECT timestamp, session_id, raw_content FROM (
					SELECT
						REPLACE(REPLACE(split_part(line, ',', 7), '/', '-'), ' ', ' ') AS timestamp,
						CAST(split_part(line, ',', 23) AS VARCHAR) AS session_id,
						line AS raw_content,
						ROW_NUMBER() OVER (PARTITION BY split_part(line, ',', 7), split_part(line, ',', 23)) as rn
					FROM read_csv('%s', header=false, columns={'line': 'VARCHAR'}, quote='', escape='')
					WHERE line NOT LIKE 'Domain,%%' AND line != ''
				) WHERE rn = 1 ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, csvPattern, tmpCold)

		coldStart := time.Now()
		log("    🧊 正在產生冷資料 (保留原始封包、視窗去重、ZSTD 壓縮)...")
		if _, err := runDuckDBQuery(coldQuery); err != nil {
			_ = os.Remove(tmpCold)
			return fmt.Errorf("冷資料轉換失敗: %w", err)
		}
		_ = os.Remove(coldParquetPath)
		_ = os.Rename(tmpCold, coldParquetPath)
		log(" 完成！(耗時: %.1f 秒)\n", time.Since(coldStart).Seconds())
	} else {
		log("    ⚡ 已跳過冷資料產出。\n")
	}

	// 清理臨時 CSV
	// 🌟 清理臨時 CSV 並一併移除當日空資料夾
	log("[4/4 空間清理] 🧹 正在清理臨時 CSV 檔案與目錄...")
	for _, f := range matches {
		_ = os.Remove(f)
	}
	// 移除該日期的暫存資料夾 (若資料夾內 CSV 都已清空，可直接移除)
	_ = os.Remove(req.FTPFolder)
	log(" 清理完成！(已移除 %s)\n", filepath.Base(req.FTPFolder))

	// 🌟 核心新增：轉檔完成後，立刻啟動 DuckDB 去重整併 (將歷史舊檔與新分塊無縫去重合併)
	log("[5/5 資料整併] 🔄 正在由 DuckDB 自動執行去重整併...\n")
	if req.LogType == "threat" {
		ConsolidateThreatParquetFiles()
		ConsolidateRawParquetFiles("threat")
	} else {
		ConsolidateParquetFiles()
		ConsolidateRawParquetFiles("traffic")
	}
	log("✅ 去重整併完成，已清除碎片！\n")

	log("🎉 全部流程順利完成！總耗時: %s\n", time.Since(totalStart).Round(time.Second))
	return nil
}