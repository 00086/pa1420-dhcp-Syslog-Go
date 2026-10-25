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
	if req.LogType == "threat" {
		hotParquetPath = filepath.Join(threatDir, fmt.Sprintf("threat_%s.parquet", req.Date))
		coldParquetPath = filepath.Join(threatRawDir, fmt.Sprintf("threat_raw_%s.parquet", req.Date))
	} else {
		hotParquetPath = filepath.Join(trafficDir, fmt.Sprintf("traffic_%s.parquet", req.Date))
		coldParquetPath = filepath.Join(trafficRawDir, fmt.Sprintf("traffic_raw_%s.parquet", req.Date))
	}

	tmpHot := filepath.ToSlash(hotParquetPath + ".tmp")
	tmpCold := filepath.ToSlash(coldParquetPath + ".tmp")

	// 熱資料 SQL
	var hotQuery string
	if req.LogType == "threat" {
		hotQuery = fmt.Sprintf(`
			COPY (
				SELECT
					REPLACE(REPLACE("Generate Time", '/', '-'), ' ', ' ') AS timestamp,
					"Type" AS subtype,
					COALESCE("Threat/Content Name", "Threat/Content Type") AS threat_name,
					"Threat/Content Type" AS threat_id,
					"Source Zone" AS from_zone,
					"Destination Zone" AS to_zone,
					"Source address" AS src,
					"Destination address" AS dst,
					TRY_CAST("Destination Port" AS INT) AS to_port,
					"Application" AS application,
					"Action" AS action,
					"Severity" AS severity,
					"Misc" AS url,
					CAST("Session ID" AS VARCHAR) AS session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY "Generate Time", "Source address", "Destination address", "Threat/Content Type", "Action"
						ORDER BY "Generate Time" DESC
					) as rn
					FROM read_csv_auto('%s', header=true, all_varchar=true, ignore_errors=true)
					WHERE "Source address" IS NOT NULL AND "Source address" != ''
				) WHERE rn = 1 ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, csvPattern, tmpHot)
	} else {
		hotQuery = fmt.Sprintf(`
			COPY (
				SELECT
					REPLACE(REPLACE("Generate Time", '/', '-'), ' ', ' ') AS timestamp,
					"Type" AS type,
					"Source Zone" AS from_zone,
					"Destination Zone" AS to_zone,
					"Source address" AS source,
					"NAT Source IP" AS nat_source_ip,
					"Destination address" AS destination,
					"NAT Destination IP" AS nat_dest_ip,
					TRY_CAST("Destination Port" AS INT) AS to_port,
					"Application" AS application,
					"Action" AS action,
					"Rule" AS rule,
					"Session End Reason" AS session_end_reason,
					TRY_CAST("Bytes" AS BIGINT) AS bytes,
					CAST("Session ID" AS VARCHAR) AS session_id
				FROM (
					SELECT *, ROW_NUMBER() OVER (
						PARTITION BY "Generate Time", "Source address", "Destination address", "Destination Port", "Session ID"
						ORDER BY "Generate Time" DESC
					) as rn
					FROM read_csv_auto('%s', header=true, all_varchar=true, ignore_errors=true)
					WHERE "Source address" IS NOT NULL AND "Source address" != ''
				) WHERE rn = 1 ORDER BY timestamp DESC
			) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
		`, csvPattern, tmpHot)
	}

	// 冷資料 SQL
	coldQuery := fmt.Sprintf(`
		COPY (
			SELECT
				REPLACE(REPLACE(t."Generate Time", '/', '-'), ' ', ' ') AS timestamp,
				CAST(t."Session ID" AS VARCHAR) AS session_id,
				to_json(t) AS raw_content
			FROM read_csv_auto('%s', header=true, all_varchar=true, ignore_errors=true) AS t
			WHERE t."Source address" IS NOT NULL AND t."Source address" != ''
		) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD);
	`, csvPattern, tmpCold)

	// 熱資料落盤
	hotStart := time.Now()
	log("    ⚡ 正在產生熱資料 (多核心去重、強型別、ZSTD 壓縮)...")
	if _, err := runDuckDBQuery(hotQuery); err != nil {
		_ = os.Remove(tmpHot)
		return fmt.Errorf("熱資料轉換失敗: %w", err)
	}
	_ = os.Remove(hotParquetPath)
	_ = os.Rename(tmpHot, hotParquetPath)
	log(" 完成！(耗時: %.1f 秒)\n", time.Since(hotStart).Seconds())

	// 冷資料落盤
	coldStart := time.Now()
	log("    🧊 正在產生冷資料 (全欄位 JSON 封裝、原始證據保存)...")
	if _, err := runDuckDBQuery(coldQuery); err != nil {
		_ = os.Remove(tmpCold)
		return fmt.Errorf("冷資料轉換失敗: %w", err)
	}
	_ = os.Remove(coldParquetPath)
	_ = os.Rename(tmpCold, coldParquetPath)
	log(" 完成！(耗時: %.1f 秒)\n", time.Since(coldStart).Seconds())

	// 清理臨時 CSV
	log("[4/4 空間清理] 🧹 正在清理 %d 個臨時 CSV 檔案...", len(matches))
	for _, f := range matches {
		_ = os.Remove(f)
	}
	log(" 完成！\n")

	log("✨ 全部流程順利完成！總耗時: %s\n", time.Since(totalStart).Round(time.Second))
	return nil
}