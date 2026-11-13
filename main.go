package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

//go:embed templates/*
var templateFS embed.FS
var pongoSet *pongo2.TemplateSet

func initPongoTemplates() {
	sub, err := fs.Sub(templateFS, "templates")
	if err != nil {
		log.Fatalf("無法載入 templates 虛擬目錄：%v", err)
	}
	loader := pongo2.NewFSLoader(sub)
	pongoSet = pongo2.NewSet("html", loader)
}

func main() {
	// 1. 初始化核心路徑與設定檔防呆
	initCore()
	ensurePAConfigTemplate()

	// ==========================================
	// 🌟 讀取 pa1420key.txt 取得 FTP 帳密 (第 6、7 行)
	// ==========================================
	ftpUser := "ftpuser" // 預設防呆值
	ftpPass := "ftppass"

	if content, err := os.ReadFile(paConfigFile); err == nil {
		var lines []string
		for _, l := range strings.Split(string(content), "\n") {
			trimmed := strings.TrimSpace(l)
			// 僅過濾明確帶說明的註解 (如 "# " 或 "# 第")，杜絕誤殺開頭帶 # 的真實密碼
			if trimmed != "" && !strings.HasPrefix(trimmed, "# ") && !strings.HasPrefix(trimmed, "# 第") {
				lines = append(lines, trimmed)
			}
		}
		if len(lines) >= 7 {
			ftpUser = strings.Trim(lines[5], "\"' \r\t")
			ftpPass = strings.Trim(lines[6], "\"' \r\t")
		}
	}

	// 跟隨當前執行檔所在目錄 (appDir/ftp_data)
	ftpDir := filepath.Join(appDir, "ftp_data")
	_ = os.MkdirAll(ftpDir, 0755)

	embeddedFTP := NewFTPServer(21, ftpDir, ftpUser, ftpPass)
	go func() {
		if err := embeddedFTP.Start(); err != nil {
			fmt.Printf("[內建 FTP] ⚠️ 啟動失敗 (請確認 Port 21 未被佔用): %v\n", err)
		} else {
			fmt.Printf("[內建 FTP] 📁 FTP 儲存目錄已就緒: %s (帳號: %s)\n", ftpDir, ftpUser)
		}
	}()
	// ==========================================

	// 2. 自動掃描並整併所有零碎的 Parquet 檔案
	go func() {
		cleaned, retained, err := ConsolidateParquetFiles()
		if err == nil && cleaned > 0 {
			fmt.Printf("[流量資料整理] 🚀 啟動整併成功！已清理 %d 個碎片，保留 %d 筆紀錄。\n", cleaned, retained)
		}

		tCleaned, tRetained, tErr := ConsolidateThreatParquetFiles()
		if tErr == nil && tCleaned > 0 {
			fmt.Printf("[威脅資料整理] 🛡️ 啟動整併成功！已清理 %d 個碎片，保留 %d 筆紀錄。\n", tCleaned, tRetained)
		}
	}()
	
	go func() {
		time.Sleep(3 * time.Second) // 等待核心初始化完成

		// 🌟 開機巡檢：檢查歷史目錄中是否有殘留的 _rollup_ 檔案，若有立即補跑整併
		files, _ := filepath.Glob(filepath.Join(trafficDir, "traffic_*_rollup_*.parquet"))
		pendingDates := make(map[string]bool)
		todayStr := time.Now().Format("2006-01-02")

		for _, f := range files {
			base := filepath.Base(f)
			parts := strings.Split(base, "_")
			if len(parts) >= 2 {
				datePart := parts[1]
				// 僅補跑「非當日」的過期碎片，當日的交由正常定時器運作
				if datePart < todayStr {
					pendingDates[datePart] = true
				}
			}
		}

		for d := range pendingDates {
			fmt.Printf("[啟動防護] 🔍 偵測到歷史未整併日期 %s，自動補跑整合作業...\n", d)
			_ = consolidateDailyTraffic(d)
		}
	}()

	// 3. 初始化樣板引擎
	initPongoTemplates()

	// 4. 健康狀態採樣
	if _, _, _, _, err := getPAConfig(); err == nil {
		logSystemHealthJob()
	}

	// 5. 排程器
	c := cron.New()
	_, _ = c.AddFunc("0 1,5,9,13,17,21 * * *", func() { fetchPADhcpJob("auto") })
	_, _ = c.AddFunc("@every 1m", func() { logSystemHealthJob() })
	c.Start()
	
	// 5-2. 啟動資安威脅自動分析巡檢引擎
	startFlowSecurityWorker()
	
	// 🌟 5-3. 啟動 CLI FTP 原始日誌自動封存排程 (PA-1420 全日 / PA-5250 每10分鐘切片與整併)
	StartAutoExportScheduler()

	// 6. Syslog 接收器
	go startSyslogReceiver(514)
	startSyslogBatchFlusher()

	// 7. Web 伺服器 (支援優雅退出)
	r := gin.Default()
	_ = r.SetTrustedProxies(nil)
	registerRoutes(r)

	fwTitle := getFWModelName()
	if fwTitle == "" {
		fwTitle = "Palo Alto"
	}

	fmt.Println("=========================================================")
	fmt.Printf("🚀 %s 智能監控聯防系統 (Go 原生高效版本) 已啟動！\n", fwTitle)
	fmt.Println("📡 Syslog 監聽服務：UDP 514 (即時串流接收)")
	fmt.Println("📁 內建 FTP 接收端：TCP 21 (日誌高速傾印)")
	fmt.Println("👉 服務監聽埠號：http://127.0.0.1:5006")
	fmt.Println("=========================================================")

	// 🌟 核心升級：以 http.Server 包裝並放入背景協程，主線程監聽系統信號
	srv := &http.Server{
		Addr:    ":5006",
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("伺服器啟動異常：%v\n", err)
		}
	}()

	// 🌟 核心升級：監聽作業系統中斷信號 (Ctrl+C / SIGINT 與 SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	fmt.Println("\n🛑 接收到關機訊號 (Ctrl+C / 終止命令)，正在安全收尾後台工作...")

	// 1. 停止定時排程器與內建 FTP 伺服器
	c.Stop()
	embeddedFTP.Stop()

	// 2. 平穩關閉 Web 伺服器 (給予 5 秒超時安全退出)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("⚠️ 關閉 Web 伺服器逾時或異常: %v\n", err)
	}

	// 3. 檢查當前是否有進行中的切片任務，確保連線平穩釋放
	taskMetaLock.Lock()
	runningTask := currentTaskName
	taskMetaLock.Unlock()

	if runningTask != "" {
		fmt.Printf("⏳ 正在等待進行中的任務 [%s] 完成收尾與釋放連線...\n", runningTask)
		time.Sleep(2 * time.Second)
	}

	fmt.Println("👋 系統已安全平穩退出！下次啟動時將自動進行切片對賬與補齊作業。")
}