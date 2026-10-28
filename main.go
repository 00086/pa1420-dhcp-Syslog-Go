package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"

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
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				lines = append(lines, trimmed)
			}
		}
		if len(lines) >= 7 {
			ftpUser = lines[5] // 索引 5 代表第 6 行
			ftpPass = lines[6] // 索引 6 代表第 7 行
		}
	}

	// 🌟 啟動 Go 內建輕量 FTP 接收服務 (接管 Port 21)
	ftpDir := `C:\python\dhcpxml-go\ftp_data`
	embeddedFTP := NewFTPServer(21, ftpDir, ftpUser, ftpPass)
	go func() {
		if err := embeddedFTP.Start(); err != nil {
			fmt.Printf("[內建 FTP] ⚠️ 啟動失敗 (請確認 Port 21 未被佔用): %v\n", err)
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

	// 6. Syslog 接收器
	go startSyslogReceiver(514)
	startSyslogBatchFlusher()

	// 7. Web 伺服器
	r := gin.Default()
	_ = r.SetTrustedProxies(nil)
	registerRoutes(r)

	fmt.Println("=========================================================")
	fmt.Println("🚀 PA-1420 智能監控聯防系統 (Go 原生高效版本) 已啟動！")
	fmt.Println("📡 Syslog 監聽服務：UDP 514 (即時串流接收)")
	fmt.Println("📁 內建 FTP 接收端：TCP 21 (日誌高速傾印)")
	fmt.Println("👉 服務監聽埠號：http://127.0.0.1:5006")
	fmt.Println("=========================================================")

	if err := r.Run(":5006"); err != nil {
		log.Fatalf("伺服器啟動異常：%v", err)
	}
}