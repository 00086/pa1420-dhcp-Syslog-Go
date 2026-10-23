package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"

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

	// 2. 自動掃描並整併所有零碎的 Parquet 檔案 (Traffic 與 Threat 雙引擎)
	go func() {
		// 流量日誌整併
		cleaned, retained, err := ConsolidateParquetFiles()
		if err == nil && cleaned > 0 {
			fmt.Printf("[流量資料整理] 🚀 啟動整併成功！已清理 %d 個碎片檔案，保留 %d 筆完整連線紀錄。\n", cleaned, retained)
		}

		// 🌟 威脅日誌整併
		tCleaned, tRetained, tErr := ConsolidateThreatParquetFiles()
		if tErr == nil && tCleaned > 0 {
			fmt.Printf("[威脅資料整理] 🛡️ 啟動整併成功！已清理 %d 個碎片檔案，保留 %d 筆完整威脅紀錄。\n", tCleaned, tRetained)
		}
	}()

	// 3. 初始化嵌入式樣板引擎
	initPongoTemplates()

	// 4. 測試 PA 連線並先行採樣健康狀態
	if _, _, _, _, err := getPAConfig(); err == nil {
		logSystemHealthJob()
	} else {
		fmt.Printf("[啟動提示] %v\n", err)
	}

	// 5. 設定背景定時排程器
	c := cron.New()
	_, _ = c.AddFunc("0 1,5,9,13,17,21 * * *", func() {
		fetchPADhcpJob("auto")
	})
	_, _ = c.AddFunc("@every 1m", func() {
		logSystemHealthJob()
	})
	c.Start()

	// 6. 啟動 Syslog 即時接收器 (UDP 514) 與批次 Parquet 寫入引擎
	go startSyslogReceiver(514)
	startSyslogBatchFlusher()

	// 7. 設定 Web 伺服器
	r := gin.Default()
	_ = r.SetTrustedProxies(nil)
	registerRoutes(r)

	fmt.Println("=========================================================")
	fmt.Println("🚀 PA-1420 智能監控聯防系統 (Go 原生高效版本) 已啟動！")
	fmt.Println("📡 Syslog 監聽服務：UDP 514 (即時串流接收)")
	fmt.Println("👉 服務監聽埠號：http://127.0.0.1:5006")
	fmt.Println("=========================================================")

	if err := r.Run(":5006"); err != nil {
		log.Fatalf("伺服器啟動異常：%v", err)
	}
}

