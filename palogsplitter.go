package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GlobalProgress 全域即時進度追蹤
type GlobalProgress struct {
	sync.RWMutex
	IsRunning   bool             `json:"is_running"`
	CurrentFile string           `json:"current_file"`
	FileIndex   int              `json:"file_index"`
	TotalFiles  int              `json:"total_files"`
	FileLines   int64            `json:"file_lines"`
	FileValids  int64            `json:"file_valids"`
	TotalLines  int64            `json:"total_lines"`
	ValidLines  int64            `json:"valid_lines"`
	StartTime   time.Time        `json:"-"`
	ElapsedSec  int              `json:"elapsed_sec"`
	FileStats   map[string]int64 `json:"file_stats"`
	RecentLogs  []string         `json:"recent_logs"`
}

var progress GlobalProgress

func (p *GlobalProgress) addLog(msg string) {
	p.Lock()
	defer p.Unlock()
	p.RecentLogs = append(p.RecentLogs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(p.RecentLogs) > 80 {
		p.RecentLogs = p.RecentLogs[len(p.RecentLogs)-80:]
	}
}

// ---------------------------------------------------------
// 🌐 內建前端 HTML (左右雙欄固定視窗，整合自動時間排序)
// ---------------------------------------------------------
const indexHTML = `
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PA 日誌自動分類整合系統</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        html, body {
            height: 100vh;
            margin: 0;
            padding: 0;
            overflow: hidden !important;
            background-color: #f0f2f5;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .app-container {
            height: 100vh;
            display: flex;
            flex-direction: column;
            padding: 12px 16px;
        }
        .main-card {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            border-radius: 8px;
        }
        .content-body {
            flex: 1;
            overflow: hidden;
            padding: 16px;
        }
        .queue-scroll-container {
            flex: 1;
            overflow-y: auto;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            background: #fff;
        }
        .console-log {
            background-color: #1a1a1a;
            color: #4af626;
            font-family: Consolas, "Courier New", monospace;
            font-size: 12.5px;
            flex: 1;
            overflow-y: auto;
            border-radius: 6px;
            padding: 10px 14px;
            white-space: pre-wrap;
            line-height: 1.45;
        }
        .upload-dropzone {
            border: 2px dashed #0d6efd;
            border-radius: 6px;
            padding: 10px 14px;
            text-align: center;
            background-color: #f1f6fe;
        }
    </style>
</head>
<body>

<div class="app-container">
    <div class="card shadow-sm border-0 main-card bg-white">
        <!-- 頂端固定的導覽標題列 -->
        <div class="card-header bg-primary text-white py-2 px-3 d-flex justify-content-between align-items-center flex-shrink-0">
            <div class="d-flex align-items-center gap-2">
                <i class="bi bi-hdd-network-fill fs-5"></i>
                <span class="fw-bold fs-6">Palo Alto (Synology) 歷史日誌自動分類器</span>
            </div>
            <span class="badge bg-light text-primary font-monospace">自動分類 + DuckDB 時間排序版</span>
        </div>

        <!-- 核心工作區：左右兩欄 -->
        <div class="card-body content-body">
            <div class="row h-100 g-3">
                
                <!-- 👈 左欄：檔案上傳選取 + 31 檔獨立滾動清單 + 啟動按鈕 -->
                <div class="col-lg-5 col-md-6 h-100 d-flex flex-column">
                    <div class="upload-dropzone mb-2 flex-shrink-0">
                        <label class="form-label small fw-bold text-primary mb-1 d-flex align-items-center justify-content-center gap-1">
                            <i class="bi bi-cloud-arrow-up-fill"></i> 選擇 Synology 匯出之 Syslog 檔案
                        </label>
                        <input class="form-control form-control-sm" type="file" id="logFiles" accept=".txt,.log,.csv" multiple required>
                        <div class="d-flex justify-content-between align-items-center mt-1">
                            <small class="text-muted" style="font-size: 11px;">支援按住 Ctrl / Shift 複選整批檔案</small>
                            <span class="badge bg-secondary font-monospace" id="queueTotalBadge" style="font-size: 11px;">未選取檔案</span>
                        </div>
                    </div>

                    <!-- 獨立滾動的檔案清單 -->
                    <div class="d-flex justify-content-between align-items-center mb-1 flex-shrink-0">
                        <span class="fw-bold small text-dark"><i class="bi bi-list-check me-1"></i>待處理檔案佇列</span>
                        <span class="text-muted font-monospace small" id="queueStatus">等待選取</span>
                    </div>
                    <div class="queue-scroll-container mb-2" id="queueScrollBox">
                        <ul class="list-group list-group-flush small font-monospace" id="queueList">
                            <li class="list-group-item text-center text-muted py-5">
                                <i class="bi bi-inbox fs-2 d-block mb-2 text-secondary"></i>
                                請先點擊上方選取日誌檔案
                            </li>
                        </ul>
                    </div>

                    <!-- 自動排序選項與啟動按鈕 -->
                    <div class="d-flex align-items-center mb-2 px-1 flex-shrink-0">
                        <div class="form-check form-switch small">
                            <input class="form-check-input" type="checkbox" id="autoSortCheck" checked>
                            <label class="form-check-label fw-bold text-dark" for="autoSortCheck">
                                <i class="bi bi-sort-numeric-down text-primary me-1"></i>分類後自動依時間排序 (DuckDB 外部排序)
                            </label>
                        </div>
                    </div>
                    <div class="d-grid flex-shrink-0">
                        <button type="button" class="btn btn-primary fw-bold py-2 shadow-sm" id="startBtn" disabled onclick="startProcessingQueue()">
                            <i class="bi bi-play-circle-fill me-1"></i>開始依日期分類寫入與排序
                        </button>
                    </div>
                </div>

                <!-- 👉 右欄：進度條 + 三大指標 + 獨立黑底終端機日誌 -->
                <div class="col-lg-7 col-md-6 h-100 d-flex flex-column">
                    <!-- 進度狀態標題 -->
                    <div class="d-flex justify-content-between align-items-center mb-1 flex-shrink-0">
                        <span class="fw-bold text-dark small" id="statusText">
                            <i class="bi bi-info-circle text-primary me-1"></i>系統待命中
                        </span>
                        <span class="text-muted font-monospace small" id="timerBadge">耗時: 0s</span>
                    </div>

                    <!-- 進度條 -->
                    <div class="progress mb-2 flex-shrink-0" style="height: 14px;">
                        <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary" id="progressBar" role="progressbar" style="width: 0%;">0%</div>
                    </div>

                    <!-- 三大指標小卡 -->
                    <div class="row g-2 mb-2 flex-shrink-0 text-center">
                        <div class="col-4">
                            <div class="p-2 bg-light border rounded">
                                <small class="text-muted d-block" style="font-size: 11px;">整體檔案進度</small>
                                <span class="fw-bold font-monospace text-primary fs-6" id="overallFileProgress">0 / 0</span>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="p-2 bg-light border rounded">
                                <small class="text-muted d-block" style="font-size: 11px;">全域累積行數</small>
                                <span class="fw-bold font-monospace text-dark fs-6" id="overallTotalLines">0 行</span>
                            </div>
                        </div>
                        <div class="col-4">
                            <div class="p-2 bg-light border rounded">
                                <small class="text-muted d-block" style="font-size: 11px;">全域有效歸檔</small>
                                <span class="fw-bold font-monospace text-success fs-6" id="overallValidLines">0 筆</span>
                            </div>
                        </div>
                    </div>

                    <!-- 終端機即時訊息 (填滿剩餘高度) -->
                    <div class="d-flex justify-content-between align-items-center mb-1 flex-shrink-0">
                        <label class="form-label small text-secondary fw-bold mb-0">
                            <i class="bi bi-terminal-fill me-1"></i>執行即時監控日誌
                        </label>
                        <small class="text-muted font-monospace" style="font-size: 11px;">自動滾動</small>
                    </div>
                    <div class="console-log mb-2" id="consoleBox">系統就緒，請選取檔案後點擊開始...</div>

                    <!-- 完成結算小卡 -->
                    <div id="summaryCard" class="alert alert-success py-2 px-3 mb-0 d-none flex-shrink-0" role="alert">
                        <div class="d-flex align-items-center justify-content-between">
                            <div>
                                <i class="bi bi-check-circle-fill me-2 fs-6"></i>
                                <strong class="small" id="summaryTitle">分類與排序全數圓滿完成！</strong>
                                <span class="small ms-2" id="summaryTime"></span>
                            </div>
                            <span class="badge bg-success font-monospace" id="summaryFileCount"></span>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>

<script>
let selectedFiles = [];
let pollInterval = null;
let globalTotalLines = 0;
let globalValidLines = 0;
let aggregatedDates = {};
let overallStartTime = 0;

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

document.getElementById('logFiles').addEventListener('change', function(e) {
    selectedFiles = Array.from(e.target.files);
    const queueList = document.getElementById('queueList');
    const startBtn = document.getElementById('startBtn');
    
    if (selectedFiles.length === 0) {
        queueList.innerHTML = '<li class="list-group-item text-center text-muted py-5">請先點擊上方選取日誌檔案</li>';
        document.getElementById('queueTotalBadge').innerText = '未選取檔案';
        document.getElementById('queueStatus').innerText = '等待選取';
        startBtn.disabled = true;
        return;
    }

    queueList.innerHTML = '';
    let totalBytes = 0;

    selectedFiles.forEach((file, index) => {
        totalBytes += file.size;
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center py-2 px-2';
        li.id = 'file-row-' + index;
        li.innerHTML = '<div class="text-truncate me-2" style="max-width: 72%;">' +
                       '<span class="badge bg-light text-dark border me-1">#' + (index + 1) + '</span>' +
                       '<span class="fw-bold">' + file.name + '</span>' +
                       '<span class="text-muted ms-1 small">(' + formatBytes(file.size) + ')</span>' +
                       '</div>' +
                       '<span class="badge bg-secondary flex-shrink-0" id="badge-file-' + index + '">等待處理 ⏳</span>';
        queueList.appendChild(li);
    });

    document.getElementById('queueTotalBadge').innerText = '共 ' + selectedFiles.length + ' 檔 (' + formatBytes(totalBytes) + ')';
    document.getElementById('queueStatus').innerText = '待命中';
    startBtn.disabled = false;
});

async function startProcessingQueue() {
    if (selectedFiles.length === 0) return;

    document.getElementById('startBtn').disabled = true;
    document.getElementById('logFiles').disabled = true;
    document.getElementById('summaryCard').classList.add('d-none');

    globalTotalLines = 0;
    globalValidLines = 0;
    aggregatedDates = {};
    overallStartTime = Date.now();

    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(fetchProgress, 500);

    const totalCount = selectedFiles.length;
    const scrollBox = document.getElementById('queueScrollBox');

    // 1. 循序串流分類各個檔案
    for (let i = 0; i < totalCount; i++) {
        const file = selectedFiles[i];
        const row = document.getElementById('file-row-' + i);
        const badge = document.getElementById('badge-file-' + i);

        row.className = 'list-group-item list-group-item-primary d-flex justify-content-between align-items-center py-2 px-2';
        badge.className = 'badge bg-primary flex-shrink-0';
        badge.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>分類寫入中...';

        if (row && scrollBox) {
            scrollBox.scrollTop = row.offsetTop - scrollBox.offsetTop;
        }

        document.getElementById('overallFileProgress').innerText = (i + 1) + ' / ' + totalCount;
        const percent = Math.round(((i + 1) / (totalCount + 1)) * 100);
        document.getElementById('progressBar').style.width = percent + '%';
        document.getElementById('progressBar').innerText = percent + '%';

        const formData = new FormData();
        formData.append('file', file);
        formData.append('file_index', i + 1);
        formData.append('total_files', totalCount);

        try {
            const resp = await fetch('/api/process-single', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();

            if (data.status === 'success') {
                row.className = 'list-group-item list-group-item-light d-flex justify-content-between align-items-center py-2 px-2';
                badge.className = 'badge bg-success flex-shrink-0';
                badge.innerHTML = '<i class="bi bi-check-lg me-1"></i>完成 (' + data.file_valids.toLocaleString() + ' 筆)';

                globalTotalLines += data.file_lines;
                globalValidLines += data.file_valids;

                for (const [d, c] of Object.entries(data.dates || {})) {
                    aggregatedDates[d] = (aggregatedDates[d] || 0) + c;
                }
            } else {
                row.className = 'list-group-item list-group-item-danger d-flex justify-content-between align-items-center py-2 px-2';
                badge.className = 'badge bg-danger flex-shrink-0';
                badge.innerText = '失敗: ' + data.message;
            }
        } catch (err) {
            row.className = 'list-group-item list-group-item-danger d-flex justify-content-between align-items-center py-2 px-2';
            badge.className = 'badge bg-danger flex-shrink-0';
            badge.innerText = '傳輸異常';
        }
    }

    // 2. 若勾選自動排序，則呼叫後端 DuckDB 排序引擎
    const needSort = document.getElementById('autoSortCheck').checked;
    const dateKeys = Object.keys(aggregatedDates);

    if (needSort && dateKeys.length > 0) {
        document.getElementById('statusText').innerHTML = '<span class="spinner-grow spinner-grow-sm text-warning me-2"></span>正在執行 DuckDB 時間外部排序...';
        document.getElementById('progressBar').className = 'progress-bar progress-bar-striped progress-bar-animated bg-warning';
        document.getElementById('progressBar').innerText = 'DuckDB 時間排序中...';

        try {
            await fetch('/api/sort-all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dates: dateKeys })
            });
        } catch (e) {}
    }

    clearInterval(pollInterval);
    fetchProgress();

    // 3. 全部完成狀態呈現
    document.getElementById('progressBar').style.width = '100%';
    document.getElementById('progressBar').className = 'progress-bar bg-success';
    document.getElementById('progressBar').innerText = '100% 全部完成';
    document.getElementById('statusText').innerHTML = '<i class="bi bi-check-circle-fill text-success me-1"></i>全數分類與排序完成！';
    document.getElementById('overallTotalLines').innerText = globalTotalLines.toLocaleString() + ' 行';
    document.getElementById('overallValidLines').innerText = globalValidLines.toLocaleString() + ' 筆';

    const costSec = Math.round((Date.now() - overallStartTime) / 1000);
    const dateCount = dateKeys.length;
    document.getElementById('summaryCard').classList.remove('d-none');
    document.getElementById('summaryTime').innerText = '共 ' + totalCount + ' 個檔案，總掃描 ' + globalTotalLines.toLocaleString() + ' 行 (有效 ' + globalValidLines.toLocaleString() + ' 筆)，耗時 ' + costSec + ' 秒';
    document.getElementById('summaryFileCount').innerText = '已排序產出 ' + dateCount + ' 個日期檔 (./output/)';

    document.getElementById('startBtn').disabled = false;
    document.getElementById('logFiles').disabled = false;
}

function fetchProgress() {
    fetch('/api/progress?_t=' + Date.now())
        .then(res => res.json())
        .then(p => {
            if (!p) return;
            const currentTotal = globalTotalLines + (p.file_lines || 0);
            const currentValid = globalValidLines + (p.file_valids || 0);
            document.getElementById('overallTotalLines').innerText = currentTotal.toLocaleString() + ' 行';
            document.getElementById('overallValidLines').innerText = currentValid.toLocaleString() + ' 筆';

            if (overallStartTime > 0) {
                const sec = Math.round((Date.now() - overallStartTime) / 1000);
                document.getElementById('timerBadge').innerText = '耗時: ' + sec + 's';
            }

            if (p.recent_logs && p.recent_logs.length > 0) {
                const consoleBox = document.getElementById('consoleBox');
                consoleBox.innerText = p.recent_logs.join('\n');
                consoleBox.scrollTop = consoleBox.scrollHeight;
            }
        })
        .catch(() => {});
}
</script>
</body>
</html>
`

// ---------------------------------------------------------
// 🚀 後端 HTTP 服務與單檔串流處理
// ---------------------------------------------------------
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})

	http.HandleFunc("/api/progress", handleGetProgress)
	http.HandleFunc("/api/process-single", handleProcessSingleFile)
	http.HandleFunc("/api/sort-all", handleSortAll)

	port := ":8080"
	fmt.Println("========================================================")
	fmt.Println("🚀 PA 日誌自動分類 Web 服務 (自動 DuckDB 排序版) 已啟動！")
	fmt.Printf("👉 請開啟瀏覽器訪問: http://localhost%s\n", port)
	fmt.Println("========================================================")

	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Printf("❌ 啟動伺服器失敗: %v\n", err)
	}
}

func handleGetProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	progress.RLock()
	defer progress.RUnlock()
	_ = json.NewEncoder(w).Encode(progress)
}

func handleProcessSingleFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(256 << 20)
	if err != nil {
		sendJSON(w, false, "解析檔案失敗: "+err.Error(), nil)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		sendJSON(w, false, "未收到檔案內容: "+err.Error(), nil)
		return
	}
	defer file.Close()

	outDir := "./output"
	_ = os.MkdirAll(outDir, 0755)

	var fileIdx, totalFiles int
	fmt.Sscanf(r.FormValue("file_index"), "%d", &fileIdx)
	fmt.Sscanf(r.FormValue("total_files"), "%d", &totalFiles)

	progress.Lock()
	progress.IsRunning = true
	progress.CurrentFile = header.Filename
	progress.FileIndex = fileIdx
	progress.TotalFiles = totalFiles
	progress.FileLines = 0
	progress.FileValids = 0
	progress.Unlock()
	progress.addLog(fmt.Sprintf("📖 [%d/%d] 開始串流解析: %s", fileIdx, totalFiles, header.Filename))

	type DayTarget struct {
		file   *os.File
		writer *bufio.Writer
		count  int64
	}

	writers := make(map[string]*DayTarget)
	defer func() {
		for _, dt := range writers {
			_ = dt.writer.Flush()
			_ = dt.file.Close()
		}
	}()

	var fileLines int64 = 0
	var fileValids int64 = 0
	dateStats := make(map[string]int64)

	reader := bufio.NewReaderSize(file, 4*1024*1024)

	for {
		lineBytes, err := reader.ReadBytes('\n')
		if len(lineBytes) > 0 {
			fileLines++
			lineStr := string(lineBytes)

			dateKey := extractLogDate(lineStr)
			if dateKey != "" {
				fileValids++

				dt, exists := writers[dateKey]
				if !exists {
					outFilePath := filepath.Join(outDir, fmt.Sprintf("%s.txt", dateKey))
					outFile, fileErr := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
					if fileErr == nil {
						dt = &DayTarget{
							file:   outFile,
							writer: bufio.NewWriterSize(outFile, 2*1024*1024),
							count:  0,
						}
						writers[dateKey] = dt
						progress.addLog(fmt.Sprintf("  📅 命中日期 [%s] -> 寫入 %s.txt", dateKey, dateKey))
					}
				}

				if dt != nil {
					dt.writer.WriteString(lineStr)
					dt.count++
					dateStats[dateKey]++
				}
			}

			if fileLines%100000 == 0 {
				progress.Lock()
				progress.FileLines = fileLines
				progress.FileValids = fileValids
				progress.Unlock()
			}
		}

		if err != nil {
			if err != io.EOF {
				progress.addLog(fmt.Sprintf("⚠️ 讀取中斷: %v", err))
			}
			break
		}
	}

	progress.Lock()
	progress.FileLines = fileLines
	progress.FileValids = fileValids
	progress.Unlock()
	progress.addLog(fmt.Sprintf("✅ [%d/%d] %s 分類寫入完成！共 %d 行 (有效 %d 筆)", fileIdx, totalFiles, header.Filename, fileLines, fileValids))

	result := map[string]interface{}{
		"file_lines":  fileLines,
		"file_valids": fileValids,
		"dates":       dateStats,
	}
	sendJSON(w, true, "單檔完成", result)
}

// ---------------------------------------------------------
// ⚡ 自動時間排序處理函式 (DuckDB 外部向量化排序)
// ---------------------------------------------------------
type SortAllRequest struct {
	Dates []string `json:"dates"`
}

func handleSortAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SortAllRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	outDir := "./output"
	datesToSort := req.Dates

	// 若未傳入指定日期，則掃描 output 目錄下所有 txt
	if len(datesToSort) == 0 {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.txt"))
		for _, m := range matches {
			base := filepath.Base(m)
			datesToSort = append(datesToSort, strings.TrimSuffix(base, ".txt"))
		}
	}

	if len(datesToSort) == 0 {
		sendJSON(w, true, "無檔案需排序", nil)
		return
	}

	progress.addLog(fmt.Sprintf("🚀 開始對產出的 %d 個日期檔案進行 DuckDB 原生事件時間排序...", len(datesToSort)))

	duckdbBin := "duckdb.exe"
	if _, err := os.Stat("duckdb.exe"); err == nil {
		duckdbBin = ".\\duckdb.exe"
	}

	for idx, dateKey := range datesToSort {
		rawPath := filepath.Join(outDir, fmt.Sprintf("%s.txt", dateKey))
		tmpPath := filepath.Join(outDir, fmt.Sprintf("%s_sort.tmp", dateKey))

		if _, err := os.Stat(rawPath); os.IsNotExist(err) {
			continue
		}

		progress.addLog(fmt.Sprintf("⏳ [%d/%d] 正在排序 %s.txt (DuckDB 向量化引擎)...", idx+1, len(datesToSort), dateKey))

		sqlRaw := filepath.ToSlash(rawPath)
		sqlTmp := filepath.ToSlash(tmpPath)

		// 關閉 enable_progress_bar 避免控制台亂碼，並依據 Generate Time 排序
		sql := fmt.Sprintf(
			"SET enable_progress_bar = false; COPY (SELECT line FROM read_csv('%s', header=false, columns={'line': 'VARCHAR'}, quote='', escape='', auto_detect=false, delim=E'\\x1f', strict_mode=false) ORDER BY CASE WHEN line LIKE '%%,TRAFFIC,%%' THEN split_part(split_part(line, ',TRAFFIC,', 2), ',', 3) WHEN line LIKE '%%,THREAT,%%' THEN split_part(split_part(line, ',THREAT,', 2), ',', 3) ELSE substr(line, 1, 19) END ASC) TO '%s' (FORMAT CSV, HEADER false, QUOTE '');",
			sqlRaw, sqlTmp,
		)

		cmd := exec.Command(duckdbBin, "-c", sql)
		output, err := cmd.CombinedOutput()
		if err != nil {
			progress.addLog(fmt.Sprintf("❌ [%s.txt] 排序失敗: %v (%s)", dateKey, err, strings.TrimSpace(string(output))))
			_ = os.Remove(tmpPath)
			continue
		}

		// Windows 下替換原檔案 (先刪除舊檔避免 Access Denied)
		_ = os.Remove(rawPath)
		if err := os.Rename(tmpPath, rawPath); err != nil {
			progress.addLog(fmt.Sprintf("⚠️ [%s.txt] 替換原檔失敗: %v", dateKey, err))
		} else {
			progress.addLog(fmt.Sprintf("✅ [%d/%d] %s.txt 排序完成！", idx+1, len(datesToSort), dateKey))
		}
	}

	progress.addLog("🎉 全數日期檔案已完成精確時間排序 (00:00:00 -> 23:59:59) 並存檔！")
	sendJSON(w, true, "全部排序完成", nil)
}

func sendJSON(w http.ResponseWriter, success bool, message string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	status := "success"
	if !success {
		status = "error"
	}
	resp := map[string]interface{}{
		"status":  status,
		"message": message,
	}
	if data != nil {
		for k, v := range data {
			resp[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func extractLogDate(line string) string {
	isTraffic := strings.Contains(line, ",TRAFFIC,")
	isThreat := strings.Contains(line, ",THREAT,")

	if isTraffic || isThreat {
		tag := ",TRAFFIC,"
		if isThreat {
			tag = ",THREAT,"
		}

		idx := strings.Index(line, tag)
		parts := strings.Split(line[idx:], ",")
		// 🌟 修正：parts[4] 才是 Generate Time (parts[3] 為版本號 2817)
		if len(parts) > 4 {
			gt := strings.TrimSpace(parts[4])
			sub := strings.Split(gt, " ")
			if len(sub) > 0 && len(sub[0]) >= 10 {
				date := strings.ReplaceAll(sub[0], "/", "-")
				if len(date) >= 10 && date[4] == '-' && date[7] == '-' {
					return date[:10]
				}
			}
		}
	}

	trimmed := strings.TrimSpace(line)
	if len(trimmed) >= 10 {
		prefix := strings.ReplaceAll(trimmed[:10], "/", "-")
		if prefix[4] == '-' && prefix[7] == '-' {
			return prefix
		}
	}
	return ""
}