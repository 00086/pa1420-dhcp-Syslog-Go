package main

import (
	"fmt"
	"net/http"
)

// ---------------------------------------------------------
// 🌐 內建前端 Web 介面 (頂端總行數 + 真實行號跳轉 + Notepad++ 雙向搜尋)
// ---------------------------------------------------------
const indexHTML = `
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>巨量文字檔 (4GB+) 極速檢視器 - Notepad++ 增強版</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        html, body {
            height: 100vh;
            margin: 0;
            padding: 0;
            overflow: hidden !important;
            background-color: #1e1e1e;
            color: #d4d4d4;
            font-family: Consolas, "Courier New", monospace;
        }
        .app-layout {
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .toolbar {
            background-color: #252526;
            border-bottom: 1px solid #3e3e3e;
            padding: 5px 14px;
            flex-shrink: 0;
        }
        .editor-container {
            flex: 1;
            display: flex;
            overflow: hidden;
            background-color: #1e1e1e;
            position: relative;
        }
        .viewer-scroll {
            flex: 1;
            overflow-y: scroll;
            overflow-x: auto;
            height: 100%;
        }
        .viewer-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            line-height: 1.45;
        }
        .line-num {
            width: 95px;
            min-width: 95px;
            text-align: right;
            padding-right: 14px;
            color: #858585;
            user-select: none;
            border-right: 1px solid #333333;
            background-color: #1e1e1e;
            vertical-align: top;
        }
        .line-text {
            padding-left: 12px;
            white-space: pre;
            color: #d4d4d4;
            vertical-align: top;
        }

        /* 🌟 高對比度搜尋關鍵字高亮 (Notepad++ / VS Code 風格) */
        .search-match {
            background-color: #ffea00 !important;
            color: #000000 !important;
            font-weight: 800;
            padding: 1px 3px;
            border-radius: 2px;
            box-shadow: 0 0 5px rgba(255, 234, 0, 0.9);
        }
        .row-has-match {
            background-color: #242933 !important;
        }
        .row-active-match {
            background-color: #2b3a4a !important;
            outline: 1px solid #0d6efd;
        }
        .line-num.active-num {
            color: #ffea00 !important;
            font-weight: bold !important;
            background-color: #353b45 !important;
            border-right: 3px solid #ffea00 !important;
        }

        .bottom-bar {
            background-color: #252526;
            border-top: 1px solid #3e3e3e;
            color: #ffffff;
            font-size: 12px;
            padding: 4px 16px;
            flex-shrink: 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .pagination-box {
            display: inline-flex;
            gap: 3px;
            align-items: center;
            user-select: none;
        }
        .page-btn {
            min-width: 28px;
            height: 25px;
            padding: 0 6px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 11.5px;
            font-family: Consolas, monospace;
            border: 1px solid #4a4a4a;
            background-color: #333333;
            color: #58a6ff;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.15s ease;
        }
        .page-btn:hover:not(.disabled):not(.active) {
            background-color: #444444;
            color: #ffffff;
        }
        .page-btn.active {
            background-color: #0d6efd !important;
            border-color: #0d6efd !important;
            color: #ffffff !important;
            font-weight: bold;
        }
        .page-btn.disabled {
            opacity: 0.35;
            cursor: not-allowed;
            color: #888888;
            border-color: #383838;
            background-color: #2a2a2a;
        }

        .welcome-box {
            border: 2px dashed #0d6efd;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            background-color: #252526;
            max-width: 650px;
            margin: auto;
        }
        input, select, button {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 12.5px !important;
        }
    </style>
</head>
<body>

<input type="file" id="nativeFileInput" style="display: none;" accept=".txt,.log,.csv">

<div class="app-layout">
    <!-- 頂端控制工具列 -->
    <div class="toolbar d-flex align-items-center justify-content-between flex-wrap gap-2">
        <!-- 檔案與頂端全域總行數 -->
        <div class="d-flex align-items-center gap-2">
            <button class="btn btn-primary btn-sm px-3 fw-bold shadow-sm" onclick="triggerNativePicker()">
                <i class="bi bi-folder2-open me-1"></i>選擇日誌檔案
            </button>
            <span class="text-truncate text-light small fw-bold ms-1" id="toolbarFilename" style="max-width: 200px;">尚未開啟檔案</span>
            <span class="badge bg-secondary font-monospace" id="toolbarTotalLines">總行數: --</span>
        </div>

        <!-- 跳至真實行號區 -->
        <div class="d-flex align-items-center gap-2">
            <div class="input-group input-group-sm" style="width: 250px;">
                <span class="input-group-text bg-dark text-secondary border-secondary">真實行號</span>
                <input type="number" class="form-control bg-dark text-light border-secondary font-monospace" id="jumpLineInput" placeholder="如 3312487" onkeydown="if(event.key==='Enter') jumpToLine()">
                <button class="btn btn-outline-info" onclick="jumpToLine()"><i class="bi bi-arrow-right-short"></i>前往</button>
            </div>

            <!-- Notepad++ 風格雙向搜尋區 (前一個 / 下一個) -->
            <div class="input-group input-group-sm" style="width: 380px;">
                <input type="text" class="form-control bg-dark text-light border-secondary font-monospace" id="searchInput" placeholder="搜尋關鍵字 (Enter 下一個 / Shift+Enter 上一個)">
                <button class="btn btn-outline-secondary text-light border-secondary text-nowrap" onclick="findPrev()" title="尋找上一個 (Shift+Enter)">
                    <i class="bi bi-chevron-up"></i> 上一個
                </button>
                <button class="btn btn-warning text-dark text-nowrap fw-bold" onclick="findNext()" title="尋找下一個 (Enter)">
                    <i class="bi bi-chevron-down"></i> 下一個
                </button>
            </div>
            <span class="badge bg-dark text-warning border border-secondary font-monospace" id="searchStatusBadge">未搜尋</span>
        </div>
    </div>

    <!-- 核心代碼檢視區 -->
    <div class="editor-container">
        <div class="viewer-scroll" id="scrollBox">
            <table class="viewer-table font-monospace">
                <tbody id="textBody">
                    <tr>
                        <td colspan="2" class="p-5 text-center">
                            <div class="welcome-box shadow">
                                <i class="bi bi-file-earmark-text text-primary" style="font-size: 3.5rem;"></i>
                                <h5 class="text-light mt-3 mb-2">巨量文字檔 (2G ~ 4G+) 毫秒級檢視器</h5>
                                <p class="text-secondary small mb-4">支援全域真實行號精確跳轉、Notepad++ 雙向高對比文字檢索、不佔用 RAM 不崩潰。</p>
                                <button class="btn btn-primary btn-lg px-4 fw-bold shadow" onclick="triggerNativePicker()">
                                    <i class="bi bi-folder2-open me-2"></i>點擊選擇本機日誌檔案
                                </button>
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 底部狀態列與分頁區 -->
    <div class="bottom-bar">
        <div class="d-flex align-items-center gap-3">
            <span class="font-monospace small fw-bold text-light" id="fileInfoLabel">尚未開啟檔案</span>
            <span class="small text-secondary" id="indexStatusLabel">就緒</span>
        </div>
        <div class="d-flex align-items-center gap-2">
            <span class="font-monospace text-light small me-2" id="pageSummaryLabel" style="font-size: 11.5px;"></span>
            <div class="pagination-box" id="paginationBar"></div>
        </div>
    </div>
</div>

<script>
let currentFile = null;
let currentPage = 1;
const pageSize = 500;
let totalLines = 0;
let totalPages = 1;
let sparseIndex = [0];
let isIndexing = false;
let sparseIndexDone = false;

let currentSearchQuery = "";
let currentMatchOffset = -1;
let currentMatchLine = 0;
let isSearching = false;

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}

function highlightText(text, keyword) {
    const escaped = escapeHtml(text);
    if (!keyword) return escaped;
    const escapedKwd = keyword.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
    const regex = new RegExp('(' + escapedKwd + ')', 'gi');
    return escaped.replace(regex, '<mark class="search-match">$1</mark>');
}

function triggerNativePicker() {
    document.getElementById('nativeFileInput').click();
}

document.getElementById('searchInput').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        if (e.shiftKey) {
            findPrev();
        } else {
            findNext();
        }
    }
});

document.getElementById('nativeFileInput').addEventListener('change', function(e) {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    currentFile = files[0];
    document.getElementById('toolbarFilename').innerText = currentFile.name;
    document.getElementById('fileInfoLabel').innerText = currentFile.name + ' (' + formatBytes(currentFile.size) + ')';
    document.getElementById('toolbarTotalLines').className = 'badge bg-secondary font-monospace';
    document.getElementById('toolbarTotalLines').innerText = '總行數: 計算中...';
    document.getElementById('searchStatusBadge').innerText = '未搜尋';

    currentPage = 1;
    sparseIndex = [0];
    sparseIndexDone = false;
    currentSearchQuery = "";
    currentMatchOffset = -1;
    currentMatchLine = 0;

    const estimated = Math.max(1, Math.round(currentFile.size / 250));
    totalLines = estimated;
    totalPages = Math.max(1, Math.ceil(totalLines / pageSize));
    renderPagination();

    goToPage(1, 0, '');
    startBackgroundSparseIndexing();
});

function goToPage(page, targetLine, highlightKeyword) {
    if (!currentFile) return;
    if (page < 1) page = 1;
    if (page > totalPages) page = totalPages;

    currentPage = page;
    const targetStartLine = (page - 1) * pageSize + 1;

    const pageIdx = page - 1;
    let seekByte = 0;
    if (pageIdx < sparseIndex.length) {
        seekByte = sparseIndex[pageIdx];
    } else {
        seekByte = Math.min(currentFile.size - 64 * 1024, Math.floor(currentFile.size * (pageIdx / totalPages)));
    }

    readLinesFromOffset(seekByte, targetStartLine, highlightKeyword, targetLine);
    renderPagination();
}

function readLinesFromOffset(startByte, startLineNum, highlightKeyword, targetLine) {
    if (!currentFile) return;

    const chunkSize = 512 * 1024;
    const slice = currentFile.slice(startByte, Math.min(currentFile.size, startByte + chunkSize));

    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        const allLines = text.split(/\r?\n/);
        const displayLines = allLines.slice(0, pageSize);

        renderLines(displayLines, startLineNum, highlightKeyword, targetLine);
    };
    reader.readAsText(slice, 'UTF-8');
}

function renderLines(lines, startLineNum, highlightKeyword, targetLine) {
    const tbody = document.getElementById('textBody');
    tbody.innerHTML = '';

    if (!lines || lines.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="text-center py-5 text-muted">無資料 (已達檔案結尾)</td></tr>';
        return;
    }

    const fragment = document.createDocumentFragment();
    lines.forEach((lineText, idx) => {
        const tr = document.createElement('tr');
        const lineNo = startLineNum + idx;
        tr.id = 'line-row-' + lineNo;

        const tdNum = document.createElement('td');
        tdNum.className = 'line-num font-monospace';
        tdNum.innerText = lineNo.toLocaleString();

        const tdText = document.createElement('td');
        tdText.className = 'line-text font-monospace';

        const hasMatch = highlightKeyword && lineText.toLowerCase().includes(highlightKeyword.toLowerCase());
        const isTarget = (targetLine > 0 && lineNo === targetLine);

        if (isTarget) {
            tr.className = 'row-active-match';
            tdNum.className += ' active-num';
        } else if (hasMatch) {
            tr.className = 'row-has-match';
        }

        tdText.innerHTML = highlightText(lineText, highlightKeyword);

        tr.appendChild(tdNum);
        tr.appendChild(tdText);
        fragment.appendChild(tr);
    });

    tbody.appendChild(fragment);

    if (targetLine >= startLineNum && targetLine < startLineNum + lines.length) {
        setTimeout(() => {
            const row = document.getElementById('line-row-' + targetLine);
            const scrollBox = document.getElementById('scrollBox');
            if (row && scrollBox) {
                const targetScroll = row.offsetTop - (scrollBox.clientHeight / 2) + (row.clientHeight / 2);
                scrollBox.scrollTop = Math.max(0, targetScroll);
            }
        }, 20);
    } else {
        document.getElementById('scrollBox').scrollTop = 0;
    }
}

function jumpToLine() {
    if (!currentFile) {
        alert('請先選擇檔案！');
        return;
    }
    const val = parseInt(document.getElementById('jumpLineInput').value, 10);
    if (isNaN(val) || val < 1) {
        alert('請輸入大於 0 的有效真實行號！');
        return;
    }

    if (sparseIndexDone && totalLines > 0 && val > totalLines) {
        alert('輸入行號超出檔案範圍！最大行數為: ' + totalLines.toLocaleString());
        return;
    }

    const targetPage = Math.floor((val - 1) / pageSize) + 1;
    document.getElementById('indexStatusLabel').innerText = '🎯 已跳轉至真實行號: 第 ' + val.toLocaleString() + ' 行 (位於第 ' + targetPage.toLocaleString() + ' 頁)';
    goToPage(targetPage, val, currentSearchQuery);
}

function startBackgroundSparseIndexing() {
    if (!currentFile || isIndexing) return;
    isIndexing = true;

    const streamChunkSize = 8 * 1024 * 1024;
    let offset = 0;
    let lineCounter = 0;
    sparseIndex = [0];

    function readNextChunk() {
        if (offset >= currentFile.size) {
            isIndexing = false;
            sparseIndexDone = true;
            totalLines = lineCounter;
            totalPages = Math.max(1, Math.ceil(totalLines / pageSize));

            const badge = document.getElementById('toolbarTotalLines');
            badge.className = 'badge bg-primary text-white font-monospace';
            badge.innerText = '總行數: ' + totalLines.toLocaleString() + ' 行';

            document.getElementById('jumpLineInput').placeholder = '1 ~ ' + totalLines.toLocaleString();
            document.getElementById('indexStatusLabel').innerText = '✅ 完整真實行號索引建立完成！共 ' + lineCounter.toLocaleString() + ' 行';
            renderPagination();
            return;
        }

        const slice = currentFile.slice(offset, offset + streamChunkSize);
        const reader = new FileReader();
        reader.onload = function(e) {
            const buffer = new Uint8Array(e.target.result);
            const len = buffer.length;
            for (let i = 0; i < len; i++) {
                if (buffer[i] === 10) {
                    lineCounter++;
                    if (lineCounter % pageSize === 0) {
                        sparseIndex.push(offset + i + 1);
                    }
                }
            }
            offset += streamChunkSize;

            if (lineCounter % 200000 === 0) {
                totalLines = lineCounter;
                totalPages = Math.max(1, Math.ceil(totalLines / pageSize));
                const pct = Math.round((offset / currentFile.size) * 100);
                document.getElementById('toolbarTotalLines').innerText = '總行數: ' + lineCounter.toLocaleString() + ' (' + pct + '%)';
                document.getElementById('indexStatusLabel').innerText = '⚡ 正在建立真實行號索引... 已掃描 ' + lineCounter.toLocaleString() + ' 行 (' + pct + '%)';
                renderPagination();
            }

            setTimeout(readNextChunk, 0);
        };
        reader.readAsArrayBuffer(slice);
    }

    readNextChunk();
}

function getExactLineFromOffset(targetOffset) {
    return new Promise((resolve) => {
        let low = 0, high = sparseIndex.length - 1;
        let k = 0;
        while (low <= high) {
            let mid = Math.floor((low + high) / 2);
            if (sparseIndex[mid] <= targetOffset) {
                k = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        const baseLine = k * pageSize + 1;
        const baseOffset = sparseIndex[k];

        if (targetOffset <= baseOffset) {
            resolve(baseLine);
            return;
        }

        const slice = currentFile.slice(baseOffset, targetOffset);
        const reader = new FileReader();
        reader.onload = function(e) {
            const buf = new Uint8Array(e.target.result);
            let count = 0;
            for (let i = 0; i < buf.length; i++) {
                if (buf[i] === 10) count++;
            }
            resolve(baseLine + count);
        };
        reader.readAsArrayBuffer(slice);
    });
}

function readFileAsText(blob) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.readAsText(blob, 'UTF-8');
    });
}

async function findNext() {
    if (!currentFile || isSearching) return;
    const q = document.getElementById('searchInput').value;
    if (!q) {
        alert('請先輸入要搜尋的關鍵字！');
        return;
    }

    if (q !== currentSearchQuery) {
        currentSearchQuery = q;
        const startLine = (currentPage - 1) * pageSize + 1;
        const currentIdx = Math.floor((startLine - 1) / pageSize);
        currentMatchOffset = sparseIndex[currentIdx] || 0;
    } else {
        currentMatchOffset = (currentMatchOffset >= 0) ? currentMatchOffset + 1 : 0;
    }

    let searchOffset = currentMatchOffset;
    if (searchOffset >= currentFile.size) {
        updateSearchStatus('已到達文件結尾！', 'warning');
        return;
    }

    isSearching = true;
    updateSearchStatus('正在向下搜尋...', 'info');

    const chunkSize = 2 * 1024 * 1024;
    const overlap = q.length - 1;

    async function scanForward() {
        if (searchOffset >= currentFile.size) {
            isSearching = false;
            updateSearchStatus('已達檔尾，查無更多結果', 'warning');
            return;
        }

        const end = Math.min(currentFile.size, searchOffset + chunkSize + overlap);
        const slice = currentFile.slice(searchOffset, end);
        const text = await readFileAsText(slice);

        const pos = text.indexOf(q);
        if (pos !== -1) {
            const matchByte = searchOffset + pos;
            const exactLine = await getExactLineFromOffset(matchByte);
            currentMatchOffset = matchByte;
            currentMatchLine = exactLine;
            isSearching = false;

            const targetPage = Math.floor((exactLine - 1) / pageSize) + 1;
            updateSearchStatus('[第 ' + exactLine.toLocaleString() + ' 行] 命中', 'success');
            goToPage(targetPage, exactLine, q);
        } else {
            searchOffset += chunkSize;
            setTimeout(scanForward, 0);
        }
    }

    scanForward();
}

async function findPrev() {
    if (!currentFile || isSearching) return;
    const q = document.getElementById('searchInput').value;
    if (!q) {
        alert('請先輸入要搜尋的關鍵字！');
        return;
    }

    if (q !== currentSearchQuery) {
        currentSearchQuery = q;
        const startLine = (currentPage - 1) * pageSize + 1;
        const currentIdx = Math.floor((startLine - 1) / pageSize);
        currentMatchOffset = sparseIndex[currentIdx] || 0;
    }

    let searchOffset = (currentMatchOffset > 0) ? currentMatchOffset - 1 : currentFile.size;
    if (searchOffset <= 0) {
        updateSearchStatus('已到達文件頂端！', 'warning');
        return;
    }

    isSearching = true;
    updateSearchStatus('正在向上搜尋...', 'info');

    const chunkSize = 2 * 1024 * 1024;
    const overlap = q.length - 1;

    async function scanBackward() {
        if (searchOffset <= 0) {
            isSearching = false;
            updateSearchStatus('已達檔首，查無更多結果', 'warning');
            return;
        }

        const start = Math.max(0, searchOffset - chunkSize);
        const end = Math.min(currentFile.size, searchOffset + overlap);
        const slice = currentFile.slice(start, end);
        const text = await readFileAsText(slice);

        const maxRelPos = searchOffset - start;
        const searchSlice = text.substring(0, maxRelPos + q.length);
        const pos = searchSlice.lastIndexOf(q);

        if (pos !== -1 && (start + pos) <= searchOffset) {
            const matchByte = start + pos;
            const exactLine = await getExactLineFromOffset(matchByte);
            currentMatchOffset = matchByte;
            currentMatchLine = exactLine;
            isSearching = false;

            const targetPage = Math.floor((exactLine - 1) / pageSize) + 1;
            updateSearchStatus('[第 ' + exactLine.toLocaleString() + ' 行] 命中', 'success');
            goToPage(targetPage, exactLine, q);
        } else {
            searchOffset = start;
            setTimeout(scanBackward, 0);
        }
    }

    scanBackward();
}

function updateSearchStatus(msg, type) {
    const badge = document.getElementById('searchStatusBadge');
    badge.innerText = msg;
    const bgClass = (type === 'success') ? 'bg-success text-white' : ((type === 'warning') ? 'bg-warning text-dark' : 'bg-info text-dark');
    badge.className = 'badge font-monospace ' + bgClass;
}

function renderPagination() {
    const container = document.getElementById('paginationBar');
    const summary = document.getElementById('pageSummaryLabel');
    if (!currentFile) {
        container.innerHTML = '';
        summary.innerText = '';
        return;
    }

    summary.innerHTML = '<span class="text-secondary">#</span> ' + totalLines.toLocaleString() + ' 行 <span class="text-secondary">(頁次 ' + currentPage.toLocaleString() + ' / ' + totalPages.toLocaleString() + ')</span>';
    container.innerHTML = '';

    container.appendChild(createPageBtn('&laquo;', currentPage === 1, () => goToPage(1, 0, currentSearchQuery), '跳至第一頁'));
    container.appendChild(createPageBtn('&lsaquo;', currentPage === 1, () => goToPage(currentPage - 1, 0, currentSearchQuery), '上一頁'));

    const maxButtons = 10;
    let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
    let endPage = startPage + maxButtons - 1;

    if (endPage > totalPages) {
        endPage = totalPages;
        startPage = Math.max(1, endPage - maxButtons + 1);
    }

    for (let p = startPage; p <= endPage; p++) {
        const btn = createPageBtn(p, false, () => goToPage(p, 0, currentSearchQuery));
        if (p === currentPage) btn.className += ' active';
        container.appendChild(btn);
    }

    container.appendChild(createPageBtn('&rsaquo;', currentPage >= totalPages, () => goToPage(currentPage + 1, 0, currentSearchQuery), '下一頁'));
    container.appendChild(createPageBtn('&raquo;', currentPage >= totalPages, () => goToPage(totalPages, 0, currentSearchQuery), '跳至最後一頁'));
}

function createPageBtn(text, disabled, onClick, title) {
    const a = document.createElement('a');
    a.className = 'page-btn';
    if (disabled) a.className += ' disabled';
    a.innerHTML = text;
    if (title) a.title = title;
    if (!disabled && onClick) {
        a.onclick = (e) => {
            e.preventDefault();
            onClick();
        };
    }
    return a;
}
</script>
</body>
</html>
`

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})

	port := ":9090"
	fmt.Println("========================================================")
	fmt.Println("🚀 巨量文字檔 (4GB+) 極速檢視器 (Notepad++ 雙向搜尋版) 已啟動！")
	fmt.Printf("👉 請開啟瀏覽器訪問: http://localhost%s\n", port)
	fmt.Println("========================================================")

	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Printf("❌ 啟動伺服器失敗: %v\n", err)
	}
}