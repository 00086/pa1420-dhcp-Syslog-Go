@echo off
setlocal
set "BAT_PATH=%~f0"
set "ARG1=%~1"
set "ARG2=%~2"
set "ARG3=%~3"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $f=[System.IO.File]::ReadAllText($env:BAT_PATH, [System.Text.Encoding]::UTF8); $i=$f.LastIndexOf('__POWERSHELL_START__'); &([ScriptBlock]::Create($f.Substring($i+22)))"
exit /b %ERRORLEVEL%

__POWERSHELL_START__
$TargetDate = $env:ARG1
$Arg2 = $env:ARG2
$Arg3 = $env:ARG3
$StartTime = ""
$TargetType = "traffic"

# 1. 互動模式 (未指定日期時)
if ([string]::IsNullOrWhiteSpace($TargetDate)) {
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  PA-1420 日期時段回溯工具 (接力推進至當日 00:00:00)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    $TargetDate = Read-Host "請輸入回溯日期 [格式 YYYY-MM-DD，例如 2026-10-23]"
    $StartTime = Read-Host "請輸入起點時間 [格式 HH:MM:SS，直接按 Enter 自動接續最舊連線]"
    $c = Read-Host "請選擇回溯類型 [1-流量日誌(預設)  2-資安威脅日誌]"
    if ($c -eq "2") { $TargetType = "threat" }
} else {
    if ($Arg2 -eq "threat") { $TargetType = "threat" }
    elseif ($Arg2 -eq "traffic") { $TargetType = "traffic" }
    elseif (-not [string]::IsNullOrWhiteSpace($Arg2)) {
        $StartTime = $Arg2
        if ($Arg3 -eq "threat") { $TargetType = "threat" }
    }
}

$Endpoint = if ($TargetType -eq "threat") { "api/threat-backfill" } else { "api/traffic-backfill" }
$TypeName = if ($TargetType -eq "threat") { "資安威脅日誌 [Threat]" } else { "連線流量日誌 [Traffic]" }
$LimitTime = "$TargetDate 00:00:00"

if ([string]::IsNullOrWhiteSpace($StartTime)) {
    $ReqParam = "rounds=5&date=$TargetDate"
    $StartDesc = "智慧斷點續傳 (自動接力該日最舊紀錄)"
} else {
    $urlStart = $StartTime.Replace(" ", "+")
    $ReqParam = "rounds=5&date=$TargetDate&before=$TargetDate+$urlStart"
    $StartDesc = "$StartTime (自 $TargetDate $StartTime 開始)"
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "[任務設定] 目標類型：$TypeName"
Write-Host "[任務設定] 回溯日期：$TargetDate"
Write-Host "[任務設定] 起點模式：$StartDesc"
Write-Host "[任務設定] 終點邊界：$LimitTime (抵達即自動停止)"
Write-Host "========================================================`n" -ForegroundColor Cyan

$RoundNum = 0
$LastTime = ""

while ($true) {
    $RoundNum++
    $t = (Get-Date).ToString("HH:mm:ss")
    Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[$t] 批次 #$RoundNum：正在向前接力 (5 輪 / 25,000 筆)..." -ForegroundColor Yellow

    if (Test-Path "backfill_status.txt") { Remove-Item "backfill_status.txt" -Force }

    # 直接呼叫 curl.exe，完全不緩衝，每輪即時跳出顯示
    $cmd = "curl.exe -N -s -X POST `"http://127.0.0.1:5006/$Endpoint?$ReqParam`""
    Invoke-Expression $cmd
    Write-Host ""

    if (-not (Test-Path "backfill_status.txt")) {
        Write-Host "⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。" -ForegroundColor Red
        break
    }

    $NewTime = (Get-Content "backfill_status.txt" -Raw).Trim()

    if ($NewTime -eq "LIMIT") {
        Write-Host "`n========================================================" -ForegroundColor Green
        Write-Host "[回溯完成] PA-1420 防火牆已回傳「已無更早歷史日誌」，已達極限！" -ForegroundColor Green
        Write-Host "========================================================" -ForegroundColor Green
        break
    }

    if ([string]::IsNullOrWhiteSpace($NewTime)) {
        Write-Host "⚠️ 無法取得最新時間點。" -ForegroundColor Red
        break
    }

    if ($NewTime -eq $LastTime) {
        Write-Host "`n[提示] 推進時間未發生變化，本地資料庫已完整涵蓋該區間。" -ForegroundColor Yellow
        break
    }

    if ($NewTime -le $LimitTime) {
        Write-Host "`n========================================================" -ForegroundColor Green
        Write-Host "[達成目標] 歷史時間已推進至當日 00:00:00 邊界！" -ForegroundColor Green
        Write-Host " 最後推進時間點：$NewTime" -ForegroundColor Green
        Write-Host " 共執行批次數：$RoundNum 次" -ForegroundColor Green
        Write-Host "========================================================" -ForegroundColor Green
        break
    }

    $LastTime = $NewTime
    $urlBefore = $NewTime.Replace(" ", "+")
    $ReqParam = "rounds=5&date=$TargetDate&before=$urlBefore"

    Write-Host "[保護機制] 冷卻 3 秒，防止 PA-1420 CPU 過載..." -ForegroundColor DarkCyan
    Start-Sleep -Seconds 3
}

if (Test-Path "backfill_status.txt") { Remove-Item "backfill_status.txt" -Force }
Write-Host "`n所有回溯任務執行完畢。"
Read-Host "Press Enter to exit..."