@echo off
set "TARGET_TYPE=%~1"
if "%TARGET_TYPE%"=="" set "TARGET_TYPE=traffic"

chcp 65001 >nul

set "ENDPOINT=api/traffic-backfill"
set "TYPE_NAME=連線流量日誌 [Traffic]"
if /I "%TARGET_TYPE%"=="threat" (
    set "ENDPOINT=api/threat-backfill"
    set "TYPE_NAME=資安威脅日誌 [Threat]"
)

echo ========================================================
echo   PA-1420 全自動歷史接力回溯引擎 (直至硬體極限)
echo   目標類型：%TYPE_NAME%
echo   運作模式：自動接力回溯，直達 PA-1420 日誌極限 (10/8 或更早)
echo ========================================================
echo.

set "BATCH_COUNT=0"
set "LAST_RECORD_TIME="

:LOOP
set /a BATCH_COUNT+=1
echo.
echo --------------------------------------------------------
echo [%TIME:~0,8%] 正在執行第 %BATCH_COUNT% 批次回溯 (5 輪 / 25,000 筆)...
echo --------------------------------------------------------

if exist backfill_status.txt del backfill_status.txt

REM 🌟 核心：直接輸出終端機，每輪即時跳出 (不緩衝)
curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%?rounds=5"
echo.

REM 讀取後端寫出的推進狀態
if not exist backfill_status.txt (
    echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
    goto :EXIT
)

set "STATUS_TIME="
set /p STATUS_TIME=<backfill_status.txt

REM 1. 檢查是否已到達硬體儲存極限
if "%STATUS_TIME%"=="LIMIT" (
    echo.
    echo ========================================================
    echo 🏁 回溯作業圓滿完成！
    echo ℹ️ PA-1420 防火牆已回傳「已無更早的歷史日誌」，已達硬體極限！
    echo    共執行批次：%BATCH_COUNT% 批
    echo ========================================================
    goto :EXIT
)

if "%STATUS_TIME%"=="" (
    echo ⚠️ 無法取得最新推進時間。
    goto :EXIT
)

REM 2. 防死循環檢查 (使用安全單行語法，絕不觸發括號語法衝突)
if not "%LAST_RECORD_TIME%"=="" if "%STATUS_TIME%"=="%LAST_RECORD_TIME%" (
    echo [提示] ⚠️ 時間未向前推進，資料庫已完整涵蓋該區間。
    goto :EXIT
)

set "LAST_RECORD_TIME=%STATUS_TIME%"

REM 3. 冷卻 3 秒保護 PA-1420 管理平面 CPU
echo [保護機制] ❄️ 冷卻 3 秒，防止 PA-1420 CPU 過載...
timeout /t 3 /nobreak >nul
goto :LOOP

:EXIT
if exist backfill_status.txt del backfill_status.txt
echo.
echo 程式執行結束。
pause