@echo off
set "TARGET_DATE=%~1"
set "ARG2=%~2"
set "ARG3=%~3"
set "START_TIME=23:59:59"
set "TARGET_TYPE=traffic"

chcp 65001 >nul

REM 1. 參數辨識
if /I "%ARG2%"=="threat" (
    set "TARGET_TYPE=threat"
) else if /I "%ARG2%"=="traffic" (
    set "TARGET_TYPE=traffic"
) else if not "%ARG2%"=="" (
    set "START_TIME=%ARG2%"
    if /I "%ARG3%"=="threat" set "TARGET_TYPE=threat"
)

REM 2. 僅在完全未傳入日期時才提問
if "%TARGET_DATE%"=="" (
    echo ========================================================
    echo   PA-1420 日期時段回溯工具 (接力推進至當日 00:00:00)
    echo ========================================================
    set /p TARGET_DATE=請輸入回溯日期 [格式 YYYY-MM-DD，例如 2026-10-23]: 
    set /p START_TIME=請輸入起點時間 [格式 HH:MM:SS，直接按 Enter 預設 23:59:59]: 
    set /p USER_CHOICE=請選擇回溯類型 [1-流量日誌(預設)  2-資安威脅日誌]: 
    if "!USER_CHOICE!"=="2" set "TARGET_TYPE=threat"
)

if "%START_TIME%"=="" set "START_TIME=23:59:59"

set "ENDPOINT=api/traffic-backfill"
set "TYPE_NAME=連線流量日誌 [Traffic]"
if /I "%TARGET_TYPE%"=="threat" (
    set "ENDPOINT=api/threat-backfill"
    set "TYPE_NAME=資安威脅日誌 [Threat]"
)

set "LIMIT_TIME=%TARGET_DATE% 00:00:00"
set "CURRENT_TIME=%TARGET_DATE% %START_TIME%"
set "ROUND_NUM=0"

echo.
echo ========================================================
echo 🎯 目標類型：%TYPE_NAME%
echo 📅 回溯日期：%TARGET_DATE%
echo ⏰ 起點時間：%START_TIME% (自 %CURRENT_TIME% 開始)
echo 🏁 終點邊界：%LIMIT_TIME% (抵達即自動停止)
echo ========================================================
echo.

:LOOP
set /a ROUND_NUM+=1
set "URL_BEFORE=%CURRENT_TIME: =+%"

echo --------------------------------------------------------
echo [%TIME:~0,8%] ⏳ 批次 #%ROUND_NUM%：自 %CURRENT_TIME% 往前接力 (5 輪 / 25,000 筆)...

if exist backfill_status.txt del backfill_status.txt

REM 🌟 核心改進：curl 直接輸出到螢幕，每一輪 (1/5, 2/5...) 即時跳出！不卡頓、不延遲！
curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%?rounds=5&before=%URL_BEFORE%"
echo.

REM 讀取後端自動寫入的最新推進時間
if not exist backfill_status.txt (
    echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
    goto :DONE
)

set "NEW_TIME="
set /p NEW_TIME=<backfill_status.txt

if "%NEW_TIME%"=="LIMIT" (
    echo.
    echo [提示] ℹ️ PA-1420 已無更早的日誌資料，回溯提前抵達極限。
    goto :DONE
)

if "%NEW_TIME%"=="" (
    echo ⚠️ 無法取得最新時間點。
    goto :DONE
)

if "%NEW_TIME%"=="%CURRENT_TIME%" (
    echo [提示] ⚠️ 時間未向前推進，該區間可能已被完整涵蓋。
    goto :DONE
)

REM 判斷是否抵達或跨過當天 00:00:00 邊界
if "%NEW_TIME%" LEQ "%LIMIT_TIME%" (
    echo.
    echo ========================================================
    echo 🎯 達成目標！歷史時間已推進至當日 00:00:00 邊界！
    echo    最後推進時間點：%NEW_TIME%
    echo    共執行批次數：%ROUND_NUM% 次
    echo ========================================================
    goto :DONE
)

set "CURRENT_TIME=%NEW_TIME%"
echo [保護機制] ❄️ 冷卻 3 秒，防止 PA-1420 CPU 過載...
timeout /t 3 /nobreak >nul
goto :LOOP

:DONE
if exist backfill_status.txt del backfill_status.txt
echo.
echo 所有回溯任務執行完畢。
pause