@echo off
set "TARGET_DATE=%~1"
set "ARG2=%~2"
set "ARG3=%~3"
set "START_TIME="
set "TARGET_TYPE=traffic"

REM 🌟 1. 只要指令有提供日期，絕對不提問，直接跳過互動介面！
if not "%TARGET_DATE%"=="" goto :PARSE_ARGS

REM 2. 未帶參數時的互動模式 (雙擊時使用)
chcp 65001 >nul
echo ========================================================
echo   PA-1420 日期時段回溯工具 (接力推進至當日 00:00:00)
echo ========================================================
set /p TARGET_DATE=請輸入回溯日期 [格式 YYYY-MM-DD，例如 2026-10-23]: 
set /p START_TIME=請輸入起點時間 [格式 HH:MM:SS，直接按 Enter 自動接續最舊連線]: 
set /p USER_CHOICE=請選擇回溯類型 [1-流量日誌(預設)  2-資安威脅日誌]: 
if "%USER_CHOICE%"=="2" set "TARGET_TYPE=threat"
goto :SETUP_ENV

:PARSE_ARGS
if /I "%ARG2%"=="threat" (
    set "TARGET_TYPE=threat"
) else if /I "%ARG2%"=="traffic" (
    set "TARGET_TYPE=traffic"
) else if not "%ARG2%"=="" (
    set "START_TIME=%ARG2%"
    if /I "%ARG3%"=="threat" set "TARGET_TYPE=threat"
)

:SETUP_ENV
chcp 65001 >nul

set "ENDPOINT=api/traffic-backfill"
set "TYPE_NAME=連線流量日誌 [Traffic]"
if /I "%TARGET_TYPE%"=="threat" (
    set "ENDPOINT=api/threat-backfill"
    set "TYPE_NAME=資安威脅日誌 [Threat]"
)

set "LIMIT_TIME=%TARGET_DATE% 00:00:00"

REM 🌟 3. 起點策略：未給時間時自動探測當日斷點，給時間時才強制指定
if "%START_TIME%"=="" (
    set "REQ_PARAM=rounds=5&date=%TARGET_DATE%"
    set "START_DESC=智慧斷點續傳 (自動接力該日最舊紀錄)"
) else (
    set "REQ_PARAM=rounds=5&before=%TARGET_DATE%+%START_TIME%"
    set "START_DESC=%START_TIME% (自 %TARGET_DATE% %START_TIME% 開始)"
)

echo.
echo ========================================================
echo 🎯 目標類型：%TYPE_NAME%
echo 📅 回溯日期：%TARGET_DATE%
echo ⏰ 起點模式：%START_DESC%
echo 🏁 終點邊界：%LIMIT_TIME% (抵達即自動停止)
echo ========================================================
echo.

set "ROUND_NUM=0"
set "LAST_TIME="

:LOOP
set /a ROUND_NUM+=1
echo --------------------------------------------------------
echo [%TIME:~0,8%] ⏳ 批次 #%ROUND_NUM%：正在向前接力 (5 輪 / 25,000 筆)...

if exist backfill_status.txt del backfill_status.txt

REM 即時串流調用後端
curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%?%REQ_PARAM%"
echo.

REM 讀取最新推進狀態
if not exist backfill_status.txt (
    echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
    goto :DONE
)

set "NEW_TIME="
set /p NEW_TIME=<backfill_status.txt

if "%NEW_TIME%"=="LIMIT" (
    echo.
    echo ========================================================
    echo 🏁 回溯作業圓滿完成！
    echo ℹ️ PA-1420 防火牆已回傳「已無更早的歷史日誌」，已達極限！
    echo ========================================================
    goto :DONE
)

if "%NEW_TIME%"=="" (
    echo ⚠️ 無法取得最新時間點。
    goto :DONE
)

REM 防死循環：單行比對，避免括號語法衝突
if not "%LAST_TIME%"=="" if "%NEW_TIME%"=="%LAST_TIME%" (
    echo [提示] ⚠️ 時間未向前推進，資料庫已完整涵蓋該區間。
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

REM 接力下一批次 (後續批次使用精確時間戳推進)
set "LAST_TIME=%NEW_TIME%"
set "URL_BEFORE=%NEW_TIME: =+%"
set "REQ_PARAM=rounds=5&before=%URL_BEFORE%"

echo [保護機制] ❄️ 冷卻 3 秒，防止 PA-1420 CPU 過載...
timeout /t 3 /nobreak >nul
goto :LOOP

:DONE
if exist backfill_status.txt del backfill_status.txt
echo.
echo 所有回溯任務執行完畢。
pause