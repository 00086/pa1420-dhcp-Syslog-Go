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

curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%?rounds=5"
echo.

if not exist backfill_status.txt goto :ERR_NO_STATUS

set "STATUS_TIME="
set /p STATUS_TIME=<backfill_status.txt

if "%STATUS_TIME%"=="LIMIT" goto :LIMIT_DONE
if "%STATUS_TIME%"=="" goto :ERR_EMPTY_TIME
if not "%LAST_RECORD_TIME%"=="" if "%STATUS_TIME%"=="%LAST_RECORD_TIME%" goto :SAME_TIME_DONE

set "LAST_RECORD_TIME=%STATUS_TIME%"

echo [保護機制] 冷卻 3 秒，防止 PA-1420 CPU 過載...
timeout /t 3 /nobreak >nul
goto :LOOP

:LIMIT_DONE
echo.
echo ========================================================
echo [回溯完成] PA-1420 防火牆已回傳「已無更早的歷史日誌」，已達極限！
echo 共執行批次：%BATCH_COUNT% 批
echo ========================================================
goto :EXIT

:SAME_TIME_DONE
echo.
echo [提示] 推進時間未發生變化，本地資料庫已完整涵蓋該區間。
goto :EXIT

:ERR_NO_STATUS
echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
goto :EXIT

:ERR_EMPTY_TIME
echo ⚠️ 無法取得最新推進時間。
goto :EXIT

:EXIT
if exist backfill_status.txt del backfill_status.txt
echo.
echo 程式執行結束。
pause