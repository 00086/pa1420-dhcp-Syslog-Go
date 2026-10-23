@echo off
set "TARGET_DATE=%~1"
set "ARG2=%~2"
set "ARG3=%~3"
set "START_TIME="
set "TARGET_TYPE=traffic"

REM 1. 只要指令有提供日期，直接跳過互動提示
if not "%TARGET_DATE%"=="" goto :PARSE_ARGS

REM 2. 未帶參數時的互動模式 (滑鼠雙擊使用)
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
if /I "%ARG2%"=="threat" set "TARGET_TYPE=threat"
if /I "%ARG2%"=="traffic" set "TARGET_TYPE=traffic"
if not "%ARG2%"=="" if not "%ARG2%"=="threat" if not "%ARG2%"=="traffic" (
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

if "%START_TIME%"=="" (
    set "REQ_PARAM=rounds=5&date=%TARGET_DATE%"
    set "START_DESC=智慧斷點續傳 (自動接力該日最舊紀錄)"
) else (
    set "REQ_PARAM=rounds=5&before=%TARGET_DATE%+%START_TIME%"
    set "START_DESC=%START_TIME% (自 %TARGET_DATE% %START_TIME% 開始)"
)

echo.
echo ========================================================
echo [任務設定] 目標類型：%TYPE_NAME%
echo [任務設定] 回溯日期：%TARGET_DATE%
echo [任務設定] 起點模式：%START_DESC%
echo [任務設定] 終點邊界：%LIMIT_TIME% (抵達即自動停止)
echo ========================================================
echo.

set "ROUND_NUM=0"
set "LAST_TIME="

:LOOP
set /a ROUND_NUM+=1
echo --------------------------------------------------------
echo [%TIME:~0,8%] 批次 #%ROUND_NUM%：正在向前接力 (5 輪 / 25,000 筆)...

if exist backfill_status.txt del backfill_status.txt

REM 即時串流調用後端
curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%?%REQ_PARAM%"
echo.

REM 讀取狀態
if not exist backfill_status.txt goto :ERR_NO_STATUS

set "NEW_TIME="
set /p NEW_TIME=<backfill_status.txt

if "%NEW_TIME%"=="LIMIT" goto :LIMIT_DONE
if "%NEW_TIME%"=="" goto :ERR_EMPTY_TIME
if not "%LAST_TIME%"=="" if "%NEW_TIME%"=="%LAST_TIME%" goto :SAME_TIME_DONE

REM 🌟 核心防護：單行判斷跳轉，杜絕複合括號位移 Bug
if "%NEW_TIME%" LEQ "%LIMIT_TIME%" goto :SUCCESS_DONE

REM 接續下一批次
set "LAST_TIME=%NEW_TIME%"
set "URL_BEFORE=%NEW_TIME: =+%"
set "REQ_PARAM=rounds=5&before=%URL_BEFORE%"

echo [保護機制] 冷卻 3 秒，防止 PA-1420 CPU 過載...
timeout /t 3 /nobreak >nul
goto :LOOP

:SUCCESS_DONE
echo.
echo ========================================================
echo [達成目標] 歷史時間已推進至當日 00:00:00 邊界！
echo 最後推進時間點：%NEW_TIME%
echo 共執行批次數：%ROUND_NUM% 次
echo ========================================================
goto :DONE

:LIMIT_DONE
echo.
echo ========================================================
echo [回溯完成] PA-1420 防火牆已回傳「已無更早歷史日誌」，已達極限！
echo ========================================================
goto :DONE

:SAME_TIME_DONE
echo.
echo [提示] 推進時間未發生變化，本地資料庫已完整涵蓋該區間。
goto :DONE

:ERR_NO_STATUS
echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
goto :DONE

:ERR_EMPTY_TIME
echo ⚠️ 無法取得最新時間點。
goto :DONE

:DONE
if exist backfill_status.txt del backfill_status.txt
echo.
echo 所有回溯任務執行完畢。
pause