@echo off
setlocal enabledelayedexpansion
set "TARGET_TYPE=%~1"
set "RUN_ALL=0"

:: 取得系統今日日期與當前時間
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set dt=%%I
if defined dt (
    set "TODAY=!dt:~0,4!-!dt:~4,2!-!dt:~6,2!"
    set "CUR_TIME=!dt:~8,2!:!dt:~10,2!:!dt:~12,2!"
) else (
    set "TODAY=%DATE:~0,4%-%DATE:~5,2%-%DATE:~8,2%"
    set "t=%TIME: =0%"
    set "CUR_TIME=!t:~0,8!"
)

:: 🌟 自動向後端 API 取得當前防火牆真實型號 (例如 PA-5250)
set "FW_MODEL=PA 防火牆"
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "try{(Invoke-RestMethod -Uri 'http://127.0.0.1:5006/api/system-health' -TimeoutSec 2).model}catch{}" 2^>nul`) do (
    if not "%%A"=="" set "FW_MODEL=%%A"
)

:: 🌟 依機型動態決定批次冷卻時間 (旗艦機種 1 秒，標準/中低階機種維持 3 秒保護)
set "COOLDOWN_SEC=3"
echo "!FW_MODEL!" | findstr /i "5250 5200 5220 5260 5450 5400 7000 7050 7080 3400" >nul
if !errorlevel! equ 0 (
    set "COOLDOWN_SEC=1"
)

if not "%TARGET_TYPE%"=="" goto :PARSE_ARGS

chcp 65001 >nul
echo ========================================================
echo   !FW_MODEL! 全自動歷史接力回溯引擎 (直至硬體極限)
echo   [模式調諧] 偵測到 !FW_MODEL!，自適應冷卻設定為 !COOLDOWN_SEC! 秒
echo ========================================================
echo 請選擇回溯類型 [直接按 Enter 預設為 1]:
echo 1. 連線流量日誌 (traffic) [預設]
echo 2. 資安威脅日誌 (threat)
echo 3. 系統紀錄日誌 (system)
echo 4. 組態變更日誌 (config)
echo 5. 執行全部四大日誌 (ALL: config -^> system -^> threat -^> traffic)
set /p USER_CHOICE="請選擇 (1-5): "
if "!USER_CHOICE!"=="2" set "TARGET_TYPE=threat"
if "!USER_CHOICE!"=="3" set "TARGET_TYPE=system"
if "!USER_CHOICE!"=="4" set "TARGET_TYPE=config"
if "!USER_CHOICE!"=="5" (
    set "TARGET_TYPE=all"
    set "RUN_ALL=1"
)
if "!TARGET_TYPE!"=="" set "TARGET_TYPE=traffic"
goto :CHECK_RUN_ALL

:PARSE_ARGS
if /I "!TARGET_TYPE!"=="all" set "RUN_ALL=1"

:CHECK_RUN_ALL
chcp 65001 >nul
if "!RUN_ALL!"=="1" (
    echo.
    echo ========================================================
    echo 🚀 [ALL 模式] 將依序回溯極限：組態 ➔ 系統 ➔ 威脅 ➔ 流量四大日誌
    echo ========================================================
    call :RUN_SINGLE_LIMIT config
    call :RUN_SINGLE_LIMIT system
    call :RUN_SINGLE_LIMIT threat
    call :RUN_SINGLE_LIMIT traffic
    echo.
    echo 🎉 所有極限回溯任務全數執行完畢！
    pause
    exit /b 0
) else (
    call :RUN_SINGLE_LIMIT !TARGET_TYPE!
    echo.
    echo 🎉 程式執行結束。
    pause
    exit /b 0
)

:RUN_SINGLE_LIMIT
set "CURRENT_TYPE=%~1"
set "ENDPOINT=api/!CURRENT_TYPE!-backfill"
if /I "!CURRENT_TYPE!"=="traffic" set "TYPE_NAME=連線流量日誌 [Traffic]"
if /I "!CURRENT_TYPE!"=="threat" set "TYPE_NAME=資安威脅日誌 [Threat]"
if /I "!CURRENT_TYPE!"=="system" set "TYPE_NAME=系統紀錄日誌 [System]"
if /I "!CURRENT_TYPE!"=="config" set "TYPE_NAME=組態變更日誌 [Config]"

echo.
echo ========================================================
echo   目標類型：!TYPE_NAME!
echo   運作模式：自當前時間 (!TODAY! !CUR_TIME!) 開始接力向歷史深挖
echo ========================================================
echo.

set "BATCH_COUNT=0"
set "LAST_RECORD_TIME="
set "REQ_PARAM=rounds=5&before=!TODAY!+!CUR_TIME!"

:LOOP_LIMIT
set /a BATCH_COUNT+=1
echo --------------------------------------------------------
echo [!TIME:~0,8!] 正在執行第 !BATCH_COUNT! 批次回溯 (5 輪 / 25,000 筆)...

if exist backfill_status.txt del backfill_status.txt

curl.exe -N -s -X POST "http://127.0.0.1:5006/!ENDPOINT!?!REQ_PARAM!"
echo.

if not exist backfill_status.txt goto :ERR_NO_STATUS

set "STATUS_TIME="
set /p STATUS_TIME=<backfill_status.txt

if "!STATUS_TIME!"=="LIMIT" goto :LIMIT_DONE
if "!STATUS_TIME!"=="" goto :ERR_EMPTY_TIME
if not "!LAST_RECORD_TIME!"=="" if "!STATUS_TIME!"=="!LAST_RECORD_TIME!" goto :SAME_TIME_DONE

set "LAST_RECORD_TIME=!STATUS_TIME!"
set "URL_BEFORE=!STATUS_TIME: =+!"
set "REQ_PARAM=rounds=5&before=!URL_BEFORE!"

echo [保護機制] 冷卻 !COOLDOWN_SEC! 秒，防止 !FW_MODEL! CPU 過載...
timeout /t !COOLDOWN_SEC! /nobreak >nul
goto :LOOP_LIMIT

:LIMIT_DONE
echo.
echo ========================================================
echo [回溯完成] !TYPE_NAME! !FW_MODEL! 防火牆已回傳「已無更早的歷史日誌」，已達極限！
echo 共執行批次：!BATCH_COUNT! 批
echo ========================================================
exit /b 0

:SAME_TIME_DONE
echo.
echo [提示] !TYPE_NAME! 推進時間未發生變化，本地資料庫已完整涵蓋該區間。
exit /b 0

:ERR_NO_STATUS
echo.
echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
exit /b 1

:ERR_EMPTY_TIME
echo.
echo ⚠️ 無法取得最新推進時間。
exit /b 1