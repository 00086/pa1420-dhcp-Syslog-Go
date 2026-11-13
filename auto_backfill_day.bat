@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: 🌟 1. 跨 Windows 所有地區語系，精準取得標準 YYYY-MM-DD 與 HH:MM:SS
for /f "tokens=1,2" %%A in ('powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'" 2^>nul') do (
    set "TODAY=%%A"
    set "CUR_TIME=%%B"
)

if "!TODAY!"=="" (
    for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set dt=%%I
    if defined dt (
        set "TODAY=!dt:~0,4!-!dt:~4,2!-!dt:~6,2!"
        set "CUR_TIME=!dt:~8,2!:!dt:~10,2!:!dt:~12,2!"
    )
)

:: 🌟 2. 自動向後端 API 取得防火牆真實型號

set "FW_MODEL=PA 防火牆"
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "try{(Invoke-RestMethod -Uri 'http://127.0.0.1:5006/api/system-health' -TimeoutSec 2).model}catch{}" 2^>nul`) do (
    if not "%%A"=="" set "FW_MODEL=%%A"
)

:: 🌟 3. 自適應冷卻時間 (PA-5250 為 1 秒，PA-1420 為 3 秒)
set "COOLDOWN_SEC=3"
echo "!FW_MODEL!" | findstr /i "5250 5200 5220 5260 5450 5400 7000 7050 7080 3400" >nul
if !errorlevel! equ 0 (
    set "COOLDOWN_SEC=1"
)

echo ========================================================
echo  !FW_MODEL! 日期時段回溯工具 (接力推進至當日 00:00:00)
echo  [模式調諧] 偵測到 !FW_MODEL!，自適應冷卻設定為 !COOLDOWN_SEC! 秒
echo ========================================================

:: 🌟 4. 全方位智慧參數識別引擎 (徹底解決參數順序與缺省問題)
set "TARGET_DATE="
set "START_TIME="
set "RAW_TYPE="
set "HAS_ARGS=0"

for %%A in ("%~1" "%~2" "%~3") do (
    set "ARG=%%~A"
    if not "!ARG!"=="" (
        set "HAS_ARGS=1"
        set "IS_TYPE="
        for %%T in (traffic threat system config all 1 2 3 4 5) do (
            if /i "!ARG!"=="%%T" set "IS_TYPE=1"
        )
        if "!IS_TYPE!"=="1" (
            set "RAW_TYPE=!ARG!"
        ) else (
            echo "!ARG!" | findstr ":" >nul
            if !errorlevel! equ 0 (
                set "START_TIME=!ARG!"
            ) else (
                set "TARGET_DATE=!ARG!"
            )
        )
    )
)

:: 若有傳入任何參數，直接進入智慧預設組裝
if "!HAS_ARGS!"=="1" (
    if "!TARGET_DATE!"=="" set "TARGET_DATE=!TODAY!"
    if "!START_TIME!"=="" (
        if "!TARGET_DATE!"=="!TODAY!" (
            set "START_TIME=!CUR_TIME!"
        ) else (
            set "START_TIME=23:59:59"
        )
    )
    if /i "!RAW_TYPE!"=="threat" set "TARGET_TYPE=threat"
    if /i "!RAW_TYPE!"=="2" set "TARGET_TYPE=threat"
    if /i "!RAW_TYPE!"=="system" set "TARGET_TYPE=system"
    if /i "!RAW_TYPE!"=="3" set "TARGET_TYPE=system"
    if /i "!RAW_TYPE!"=="config" set "TARGET_TYPE=config"
    if /i "!RAW_TYPE!"=="4" set "TARGET_TYPE=config"
    if /i "!RAW_TYPE!"=="all" set "TARGET_TYPE=all"
    if /i "!RAW_TYPE!"=="5" set "TARGET_TYPE=all"
    if "!TARGET_TYPE!"=="" set "TARGET_TYPE=traffic"
    goto :START_RUN
)

:PROMPT_USER
echo.
set "USER_IN_DATE="
set /p USER_IN_DATE="請輸入回溯日期 [格式 YYYY-MM-DD，直接按 Enter 預設為今日 !TODAY!]: "
if not "!USER_IN_DATE!"=="" (
    set "TARGET_DATE=!USER_IN_DATE!"
) else (
    set "TARGET_DATE=!TODAY!"
)

set "DEFAULT_START=!CUR_TIME!"
if not "!TARGET_DATE!"=="!TODAY!" set "DEFAULT_START=23:59:59"

set "USER_IN_TIME="
set /p USER_IN_TIME="請輸入起點時間 [格式 HH:MM:SS，直接按 Enter 預設自 !DEFAULT_START! 開始]: "
if not "!USER_IN_TIME!"=="" (
    set "START_TIME=!USER_IN_TIME!"
) else (
    set "START_TIME=!DEFAULT_START!"
)

echo.
echo 請選擇回溯類型：
echo 1. 連線流量日誌 (traffic) [預設]
echo 2. 資安威脅日誌 (threat)
echo 3. 系統紀錄日誌 (system)
echo 4. 組態變更日誌 (config)
echo 5. 執行全部四大日誌 (ALL: config -^> system -^> threat -^> traffic)

set "TYPE_CHOICE="
set /p TYPE_CHOICE="請選擇 (1-5): "
if "!TYPE_CHOICE!"=="2" (
    set "TARGET_TYPE=threat"
) else if "!TYPE_CHOICE!"=="3" (
    set "TARGET_TYPE=system"
) else if "!TYPE_CHOICE!"=="4" (
    set "TARGET_TYPE=config"
) else if "!TYPE_CHOICE!"=="5" (
    set "TARGET_TYPE=all"
) else (
    set "TARGET_TYPE=traffic"
)

:START_RUN
if "!TARGET_TYPE!"=="all" (
    call :RUN_LOG_TASK "config"
    call :RUN_LOG_TASK "system"
    call :RUN_LOG_TASK "threat"
    call :RUN_LOG_TASK "traffic"
    echo.
    echo ========================================================
    echo  🎉 全部四大日誌回溯任務全數圓滿完成！
    echo ========================================================
    pause
    exit /b 0
) else (
    call :RUN_LOG_TASK "!TARGET_TYPE!"
    echo.
    echo ========================================================
    echo  🎉 回溯任務執行完畢。
    echo ========================================================
    pause
    exit /b 0
)

:: ========================================================
:: 核心回溯子函式
:: ========================================================
:RUN_LOG_TASK
set "CURRENT_TYPE=%~1"
set "LABEL=連線流量日誌 [Traffic]"
set "API_ENDPOINT=traffic-backfill"

if "!CURRENT_TYPE!"=="threat" (
    set "LABEL=資安威脅日誌 [Threat]"
    set "API_ENDPOINT=threat-backfill"
)
if "!CURRENT_TYPE!"=="system" (
    set "LABEL=系統日誌 [System]"
    set "API_ENDPOINT=system-backfill"
)
if "!CURRENT_TYPE!"=="config" (
    set "LABEL=組態變更日誌 [Config]"
    set "API_ENDPOINT=config-backfill"
)

echo.
echo ========================================================
echo [任務設定] 目標類型：!LABEL!
echo [任務設定] 回溯日期：!TARGET_DATE!
echo [任務設定] 起點模式：!START_TIME! (自 !TARGET_DATE! !START_TIME! 向前完整倒推)
echo [任務設定] 終點邊界：!TARGET_DATE! 00:00:00 (抵達即自動停止)
echo ========================================================

set "URL_BEFORE=!TARGET_DATE!+!START_TIME: =+!"
set "REQ_PARAM=rounds=5&date=!TARGET_DATE!&before=!URL_BEFORE!"
set "BATCH_COUNT=0"
set "LAST_RECORD_TIME="

:BACKFILL_LOOP
set /a BATCH_COUNT+=1
echo --------------------------------------------------------
echo [!TIME:~0,8!] 批次 #!BATCH_COUNT!: 正在向前接力 (5 輪 / 25,000 筆)...

if exist backfill_status.txt del backfill_status.txt

curl.exe -N -X POST "http://127.0.0.1:5006/api/!API_ENDPOINT!?!REQ_PARAM!"
echo.

if not exist backfill_status.txt (
    echo.
    echo ⚠️ 未收到後端進度更新，請確認 PA1420_Monitor.exe 是否正常運行中。
    exit /b 1
)

set "STATUS_TIME="
set /p STATUS_TIME=<backfill_status.txt

:: 🌟 核心修復：使用安全方括號，徹底解決 CMD 括號閉合語法中斷問題
if "!STATUS_TIME!"=="LIMIT" (
    echo.
    echo [提示] 防火牆回報歷史日誌已達邊界 [00:00:00] 或抵達儲存極限！
    goto :TASK_DONE
)

if "!STATUS_TIME!"=="" (
    echo [提示] 推進時間為空，任務終止。
    goto :TASK_DONE
)

if not "!LAST_RECORD_TIME!"=="" if "!STATUS_TIME!"=="!LAST_RECORD_TIME!" (
    echo.
    echo [提示] 推進時間點未發生變化，日誌已完整涵蓋。
    goto :TASK_DONE
)

set "LAST_RECORD_TIME=!STATUS_TIME!"
set "URL_BEFORE=!STATUS_TIME: =+!"
set "REQ_PARAM=rounds=5&date=!TARGET_DATE!&before=!URL_BEFORE!"

echo [保護機制] 冷卻 !COOLDOWN_SEC! 秒，防止 !FW_MODEL! CPU 過載...
timeout /t !COOLDOWN_SEC! /nobreak >nul
goto :BACKFILL_LOOP

:TASK_DONE
exit /b 0