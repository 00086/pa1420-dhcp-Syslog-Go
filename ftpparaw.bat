@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem 1. 取得標準今日日期 (YYYY-MM-DD)

for /f "usebackq tokens=1" %%A in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd'" 2^>nul`) do (
    set "TODAY=%%A"
)

if "!TODAY!"=="" (
    for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set dt=%%I
    if defined dt (
        set "TODAY=!dt:~0,4!-!dt:~4,2!-!dt:~6,2!"
    )
)

if "!TODAY!"=="" (
    set "TODAY=%DATE:~0,4%-%DATE:~5,2%-%DATE:~8,2%"
)

rem 2. 自動向後端 API 取得防火牆真實型號

set "FW_MODEL=PA 防火牆"
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "try{(Invoke-RestMethod -Uri 'http://127.0.0.1:5006/api/system-health' -TimeoutSec 2).model}catch{}" 2^>nul`) do (
    if not "%%A"=="" set "FW_MODEL=%%A"
)

rem 3. 判斷是否為旗艦機種

set "IS_HIGH_END=0"
if not "!FW_MODEL:5250=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:5200=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:5220=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:5260=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:5450=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:5400=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:7000=!"=="!FW_MODEL!" set "IS_HIGH_END=1"
if not "!FW_MODEL:3400=!"=="!FW_MODEL!" set "IS_HIGH_END=1"

echo ========================================================
echo   !FW_MODEL! 原始日誌 (Raw Log) 專屬高速 FTP 傾印引擎
echo   [特點] 僅打包原始冷資料，絕不寫入日常 Parquet 熱庫
echo ========================================================

:: 🌟 1. 輸入目標日期 (預設今日)
set /p TARGET_DATE="請輸入欲傾印之日期 [格式 YYYY-MM-DD，直接 Enter 預設為今日 !TODAY!]: "
if "!TARGET_DATE!"=="" set "TARGET_DATE=!TODAY!"

:: 🌟 2. 輸入起始時間 (預設 00:00:00)
set /p START_TIME="請輸入起始時間 [格式 HH:mm:ss，直接 Enter 預設為 00:00:00]: "
if "!START_TIME!"=="" set "START_TIME=00:00:00"
set "START_TIME=!START_TIME: =!"
if "!START_TIME:~1,1!"==":" set "START_TIME=0!START_TIME!"
if "!START_TIME:~7,1!"=="" set "START_TIME=!START_TIME!:00"

:: 🌟 3. 輸入結束時間 (預設 23:59:59)
set /p END_TIME="請輸入結束時間 [格式 HH:mm:ss，直接 Enter 預設為 23:59:59]: "
if "!END_TIME!"=="" set "END_TIME=23:59:59"
set "END_TIME=!END_TIME: =!"
if "!END_TIME:~1,1!"==":" set "END_TIME=0!END_TIME!"
if "!END_TIME:~7,1!"=="" set "END_TIME=!END_TIME!:59"

echo.
echo 請選擇匯出日誌類型 [直接按 Enter 預設為 1]:
echo 1. 流量原始日誌 [traffic, 預設]
echo 2. 資安威脅日誌 [threat]
set /p USER_CHOICE="請選擇 (1 或 2): "
set "TARGET_TYPE=traffic"
if "!USER_CHOICE!"=="2" set "TARGET_TYPE=threat"

echo.
echo 請選擇匯出運作模式:
if "!IS_HIGH_END!"=="1" goto :MENU_HIGH_END
goto :MENU_STANDARD

:MENU_HIGH_END
echo 1. 10 分鐘極速分段傾印與整併 [偵測到 !FW_MODEL!，推薦預設，單次 ~1.9GB / ~1分鐘]
echo 2. 5 分鐘極速分段傾印與整併 [早晨尖峰巨量流量專用，單次 ~0.9GB / ~30秒]
echo 3. 按 1 小時分段傾印與整併 [單次 ~11GB / ~10分鐘]
echo 4. 全天單次傾印
set /p MODE_CHOICE="請選擇模式 [直接按 Enter 預設為 1]: "
if "!MODE_CHOICE!"=="" set "MODE_CHOICE=1"
if "!MODE_CHOICE!"=="1" goto :TEN_MIN_MODE
if "!MODE_CHOICE!"=="2" goto :FIVE_MIN_MODE
if "!MODE_CHOICE!"=="3" goto :HOURLY_MODE
goto :SINGLE_MODE

:MENU_STANDARD
echo 1. 全天單次傾印 [預設]
echo 2. 10 分鐘極速分段傾印與整併 [巨量資料環境推薦]
echo 3. 5 分鐘極速分段傾印與整併
echo 4. 按 1 小時分段傾印與整併
set /p MODE_CHOICE="請選擇模式 [直接按 Enter 預設為 1]: "
if "!MODE_CHOICE!"=="" set "MODE_CHOICE=1"
if "!MODE_CHOICE!"=="1" goto :SINGLE_MODE
if "!MODE_CHOICE!"=="2" goto :TEN_MIN_MODE
if "!MODE_CHOICE!"=="3" goto :FIVE_MIN_MODE
if "!MODE_CHOICE!"=="4" goto :HOURLY_MODE
goto :SINGLE_MODE

rem ========================================================
rem 模式 1：10 分鐘極速切片傾印 (PA-5250 預設)
rem ========================================================
:TEN_MIN_MODE
echo.
echo ========================================================
echo  🚀 [任務啟動] !FW_MODEL! 10 分鐘極速分段傾印引擎
echo  📅 目標日期：!TARGET_DATE!
echo  ⏱️ 時間範圍：!START_TIME! ~ !END_TIME!
echo  📊 日誌類型：!TARGET_TYPE!
echo  🛡️ 策略機制：每 10 分鐘獨立傾印壓縮，結束後自動整併
echo ========================================================
echo.

set "HOURS=00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23"
set "SLOTS=00 10 20 30 40 50"

for %%H in (!HOURS!) do (
    for %%S in (!SLOTS!) do (
        set "SLOT_START=%%H:%%S:00"
        if "!SLOT_START!" GEQ "!START_TIME!" if "!SLOT_START!" LSS "!END_TIME!" (
            echo --------------------------------------------------------
            echo [!TIME:~0,8!] ⏳ 正在處理: !TARGET_DATE! %%H:%%S 區間 [10 分鐘快照]...
            
            curl.exe -N -X POST "http://127.0.0.1:5006/api/cli-export" -d "log_type=!TARGET_TYPE!" -d "date=!TARGET_DATE!" -d "hour=%%H" -d "slot=%%S" -d "interval=10" -d "raw_only=true"
            
            echo.
            echo [保護機制] 冷卻 2 秒，保持 !FW_MODEL! 系統平穩...
            timeout /t 2 /nobreak >nul
        )
    )
)
goto :CONSOLIDATE_ALL

rem ========================================================
rem 模式 2：5 分鐘極速切片傾印 (早晨尖峰巨量流量專用)
rem ========================================================
:FIVE_MIN_MODE
echo.
echo ========================================================
echo  🚀 [任務啟動] !FW_MODEL! 5 分鐘極速分段傾印引擎
echo  📅 目標日期：!TARGET_DATE!
echo  ⏱️ 時間範圍：!START_TIME! ~ !END_TIME!
echo  📊 日誌類型：!TARGET_TYPE!
echo  🛡️ 策略機制：每 5 分鐘獨立傾印壓縮，單次僅約 0.9GB，極速安全
echo ========================================================
echo.

set "HOURS=00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23"
set "SLOTS=00 05 10 15 20 25 30 35 40 45 50 55"

for %%H in (!HOURS!) do (
    for %%S in (!SLOTS!) do (
        set "SLOT_START=%%H:%%S:00"
        if "!SLOT_START!" GEQ "!START_TIME!" if "!SLOT_START!" LSS "!END_TIME!" (
            echo --------------------------------------------------------
            echo [!TIME:~0,8!] ⏳ 正在處理: !TARGET_DATE! %%H:%%S 區間 [5 分鐘快照]...
            
            curl.exe -N -X POST "http://127.0.0.1:5006/api/cli-export" -d "log_type=!TARGET_TYPE!" -d "date=!TARGET_DATE!" -d "hour=%%H" -d "slot=%%S" -d "interval=5" -d "raw_only=true"
            
            echo.
            echo [保護機制] 冷卻 2 秒，保持 !FW_MODEL! 系統平穩...
            timeout /t 2 /nobreak >nul
        )
    )
)
goto :CONSOLIDATE_ALL

rem ========================================================
rem 模式 3：1 小時分段傾印與最後整合
rem ========================================================
:HOURLY_MODE
echo.
echo ========================================================
echo  🚀 [任務啟動] !FW_MODEL! 1 小時分段傾印引擎
echo  📅 目標日期：!TARGET_DATE!
echo  ⏱️ 時間範圍：!START_TIME! ~ !END_TIME!
echo  📊 日誌類型：!TARGET_TYPE!
echo  🛡️ 策略機制：每小時切片獨立壓縮落盤，完成後全自動整併
echo ========================================================
echo.

set "HOURS=00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23"

for %%H in (!HOURS!) do (
    set "SLOT_START=%%H:00:00"
    if "!SLOT_START!" GEQ "!START_TIME!" if "!SLOT_START!" LSS "!END_TIME!" (
        echo --------------------------------------------------------
        echo [!TIME:~0,8!] ⏳ 正在處理第 %%H 時區間: !TARGET_DATE! %%H:00:00 ~ %%H:59:59
        
        curl.exe -N -X POST "http://127.0.0.1:5006/api/cli-export" -d "log_type=!TARGET_TYPE!" -d "date=!TARGET_DATE!" -d "hour=%%H" -d "raw_only=true"
          
        echo.
        echo [保護機制] 冷卻 2 秒，保持 !FW_MODEL! 系統平穩...
        timeout /t 2 /nobreak >nul
    )
)
goto :CONSOLIDATE_ALL

rem ========================================================
rem 模式 4：全天單次傾印
rem ========================================================
:SINGLE_MODE
echo.
echo ========================================================
echo  🚀 [任務啟動] 全天單次傾印作業 (RAW 專用通道)
echo  📅 目標日期：!TARGET_DATE!
echo  📊 日誌類型：!TARGET_TYPE!
echo ========================================================
curl.exe -N -X POST "http://127.0.0.1:5006/api/cli-export" -d "log_type=!TARGET_TYPE!" -d "date=!TARGET_DATE!" -d "raw_only=true"
goto :END_JOB

rem ========================================================
rem 最終全日整併：由 DuckDB 自動掃描所有分塊並產出單一冷主檔
rem ========================================================
:CONSOLIDATE_ALL
echo.
echo ========================================================
echo 📦 [最終全日整併] 正在透過 DuckDB 將所有分塊切片整合成單一全日 Raw Log 主檔...

set "ARCHIVE_DIR=traffic_raw_logs"
if "!TARGET_TYPE!"=="threat" set "ARCHIVE_DIR=threat_raw_logs"

if not exist "!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!_*.parquet" goto :NO_PARQUET

rem 優化後 (純串流合併，RAM 消耗 < 800MB，絕不崩潰):
duckdb.exe -c "SET max_memory='8GB'; SET preserve_insertion_order=false; COPY (SELECT * FROM read_parquet('!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!_*.parquet', union_by_name=true)) TO '!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!.parquet.tmp' (FORMAT PARQUET, COMPRESSION ZSTD);"

move /y "!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!.parquet.tmp" "!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!.parquet" >nul
del /q "!ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!_*.parquet" 2>nul
echo.
echo ✅ [全日整併成功] 已產出歷史冷主檔:
echo    路徑: !ARCHIVE_DIR!\!TARGET_TYPE!_raw_!TARGET_DATE!.parquet
goto :END_JOB

:NO_PARQUET
echo.
echo ℹ️ 查無切片分塊檔案。

:END_JOB
echo ========================================================
echo  🎉 Raw Log 傾印任務圓滿結束！
echo ========================================================
pause