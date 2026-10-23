@echo off
chcp 65001 >nul
title PA-1420 批次歷史回溯工具

set RUN_TIMES=%1
set TARGET_TYPE=%2
set TARGET_CHOICE=

:: 若未帶參數執行，進入互動式輸入
if "%RUN_TIMES%"=="" (
    echo ========================================================
    echo        PA-1420 歷史日誌自動接力回溯工具
    echo ========================================================
    set /p RUN_TIMES=請輸入要執行幾次 5 輪 [例如輸入 3 代表 75,000 筆]: 
    set /p TARGET_CHOICE=請選擇回溯類型 [1-流量日誌  2-資安威脅日誌]: 
)

:: 辨識回溯類型 (支援輸入 threat / traffic 或代號 1 / 2)
if "%TARGET_CHOICE%"=="2" set TARGET_TYPE=threat
if "%TARGET_CHOICE%"=="1" set TARGET_TYPE=traffic
if "%TARGET_TYPE%"=="2" set TARGET_TYPE=threat
if "%TARGET_TYPE%"=="1" set TARGET_TYPE=traffic
if "%TARGET_TYPE%"=="" set TARGET_TYPE=traffic

set ENDPOINT=api/traffic-backfill
set TYPE_NAME=連線流量日誌 [Traffic]

if /I "%TARGET_TYPE%"=="threat" (
    set ENDPOINT=api/threat-backfill
    set TYPE_NAME=資安威脅日誌 [Threat]
)

echo.
echo ========================================================
echo 🎯 目標類型：%TYPE_NAME%
echo 🔄 預計次數：%RUN_TIMES% 次 [每次 5 輪 = 25,000 筆]
echo ========================================================
echo.

setlocal enabledelayedexpansion
for /L %%i in (1, 1, %RUN_TIMES%) do (
    echo --------------------------------------------------------
    echo [!TIME:~0,8!] ⏳ 正在執行第 %%i/%RUN_TIMES% 次回溯 [5 輪 / 25,000 筆]...
    curl.exe -N -s -X POST "http://127.0.0.1:5006/%ENDPOINT%" -d "rounds=5"
    echo.

    if %%i LSS %RUN_TIMES% (
        echo [保護機制] ❄️ 冷卻 3 秒，防止 PA-1420 管理 CPU 過載...
        timeout /t 3 /nobreak >nul
    )
)
endlocal

echo --------------------------------------------------------
echo ✅ 所有批次執行完成！
echo.
pause