@echo off
chcp 65001 >nul
setlocal

set "TARGET_DATE=%~1"
set "ARG_TYPE=%~2"
set "TARGET_TYPE=traffic"

if not "%TARGET_DATE%"=="" goto :CHECK_ARGS

echo ========================================================
echo   PA-1420 高速日誌傾印與冷熱資料湖倉工具
echo ========================================================

:INPUT_DATE
set /p TARGET_DATE="請輸入匯出日期 [格式 YYYY-MM-DD，例如 2026-10-24]: "
if "%TARGET_DATE%"=="" (
    echo ❌ 錯誤：日期為必要欄位，不可留空！
    echo.
    goto :INPUT_DATE
)

echo.
echo 請選擇匯出日誌類型 [直接按 Enter 預設為 1]:
echo 1. 流量日誌 (traffic) [預設]
echo 2. 資安威脅日誌 (threat)
set /p USER_CHOICE="請選擇 (1 或 2): "
if "%USER_CHOICE%"=="2" (
    set "TARGET_TYPE=threat"
) else (
    set "TARGET_TYPE=traffic"
)
goto :START_JOB

:CHECK_ARGS
if /I "%ARG_TYPE%"=="threat" (
    set "TARGET_TYPE=threat"
) else (
    set "TARGET_TYPE=traffic"
)

:START_JOB
echo.
echo ========================================================
echo  🚀 [任務啟動] PA-1420 高速傾印與資料湖倉整合
echo  📅 目標日期：%TARGET_DATE%
echo  📊 日誌類型：%TARGET_TYPE%
echo  ⏳ 傳輸與轉檔進度將即時跳動顯示於下方...
echo ========================================================
echo.

:: 傳參極簡化：不再傳遞任何帳密與 ftp_host
curl.exe -N -X POST http://127.0.0.1:5006/api/cli-export ^
  -d "log_type=%TARGET_TYPE%" ^
  -d "date=%TARGET_DATE%" ^

echo.
echo ========================================================
echo  🎉 執行結束！
echo ========================================================
pause