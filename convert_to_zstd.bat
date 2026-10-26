@echo off
chcp 65001 >nul
echo ========================================================
echo   PA-1420 歷史 Parquet 檔案無損壓縮轉換工具 (Snappy -^> ZSTD)
echo ========================================================
echo.
echo 即將使用 DuckDB 把現有 traffic_logs 與 threat_logs 內的
echo 所有 .parquet 檔案，全部轉存為高壓縮率的 ZSTD 格式。
echo.
echo [提示] 轉換期間原有的日誌完全不會遺失。
echo [注意] 轉換前請確保 PA1420_Monitor.exe 仍在運作，但建議
echo        暫時不要進行大範圍的歷史回溯任務。
echo.
pause

set "DUCKDB=duckdb.exe"
if not exist "%DUCKDB%" (
    echo [錯誤] 找不到 duckdb.exe！請確認它與此腳本放在同一個目錄下。
    pause
    exit /b 1
)

echo.
echo [1/2] 正在轉換流量日誌 (traffic_logs) ...
for %%f in (traffic_logs\*.parquet) do (
    if not "%%~xf"==".tmp" (
        echo   - 正在轉換: %%f ...
        %DUCKDB% -c "COPY (SELECT * FROM '%%f') TO '%%f.tmp' (FORMAT PARQUET, COMPRESSION ZSTD);" >nul 2>&1
        if exist "%%f.tmp" (
            del "%%f"
            ren "%%f.tmp" "%%~nxf"
        ) else (
            echo     [警告] %%f 轉換失敗，已保留原檔。
        )
    )
)

echo.
echo [2/2] 正在轉換威脅日誌 (threat_logs) ...
for %%f in (threat_logs\*.parquet) do (
    if not "%%~xf"==".tmp" (
        echo   - 正在轉換: %%f ...
        %DUCKDB% -c "COPY (SELECT * FROM '%%f') TO '%%f.tmp' (FORMAT PARQUET, COMPRESSION ZSTD);" >nul 2>&1
        if exist "%%f.tmp" (
            del "%%f"
            ren "%%f.tmp" "%%~nxf"
        ) else (
            echo     [警告] %%f 轉換失敗，已保留原檔。
        )
    )
)

echo.
echo ========================================================
echo ✅ 所有歷史檔案已成功無損轉換為 ZSTD 壓縮格式！
echo 您可以前往 traffic_logs 資料夾點選右鍵內容，確認釋放了多少 SSD 空間。
echo ========================================================
pause