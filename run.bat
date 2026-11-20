@echo off
cd /d "%~dp0"
echo ========================================================
echo  Website Guard - Fake Website Detection System
echo ========================================================
echo.
echo Starting local server on http://127.0.0.1:8000 ...
echo Press Ctrl+C in this window to stop the server.
echo.
start http://127.0.0.1:8000
.\.venv\Scripts\python.exe app.py
pause
