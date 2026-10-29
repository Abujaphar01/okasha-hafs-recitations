@echo off
title Sheikh Okasha Kameny - Hafs Recitations Web App
color 0A
echo ======================================================================
echo    SHEIKH OKASHA KAMENY - HAFS 'AN-ASIM RECITATIONS (WEB APP)
echo    Forensically Audited • 100%% Pure Hafs • PWA Offline Ready
echo ======================================================================
echo.
cd /d "%~dp0"

echo [1/2] Launching Web Browser at http://localhost:8000 ...
start http://localhost:8000

echo [2/2] Starting Local Web App Server on port 8000 ...
echo.
echo Press Ctrl+C in this window anytime to stop the server.
echo.

python -m http.server 8000

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [Notice] Python port 8000 busy or python not found, trying virtual environment...
    "..\.venv\Scripts\python.exe" -m http.server 8080
)
pause
