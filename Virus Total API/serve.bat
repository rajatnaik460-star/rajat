@echo off
setlocal enableextensions
cd /d "%~dp0"

set PORT=5500
set URL=http://localhost:%PORT%

start "Server" cmd /c python -m http.server %PORT% -d .

ping -n 2 127.0.0.1 >nul

start "" %URL%

echo Server started on %URL%
endlocal

