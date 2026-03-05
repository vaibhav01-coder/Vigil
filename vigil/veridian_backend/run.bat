@echo off
setlocal

REM Simple UAC elevation launcher for VERIDIAN backend.

cd /d "%~dp0"

REM Try to run main.py as administrator via PowerShell.
powershell -Command "Start-Process python 'main.py' -Verb RunAs"

endlocal

