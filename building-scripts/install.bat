REM Flow sketch: phase selection -> build/install action -> CLI availability
REM Pseudo-block:
REM   choose command -> run command -> return status

@echo off
setlocal
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1" %*
if errorlevel 1 (
  exit /b %errorlevel%
)
endlocal


