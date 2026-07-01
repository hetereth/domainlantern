@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\domain-lantern.exe" --interactive --plain
) else (
  echo First run install.cmd, then RUN.cmd again.
  echo.
  pause
)
