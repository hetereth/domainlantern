@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"

where py > nul 2> nul
if %errorlevel%==0 (
  py -m venv .venv
) else (
  python -m venv .venv
)

".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -e .

echo.
echo Domain Lantern installed.
echo Start it with: RUN.cmd
