@echo off
REM Assay — start the web UI on Windows (double-click or run from cmd).
setlocal
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
if not exist ".venv\Scripts\python.exe" (
  echo [assay] Creating virtual environment...
  %PY% -m venv .venv || (echo Python 3.11+ is required: https://www.python.org/downloads/ & pause & exit /b 1)
  ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt || (echo Dependency installation failed. & pause & exit /b 1)
)
if not exist "frontend\dist\index.html" echo [assay] WARNING: frontend\dist is missing - the API runs but the UI needs "npm run build" in frontend\.
cd backend
"..\.venv\Scripts\python.exe" -m app.cli serve --open %*
