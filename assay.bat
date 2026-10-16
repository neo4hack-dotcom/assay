@echo off
REM Assay command line on Windows, e.g.:  assay scan C:\repos\orders-mcp --out reports
setlocal
set ROOT=%~dp0
if not exist "%ROOT%.venv\Scripts\python.exe" (echo Run run.bat once first to install Assay. & exit /b 1)
set PYTHONPATH=%ROOT%backend
"%ROOT%.venv\Scripts\python.exe" -m app.cli %*
