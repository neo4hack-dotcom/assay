# Assay — start the web UI from PowerShell:  .\run.ps1   (or: .\run.ps1 --host 0.0.0.0 --port 3101)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[assay] Creating virtual environment..."
    if ($py -eq "py") { & py -3 -m venv .venv } else { & python -m venv .venv }
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Null
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}
if (-not (Test-Path "frontend\dist\index.html")) { Write-Warning "frontend\dist is missing: run 'npm ci; npm run build' in frontend\" }
Set-Location backend
& ..\.venv\Scripts\python.exe -m app.cli serve --open @args
