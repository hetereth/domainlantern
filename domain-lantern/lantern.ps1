$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
Set-Location $PSScriptRoot

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$venvCommand = Join-Path $PSScriptRoot ".venv\Scripts\domain-lantern.exe"
if (Test-Path $venvPython) {
    & $venvCommand "--interactive" "--plain"
} else {
    Write-Host "First run install.cmd, then lantern.ps1 again."
}
