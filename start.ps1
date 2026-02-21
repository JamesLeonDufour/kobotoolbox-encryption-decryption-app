param(
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

$appFile = 'app.py'
$requirements = 'requirements.txt'
$venvDir = '.venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'

if (-not (Test-Path $appFile) -or -not (Test-Path $requirements)) {
  Write-Error 'Run this script from the project root (where app.py and requirements.txt exist).'
}

$pythonCmd = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
  $pythonCmd = 'py -3'
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $pythonCmd = 'python'
} else {
  Write-Error 'Python 3.10+ not found. Install Python and try again.'
}

Write-Host 'Creating virtual environment (if needed)...'
Invoke-Expression "$pythonCmd -m venv $venvDir"

Write-Host 'Installing dependencies...'
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r $requirements

Write-Host ''
Write-Host 'Starting app...'
Write-Host 'Open: http://localhost:8501'

if ($NoBrowser) {
  & $venvPython -m streamlit run $appFile --server.headless true
} else {
  & $venvPython -m streamlit run $appFile
}
