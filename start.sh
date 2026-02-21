#!/usr/bin/env bash
set -euo pipefail

APP_FILE="app.py"
REQUIREMENTS_FILE="requirements.txt"
VENV_DIR=".venv"

if [ ! -f "$APP_FILE" ] || [ ! -f "$REQUIREMENTS_FILE" ]; then
  echo "Error: run this script from the project root (where app.py exists)."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is not installed or not in PATH."
  echo "Install Python 3.10+ and try again."
  echo "Windows users in PowerShell should run: ./start.ps1"
  exit 1
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  echo "Detected WSL/Linux environment."
fi

echo "Creating virtual environment (if needed)..."
if ! python3 -m venv "$VENV_DIR"; then
  echo
  echo "Failed to create virtual environment with python3 -m venv."
  echo "If you are on Debian/Ubuntu/WSL, install venv support first:"
  echo "  sudo apt update && sudo apt install python3-venv"
  echo
  echo "If you are on Windows PowerShell, run:"
  echo "  ./start.ps1"
  exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r "$REQUIREMENTS_FILE"

echo
echo "Starting app..."
echo "Open: http://localhost:8501"
exec streamlit run "$APP_FILE"
