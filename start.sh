#!/usr/bin/env bash
set -euo pipefail

APP_FILE="app.py"
REQUIREMENTS_FILE="requirements.txt"
VENV_DIR=".venv"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is not installed or not in PATH."
  echo "Install Python 3.10+ and try again."
  exit 1
fi

if [ ! -f "$APP_FILE" ] || [ ! -f "$REQUIREMENTS_FILE" ]; then
  echo "Error: run this script from the project root (where app.py exists)."
  exit 1
fi

echo "Creating virtual environment (if needed)..."
python3 -m venv "$VENV_DIR"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r "$REQUIREMENTS_FILE"

echo
echo "Starting app..."
echo "Open: http://localhost:8501"
exec streamlit run "$APP_FILE"
