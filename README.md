# KoboToolbox Decryption App

A Streamlit web application for encrypting and decrypting KoboToolbox form submissions using RSA and AES encryption.

![App Screenshot](screenshot.png)

## Features

- **Connect to KoboToolbox** - Authenticate with your KoboToolbox server
- **Project Selection** - Choose an encrypted project to decrypt
- **Project Encryption Automation** - Push public key and redeploy directly from the app
- **API Decryption** - Fetch encrypted submissions and attachments directly from the API
- **Batch Decryption** - Decrypt multiple encrypted submissions at once
- **Encrypted Media Support** - Decrypt encrypted photo/audio/video attachments
- **Table Preview** - View decrypted data in a table
- **Excel Export** - Download decrypted data as an XLSX file
- **Media ZIP Export** - Download decrypted media files in a single ZIP package
- **Last Encryption Result Panel** - Shows form name, encrypted status, version, and private key download
- **Activity Terminal** - View all automation and decryption logs in one collapsible panel at the bottom of the page

## Requirements

- Python 3.10+
- Streamlit
- Cryptography library
- Requests library
- pandas
- openpyxl

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd kobo-encrypt

# Install dependencies
pip install -r requirements.txt
```

## Quick Start (One Command)

For beginners, use the helper launcher for your shell:

### Windows PowerShell

```powershell
.\start.ps1
```

If script execution is blocked:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

### Linux/macOS/Git Bash

```bash
# from project root
chmod +x start.sh
bash start.sh
```

If `chmod` is not needed on your shell, this is enough:

```bash
bash start.sh
```

What it does automatically:
- Creates `.venv` if missing
- Installs/updates dependencies
- Starts Streamlit app

## Usage

```bash
# Run the app
streamlit run app.py
```

The app will open in your browser at http://localhost:8501

## Getting Your KoboToolbox API Token

1. Log in to your KoboToolbox server
2. Go to **Account Settings** (click your username in the top right)
3. Click on the **Tokens** tab
4. Create a new token and copy it

## Workflow

### Step 1: Generate Encryption Keys

1. Click "Generate Key Pair" in the sidebar
2. The app auto-downloads both private and public PEM files
3. Copy the public key (for KoboToolbox form settings)

### Step 2: Configure Encryption (manual or automated)

Option A (manual in KoboToolbox):
1. In KoboToolbox, go to your form's **Settings** -> **Encryption**
2. Enable encryption
3. Paste the public key you generated
4. Redeploy the form

Option B (from this app):
1. Connect and select the project
2. Go to **Project Encryption**
3. Click **Push Public Key + Redeploy**
4. Review **Last Encryption Result** on the main page

### Step 3: Connect, Select, Decrypt

1. In the sidebar, enter your server URL (e.g., https://kf.kobotoolbox.org)
2. Enter your API token and click **Connect**
3. Select the project
4. Upload your private key
5. Click **Decrypt All Records**
6. Review the decrypted table
7. Download the decrypted XLSX
8. Download the decrypted media ZIP (if encrypted media exists)
9. Open **Activity Terminal** at the bottom of the page to inspect actions/errors in one place

## Security Notes

- **Never share your private key**
- The private key is used locally and never sent to any server
- Only the public key should be configured in KoboToolbox

## Troubleshooting

### "No encrypted records found"
- Ensure the form has encrypted submissions
- Confirm the API token can access the data endpoint

### "Key decryption failed"
- Verify you're using the correct private key for the form
- Check that the form wasn't redeployed with a different key

### "No download_url for attachment"
- Ensure the API token has access to the project data
- Some records may not have attachments; the app skips them safely

### "Permission denied while updating settings/redeploying"
- Your token does not have required project permissions
- Try with an owner/admin token for that project

### "Endpoint unsupported (404/405) during automation"
- Some self-hosted Kobo versions do not expose the same update/redeploy endpoints
- Use manual encryption settings and redeploy in KoboToolbox UI

### `bash start.sh` fails with `ensurepip is not available`
- You are likely using WSL/Linux Python without venv support.
- On Debian/Ubuntu/WSL, run:
  - `sudo apt update && sudo apt install python3-venv`
- On Windows PowerShell, use:
  - `.\start.ps1`

### Notes on public key format
- The app validates PEM keys but sends `settings.public_key` to Kobo API without `BEGIN/END` envelope lines.
- The app also sets `settings.submission_url` based on the connected server host.

## Project Structure

```
kobo-encrypt/
|-- app.py                 # Main Streamlit application
|-- requirements.txt       # Python dependencies
|-- start.sh               # Beginner one-command launcher
|-- start.ps1              # Beginner launcher for PowerShell
|-- README.md              # This file
|-- AGENTS.md              # Agent guidance
|-- .gitignore             # Git ignore rules

```

## License

MIT License
