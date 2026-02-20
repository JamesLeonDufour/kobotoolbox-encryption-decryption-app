# KoboToolbox Decryption App

A Streamlit web application for encrypting and decrypting KoboToolbox form submissions using RSA and AES encryption.

## Features

- **Connect to KoboToolbox** - Authenticate with your KoboToolbox server
- **Project Selection** - Choose an encrypted project to decrypt
- **API Decryption** - Fetch encrypted submissions and attachments directly from the API
- **Batch Decryption** - Decrypt multiple encrypted submissions at once
- **Table Preview** - View decrypted data in a table
- **Excel Export** - Download decrypted data as an XLSX file

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
2. Copy the public key (for KoboToolbox form settings)
3. Download the private and public key PEMs (keep the private key safe)

### Step 2: Configure Your Form in KoboToolbox

1. In KoboToolbox, go to your form's **Settings** -> **Encryption**
2. Enable encryption
3. Paste the public key you generated
4. Redeploy the form

### Step 3: Connect, Select, Decrypt

1. In the sidebar, enter your server URL (e.g., https://kf.kobotoolbox.org)
2. Enter your API token and click **Connect**
3. Select the project
4. Upload your private key
5. Click **Decrypt All Records**
6. Review the decrypted table
7. Download the decrypted XLSX

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

## Project Structure

```
kobo-encrypt/
|-- app.py                 # Main Streamlit application
|-- requirements.txt       # Python dependencies
|-- README.md              # This file
|-- .gitignore             # Git ignore rules
|-- AGENTS.md              # AI agent guidance

```


## Future Development Ideas

- **Push public key to KoboToolbox form settings**: Automate enabling encryption by updating the form settings from the app.
- **Redeploy from the app**: Trigger a redeploy after updating encryption settings.
- **Handle encrypted media attachments**: Decrypt and export photo/audio/video attachments alongside submission XML.

These are good next steps, but they depend on KoboToolbox API support and permissions for updating form settings and redeploying. If your server exposes those endpoints, we can wire them into the app.

## License

MIT License
