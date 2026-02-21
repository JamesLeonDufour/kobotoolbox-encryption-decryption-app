# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview
- **Type**: Python Streamlit web application for KoboToolbox encrypted form management
- **Run**: `streamlit run app.py`
- **Install**: `pip install -r requirements.txt`
- **Beginner run**: `bash start.sh`

## Non-Obvious Patterns

### OAEP Decryption Variants
KoboToolbox may use different OAEP padding variants. The `decrypt_encrypted_key()` function tries 4 combinations in order:
1. SHA256-SHA256
2. SHA256-SHA1
3. SHA1-SHA1
4. SHA1-SHA256

Do not remove any variant; different servers use different ones.

### AES CFB Unpadding Edge Case
`aes_cfb_decrypt()` attempts PKCS7 unpadding but falls back to raw data if it fails.
This is intentional; some encrypted data may not have padding.

### Instance ID Normalization
`normalize_instance_id()` adds `uuid:` prefix and validates UUID formats.
Always use this when processing records.

### Server URL Handling
`normalize_server_url()` auto-prepends `https://` if missing and strips trailing slashes.
Required for API calls to work.

### Public Key Push Format
When updating Kobo settings, the app validates PEM input but sends `settings.public_key` as key body only (without PEM envelope lines).
Do not reintroduce `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` into API payload values.

### Submission URL in Settings
The app sets `settings.submission_url` during encryption update.
It is derived from server URL host mapping (for example `kf.* -> kc.*`, `kf-* -> kc-*`) and suffixed with `/submission`.

### Redeploy Strategy
Redeploy currently prioritizes:
`PATCH /api/v2/assets/{uid_asset}/deployment/` with payload:
`{"active": true, "version_id": <asset version_id>}`

Fallback methods are attempted if needed.
A follow-up confirmation check validates deployment state changes.

### Streamlit Session State
All state is stored in `st.session_state`. No database.
Session state persists only while the browser tab is open.

### Automation Result Surface
After successful key push, the main page shows **Last Encryption Result** with:
- form name
- encrypted status
- version
- private key download (if available)

### Unified Logs
Automation and decryption logs are appended to one expandable **Terminal** panel on main page.
When adding new operations, append log lines via existing helper(s) so terminal remains the single source of truth.

### Record Extraction Fallbacks
`extract_records_from_json_obj()` handles both dict-with-results and list formats from Kobo API.
Uses multiple field names for instance ID (`meta/instanceID`, `meta/rootUuid`, `_uuid`).
