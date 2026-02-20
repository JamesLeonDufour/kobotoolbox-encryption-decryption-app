# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview
- **Type**: Python Streamlit web application for KoboToolbox encrypted form management
- **Run**: `streamlit run app.py`
- **Install**: `pip install -r requirements.txt`

## Non-Obvious Patterns

### OAEP Decryption Variants
KoboToolbox may use different OAEP padding variants. The [`decrypt_encrypted_key()`](app.py:56) function tries 4 combinations in order:
1. SHA256-SHA256, 2. SHA256-SHA1, 3. SHA1-SHA1, 4. SHA1-SHA256
Don't remove any variant—different servers use different ones.

### AES CFB Unpadding Edge Case
[`aes_cfb_decrypt()`](app.py:178) attempts PKCS7 unpadding but falls back to raw data if it fails. This is intentional—some encrypted data may not have padding.

### Instance ID Normalization
[`normalize_instance_id()`](app.py:38) adds `uuid:` prefix and validates UUID formats. Always use this when processing records.

### Server URL Handling
[`normalize_server_url()`](app.py:29) auto-prepends `https://` if missing and strips trailing slashes. Required for API calls to work.

### Streamlit Session State
All state is stored in `st.session_state`. No database. Session state persists only while the browser tab is open.

### Record Extraction Fallbacks
[`extract_records_from_json_obj()`](app.py:188) handles both dict-with-results and list formats from Kobo API. Uses multiple field names for instance ID (`meta/instanceID`, `meta/rootUuid`, `_uuid`).
