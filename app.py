import io
import re
from datetime import datetime, timezone

import base64
import hashlib
import pandas as pd
import requests
import streamlit as st
import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad

# API request timeout
REQUEST_TIMEOUT = 30

# Set page config FIRST (required by Streamlit)
st.set_page_config(
    page_title="KoboToolbox Decryption App",
    layout="wide",
)

# Custom CSS for improved design
st.markdown("""
<style>
    /* Main title styling */
    .main-title {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 0;
    }
    .main-title img {
        height: 40px;
        width: 40px;
    }
    .main-title h1 {
        margin: 0;
        padding: 0;
        font-size: 28px;
        font-weight: 600;
        color: #1a1a2e;
    }
    
    /* Sidebar section headers */
    [data-testid="stSidebar"] .css-17lntkn {
        font-size: 14px;
        font-weight: 600;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: #f8f9fa;
        border-right: 1px solid #dee2e6;
    }
    
    /* Sidebar markdown headers */
    [data-testid="stSidebar"] h3 {
        color: #003f5c;
        font-size: 16px;
        font-weight: 600;
        margin-top: 20px;
        margin-bottom: 10px;
        padding-bottom: 8px;
        border-bottom: 2px solid #003f5c;
    }
    
    /* Button styling */
    div.stButton > button {
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    /* Primary button - KoboToolbox blue */
    div.stButton > button[kind="primary"] {
        background: #003f5c;
        border: none;
    }
    div.stButton > button[kind="primary"]:hover {
        background: #002a3f;
    }
    
    /* Status indicators */
    .status-connected {
        color: #28a745;
        font-weight: 600;
    }
    .status-disconnected {
        color: #dc3545;
        font-weight: 600;
    }
    
    /* Progress bar - KoboToolbox blue */
    .stProgress > div > div > div {
        background: #003f5c;
    }
    
    /* DataFrame styling */
    [data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }
    
    /* Info boxes */
    .info-box {
        background: #e7f3ff;
        border-left: 4px solid #003f5c;
        padding: 16px 20px;
        border-radius: 8px;
        margin: 12px 0;
    }
    .info-box h3 {
        margin-top: 0;
        color: #003f5c;
    }
    .info-box ol {
        margin-bottom: 0;
    }
    .info-box li {
        margin: 8px 0;
    }
    
    /* Warning boxes */
    .warning-box {
        background: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 8px 0;
    }
    
    /* Success boxes */
    .success-box {
        background: #d4edda;
        border-left: 4px solid #28a745;
        padding: 12px 16px;
        border-radius: 4px;
        margin: 8px 0;
    }
    
    /* Metric containers */
    [data-testid="stMetricValue"] {
        font-size: 16px;
    }
    
    /* Expander styling */
    [data-testid="stExpander"] {
        border-radius: 8px;
        border: 1px solid #e0e0e0;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        color: #666;
        padding: 20px;
    }
</style>
""", unsafe_allow_html=True)

st.title("KoboToolbox Decryption App")
st.markdown("---")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_server_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = f"https://{url}"
    return url.rstrip("/")


def normalize_instance_id(value: str | None) -> str | None:
    if not value:
        return None
    s = value.strip()
    if not s:
        return None
    if s.startswith("uuid:"):
        return s
    if re.fullmatch(r"[0-9a-fA-F-]{36}", s):
        return f"uuid:{s}"
    return s


def load_private_key(pem_bytes: bytes, password: str | None):
    pwd = password.encode() if password else None
    return serialization.load_pem_private_key(pem_bytes, password=pwd, backend=default_backend())


def decrypt_encrypted_key(b64_enc_key: str, private_key) -> tuple[bytes, str]:
    enc_key = base64.b64decode(b64_enc_key)
    attempts = [
        ("OAEP-SHA256-MGF1-SHA256", hashes.SHA256(), hashes.SHA256()),
        ("OAEP-SHA256-MGF1-SHA1", hashes.SHA256(), hashes.SHA1()),
        ("OAEP-SHA1-MGF1-SHA1", hashes.SHA1(), hashes.SHA1()),
        ("OAEP-SHA1-MGF1-SHA256", hashes.SHA1(), hashes.SHA256()),
    ]

    failures: list[str] = []
    for mode_name, algo, mgf_algo in attempts:
        try:
            return (
                private_key.decrypt(
                    enc_key,
                    asympad.OAEP(
                        mgf=asympad.MGF1(algorithm=mgf_algo),
                        algorithm=algo,
                        label=None,
                    ),
                ),
                mode_name,
            )
        except Exception as e:
            failures.append(f"{mode_name}: {e}")

    raise ValueError("Failed to decrypt AES key with OAEP variants. " + "; ".join(failures))


def rsa_plain_block_prefix_info(b64_enc_key: str, private_key) -> tuple[str, bool]:
    enc_key = base64.b64decode(b64_enc_key)
    numbers = private_key.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d
    k = (n.bit_length() + 7) // 8
    c = int.from_bytes(enc_key, "big")
    m = pow(c, d, n).to_bytes(k, "big")
    return m[:16].hex(), m[0] == 0


def safe_b64_decoded_length(value: str) -> int | None:
    try:
        return len(base64.b64decode(value))
    except Exception:
        return None


def key_fingerprint_sha256(private_key) -> str:
    spki_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def flatten_xml_fields(xml_bytes: bytes) -> dict[str, str]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise ValueError(f"XML parse error: {e}")

    def local_name(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    fields: dict[str, str] = {}
    counts: dict[str, int] = {}

    def add_field(path: str, value: str) -> None:
        key = path
        if key in fields:
            counts[key] = counts.get(key, 1) + 1
            key = f"{key}_{counts[key]}"
        fields[key] = value

    def walk(elem: ET.Element, prefix: str) -> None:
        children = list(elem)
        tag = local_name(elem.tag)
        path = f"{prefix}/{tag}" if prefix else tag
        if not children:
            text = (elem.text or "").strip()
            if text:
                add_field(path, text)
            return
        for child in children:
            walk(child, path)

    children = list(root)
    if children:
        for child in children:
            walk(child, "")
    else:
        walk(root, "")
    return fields


def derive_iv(instance_id: str, aes_key: bytes, file_index: int) -> bytes:
    seed = bytearray(hashlib.md5(instance_id.encode("utf-8") + aes_key).digest())
    for c in range(file_index):
        idx = c % 16
        seed[idx] = (seed[idx] + 1) % 256
    return bytes(seed)


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = sympad.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        return pkcs7_unpad(padded)
    except Exception:
        return padded


def extract_records_from_json_obj(data) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        items = data["results"]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    results: list[dict] = []
    for rec in items:
        if not isinstance(rec, dict):
            continue

        b64_key = rec.get("base64EncryptedKey")
        instance_id = (
            rec.get("meta/instanceID")
            or rec.get("meta/rootUuid")
            or rec.get("_uuid")
            or rec.get("meta", {}).get("instanceID")
            or rec.get("meta", {}).get("rootUuid")
        )
        instance_id = normalize_instance_id(instance_id)

        record_id = rec.get("_id") or rec.get("id")
        attachments = rec.get("_attachments") if isinstance(rec.get("_attachments"), list) else []
        submission_att = None
        media_count = 0
        for att in attachments:
            if not isinstance(att, dict):
                continue
            filename = att.get("filename", "") or ""
            basename = att.get("media_file_basename", "") or ""
            is_submission = (
                basename == "submission.xml.enc"
                or filename.endswith("/submission.xml.enc")
                or filename.endswith("\\submission.xml.enc")
            )
            if is_submission and submission_att is None:
                submission_att = att
            else:
                media_count += 1

        if b64_key and instance_id:
            results.append({
                "instance_id": instance_id,
                "b64_key": b64_key,
                "record_id": record_id,
                "media_count": media_count,
                "attachment_url": submission_att.get("download_url") if submission_att else None,
                "attachment_name": submission_att.get("filename") if submission_att else None,
            })

    return results


def fetch_kobo_assets(server_url: str, api_token: str) -> list[dict]:
    headers = {"Authorization": f"Token {api_token}"}
    resp = requests.get(f"{server_url}/api/v2/assets/", headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise ValueError(f"Assets fetch failed: {resp.status_code}")
    data = resp.json()
    return data.get("results", []) if isinstance(data, dict) else []


def fetch_kobo_data_records(server_url: str, api_token: str, asset_uid: str) -> list[dict]:
    headers = {"Authorization": f"Token {api_token}"}
    url = f"{server_url}/api/v2/assets/{asset_uid}/data/"
    records: list[dict] = []
    while url:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            raise ValueError(f"Data fetch failed: {resp.status_code}")
        data = resp.json()
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            records.extend(data["results"])
            url = data.get("next")
        elif isinstance(data, list):
            records.extend(data)
            url = None
        else:
            url = None
    return records


def fetch_kobo_record_attachments(
    server_url: str,
    api_token: str,
    asset_uid: str,
    record_id,
) -> list[dict]:
    headers = {"Authorization": f"Token {api_token}"}
    url = f"{server_url}/api/v2/assets/{asset_uid}/data/{record_id}/attachments/"
    resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise ValueError(f"Attachments fetch failed: {resp.status_code}")
    data = resp.json()
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    if isinstance(data, list):
        return data
    return []


def select_submission_attachment(attachments: list[dict]) -> dict | None:
    for att in attachments:
        if not isinstance(att, dict):
            continue
        filename = att.get("filename", "") or ""
        basename = att.get("media_file_basename", "") or ""
        is_submission = (
            basename == "submission.xml.enc"
            or filename.endswith("/submission.xml.enc")
            or filename.endswith("\\submission.xml.enc")
        )
        if is_submission:
            return att
    return None


def build_record_meta_map(records: list[dict]) -> dict[str, dict]:
    mapping: dict[str, dict] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        instance_id = (
            rec.get("meta/instanceID")
            or rec.get("meta/rootUuid")
            or rec.get("_uuid")
            or rec.get("meta", {}).get("instanceID")
            or rec.get("meta", {}).get("rootUuid")
        )
        instance_id = normalize_instance_id(instance_id)
        if not instance_id:
            continue
        record_id = rec.get("_id") or rec.get("id")
        attachments = rec.get("_attachments") if isinstance(rec.get("_attachments"), list) else []
        submission_att = select_submission_attachment(attachments) if attachments else None
        mapping[instance_id] = {
            "record_id": record_id,
            "attachment_url": submission_att.get("download_url") if submission_att else None,
            "attachment_name": submission_att.get("filename") if submission_att else None,
        }
    return mapping


# Session state
if "api_token" not in st.session_state:
    st.session_state.api_token = ""
if "server_url" not in st.session_state:
    st.session_state.server_url = ""
if "assets_cache" not in st.session_state:
    st.session_state.assets_cache = []
if "last_decrypt_log_text" not in st.session_state:
    st.session_state.last_decrypt_log_text = ""
if "last_decrypt_log_filename" not in st.session_state:
    st.session_state.last_decrypt_log_filename = ""
if "generated_private_pem" not in st.session_state:
    st.session_state.generated_private_pem = b""
if "generated_public_pem" not in st.session_state:
    st.session_state.generated_public_pem = b""
if "last_decrypted_rows" not in st.session_state:
    st.session_state.last_decrypted_rows = []
if "last_decrypted_excel_bytes" not in st.session_state:
    st.session_state.last_decrypted_excel_bytes = b""
if "last_decrypted_excel_filename" not in st.session_state:
    st.session_state.last_decrypted_excel_filename = ""

# Sidebar with improved sections
with st.sidebar:
    st.markdown("### Key Generation")
    with st.expander("Generate or Load Keys", expanded=False):
        if st.button("Generate Key Pair", use_container_width=True):
            try:
                priv_pem, pub_pem = generate_rsa_keypair()
                st.session_state.generated_private_pem = priv_pem
                st.session_state.generated_public_pem = pub_pem
                st.success("Key pair generated.")
            except Exception as e:
                st.error(f"Key generation failed: {e}")

        if st.session_state.generated_public_pem:
            st.text_area(
                "Public key (for KoboToolbox)",
                value=st.session_state.generated_public_pem.decode("utf-8", errors="replace"),
                height=120,
            )
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    "Download Private Key",
                    data=st.session_state.generated_private_pem,
                    file_name="private_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )
            with col2:
                st.download_button(
                    "Download Public Key",
                    data=st.session_state.generated_public_pem,
                    file_name="public_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )

    st.markdown("### Connection")
    server_url_input = st.text_input("Server URL", value=st.session_state.server_url, placeholder="https://kf.kobotoolbox.org")
    api_token_input = st.text_input("API Token", type="password", value=st.session_state.api_token, placeholder="Enter your API token")
    connect_clicked = st.button("Connect / Refresh", type="primary", use_container_width=True)

    if connect_clicked:
        server_url = normalize_server_url(server_url_input)
        if not server_url or not api_token_input:
            st.error("Server URL and API token are required.")
        else:
            try:
                assets = fetch_kobo_assets(server_url, api_token_input)
                st.session_state.server_url = server_url
                st.session_state.api_token = api_token_input
                st.session_state.assets_cache = assets
                st.success(f"Connected. Found {len(assets)} projects.")
            except Exception as e:
                st.error(f"Connection failed: {e}")

    st.markdown("### Project Selection")
    assets = st.session_state.assets_cache
    selected_asset_uid = ""
    selected_asset_name = ""
    if assets:
        choices = {a.get("name", a.get("uid", "(unnamed)")): a.get("uid") for a in assets}
        selected_asset_name = st.selectbox("Select project", list(choices.keys()))
        selected_asset_uid = choices.get(selected_asset_name) or ""
    else:
        st.info("Connect to load projects.")

    st.markdown("### Private Key")
    uploaded_key = st.file_uploader("Upload private key (PEM)", type="pem")
    key_password = st.text_input("Passphrase (if encrypted)", type="password")

    st.markdown("### Run Decryption")
    run_clicked = st.button("Decrypt All Records", type="primary", use_container_width=True)

# Main area
data_source = "API JSON"

# Status cards with better design
st.subheader("Status")
status_cols = st.columns(3)

# Server status
with status_cols[0]:
    server_status = st.session_state.server_url or 'not connected'
    is_connected = bool(st.session_state.server_url and st.session_state.api_token)
    st.metric(
        label="Server",
        value=server_status[:30] + "..." if len(server_status) > 30 else server_status,
        delta="Connected" if is_connected else "Disconnected"
    )

# Project status
with status_cols[1]:
    project_status = selected_asset_name or 'none'
    st.metric(
        label="Project",
        value=project_status[:30] + "..." if len(project_status) > 30 else project_status,
        delta=f"{len(st.session_state.assets_cache)} projects" if st.session_state.assets_cache else "No projects"
    )

# Data source status
with status_cols[2]:
    st.metric(
        label="Data Source",
        value=data_source,
        delta="Ready" if is_connected and selected_asset_uid else "Pending"
    )

st.markdown("---")

# Welcome/Instructions section when not running
if not st.session_state.last_decrypted_rows:
    st.markdown("""
    <div class="info-box">
        <h3>Getting Started</h3>
        <ol>
            <li><strong>Connect</strong> - Enter your KoboToolbox server URL and API token in the sidebar</li>
            <li><strong>Select Project</strong> - Choose an encrypted project from the dropdown</li>
            <li><strong>Upload Key</strong> - Upload your private key (.pem file) or generate a new key pair</li>
            <li><strong>Decrypt</strong> - Click "Decrypt All Records" to fetch and decrypt submissions</li>
            <li><strong>Export</strong> - Download the decrypted data as Excel</li>
        </ol>
        <p><em>Note: Your private key is used locally and never sent to any server.</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Quick help in columns
    help_cols = st.columns(3)
    with help_cols[0]:
        st.info("**Need Keys?**\n\nGenerate a new key pair in the sidebar, or use an existing private key.")
    with help_cols[1]:
        st.info("**API Token?**\n\nFind it in Account Settings -> Tokens on your KoboToolbox server.")
    with help_cols[2]:
        st.info("**Encrypted Data?**\n\nYour form must have encryption enabled in KoboToolbox settings.")

if run_clicked:
    if not st.session_state.server_url or not st.session_state.api_token:
        st.error("Please connect to KoboToolbox first. Check the sidebar.")
    elif not selected_asset_uid:
        st.error("Please select a project from the dropdown.")
    elif not uploaded_key and not st.session_state.generated_private_pem:
        st.error("Please upload a private key or generate a new key pair.")
    else:
        st.session_state.last_decrypted_rows = []
        st.session_state.last_decrypted_excel_bytes = b""
        st.session_state.last_decrypted_excel_filename = ""
        log_lines: list[str] = []
        key_decrypt_failures = 0
        rsa_prefix_nonzero_count = 0
        try:
            log_lines.append(f"run_started_utc={utc_now_iso()}")
            log_lines.append(f"server_url={st.session_state.server_url}")
            log_lines.append(f"asset_uid={selected_asset_uid}")
            log_lines.append(f"data_source={data_source}")

            # Load key
            key_source = "generated"
            if uploaded_key:
                key_source = "uploaded"
                try:
                    uploaded_key.seek(0)
                except Exception:
                    pass
                key_bytes = uploaded_key.read()
                key_pass = key_password or None
            else:
                key_bytes = st.session_state.generated_private_pem
                key_pass = None
            private_key = load_private_key(key_bytes, key_pass)
            log_lines.append(f"private_key_source={key_source}")
            log_lines.append(f"private_key_spki_sha256={key_fingerprint_sha256(private_key)}")

            # Fetch records
            json_records = fetch_kobo_data_records(
                st.session_state.server_url,
                st.session_state.api_token,
                selected_asset_uid,
            )
            records = extract_records_from_json_obj(json_records)

            record_meta_map = build_record_meta_map(json_records)
            attachments_cache: dict[str, dict | None] = {}
            log_lines.append(f"record_count={len(records)}")
            log_lines.append(f"attachment_map_count={len(record_meta_map)}")

            if not records:
                st.warning("No encrypted records found. Make sure the form has encryption enabled and contains submissions.")
            else:
                progress = st.progress(0)
                decrypted_rows: list[dict] = []
                success = 0
                failed = []
                total = len(records)
                for idx, rec in enumerate(records, start=1):
                    inst_id = rec["instance_id"]
                    b64k = rec["b64_key"]
                    mcount = rec.get("media_count", 0) or 0
                    key_blob_len = safe_b64_decoded_length(b64k)
                    log_lines.append(
                        f"record_{idx}_instance={inst_id} media_count={mcount} "
                        f"enc_key_b64_len={len(b64k)} enc_key_decoded_len={key_blob_len}"
                    )

                    try:
                        aes_key, oaep_mode = decrypt_encrypted_key(b64k, private_key)
                        log_lines.append(f"record_{idx}_key_decrypt=ok mode={oaep_mode} aes_len={len(aes_key)}")
                    except ValueError as e:
                        failed.append((inst_id, f"key decrypt: {e}"))
                        log_lines.append(f"record_{idx}_key_decrypt=fail error={e}")
                        try:
                            prefix_hex, starts_with_zero = rsa_plain_block_prefix_info(b64k, private_key)
                            log_lines.append(
                                f"record_{idx}_rsa_block_prefix16={prefix_hex} "
                                f"rsa_block_starts_with_00={starts_with_zero}"
                            )
                            if not starts_with_zero:
                                rsa_prefix_nonzero_count += 1
                        except Exception as prefix_error:
                            log_lines.append(f"record_{idx}_rsa_block_inspect_error={prefix_error}")
                        key_decrypt_failures += 1
                        progress.progress(idx / total)
                        continue

                    iv = derive_iv(inst_id, aes_key, mcount + 1)
                    log_lines.append(f"record_{idx}_iv={iv.hex()}")

                    meta = record_meta_map.get(inst_id) or {}
                    record_id = rec.get("record_id") or meta.get("record_id")
                    att_url = rec.get("attachment_url") or meta.get("attachment_url")
                    att_name = rec.get("attachment_name") or meta.get("attachment_name")
                    log_lines.append(f"record_{idx}_record_id={record_id}")
                    log_lines.append(f"record_{idx}_attachment_name={att_name}")

                    if not att_url and record_id:
                        cache_key = str(record_id)
                        if cache_key in attachments_cache:
                            submission_att = attachments_cache[cache_key]
                        else:
                            try:
                                attachments = fetch_kobo_record_attachments(
                                    st.session_state.server_url,
                                    st.session_state.api_token,
                                    selected_asset_uid,
                                    record_id,
                                )
                                submission_att = select_submission_attachment(attachments)
                                attachments_cache[cache_key] = submission_att
                            except Exception as e:
                                attachments_cache[cache_key] = None
                                log_lines.append(f"record_{idx}_attachment_lookup_error={e}")
                                submission_att = None

                        if submission_att:
                            att_url = submission_att.get("download_url")
                            att_name = submission_att.get("filename")
                            log_lines.append(f"record_{idx}_attachment_lookup=api")

                    if not att_url:
                        failed.append((inst_id, "submission.xml.enc download_url not found"))
                        log_lines.append(f"record_{idx}_attachment_url=missing")
                        progress.progress(idx / total)
                        continue

                    headers = {"Authorization": f"Token {st.session_state.api_token}"}
                    try:
                        resp = requests.get(att_url, headers=headers, timeout=REQUEST_TIMEOUT)
                        if resp.status_code != 200:
                            failed.append((inst_id, f"download status: {resp.status_code}"))
                            log_lines.append(f"record_{idx}_attachment_download_status={resp.status_code}")
                            progress.progress(idx / total)
                            continue
                        ciphertext = resp.content
                    except Exception as e:
                        failed.append((inst_id, f"download error: {e}"))
                        log_lines.append(f"record_{idx}_attachment_download_error={e}")
                        progress.progress(idx / total)
                        continue

                    try:
                        plaintext = aes_cfb_decrypt(ciphertext, aes_key, iv)
                        row = {"instance_id": inst_id}
                        if record_id is not None:
                            row["record_id"] = record_id
                        try:
                            row.update(flatten_xml_fields(plaintext))
                        except Exception as e:
                            row["_raw_xml"] = plaintext.decode("utf-8", errors="replace")
                            log_lines.append(f"record_{idx}_xml_parse_error={e}")
                        decrypted_rows.append(row)
                        log_lines.append(
                            f"record_{idx}_decrypt=ok ciphertext_len={len(ciphertext)} "
                            f"plaintext_len={len(plaintext)}"
                        )
                        success += 1
                    except Exception as e:
                        failed.append((inst_id, f"decrypt: {e}"))
                        log_lines.append(f"record_{idx}_decrypt=fail error={e}")

                    progress.progress(idx / total)

                log_lines.append(f"summary_success={success}")
                log_lines.append(f"summary_failed={len(failed)}")
                log_lines.append(f"summary_key_decrypt_failures={key_decrypt_failures}")
                log_lines.append(f"summary_rsa_prefix_nonzero_count={rsa_prefix_nonzero_count}")

                if success:
                    st.success(f"Decrypted {success} submission(s).")
                    export_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    st.session_state.last_decrypted_rows = decrypted_rows
                    df = pd.DataFrame(decrypted_rows)
                    excel_buf = io.BytesIO()
                    with pd.ExcelWriter(excel_buf, engine="openpyxl") as writer:
                        df.to_excel(writer, index=False, sheet_name="decrypted")
                    st.session_state.last_decrypted_excel_bytes = excel_buf.getvalue()
                    st.session_state.last_decrypted_excel_filename = f"decrypted_submissions_{export_stamp}.xlsx"
                if failed:
                    st.warning("Some records could not be decrypted:")
                    for inst, err in failed:
                        st.write(f"- {inst}: {err}")
                if key_decrypt_failures == len(records) and records:
                    st.error(
                        "All records failed at AES key decryption. This usually means the private key "
                        "does not match the key/version used to encrypt this form."
                    )
                    if rsa_prefix_nonzero_count == len(records):
                        st.error(
                            "Diagnostic signal: all raw RSA blocks fail to start with 0x00. "
                            "This strongly indicates private key mismatch (wrong key or wrong form version)."
                        )

        except Exception as e:
            st.error(f"Error: {e}")
            log_lines.append(f"fatal_error={e}")
        finally:
            if log_lines:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                st.session_state.last_decrypt_log_text = "\n".join(log_lines)
                st.session_state.last_decrypt_log_filename = f"decryption_log_{stamp}.txt"

if st.session_state.last_decrypted_rows:
    st.markdown("### Decrypted Data")
    df = pd.DataFrame(st.session_state.last_decrypted_rows)
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No data to display.")
    
    if st.session_state.last_decrypted_excel_bytes:
        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            st.download_button(
                "Download Excel (XLSX)",
                data=st.session_state.last_decrypted_excel_bytes,
                file_name=st.session_state.last_decrypted_excel_filename or "decrypted_submissions.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary",
                use_container_width=True,
            )

if st.session_state.last_decrypt_log_text:
    with st.expander("Decryption Log"):
        st.code(st.session_state.last_decrypt_log_text, language="text")
        st.download_button(
            "Download Log (TXT)",
            data=st.session_state.last_decrypt_log_text.encode("utf-8"),
            file_name=st.session_state.last_decrypt_log_filename or "decryption_log.txt",
            mime="text/plain",
            key="download_decryption_log",
            use_container_width=True,
        )

# Footer
st.markdown("""
---
<div style="text-align: center; color: #666; padding: 20px;">
    <p><strong>KoboToolbox Decryption App</strong> | Secure Local Decryption</p>
    <p><small>Your private key never leaves your browser. All decryption happens locally.</small></p>
</div>
""", unsafe_allow_html=True)
