import io
import re
import copy
import zipfile
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
ERROR_DETAIL_LIMIT = 500

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


class KoboApiError(ValueError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        url: str | None = None,
        details: str | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.details = details or ""


def classify_http_status(status_code: int | None) -> str:
    if status_code in (401, 403):
        return "permission"
    if status_code in (404, 405):
        return "unsupported"
    if status_code in (409, 422):
        return "payload_or_state"
    if status_code is None:
        return "network"
    if 400 <= status_code < 500:
        return "client_error"
    if status_code >= 500:
        return "server_error"
    return "unknown"


def read_json_if_possible(resp: requests.Response):
    try:
        return resp.json()
    except Exception:
        return None


def short_error_detail(resp: requests.Response) -> str:
    data = read_json_if_possible(resp)
    if isinstance(data, dict):
        detail = data.get("detail") or data.get("message")
        if detail:
            return str(detail)[:ERROR_DETAIL_LIMIT]
    text = (resp.text or "").strip()
    if not text:
        return ""
    return text[:ERROR_DETAIL_LIMIT]


def kobo_request(
    method: str,
    url: str,
    api_token: str,
    json: dict | None = None,
    allow_statuses: set[int] | None = None,
) -> requests.Response:
    headers = {
        "Authorization": f"Token {api_token}",
        "Accept": "application/json",
    }
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=json,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        raise KoboApiError(f"Request failed: {e}", url=url) from e

    if allow_statuses and resp.status_code in allow_statuses:
        return resp
    if 200 <= resp.status_code < 300:
        return resp

    detail = short_error_detail(resp)
    msg = f"HTTP {resp.status_code}"
    if detail:
        msg = f"{msg} - {detail}"
    raise KoboApiError(msg, status_code=resp.status_code, url=url, details=detail)


def get_asset(server_url: str, api_token: str, asset_uid: str) -> dict:
    url = f"{server_url}/api/v2/assets/{asset_uid}/"
    resp = kobo_request("GET", url, api_token)
    data = read_json_if_possible(resp)
    if not isinstance(data, dict):
        raise KoboApiError("Asset response is not a JSON object.", status_code=resp.status_code, url=url)
    return data


def parse_allow_header(resp: requests.Response) -> set[str]:
    raw = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
    methods = set()
    for part in raw.split(","):
        method = part.strip().upper()
        if method:
            methods.add(method)
    return methods


def probe_endpoint_methods(url: str, api_token: str) -> dict:
    try:
        resp = kobo_request(
            "OPTIONS",
            url,
            api_token,
            allow_statuses={200, 204, 401, 403, 404, 405},
        )
        return {
            "url": url,
            "status_code": resp.status_code,
            "allow_methods": sorted(parse_allow_header(resp)),
            "error": "",
        }
    except KoboApiError as e:
        return {
            "url": url,
            "status_code": e.status_code,
            "allow_methods": [],
            "error": str(e),
        }


def probe_asset_update_capabilities(server_url: str, api_token: str, asset_uid: str) -> dict:
    asset_url = f"{server_url}/api/v2/assets/{asset_uid}/"
    deployment_url = f"{server_url}/api/v2/assets/{asset_uid}/deployment/"

    asset_readable = False
    asset_error = ""
    try:
        get_asset(server_url, api_token, asset_uid)
        asset_readable = True
    except KoboApiError as e:
        asset_error = str(e)

    asset_probe = probe_endpoint_methods(asset_url, api_token)
    deployment_probe = probe_endpoint_methods(deployment_url, api_token)
    asset_methods = set(asset_probe.get("allow_methods", []))
    deployment_methods = set(deployment_probe.get("allow_methods", []))

    return {
        "asset_readable": asset_readable,
        "asset_error": asset_error,
        "asset_probe": asset_probe,
        "deployment_probe": deployment_probe,
        "asset_patch": "PATCH" in asset_methods,
        "deployment_patch": "PATCH" in deployment_methods,
        "deployment_post": "POST" in deployment_methods,
    }


def normalize_public_key_pem(public_key_pem: bytes | str) -> str:
    if isinstance(public_key_pem, bytes):
        text = public_key_pem.decode("utf-8", errors="replace")
    else:
        text = public_key_pem
    text = text.strip()
    if not text:
        return ""
    return text + "\n"


def derive_public_key_from_private_pem(private_pem_bytes: bytes, password: str | None) -> bytes:
    private_key = load_private_key(private_pem_bytes, password or None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def make_encryption_payload_candidates(asset: dict, public_key_text: str) -> list[dict]:
    name = str(asset.get("name") or "").strip() or "Untitled Asset"
    content = copy.deepcopy(asset.get("content")) if isinstance(asset.get("content"), dict) else {}
    settings = content.get("settings")
    if not isinstance(settings, dict):
        settings = {}

    settings_a = copy.deepcopy(settings)
    settings_a["public_key"] = public_key_text
    settings_a["encrypted"] = True
    content_a = copy.deepcopy(content)
    content_a["settings"] = settings_a

    settings_b = copy.deepcopy(settings)
    settings_b["submission_encryption"] = {
        "enabled": True,
        "public_key": public_key_text,
    }
    content_b = copy.deepcopy(content)
    content_b["settings"] = settings_b

    settings_c = copy.deepcopy(settings)
    settings_c["public_key"] = public_key_text
    settings_c["submission_encryption"] = {
        "enabled": True,
        "public_key": public_key_text,
    }
    content_c = copy.deepcopy(content)
    content_c["settings"] = settings_c

    return [
        {
            "strategy": "asset_patch_name_content_public_key_encrypted",
            "payload": {"name": name, "content": content_a},
        },
        {
            "strategy": "asset_patch_name_content_submission_encryption",
            "payload": {"name": name, "content": content_b},
        },
        {
            "strategy": "asset_patch_name_content_combined_settings",
            "payload": {"name": name, "content": content_c},
        },
    ]


def update_encryption_settings(
    server_url: str,
    api_token: str,
    asset_uid: str,
    public_key_pem: bytes | str,
) -> dict:
    asset_url = f"{server_url}/api/v2/assets/{asset_uid}/"
    public_key_text = normalize_public_key_pem(public_key_pem)
    if not public_key_text:
        return {
            "ok": False,
            "status_code": None,
            "category": "payload_or_state",
            "strategy": "",
            "errors": [
                {
                    "strategy": "input_validation",
                    "status_code": None,
                    "category": "payload_or_state",
                    "message": "Public key is empty.",
                }
            ],
        }

    try:
        asset = get_asset(server_url, api_token, asset_uid)
    except KoboApiError as e:
        category = classify_http_status(e.status_code)
        return {
            "ok": False,
            "status_code": e.status_code,
            "category": category,
            "strategy": "",
            "errors": [
                {
                    "strategy": "get_asset",
                    "status_code": e.status_code,
                    "category": category,
                    "message": str(e),
                }
            ],
        }

    errors: list[dict] = []
    for candidate in make_encryption_payload_candidates(asset, public_key_text):
        strategy = candidate["strategy"]
        payload = candidate["payload"]
        try:
            resp = kobo_request("PATCH", asset_url, api_token, json=payload)
            body = read_json_if_possible(resp)
            return {
                "ok": True,
                "status_code": resp.status_code,
                "category": "success",
                "strategy": strategy,
                "errors": errors,
                "response": body if isinstance(body, dict) else {},
            }
        except KoboApiError as e:
            category = classify_http_status(e.status_code)
            errors.append(
                {
                    "strategy": strategy,
                    "status_code": e.status_code,
                    "category": category,
                    "message": str(e),
                }
            )
            if category in {"permission", "unsupported"}:
                break

    last_status = errors[-1]["status_code"] if errors else None
    return {
        "ok": False,
        "status_code": last_status,
        "category": classify_http_status(last_status),
        "strategy": "",
        "errors": errors,
    }


def trigger_redeploy(server_url: str, api_token: str, asset_uid: str) -> dict:
    deployment_url = f"{server_url}/api/v2/assets/{asset_uid}/deployment/"
    version_id = None
    try:
        asset = get_asset(server_url, api_token, asset_uid)
        version_id = asset.get("version_id")
    except KoboApiError:
        version_id = None

    candidates = [
        ("deployment_post_active", "POST", {"active": True}),
        ("deployment_patch_active", "PATCH", {"active": True}),
    ]
    if version_id:
        candidates.append(("deployment_patch_active_with_version", "PATCH", {"active": True, "version_id": version_id}))

    errors: list[dict] = []
    for strategy, method, payload in candidates:
        try:
            resp = kobo_request(method, deployment_url, api_token, json=payload)
            body = read_json_if_possible(resp)
            return {
                "ok": True,
                "status_code": resp.status_code,
                "category": "success",
                "strategy": strategy,
                "errors": errors,
                "response": body if isinstance(body, dict) else {},
            }
        except KoboApiError as e:
            category = classify_http_status(e.status_code)
            errors.append(
                {
                    "strategy": strategy,
                    "status_code": e.status_code,
                    "category": category,
                    "message": str(e),
                }
            )
            if category in {"permission", "unsupported"}:
                break

    last_status = errors[-1]["status_code"] if errors else None
    return {
        "ok": False,
        "status_code": last_status,
        "category": classify_http_status(last_status),
        "strategy": "",
        "errors": errors,
    }


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
            if is_submission_attachment(att) and submission_att is None:
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
    url = f"{server_url}/api/v2/assets/"
    assets: list[dict] = []
    while url:
        resp = kobo_request("GET", url, api_token)
        data = read_json_if_possible(resp)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            assets.extend(data["results"])
            url = data.get("next")
        elif isinstance(data, list):
            assets.extend(data)
            url = None
        else:
            url = None
    return assets


def fetch_kobo_data_records(server_url: str, api_token: str, asset_uid: str) -> list[dict]:
    url = f"{server_url}/api/v2/assets/{asset_uid}/data/"
    records: list[dict] = []
    while url:
        resp = kobo_request("GET", url, api_token)
        data = read_json_if_possible(resp)
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
    url = f"{server_url}/api/v2/assets/{asset_uid}/data/{record_id}/attachments/"
    resp = kobo_request("GET", url, api_token)
    data = read_json_if_possible(resp)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    if isinstance(data, list):
        return data
    return []


def is_submission_attachment(att: dict) -> bool:
    filename = att.get("filename", "") or ""
    basename = att.get("media_file_basename", "") or ""
    return (
        basename == "submission.xml.enc"
        or filename.endswith("/submission.xml.enc")
        or filename.endswith("\\submission.xml.enc")
    )


def is_encrypted_media_attachment(att: dict) -> bool:
    if not isinstance(att, dict):
        return False
    if is_submission_attachment(att):
        return False
    basename = str(att.get("media_file_basename") or "").strip()
    filename = str(att.get("filename") or "").strip()
    candidate = basename or filename.split("/")[-1].split("\\")[-1]
    return candidate.endswith(".enc")


def attachment_basename(att: dict, fallback: str) -> str:
    basename = str(att.get("media_file_basename") or "").strip()
    if basename:
        return basename
    filename = str(att.get("filename") or "").strip()
    if filename:
        return filename.split("/")[-1].split("\\")[-1]
    return fallback


def decrypted_media_name(att: dict, index: int) -> str:
    base = attachment_basename(att, f"media_{index}.bin.enc")
    if base.endswith(".enc"):
        base = base[:-4]
    if not base:
        base = f"media_{index}.bin"
    return base


def make_instance_folder(instance_id: str) -> str:
    return instance_id.replace("/", "_").replace("\\", "_")


def unique_zip_member_path(path: str, path_counts: dict[str, int]) -> str:
    count = path_counts.get(path, 0) + 1
    path_counts[path] = count
    if count == 1:
        return path

    if "." in path:
        stem, ext = path.rsplit(".", 1)
        return f"{stem}_{count}.{ext}"
    return f"{path}_{count}"


def append_automation_log_lines(lines: list[str]) -> None:
    if not lines:
        return
    combined = "\n".join(lines)
    existing = st.session_state.last_automation_log_text
    if existing:
        st.session_state.last_automation_log_text = f"{existing}\n{combined}"
    else:
        st.session_state.last_automation_log_text = combined
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    st.session_state.last_automation_log_filename = f"automation_log_{stamp}.txt"


def count_media_attachments(attachments: list[dict]) -> int:
    count = 0
    for att in attachments:
        if not isinstance(att, dict):
            continue
        if not is_submission_attachment(att):
            count += 1
    return count


def select_submission_attachment(attachments: list[dict]) -> dict | None:
    for att in attachments:
        if not isinstance(att, dict):
            continue
        if is_submission_attachment(att):
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
            "attachments": attachments,
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
if "automation_capabilities" not in st.session_state:
    st.session_state.automation_capabilities = {}
if "last_key_push_result" not in st.session_state:
    st.session_state.last_key_push_result = {}
if "last_redeploy_result" not in st.session_state:
    st.session_state.last_redeploy_result = {}
if "last_media_zip_bytes" not in st.session_state:
    st.session_state.last_media_zip_bytes = b""
if "last_media_zip_filename" not in st.session_state:
    st.session_state.last_media_zip_filename = ""
if "last_automation_log_text" not in st.session_state:
    st.session_state.last_automation_log_text = ""
if "last_automation_log_filename" not in st.session_state:
    st.session_state.last_automation_log_filename = ""
if "selected_asset_uid_for_automation" not in st.session_state:
    st.session_state.selected_asset_uid_for_automation = ""

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
                st.session_state.automation_capabilities = {}
                st.session_state.last_key_push_result = {}
                st.session_state.last_redeploy_result = {}
                st.success(f"Connected. Found {len(assets)} projects.")
            except Exception as e:
                st.error(f"Connection failed: {e}")

    st.markdown("### Project Selection")
    assets = st.session_state.assets_cache
    selected_asset_uid = ""
    selected_asset_name = ""
    if assets:
        asset_items = [
            {
                "uid": a.get("uid") or "",
                "name": a.get("name") or "(unnamed)",
            }
            for a in assets
        ]
        selected_asset = st.selectbox(
            "Select project",
            asset_items,
            format_func=lambda item: f"{item['name']} ({item['uid']})" if item["uid"] else item["name"],
        )
        if selected_asset:
            selected_asset_uid = selected_asset.get("uid") or ""
            selected_asset_name = selected_asset.get("name") or ""
    else:
        st.info("Connect to load projects.")

    if selected_asset_uid != st.session_state.selected_asset_uid_for_automation:
        st.session_state.selected_asset_uid_for_automation = selected_asset_uid
        st.session_state.automation_capabilities = {}
        st.session_state.last_key_push_result = {}
        st.session_state.last_redeploy_result = {}

    st.markdown("### Private Key")
    uploaded_key = st.file_uploader("Upload private key (PEM)", type="pem")
    key_password = st.text_input("Passphrase (if encrypted)", type="password")

    st.markdown("### Encryption Automation")
    can_automate = bool(st.session_state.server_url and st.session_state.api_token and selected_asset_uid)
    key_push_ok = bool(st.session_state.last_key_push_result.get("ok"))
    probe_caps_clicked = st.button("Probe API Capabilities", use_container_width=True, disabled=not can_automate)
    push_key_clicked = st.button("Push Public Key", use_container_width=True, disabled=not can_automate)
    confirm_redeploy = st.checkbox("I confirm redeploy now", value=False, disabled=not key_push_ok)
    redeploy_clicked = st.button(
        "Redeploy Form",
        use_container_width=True,
        disabled=not key_push_ok or not confirm_redeploy or not can_automate,
    )

    if probe_caps_clicked:
        if not can_automate:
            st.error("Connect to KoboToolbox and select a project first.")
        else:
            caps = probe_asset_update_capabilities(
                st.session_state.server_url,
                st.session_state.api_token,
                selected_asset_uid,
            )
            st.session_state.automation_capabilities = caps
            cap_lines = [
                f"probe_started_utc={utc_now_iso()}",
                f"asset_uid={selected_asset_uid}",
                f"asset_readable={caps.get('asset_readable')}",
                f"asset_patch={caps.get('asset_patch')}",
                f"deployment_post={caps.get('deployment_post')}",
                f"deployment_patch={caps.get('deployment_patch')}",
                f"asset_allow={','.join(caps.get('asset_probe', {}).get('allow_methods', []))}",
                f"deployment_allow={','.join(caps.get('deployment_probe', {}).get('allow_methods', []))}",
            ]
            if caps.get("asset_error"):
                cap_lines.append(f"asset_error={caps.get('asset_error')}")
            append_automation_log_lines(cap_lines)
            st.success("Capability probe finished.")

    if push_key_clicked:
        auto_lines = [f"key_push_started_utc={utc_now_iso()}", f"asset_uid={selected_asset_uid}"]
        if not can_automate:
            st.error("Connect to KoboToolbox and select a project first.")
            auto_lines.append("key_push_error=missing_connection_or_project")
        else:
            public_key_bytes = b""
            key_source = ""
            if st.session_state.generated_public_pem:
                public_key_bytes = st.session_state.generated_public_pem
                key_source = "generated_public_key"
            elif uploaded_key:
                try:
                    uploaded_key.seek(0)
                except Exception:
                    pass
                uploaded_bytes = uploaded_key.read()
                try:
                    public_key_bytes = derive_public_key_from_private_pem(uploaded_bytes, key_password or None)
                    key_source = "derived_from_uploaded_private_key"
                except Exception as e:
                    st.error(f"Could not derive public key from private key: {e}")
                    auto_lines.append(f"key_push_error=derive_public_key_failed:{e}")
            else:
                st.error("No public key available. Generate a key pair or upload a private key.")
                auto_lines.append("key_push_error=no_key_source")

            if public_key_bytes:
                result = update_encryption_settings(
                    st.session_state.server_url,
                    st.session_state.api_token,
                    selected_asset_uid,
                    public_key_bytes,
                )
                st.session_state.last_key_push_result = result
                st.session_state.last_redeploy_result = {}
                auto_lines.append(f"key_push_source={key_source}")
                auto_lines.append(f"key_push_ok={result.get('ok')}")
                auto_lines.append(f"key_push_strategy={result.get('strategy')}")
                auto_lines.append(f"key_push_status={result.get('status_code')}")
                if result.get("ok"):
                    st.success(f"Public key pushed successfully using strategy: {result.get('strategy')}")
                else:
                    category = result.get("category")
                    if category == "permission":
                        st.error("Permission denied while updating form settings (401/403).")
                    elif category == "unsupported":
                        st.error("This server does not support the required update endpoint (404/405).")
                    elif category == "payload_or_state":
                        st.error("Server rejected payload/state for key update (409/422).")
                    else:
                        st.error("Public key push failed.")
                    for err in result.get("errors", []):
                        auto_lines.append(
                            f"key_push_attempt strategy={err.get('strategy')} status={err.get('status_code')} "
                            f"category={err.get('category')} message={err.get('message')}"
                        )
        append_automation_log_lines(auto_lines)

    if redeploy_clicked:
        redeploy_lines = [f"redeploy_started_utc={utc_now_iso()}", f"asset_uid={selected_asset_uid}"]
        if not key_push_ok:
            st.error("Push public key first, then redeploy.")
            redeploy_lines.append("redeploy_error=key_not_pushed")
        else:
            result = trigger_redeploy(
                st.session_state.server_url,
                st.session_state.api_token,
                selected_asset_uid,
            )
            st.session_state.last_redeploy_result = result
            redeploy_lines.append(f"redeploy_ok={result.get('ok')}")
            redeploy_lines.append(f"redeploy_strategy={result.get('strategy')}")
            redeploy_lines.append(f"redeploy_status={result.get('status_code')}")
            if result.get("ok"):
                st.success(f"Redeploy triggered using strategy: {result.get('strategy')}")
            else:
                category = result.get("category")
                if category == "permission":
                    st.error("Permission denied while redeploying (401/403).")
                elif category == "unsupported":
                    st.error("Redeploy endpoint is not available on this server (404/405).")
                elif category == "payload_or_state":
                    st.error("Server rejected redeploy payload/state (409/422).")
                else:
                    st.error("Redeploy failed.")
                for err in result.get("errors", []):
                    redeploy_lines.append(
                        f"redeploy_attempt strategy={err.get('strategy')} status={err.get('status_code')} "
                        f"category={err.get('category')} message={err.get('message')}"
                    )
        append_automation_log_lines(redeploy_lines)

    if st.session_state.automation_capabilities:
        caps = st.session_state.automation_capabilities
        st.caption(
            "Capabilities: "
            f"Asset PATCH={caps.get('asset_patch')} | "
            f"Deployment POST={caps.get('deployment_post')} | "
            f"Deployment PATCH={caps.get('deployment_patch')}"
        )

    if st.session_state.last_key_push_result:
        key_result = st.session_state.last_key_push_result
        if key_result.get("ok"):
            st.caption(f"Last key push: success ({key_result.get('strategy')})")
        else:
            st.caption(
                f"Last key push: failed "
                f"(category={key_result.get('category')}, status={key_result.get('status_code')})"
            )

    if st.session_state.last_redeploy_result:
        redeploy_result = st.session_state.last_redeploy_result
        if redeploy_result.get("ok"):
            st.caption(f"Last redeploy: success ({redeploy_result.get('strategy')})")
        else:
            st.caption(
                f"Last redeploy: failed "
                f"(category={redeploy_result.get('category')}, status={redeploy_result.get('status_code')})"
            )

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
        st.session_state.last_media_zip_bytes = b""
        st.session_state.last_media_zip_filename = ""
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
            attachments_cache: dict[str, list[dict]] = {}
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
                media_zip_buf = io.BytesIO()
                media_zip_path_counts: dict[str, int] = {}
                media_files_written = 0
                media_files_failed = 0
                with zipfile.ZipFile(media_zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as media_zip:
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

                        meta = record_meta_map.get(inst_id) or {}
                        record_id = rec.get("record_id") or meta.get("record_id")
                        att_url = rec.get("attachment_url") or meta.get("attachment_url")
                        att_name = rec.get("attachment_name") or meta.get("attachment_name")
                        attachments = meta.get("attachments") if isinstance(meta.get("attachments"), list) else []
                        log_lines.append(f"record_{idx}_record_id={record_id}")
                        log_lines.append(f"record_{idx}_attachment_name={att_name}")

                        if not attachments and record_id is not None:
                            cache_key = str(record_id)
                            if cache_key in attachments_cache:
                                attachments = attachments_cache[cache_key]
                            else:
                                try:
                                    attachments = fetch_kobo_record_attachments(
                                        st.session_state.server_url,
                                        st.session_state.api_token,
                                        selected_asset_uid,
                                        record_id,
                                    )
                                    attachments_cache[cache_key] = attachments
                                except Exception as e:
                                    attachments_cache[cache_key] = []
                                    log_lines.append(f"record_{idx}_attachment_lookup_error={e}")
                                    attachments = []

                        if attachments:
                            submission_att = select_submission_attachment(attachments)
                            if submission_att:
                                att_url = submission_att.get("download_url") or att_url
                                att_name = submission_att.get("filename") or att_name
                                log_lines.append("record_{idx}_attachment_lookup=attachments".format(idx=idx))
                            mcount = count_media_attachments(attachments)
                            log_lines.append(f"record_{idx}_media_count_from_attachments={mcount}")

                        if not att_url:
                            failed.append((inst_id, "submission.xml.enc download_url not found"))
                            log_lines.append(f"record_{idx}_attachment_url=missing")
                            progress.progress(idx / total)
                            continue

                        iv = derive_iv(inst_id, aes_key, mcount + 1)
                        log_lines.append(f"record_{idx}_iv={iv.hex()}")

                        try:
                            ciphertext = kobo_request("GET", att_url, st.session_state.api_token).content
                        except KoboApiError as e:
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

                            media_attachments = [att for att in attachments if is_encrypted_media_attachment(att)]
                            media_ok = 0
                            media_fail = 0
                            for media_index, media_att in enumerate(media_attachments, start=1):
                                media_url = media_att.get("download_url")
                                if not media_url:
                                    media_fail += 1
                                    media_files_failed += 1
                                    log_lines.append(
                                        f"record_{idx}_media_{media_index}_download_url=missing"
                                    )
                                    continue
                                media_iv = derive_iv(inst_id, aes_key, media_index)
                                try:
                                    media_cipher = kobo_request("GET", media_url, st.session_state.api_token).content
                                    media_plain = aes_cfb_decrypt(media_cipher, aes_key, media_iv)
                                    folder = make_instance_folder(inst_id)
                                    filename = decrypted_media_name(media_att, media_index)
                                    member_path = unique_zip_member_path(
                                        f"{folder}/{filename}",
                                        media_zip_path_counts,
                                    )
                                    media_zip.writestr(member_path, media_plain)
                                    media_ok += 1
                                    media_files_written += 1
                                    log_lines.append(
                                        f"record_{idx}_media_{media_index}_decrypt=ok path={member_path} "
                                        f"ciphertext_len={len(media_cipher)} plaintext_len={len(media_plain)}"
                                    )
                                except Exception as e:
                                    media_fail += 1
                                    media_files_failed += 1
                                    log_lines.append(f"record_{idx}_media_{media_index}_decrypt=fail error={e}")

                            row["media_total"] = len(media_attachments)
                            row["media_decrypted"] = media_ok
                            row["media_failed"] = media_fail
                            decrypted_rows.append(row)
                            log_lines.append(
                                f"record_{idx}_decrypt=ok ciphertext_len={len(ciphertext)} "
                                f"plaintext_len={len(plaintext)} media_total={len(media_attachments)} "
                                f"media_ok={media_ok} media_failed={media_fail}"
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
                log_lines.append(f"summary_media_files_written={media_files_written}")
                log_lines.append(f"summary_media_files_failed={media_files_failed}")

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
                    if media_files_written > 0:
                        st.session_state.last_media_zip_bytes = media_zip_buf.getvalue()
                        st.session_state.last_media_zip_filename = f"decrypted_media_{export_stamp}.zip"
                        st.info(f"Prepared media ZIP with {media_files_written} file(s).")
                    elif media_files_failed > 0:
                        st.warning("No media files were decrypted successfully.")
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
        with col_dl2:
            if st.session_state.last_media_zip_bytes:
                st.download_button(
                    "Download Media ZIP",
                    data=st.session_state.last_media_zip_bytes,
                    file_name=st.session_state.last_media_zip_filename or "decrypted_media.zip",
                    mime="application/zip",
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

if st.session_state.last_automation_log_text:
    with st.expander("Automation Log"):
        st.code(st.session_state.last_automation_log_text, language="text")
        st.download_button(
            "Download Automation Log (TXT)",
            data=st.session_state.last_automation_log_text.encode("utf-8"),
            file_name=st.session_state.last_automation_log_filename or "automation_log.txt",
            mime="text/plain",
            key="download_automation_log",
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
