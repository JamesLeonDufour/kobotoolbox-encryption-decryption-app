import io
import re
import copy
import zipfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import base64
import hashlib
import pandas as pd
import requests
import streamlit as st
import streamlit.components.v1 as components
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
    page_title="KoboToolbox Encryption and Decryption App",
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

    /* Disabled buttons should not keep the active primary blue styling */
    div.stButton > button:disabled,
    div.stButton > button[kind="primary"]:disabled {
        background: #e9ecef !important;
        color: #6c757d !important;
        border: 1px solid #ced4da !important;
        box-shadow: none !important;
        transform: none !important;
        cursor: not-allowed !important;
        opacity: 1 !important;
    }
    div.stButton > button:disabled:hover,
    div.stButton > button[kind="primary"]:disabled:hover {
        background: #e9ecef !important;
        box-shadow: none !important;
        transform: none !important;
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

st.title("KoboToolbox Encryption and Decryption App")
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


def derive_submission_url(server_url: str) -> str:
    normalized = normalize_server_url(server_url)
    parsed = urlparse(normalized)
    scheme = parsed.scheme or "https"
    host = (parsed.netloc or "").strip().lower()

    if not host:
        return ""
    if host.startswith("kc.") or host.startswith("kc-"):
        submit_host = host
    elif host.startswith("kf."):
        submit_host = "kc." + host[3:]
    elif host.startswith("kf-"):
        submit_host = "kc-" + host[3:]
    elif host == "eu.kobotoolbox.org":
        submit_host = "kc-eu.kobotoolbox.org"
    else:
        submit_host = host

    return f"{scheme}://{submit_host}/submission"


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


def trigger_browser_download(file_name: str, data: bytes, mime: str) -> None:
    b64 = base64.b64encode(data).decode("ascii")
    safe_name = file_name.replace("\\", "_").replace("'", "_")
    components.html(
        f"""
        <script>
        const link = document.createElement('a');
        link.href = 'data:{mime};base64,{b64}';
        link.download = '{safe_name}';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        </script>
        """,
        height=0,
        width=0,
    )


def require_generated_private_key_download_confirmation() -> bool:
    return bool(
        st.session_state.get("generated_public_pem")
        and st.session_state.get("generated_private_pem")
        and not st.session_state.get("generated_private_key_download_confirmed", False)
    )


def open_private_key_confirmation_prompt(auto_proceed: bool = False) -> None:
    st.session_state.show_private_key_confirm_dialog = True
    st.session_state.private_key_confirm_auto_proceed = auto_proceed


def render_private_key_confirmation_prompt() -> None:
    if not st.session_state.get("show_private_key_confirm_dialog"):
        return

    def _render_dialog_contents() -> None:
        st.markdown(
            """
            <style>
            [data-testid="stDialog"] div.stButton > button[kind="primary"]:disabled {
                background: #dc3545 !important;
                color: #ffffff !important;
                border: 1px solid #dc3545 !important;
                opacity: 1 !important;
                box-shadow: none !important;
                transform: none !important;
            }
            [data-testid="stDialog"] div.stButton > button[kind="primary"]:not(:disabled) {
                background: #28a745 !important;
                color: #ffffff !important;
                border: 1px solid #28a745 !important;
            }
            [data-testid="stDialog"] div.stButton > button[kind="primary"]:not(:disabled):hover {
                background: #218838 !important;
                border-color: #218838 !important;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15) !important;
                transform: translateY(-2px) !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
        st.warning(
            "Download and store the private key before encrypting the form. "
            "You will need it later to decrypt submissions."
        )
        private_key_bytes = st.session_state.get("generated_private_pem") or b""
        if private_key_bytes:
            downloaded_now = st.download_button(
                "Download Private Key",
                data=private_key_bytes,
                file_name="private_key.pem",
                mime="application/x-pem-file",
                use_container_width=True,
                key="confirm_modal_download_private_key",
            )
            if downloaded_now:
                st.session_state.generated_private_key_download_confirmed = True
                st.success("Private key download confirmed.")
        else:
            st.error("No generated private key found. Generate a key pair first.")

        col1, col2 = st.columns(2)
        with col1:
            continue_clicked = st.button(
                "Continue to Encrypt",
                type="primary",
                use_container_width=True,
                disabled=not st.session_state.get("generated_private_key_download_confirmed", False),
                key="confirm_modal_continue_encrypt",
            )
        with col2:
            cancel_clicked = st.button(
                "Cancel",
                use_container_width=True,
                key="confirm_modal_cancel",
            )

        if continue_clicked:
            st.session_state.show_private_key_confirm_dialog = False
            if st.session_state.get("private_key_confirm_auto_proceed"):
                st.session_state.pending_encrypt_after_private_key_confirm = True
            st.session_state.private_key_confirm_auto_proceed = False
            st.rerun()

        if cancel_clicked:
            st.session_state.show_private_key_confirm_dialog = False
            st.session_state.private_key_confirm_auto_proceed = False
            st.rerun()

    if hasattr(st, "dialog"):
        @st.dialog("Confirm Private Key Download")
        def _private_key_dialog() -> None:
            _render_dialog_contents()

        _private_key_dialog()
    else:
        with st.container(border=True):
            st.markdown("#### Confirm Private Key Download")
            _render_dialog_contents()


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
    text = (text or "").strip()
    if not text:
        return ""

    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if "BEGIN PUBLIC KEY" not in normalized:
        body = re.sub(r"\s+", "", normalized)
        if not body:
            return ""
        wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
        normalized = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----"

    if not normalized.endswith("\n"):
        normalized += "\n"

    try:
        parsed = serialization.load_pem_public_key(
            normalized.encode("utf-8"),
            backend=default_backend(),
        )
    except Exception as e:
        raise ValueError(f"Invalid public key format: {e}") from e

    canonical = parsed.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    canonical_text = canonical.decode("utf-8")
    body_lines = []
    for line in canonical_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("-----BEGIN ") or s.startswith("-----END "):
            continue
        body_lines.append(s)
    # Kobo settings.public_key expects key body without PEM envelope lines.
    # Keep 64-char line wrapping to match typical XLSForm settings format.
    return "\n".join(body_lines)


def derive_public_key_from_private_pem(private_pem_bytes: bytes, password: str | None) -> bytes:
    private_key = load_private_key(private_pem_bytes, password or None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def make_encryption_payload_candidates(asset: dict, public_key_text: str, submission_url: str) -> list[dict]:
    name = str(asset.get("name") or "").strip() or "Untitled Asset"
    content = copy.deepcopy(asset.get("content")) if isinstance(asset.get("content"), dict) else {}
    settings = content.get("settings")
    if not isinstance(settings, dict):
        settings = {}

    settings_a = copy.deepcopy(settings)
    settings_a["public_key"] = public_key_text
    settings_a["submission_url"] = submission_url
    content_a = copy.deepcopy(content)
    content_a["settings"] = settings_a

    settings_b = copy.deepcopy(settings)
    settings_b["public_key"] = public_key_text
    settings_b["encrypted"] = True
    settings_b["submission_url"] = submission_url
    content_b = copy.deepcopy(content)
    content_b["settings"] = settings_b

    settings_c = copy.deepcopy(settings)
    settings_c["public_key"] = public_key_text
    settings_c["submission_url"] = submission_url
    settings_c["submission_encryption"] = {
        "enabled": True,
        "public_key": public_key_text,
    }
    content_c = copy.deepcopy(content)
    content_c["settings"] = settings_c

    return [
        {
            "strategy": "asset_patch_name_content_settings_public_key_only",
            "payload": {"name": name, "content": content_a},
        },
        {
            "strategy": "asset_patch_name_content_public_key_encrypted",
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
    submission_url = derive_submission_url(server_url)
    try:
        public_key_text = normalize_public_key_pem(public_key_pem)
    except ValueError as e:
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
                    "message": str(e),
                }
            ],
        }
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
    for candidate in make_encryption_payload_candidates(asset, public_key_text, submission_url):
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
    deployment_url_no_slash = f"{server_url}/api/v2/assets/{asset_uid}/deployment"
    version_id = None
    deployment_link_urls: list[str] = []
    try:
        asset = get_asset(server_url, api_token, asset_uid)
        version_id = asset.get("version_id")
        links = asset.get("deployment__links")
        if isinstance(links, dict):
            for key, value in links.items():
                if not isinstance(value, str):
                    continue
                link = value.strip()
                if not link:
                    continue
                key_text = str(key).lower()
                if key_text == "url" or "deployment" in key_text or "/deployment" in link:
                    deployment_link_urls.append(link)
    except KoboApiError:
        version_id = None

    deployment_urls: list[tuple[str, str]] = [
        ("api_v2_with_slash", deployment_url),
        ("api_v2_no_slash", deployment_url_no_slash),
    ]
    existing_urls = {deployment_url, deployment_url_no_slash}
    for idx, deployment_link_url in enumerate(deployment_link_urls, start=1):
        if deployment_link_url.startswith("/"):
            deployment_link_url = f"{server_url}{deployment_link_url}"
        if deployment_link_url not in existing_urls:
            deployment_urls.append((f"deployment_link_{idx}", deployment_link_url))
            existing_urls.add(deployment_link_url)

    candidates: list[tuple[str, str, str, dict | None]] = []
    for label, url in deployment_urls:
        # Preferred for this Kobo deployment: PATCH with active=true and version_id.
        if version_id:
            candidates.append(
                (
                    f"deployment_patch_active_version_{label}",
                    "PATCH",
                    url,
                    {"active": True, "version_id": version_id},
                )
            )
        # Fallback PATCH without explicit version_id.
        candidates.append((f"deployment_patch_active_{label}", "PATCH", url, {"active": True}))
        # Keep POST fallbacks for servers that only support create/redeploy via POST.
        candidates.append((f"deployment_post_active_{label}", "POST", url, {"active": True}))
        candidates.append((f"deployment_post_nobody_{label}", "POST", url, None))

    errors: list[dict] = []
    for strategy, method, target_url, payload in candidates:
        try:
            resp = kobo_request(method, target_url, api_token, json=payload)
            body = read_json_if_possible(resp)
            result = {
                "ok": True,
                "status_code": resp.status_code,
                "category": "success",
                "strategy": strategy,
                "errors": errors,
                "response": body if isinstance(body, dict) else {},
            }
            if isinstance(body, dict):
                result["deploy_active"] = body.get("active")
                result["deploy_version_id"] = body.get("version_id")
                result["deploy_backend"] = body.get("backend")
            return result
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
            if category == "permission":
                break

    last_status = errors[-1]["status_code"] if errors else None
    return {
        "ok": False,
        "status_code": last_status,
        "category": classify_http_status(last_status),
        "strategy": "",
        "errors": errors,
    }


def _redeploy_state_snapshot(asset: dict) -> dict:
    return {
        "version_id": asset.get("version_id"),
        "deployed_version_id": asset.get("deployed_version_id"),
        "date_deployed": asset.get("date_deployed"),
        "deployment_active": asset.get("deployment__active"),
    }


def confirm_redeploy_effect(
    server_url: str,
    api_token: str,
    asset_uid: str,
    baseline_state: dict | None,
    expected_version_id,
    retries: int = 4,
    delay_seconds: float = 1.5,
) -> dict:
    last_state = None
    last_error = ""
    base_deployed = baseline_state.get("deployed_version_id") if isinstance(baseline_state, dict) else None
    base_date = baseline_state.get("date_deployed") if isinstance(baseline_state, dict) else None

    for attempt in range(1, retries + 1):
        try:
            current_asset = get_asset(server_url, api_token, asset_uid)
            current_state = _redeploy_state_snapshot(current_asset)
            last_state = current_state

            if expected_version_id and str(current_state.get("deployed_version_id")) == str(expected_version_id):
                return {"confirmed": True, "reason": "deployed_version_matches_asset_version", "attempt": attempt, "state": current_state}
            if current_state.get("deployed_version_id") and current_state.get("deployed_version_id") != base_deployed:
                return {"confirmed": True, "reason": "deployed_version_changed", "attempt": attempt, "state": current_state}
            if current_state.get("date_deployed") and current_state.get("date_deployed") != base_date:
                return {"confirmed": True, "reason": "date_deployed_changed", "attempt": attempt, "state": current_state}
        except KoboApiError as e:
            last_error = str(e)

        if attempt < retries:
            time.sleep(delay_seconds)

    return {"confirmed": False, "reason": "no_state_change_detected", "attempt": retries, "state": last_state, "error": last_error}


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


def append_terminal_log(section: str, lines: list[str]) -> None:
    if not lines:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = f"[{stamp}] [{section.upper()}]"
    block = "\n".join([header, *lines])
    existing = st.session_state.last_terminal_log_text
    if existing:
        st.session_state.last_terminal_log_text = f"{existing}\n\n{block}"
    else:
        st.session_state.last_terminal_log_text = block
    file_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    st.session_state.last_terminal_log_filename = f"activity_terminal_{file_stamp}.txt"


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
    append_terminal_log("automation", lines)


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
if "last_terminal_log_text" not in st.session_state:
    st.session_state.last_terminal_log_text = ""
if "last_terminal_log_filename" not in st.session_state:
    st.session_state.last_terminal_log_filename = ""
if "last_encryption_summary" not in st.session_state:
    st.session_state.last_encryption_summary = {}
if "generated_private_key_download_confirmed" not in st.session_state:
    st.session_state.generated_private_key_download_confirmed = False
if "show_private_key_confirm_dialog" not in st.session_state:
    st.session_state.show_private_key_confirm_dialog = False
if "private_key_confirm_auto_proceed" not in st.session_state:
    st.session_state.private_key_confirm_auto_proceed = False
if "pending_encrypt_after_private_key_confirm" not in st.session_state:
    st.session_state.pending_encrypt_after_private_key_confirm = False

# Sidebar with improved sections
with st.sidebar:
    st.markdown("### Connection")
    server_url_input = st.text_input(
        "Server URL",
        value=st.session_state.server_url,
        placeholder="https://kf.kobotoolbox.org",
        label_visibility="collapsed",
        help="Your KoboToolbox server base URL.",
    )
    api_token_input = st.text_input(
        "API Token",
        type="password",
        value=st.session_state.api_token,
        placeholder="API token",
        label_visibility="collapsed",
        help="Create this from Account Settings -> Tokens in KoboToolbox.",
    )
    connect_clicked = st.button(
        "Connect",
        type="primary",
        use_container_width=False,
        help="Connect and refresh your project list.",
    )

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
                "encrypted": bool(a.get("deployment__encrypted")),
            }
            for a in assets
        ]
        encrypted_count = sum(1 for item in asset_items if item["encrypted"])
        unencrypted_count = len(asset_items) - encrypted_count
        st.caption(f"Encrypted projects: {encrypted_count} | Not encrypted: {unencrypted_count}")
        selected_asset = st.selectbox(
            "Select project",
            asset_items,
            format_func=lambda item: (
                f"[ENCRYPTED] {item['name']} ({item['uid']})"
                if item["encrypted"] and item["uid"]
                else f"[ENCRYPTED] {item['name']}"
                if item["encrypted"]
                else f"[NOT ENCRYPTED] {item['name']} ({item['uid']})"
                if item["uid"]
                else f"[NOT ENCRYPTED] {item['name']}"
            ),
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
        st.session_state.last_encryption_summary = {}

    st.markdown("### Project Encryption")
    with st.expander("Key Generation", expanded=False):
        if st.button(
            "Generate Key Pair",
            use_container_width=True,
            help="Generate RSA keys locally and auto-download both PEM files.",
        ):
            try:
                priv_pem, pub_pem = generate_rsa_keypair()
                st.session_state.generated_private_pem = priv_pem
                st.session_state.generated_public_pem = pub_pem
                st.session_state.generated_private_key_download_confirmed = False
                st.session_state.show_private_key_confirm_dialog = False
                st.session_state.private_key_confirm_auto_proceed = False
                st.session_state.pending_encrypt_after_private_key_confirm = False
                st.success("Key pair generated.")
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                trigger_browser_download(
                    f"private_key_{stamp}.pem",
                    priv_pem,
                    "application/x-pem-file",
                )
                trigger_browser_download(
                    f"public_key_{stamp}.pem",
                    pub_pem,
                    "application/x-pem-file",
                )
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
                private_key_downloaded = st.download_button(
                    "Download Private Key",
                    data=st.session_state.generated_private_pem,
                    file_name="private_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )
                if private_key_downloaded:
                    st.session_state.generated_private_key_download_confirmed = True
            with col2:
                st.download_button(
                    "Download Public Key",
                    data=st.session_state.generated_public_pem,
                    file_name="public_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                )

    st.markdown("#### Encrypt Form and Redeploy")
    st.caption("Push the public key to the selected project and trigger redeploy.")
    can_automate = bool(st.session_state.server_url and st.session_state.api_token and selected_asset_uid)
    requires_private_key_confirmation = require_generated_private_key_download_confirmation()
    if requires_private_key_confirmation:
        st.warning(
            "Encryption is disabled until the generated private key is downloaded and confirmed."
        )

    encrypt_help = "Uses generated public key first, otherwise derives from uploaded private key."
    if requires_private_key_confirmation:
        encrypt_help += " Download/confirm the private key first."

    encrypt_button_clicked = st.button(
        "Push Public Key + Redeploy",
        use_container_width=True,
        disabled=not can_automate,
        help=encrypt_help,
    )

    if encrypt_button_clicked and requires_private_key_confirmation:
        open_private_key_confirmation_prompt(auto_proceed=True)
        encrypt_button_clicked = False

    render_private_key_confirmation_prompt()
    pending_encrypt_after_confirm = bool(
        st.session_state.get("pending_encrypt_after_private_key_confirm", False)
    )
    if pending_encrypt_after_confirm:
        st.session_state.pending_encrypt_after_private_key_confirm = False
    push_and_redeploy_clicked = encrypt_button_clicked or pending_encrypt_after_confirm

    if push_and_redeploy_clicked:
        auto_lines = [f"automation_started_utc={utc_now_iso()}", f"asset_uid={selected_asset_uid}"]
        if not can_automate:
            st.error("Connect to KoboToolbox and select a project first.")
            auto_lines.append("automation_error=missing_connection_or_project")
        else:
            public_key_bytes = b""
            key_source = ""
            private_key_bytes_for_summary = b""
            if st.session_state.generated_public_pem:
                public_key_bytes = st.session_state.generated_public_pem
                key_source = "generated_public_key"
                private_key_bytes_for_summary = st.session_state.generated_private_pem or b""
            else:
                uploaded_key_for_automation = st.session_state.get("private_key_upload")
                key_password_for_automation = st.session_state.get("private_key_password") or None
                if uploaded_key_for_automation:
                    try:
                        uploaded_key_for_automation.seek(0)
                    except Exception:
                        pass
                    uploaded_bytes = uploaded_key_for_automation.read()
                    try:
                        public_key_bytes = derive_public_key_from_private_pem(
                            uploaded_bytes,
                            key_password_for_automation,
                        )
                        key_source = "derived_from_uploaded_private_key"
                        private_key_bytes_for_summary = uploaded_bytes
                    except Exception as e:
                        st.error(f"Could not derive public key from private key: {e}")
                        auto_lines.append(f"key_push_error=derive_public_key_failed:{e}")
                else:
                    st.error("No public key available. Generate a key pair or upload a private key.")
                    auto_lines.append("key_push_error=no_key_source")

            if public_key_bytes:
                push_result = update_encryption_settings(
                    st.session_state.server_url,
                    st.session_state.api_token,
                    selected_asset_uid,
                    public_key_bytes,
                )
                st.session_state.last_key_push_result = push_result
                auto_lines.append(f"key_push_submission_url={derive_submission_url(st.session_state.server_url)}")
                auto_lines.append(f"key_push_source={key_source}")
                auto_lines.append(f"key_push_ok={push_result.get('ok')}")
                auto_lines.append(f"key_push_strategy={push_result.get('strategy')}")
                auto_lines.append(f"key_push_status={push_result.get('status_code')}")
                auto_lines.append(f"key_push_form_name={selected_asset_name}")

                if push_result.get("ok"):
                    baseline_state = None
                    expected_version_id = None
                    try:
                        asset_before_redeploy = get_asset(
                            st.session_state.server_url,
                            st.session_state.api_token,
                            selected_asset_uid,
                        )
                        baseline_state = _redeploy_state_snapshot(asset_before_redeploy)
                        expected_version_id = asset_before_redeploy.get("version_id")
                        auto_lines.append(f"redeploy_baseline_deployed_version_id={baseline_state.get('deployed_version_id')}")
                        auto_lines.append(f"redeploy_expected_version_id={expected_version_id}")
                    except KoboApiError as e:
                        auto_lines.append(f"redeploy_baseline_fetch_error={e}")

                    redeploy_result = trigger_redeploy(
                        st.session_state.server_url,
                        st.session_state.api_token,
                        selected_asset_uid,
                    )
                    if redeploy_result.get("ok") and redeploy_result.get("deploy_active") is False:
                        redeploy_result["ok"] = False
                        redeploy_result["category"] = "payload_or_state"
                        redeploy_result["errors"] = redeploy_result.get("errors", []) + [
                            {
                                "strategy": redeploy_result.get("strategy"),
                                "status_code": redeploy_result.get("status_code"),
                                "category": "payload_or_state",
                                "message": "Deployment response indicates active=false.",
                            }
                        ]
                    st.session_state.last_redeploy_result = redeploy_result
                    auto_lines.append(f"redeploy_ok={redeploy_result.get('ok')}")
                    auto_lines.append(f"redeploy_strategy={redeploy_result.get('strategy')}")
                    auto_lines.append(f"redeploy_status={redeploy_result.get('status_code')}")
                    auto_lines.append(f"redeploy_response_active={redeploy_result.get('deploy_active')}")
                    auto_lines.append(f"redeploy_response_version_id={redeploy_result.get('deploy_version_id')}")
                    auto_lines.append(f"redeploy_response_backend={redeploy_result.get('deploy_backend')}")
                    if redeploy_result.get("ok"):
                        confirm = confirm_redeploy_effect(
                            st.session_state.server_url,
                            st.session_state.api_token,
                            selected_asset_uid,
                            baseline_state=baseline_state,
                            expected_version_id=expected_version_id,
                        )
                        redeploy_result["confirmed"] = confirm.get("confirmed")
                        redeploy_result["confirm_reason"] = confirm.get("reason")
                        auto_lines.append(f"redeploy_confirmed={confirm.get('confirmed')}")
                        auto_lines.append(f"redeploy_confirm_reason={confirm.get('reason')}")
                        auto_lines.append(f"redeploy_confirm_attempt={confirm.get('attempt')}")
                        if confirm.get("state"):
                            cstate = confirm["state"]
                            auto_lines.append(
                                f"redeploy_confirm_state deployed_version_id={cstate.get('deployed_version_id')} "
                                f"date_deployed={cstate.get('date_deployed')}"
                            )
                        if confirm.get("confirmed"):
                            st.success("Public key pushed and redeploy confirmed.")
                        else:
                            st.warning(
                                "Public key was pushed, and redeploy API returned success, but deployment change "
                                "could not be confirmed yet. Check deployment status in KoboToolbox."
                            )
                    else:
                        category = redeploy_result.get("category")
                        if category == "unsupported":
                            st.warning(
                                "Public key was pushed, but automatic redeploy is not available on this server "
                                "(404/405). Redeploy manually in KoboToolbox."
                            )
                        elif category == "permission":
                            st.error("Public key was pushed, but redeploy permission was denied (401/403).")
                        elif category == "payload_or_state":
                            st.error("Public key was pushed, but redeploy payload/state was rejected (409/422).")
                        else:
                            st.error("Public key was pushed, but redeploy failed.")
                        for err in redeploy_result.get("errors", []):
                            auto_lines.append(
                                f"redeploy_attempt strategy={err.get('strategy')} status={err.get('status_code')} "
                                f"category={err.get('category')} message={err.get('message')}"
                            )
                else:
                    st.session_state.last_redeploy_result = {}
                    category = push_result.get("category")
                    if category == "permission":
                        st.error("Permission denied while updating form settings (401/403).")
                    elif category == "unsupported":
                        st.error("This server does not support form settings update through this endpoint (404/405).")
                    elif category == "payload_or_state":
                        st.error("Server rejected payload/state for key update (409/422).")
                    else:
                        st.error("Public key push failed.")
                    for err in push_result.get("errors", []):
                        auto_lines.append(
                            f"key_push_attempt strategy={err.get('strategy')} status={err.get('status_code')} "
                            f"category={err.get('category')} message={err.get('message')}"
                        )

                if push_result.get("ok"):
                    try:
                        updated_asset = get_asset(
                            st.session_state.server_url,
                            st.session_state.api_token,
                            selected_asset_uid,
                        )
                    except KoboApiError:
                        updated_asset = {}

                    summary_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    encrypted_flag = bool(updated_asset.get("deployment__encrypted"))
                    version_value = (
                        updated_asset.get("deployed_version_id")
                        or updated_asset.get("version_id")
                        or ""
                    )
                    st.session_state.last_encryption_summary = {
                        "timestamp": utc_now_iso(),
                        "asset_uid": selected_asset_uid,
                        "asset_name": selected_asset_name or "(unnamed)",
                        "encrypted": encrypted_flag,
                        "version": str(version_value) if version_value is not None else "",
                        "key_source": key_source,
                        "push_strategy": push_result.get("strategy"),
                        "redeploy_strategy": st.session_state.last_redeploy_result.get("strategy"),
                        "private_key_bytes": private_key_bytes_for_summary or b"",
                        "private_key_filename": f"private_key_{selected_asset_uid}_{summary_stamp}.pem",
                    }
        append_automation_log_lines(auto_lines)

    st.markdown("### Decrypt Submissions")
    uploaded_key = st.file_uploader(
        "Upload private key (PEM)",
        type="pem",
        key="private_key_upload",
        help="Private key used to decrypt form submissions.",
    )
    key_password = st.text_input(
        "Passphrase (if encrypted)",
        type="password",
        key="private_key_password",
        help="Enter passphrase only if your private key is encrypted.",
    )
    run_clicked = st.button(
        "Decrypt All Records",
        type="primary",
        use_container_width=True,
        help="Fetch submissions, decrypt XML, and export Excel/ZIP outputs.",
    )

# Main area

if st.session_state.last_encryption_summary:
    summary = st.session_state.last_encryption_summary
    st.markdown("### Last Encryption Result")
    s_col1, s_col2 = st.columns([2, 1])
    with s_col1:
        st.success("Form encryption settings were updated successfully.")
        st.write(f"**Form:** {summary.get('asset_name', '(unnamed)')}")
        st.write(f"**Asset UID:** {summary.get('asset_uid', '')}")
        st.write(f"**Encrypted:** {'Yes' if summary.get('encrypted') else 'No'}")
        st.write(f"**Version:** {summary.get('version') or '(unknown)'}")
        st.write(f"**Pushed At (UTC):** {summary.get('timestamp')}")
    with s_col2:
        private_bytes = summary.get("private_key_bytes") or b""
        if private_bytes:
            st.download_button(
                "Download Private Key",
                data=private_bytes,
                file_name=summary.get("private_key_filename") or "private_key.pem",
                mime="application/x-pem-file",
                use_container_width=True,
                key="download_last_encryption_private_key",
            )
    st.markdown("---")

if not st.session_state.last_encryption_summary and not st.session_state.last_decrypted_rows:
    st.markdown("""
    <div class="info-box">
        <h3>Getting Started</h3>
        <ol>
            <li><strong>Connect</strong> - Enter server URL and API token, then click Connect</li>
            <li><strong>Select Project</strong> - Choose the project you want to work on</li>
            <li><strong>Project Encryption</strong> - Generate keys and use Push Public Key + Redeploy (optional)</li>
            <li><strong>Decrypt Submissions</strong> - Upload private key (or use generated key), then click Decrypt All Records</li>
            <li><strong>Download Outputs</strong> - Export Excel and media ZIP files</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

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
                append_terminal_log("decryption", log_lines)

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

with st.expander("Terminal (Expand/Collapse)", expanded=False):
    if st.session_state.last_terminal_log_text:
        st.code(st.session_state.last_terminal_log_text, language="text")
        st.download_button(
            "Download Activity Log (TXT)",
            data=st.session_state.last_terminal_log_text.encode("utf-8"),
            file_name=st.session_state.last_terminal_log_filename or "activity_terminal.txt",
            mime="text/plain",
            key="download_activity_log",
            use_container_width=True,
        )
    else:
        st.info("No activity yet. Actions like connect, automate, and decrypt will appear here.")

# Footer
st.markdown("""
---
<div style="text-align: center; color: #666; padding: 20px;">
    <p><strong>KoboToolbox Encryption and Decryption App</strong> | Secure Local Encryption &amp; Decryption</p>
    <p><small>Your private key never leaves your browser. All decryption happens locally.</small></p>
</div>
""", unsafe_allow_html=True)
