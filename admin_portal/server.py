from __future__ import annotations

import datetime as dt
import base64
import bcrypt
import hashlib
import hmac
import ipaddress
import json
import gzip
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import api_security

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"

HOST = os.getenv("ADMIN_HOST", "127.0.0.1")
PORT = int(os.getenv("ADMIN_PORT", "8787"))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
LICENSE_SECRET = os.getenv(
    "ADMIN_LICENSE_SECRET",
    "7c1e4b9a2f6d8c3e1a9f5b2d7c4e8a1f6b3d9c2e7a5f1b4c8d6e2a9f",
)

SESSION_TTL_SECONDS = 60 * 60 * 12
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ADMIN_ACCESS_TOKEN_TTL_SECONDS", "900"))
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("ADMIN_REFRESH_TOKEN_TTL_SECONDS", str(7 * 86400)))
sessions: dict[str, dict[str, Any]] = {}


def resolve_db_path() -> Path:
    # 1) Explicit override for production/shared deployments.
    raw = str(os.getenv("ADMIN_DB_PATH", "")).strip()
    if raw:
        return Path(raw).resolve()

    # 2) Source default.
    source_default = BASE_DIR / "data" / "admin.db"
    if source_default.parent.exists():
        return source_default

    # 3) EXE in dist/ -> use project-level admin_portal/data/admin.db.
    dist_shared = BASE_DIR.parent / "admin_portal" / "data" / "admin.db"
    if dist_shared.parent.exists():
        return dist_shared

    # 4) Fallback create local data beside current script/exe.
    return source_default


DB_PATH = resolve_db_path()
DATA_DIR = DB_PATH.parent
BACKUP_DIR = DATA_DIR / "backups"


def now_ts() -> int:
    return int(time.time())


def sign_hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _bcrypt_hash_password(password: str) -> str:
    return bcrypt.hashpw(str(password or "").encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _bcrypt_verify_password(password: str, hashed: str) -> bool:
    try:
        return bool(bcrypt.checkpw(str(password or "").encode("utf-8"), str(hashed or "").encode("utf-8")))
    except Exception:
        return False


def _b64u_encode_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode_bytes(text: str) -> bytes:
    padded = str(text or "") + ("=" * ((4 - (len(str(text or "")) % 4)) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _issue_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h64 = _b64u_encode_json(header)
    p64 = _b64u_encode_json(payload)
    sig = hmac.new(LICENSE_SECRET.encode("utf-8"), f"{h64}.{p64}".encode("utf-8"), hashlib.sha256).digest()
    s64 = _b64u_encode_bytes(sig)
    return f"{h64}.{p64}.{s64}"


def _verify_jwt(token: str, expected_type: str) -> tuple[dict[str, Any] | None, str]:
    raw = str(token or "").strip()
    parts = raw.split(".")
    if len(parts) != 3:
        return None, "invalid_token_format"
    h64, p64, s64 = parts
    try:
        sig = _b64u_decode_bytes(s64)
    except Exception:
        return None, "invalid_token_signature"
    exp_sig = hmac.new(LICENSE_SECRET.encode("utf-8"), f"{h64}.{p64}".encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(sig, exp_sig):
        return None, "invalid_token_signature"
    payload = _b64u_decode_json(p64)
    if not payload:
        return None, "invalid_token_payload"
    try:
        exp = int(payload.get("exp") or 0)
        typ = str(payload.get("typ") or "")
    except Exception:
        return None, "invalid_token_payload"
    if typ != expected_type:
        return None, "invalid_token_type"
    if exp <= 0 or now_ts() >= exp:
        return None, "token_expired"
    return payload, ""


def _normalize_username(username: str) -> str:
    return str(username or "").strip().lower()


def _is_valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9_.-]{3,32}", str(username or "").strip()))


def _is_valid_role(role: str) -> bool:
    return str(role or "").strip().lower() in {"admin", "mod"}


def _totp_normalize_secret(secret: str) -> str:
    s = re.sub(r"[^A-Z2-7]", "", str(secret or "").strip().upper())
    return s


def _totp_generate_secret(length: int = 32) -> str:
    # Base32 alphabet; 32 chars ~ 160 bits
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(max(16, int(length))))


def _totp_code(secret: str, ts: int, period: int = 30, digits: int = 6) -> str:
    sec = _totp_normalize_secret(secret)
    if not sec:
        return ""
    pad = "=" * ((8 - (len(sec) % 8)) % 8)
    key = base64.b32decode(sec + pad, casefold=True)
    counter = int(ts // period)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code_int = int.from_bytes(digest[off : off + 4], "big") & 0x7FFFFFFF
    mod = 10 ** int(digits)
    return str(code_int % mod).zfill(digits)


def _verify_totp(secret: str, code: str, *, now: int | None = None, skew_steps: int = 1) -> bool:
    c = re.sub(r"\D", "", str(code or "").strip())
    if len(c) != 6:
        return False
    t = int(now if now is not None else now_ts())
    for i in range(-int(skew_steps), int(skew_steps) + 1):
        if _totp_code(secret, t + i * 30) == c:
            return True
    return False


def hash_license_key(license_key: str) -> str:
    msg = f"{LICENSE_SECRET}|{str(license_key or '').strip()}"
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def _is_hex64(text: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(text or "").strip()))


def hash_hwid(machine_id: str) -> str:
    """SHA-256(HWID) với pepper — chỉ lưu giá trị này trong DB, không lưu plaintext."""
    msg = f"{LICENSE_SECRET}|HWID|{str(machine_id or '').strip()}"
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def normalize_hwid_hash(value: str) -> str:
    """Chuẩn hóa HWID để lưu/so khớp: nếu đã là hex 64 (hash) thì giữ; không thì hash."""
    s = str(value or "").strip()
    if not s:
        return ""
    if _is_hex64(s):
        return s.lower()
    return hash_hwid(s)


def mask_hwid_hash(h: str) -> str:
    s = str(h or "").strip()
    if not s:
        return ""
    if len(s) <= 12:
        return (s[:6] + "...") if len(s) > 6 else s
    return s[:8] + "..." + s[-4:]


def normalize_prefix(prefix: str) -> str:
    p = re.sub(r"[^A-Z0-9]", "", str(prefix or "").upper())
    return p[:8] or "VE03"


def make_secure_license_key(prefix: str = "VE03") -> str:
    p = normalize_prefix(prefix)
    rnd = f"{uuid.uuid4().hex}{secrets.token_hex(8)}"
    digest = hashlib.sha256(rnd.encode("utf-8")).hexdigest().upper()
    return f"{p}-{digest[:4]}-{digest[4:8]}-{digest[8:12]}"


def normalize_app_version_for_sig(s: str) -> str:
    """Chuỗi an toàn đưa vào canonical (tránh & phá format)."""
    return re.sub(r"[^\w.\-]", "", str(s or ""))[:64]


def canonical_request_legacy(license_key: str, machine_id: str, ts: int, nonce: str) -> str:
    """Định dạng HMAC cũ (không có app_version) — chỉ dùng khi bật license_signature_allow_legacy."""
    return f"license_key={license_key}&machine_id={machine_id}&ts={int(ts)}&nonce={nonce}"


def canonical_request(license_key: str, machine_id: str, ts: int, nonce: str, app_version: str = "") -> str:
    """Chuỗi canonical cho HMAC request; phải khớp client (License.py)."""
    av = normalize_app_version_for_sig(app_version)
    return (
        f"license_key={license_key}&machine_id={machine_id}&ts={int(ts)}&nonce={nonce}&app_version={av}"
    )


def license_request_nonce_fingerprint(nonce: str, license_key_hash: str, ts: int) -> str:
    """Fingerprint nonce+key+ts để chống replay (không lưu plaintext nonce)."""
    msg = f"{LICENSE_SECRET}|NONCE|{nonce}|{license_key_hash}|{int(ts)}"
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def canonical_response(ok: bool, license_key: str, machine_id: str, expires_at: int, features: str, server_ts: int, nonce: str) -> str:
    ok_str = "true" if ok else "false"
    return f"ok={ok_str}&license_key={license_key}&machine_id={machine_id}&expires_at={int(expires_at)}&features={features}&server_ts={int(server_ts)}&nonce={nonce}"


def canonical_response_core(ok: bool, license_key: str, machine_id: str, expires_at: int, server_ts: int, nonce: str) -> str:
    ok_str = "true" if ok else "false"
    return (
        f"ok={ok_str}&license_key={license_key}&machine_id={machine_id}"
        f"&expires_at={int(expires_at)}&server_ts={int(server_ts)}&nonce={nonce}"
    )


def _b64u_encode_json(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode_json(text: str) -> dict[str, Any] | None:
    try:
        padded = text + ("=" * ((4 - (len(text) % 4)) % 4))
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def issue_license_proof_token(key_hash: str, hwid_hash: str, ttl_seconds: int) -> tuple[str, int]:
    now = now_ts()
    exp = now + max(30, int(ttl_seconds))
    payload = {
        "v": 1,
        "kh": str(key_hash or ""),
        "hh": str(hwid_hash or ""),
        "iat": now,
        "exp": exp,
        "jti": secrets.token_hex(8),
    }
    b64 = _b64u_encode_json(payload)
    sig = sign_hmac_hex(LICENSE_SECRET, f"proof={b64}")
    return f"{b64}.{sig}", exp


def verify_license_proof_token(token: str) -> tuple[dict[str, Any] | None, str]:
    raw = str(token or "").strip()
    if not raw or "." not in raw:
        return None, "invalid_proof_format"
    b64, sig = raw.split(".", 1)
    expect_sig = sign_hmac_hex(LICENSE_SECRET, f"proof={b64}")
    if not hmac.compare_digest(expect_sig, str(sig or "")):
        return None, "invalid_proof_signature"
    payload = _b64u_decode_json(b64)
    if not payload:
        return None, "invalid_proof_payload"
    try:
        exp = int(payload.get("exp") or 0)
        kh = str(payload.get("kh") or "")
        hh = str(payload.get("hh") or "")
    except Exception:
        return None, "invalid_proof_payload"
    if exp <= 0 or now_ts() >= exp:
        return None, "proof_expired"
    if not kh or not hh:
        return None, "invalid_proof_payload"
    return payload, ""


def db_connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db_connect()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                duration_days INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                machine_id TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                last_used_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expire_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS banned_hwids (
                hwid TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expire_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                action TEXT NOT NULL,
                ip TEXT NOT NULL DEFAULT '',
                license_key TEXT NOT NULL DEFAULT '',
                machine_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'mod',
                is_active INTEGER NOT NULL DEFAULT 1,
                totp_secret TEXT NOT NULL DEFAULT '',
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        user_cols = {r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
        if "totp_secret" not in user_cols:
            cur.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''")
        if "totp_enabled" not in user_cols:
            cur.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
        license_cols = {r[1] for r in cur.execute("PRAGMA table_info(licenses)").fetchall()}
        if "last_used_at" not in license_cols:
            cur.execute("ALTER TABLE licenses ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0")
        if "key_hash" not in license_cols:
            cur.execute("ALTER TABLE licenses ADD COLUMN key_hash TEXT NOT NULL DEFAULT ''")
        if "key_prefix" not in license_cols:
            cur.execute("ALTER TABLE licenses ADD COLUMN key_prefix TEXT NOT NULL DEFAULT 'VE03'")
        if "key_mask" not in license_cols:
            cur.execute("ALTER TABLE licenses ADD COLUMN key_mask TEXT NOT NULL DEFAULT ''")
        ip_cols = {r[1] for r in cur.execute("PRAGMA table_info(banned_ips)").fetchall()}
        if "expire_at" not in ip_cols:
            cur.execute("ALTER TABLE banned_ips ADD COLUMN expire_at INTEGER NOT NULL DEFAULT 0")
        hwid_cols = {r[1] for r in cur.execute("PRAGMA table_info(banned_hwids)").fetchall()}
        if "expire_at" not in hwid_cols:
            cur.execute("ALTER TABLE banned_hwids ADD COLUMN expire_at INTEGER NOT NULL DEFAULT 0")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_machine_ts ON events(machine_id, ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_license_ts ON events(license_key, ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_action_ts ON events(action, ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, ts DESC)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS license_hwid_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL,
                hwid_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(key_hash, hwid_hash)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_license_hwid_bindings_key ON license_hwid_bindings(key_hash)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS license_used_nonces (
                nonce_fp TEXT PRIMARY KEY,
                used_at INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_license_used_nonces_used_at ON license_used_nonces(used_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                refresh_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NOT NULL DEFAULT 0,
                last_ip TEXT NOT NULL DEFAULT '',
                last_ua TEXT NOT NULL DEFAULT '',
                suspicious_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh_hash ON auth_sessions(refresh_hash)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS client_security_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT '',
                key_hash TEXT NOT NULL DEFAULT '',
                hwid_hash TEXT NOT NULL DEFAULT '',
                signal_type TEXT NOT NULL DEFAULT '',
                score INTEGER NOT NULL DEFAULT 0,
                detail TEXT NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_client_security_ip_ts ON client_security_signals(ip, ts DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_client_security_key_ts ON client_security_signals(key_hash, ts DESC)")
        defaults = {
            "default_key_duration_days": "30",
            "max_devices_per_key": "1",
            "enable_hwid_binding": "1",
            "auto_ban_rules": "0",
            "auto_ban_failed_attempt_limit": "6",
            "auto_ban_window_seconds": "600",
            "auto_ban_duration_seconds": "3600",
            "auto_ban_mismatch_limit": "3",
            "hwid_swap_auto_ban_enabled": "1",
            "hwid_swap_fail_limit": "5",
            "hwid_swap_window_seconds": "3600",
            "api_rate_ip_per_minute": "120",
            "api_rate_key_per_minute": "60",
            "api_rate_window_seconds": "60",
            "api_allowed_origins": "",
            "api_total_requests": "0",
            "api_rate_rejections": "0",
            "api_auto_ban_on_rate_violations": "1",
            "api_rate_violation_ban_threshold": "25",
            "api_rate_violation_ban_window_sec": "600",
            "auto_ban_rule_failed_attempts": "1",
            "auto_ban_rule_hwid_mismatch": "1",
            "auto_ban_rule_multi_hwid_ip": "0",
            "multi_hwid_ip_limit": "15",
            "multi_hwid_ip_window_seconds": "900",
            "auto_ban_rule_invalid_signature": "1",
            "invalid_sig_ban_limit": "18",
            "invalid_sig_window_seconds": "600",
            "license_signature_required": "1",
            "license_clock_skew_seconds": "300",
            "license_nonce_retain_seconds": "172800",
            "license_signature_allow_legacy": "1",
            "license_nonce_min_length": "16",
            "license_proof_ttl_seconds": "120",
            "session_access_ttl_seconds": str(max(120, ACCESS_TOKEN_TTL_SECONDS)),
            "session_refresh_ttl_seconds": str(max(3600, REFRESH_TOKEN_TTL_SECONDS)),
            "session_suspicious_ip_change_limit": "3",
            "session_suspicious_ua_change_limit": "3",
            "session_auto_revoke_on_suspicious": "1",
            "auth_access_token_ttl_seconds": str(max(120, ACCESS_TOKEN_TTL_SECONDS)),
            "auth_refresh_token_ttl_seconds": str(max(3600, REFRESH_TOKEN_TTL_SECONDS)),
            "password_policy_min_length": "8",
            "password_policy_require_upper": "1",
            "password_policy_require_lower": "1",
            "password_policy_require_digit": "1",
            "password_policy_require_special": "0",
            "db_backup_enabled": "1",
            "db_backup_interval_seconds": "3600",
            "db_backup_retention_days": "14",
            "db_integrity_check_interval_seconds": "1800",
            "db_backup_encryption_key": "",
            "client_security_signal_auto_ban": "1",
            "client_security_signal_ban_threshold": "80",
            "client_security_signal_window_seconds": "3600",
            "api_base_url": f"http://{HOST}:{PORT}",
        }
        for k, v in defaults.items():
            cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))

        # Bootstrap admin user (bcrypt) nếu chưa tồn tại.
        now = now_ts()
        admin_user = _normalize_username(ADMIN_USER)
        admin_row = cur.execute("SELECT username FROM users WHERE username=?", (admin_user,)).fetchone()
        if not admin_row:
            cur.execute(
                """
                INSERT INTO users(username, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, 'admin', 1, ?, ?)
                """,
                (admin_user, _bcrypt_hash_password(ADMIN_PASS), now, now),
            )

        # Migrate legacy plaintext keys to hashed storage in-place.
        legacy_rows = cur.execute(
            "SELECT license_key, key_hash, key_prefix, key_mask FROM licenses"
        ).fetchall()
        for row in legacy_rows:
            old_value = str(row["license_key"] or "")
            existing_hash = str(row["key_hash"] or "")
            if existing_hash:
                continue
            key_hash = hash_license_key(old_value)
            prefix = normalize_prefix(old_value.split("-")[0] if "-" in old_value else "VE03")
            key_mask = mask_license(old_value)
            cur.execute(
                """
                UPDATE licenses
                SET license_key=?, key_hash=?, key_prefix=?, key_mask=?
                WHERE license_key=?
                """,
                (key_hash, key_hash, prefix, key_mask, old_value),
            )
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash)")

        # Migrate HWID: plaintext -> hash trong licenses.machine_id + bảng bindings.
        try:
            ban_hwid_rows = cur.execute("SELECT hwid, reason, created_at, expire_at FROM banned_hwids").fetchall()
            for br in ban_hwid_rows:
                old_hw = str(br["hwid"] or "").strip()
                if not old_hw:
                    continue
                new_hw = normalize_hwid_hash(old_hw)
                if new_hw == old_hw:
                    continue
                dup = cur.execute("SELECT hwid FROM banned_hwids WHERE hwid=?", (new_hw,)).fetchone()
                if dup:
                    cur.execute("DELETE FROM banned_hwids WHERE hwid=?", (old_hw,))
                else:
                    cur.execute("UPDATE banned_hwids SET hwid=? WHERE hwid=?", (new_hw, old_hw))
        except Exception:
            pass

        try:
            lic_hw = cur.execute(
                "SELECT license_key, key_hash, machine_id FROM licenses WHERE TRIM(COALESCE(machine_id,''))<>''"
            ).fetchall()
            for lr in lic_hw:
                kh = str(lr["key_hash"] or lr["license_key"] or "").strip()
                mid = str(lr["machine_id"] or "").strip()
                if not kh or not mid:
                    continue
                hh = normalize_hwid_hash(mid)
                cur.execute(
                    "INSERT OR IGNORE INTO license_hwid_bindings(key_hash, hwid_hash, created_at) VALUES (?, ?, ?)",
                    (kh, hh, now_ts()),
                )
                if hh != mid:
                    cur.execute("UPDATE licenses SET machine_id=? WHERE license_key=?", (hh, lr["license_key"]))
        except Exception:
            pass

        conn.commit()
    finally:
        conn.close()


def _parse_optional_ts(value: Any) -> int:
    try:
        ts = int(value or 0)
        return ts if ts > 0 else 0
    except Exception:
        return 0


def _ban_status(expire_at: int) -> str:
    if int(expire_at or 0) <= 0:
        return "active"
    return "active" if int(expire_at) > now_ts() else "expired"


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception:
        return False


def _is_true_value(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _setting_int(settings_map: dict[str, str], key: str, default: int, min_value: int, max_value: int) -> int:
    raw = str(settings_map.get(key, default)).strip()
    try:
        n = int(raw)
    except Exception:
        n = int(default)
    if n < min_value:
        return min_value
    if n > max_value:
        return max_value
    return n


def _setting_bool(settings_map: dict[str, str], key: str, default: str = "0") -> bool:
    return _is_true_value(settings_map.get(key, default))


def _validate_password_by_policy(password: str, settings_map: dict[str, str]) -> str:
    pwd = str(password or "")
    min_len = _setting_int(settings_map, "password_policy_min_length", 8, 6, 128)
    if len(pwd) < min_len:
        return f"password_too_short_min_{min_len}"
    if _setting_bool(settings_map, "password_policy_require_upper", "1") and not re.search(r"[A-Z]", pwd):
        return "password_missing_upper"
    if _setting_bool(settings_map, "password_policy_require_lower", "1") and not re.search(r"[a-z]", pwd):
        return "password_missing_lower"
    if _setting_bool(settings_map, "password_policy_require_digit", "1") and not re.search(r"\d", pwd):
        return "password_missing_digit"
    if _setting_bool(settings_map, "password_policy_require_special", "0") and not re.search(r"[^A-Za-z0-9]", pwd):
        return "password_missing_special"
    return ""


def _settings_map_conn(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {str(r["key"]): str(r["value"]) for r in rows}


def _insert_event_conn(conn: sqlite3.Connection, action: str, ip: str = "", license_key: str = "", machine_id: str = "", status: str = "", detail: str = "") -> None:
    conn.execute(
        "INSERT INTO events(ts, action, ip, license_key, machine_id, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (now_ts(), action, ip, license_key, machine_id, status, detail),
    )


def _ip_currently_banned(conn: sqlite3.Connection, ip: str, now: int) -> bool:
    return bool(
        conn.execute(
            "SELECT ip FROM banned_ips WHERE ip=? AND (expire_at<=0 OR expire_at>?)",
            (ip, now),
        ).fetchone()
    )


def _hwid_currently_banned(conn: sqlite3.Connection, hwid_hash: str, now: int) -> bool:
    return bool(
        conn.execute(
            "SELECT hwid FROM banned_hwids WHERE hwid=? AND (expire_at<=0 OR expire_at>?)",
            (hwid_hash, now),
        ).fetchone()
    )


def _apply_auto_ban_rules(conn: sqlite3.Connection, ip: str, hwid_hash: str) -> None:
    """
    Ban tự động thông minh (khi auto_ban_rules=1):
    - IP: quá nhiều lần check key thất bại
    - HWID: quá nhiều mismatch (giả mạo / share slot)
    - IP: nhiều HWID hash khác nhau trong thất bại (xoay HWID — tùy chọn, cẩn thận NAT)
    - IP: flood chữ ký / nonce không hợp lệ
    """
    settings = _settings_map_conn(conn)
    if not _is_true_value(settings.get("auto_ban_rules", "0")):
        return

    now = now_ts()
    fail_limit = _setting_int(settings, "auto_ban_failed_attempt_limit", 6, 2, 100)
    window_seconds = _setting_int(settings, "auto_ban_window_seconds", 600, 60, 86400)
    ban_seconds = _setting_int(settings, "auto_ban_duration_seconds", 3600, 60, 604800)
    mismatch_limit = _setting_int(settings, "auto_ban_mismatch_limit", 3, 1, 50)

    wrote = False

    if ip and _is_true_value(settings.get("auto_ban_rule_failed_attempts", "1")):
        if not _ip_currently_banned(conn, ip, now):
            failed_count = int(
                conn.execute(
                    """
                    SELECT COUNT(*) c
                    FROM events
                    WHERE action='license_check' AND ip=? AND status='failed' AND ts>=?
                    """,
                    (ip, now - window_seconds),
                ).fetchone()["c"]
            )
            if failed_count >= fail_limit:
                conn.execute(
                    "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                    (ip, f"auto_ban_failed_attempts:{failed_count}", now, now + ban_seconds),
                )
                _insert_event_conn(
                    conn,
                    "auto_ban_ip",
                    ip=ip,
                    status="ok",
                    detail=f"rule=failed_attempts;failed={failed_count};window={window_seconds};ban={ban_seconds}",
                )
                wrote = True

    if hwid_hash and _is_true_value(settings.get("auto_ban_rule_hwid_mismatch", "1")):
        if not _hwid_currently_banned(conn, hwid_hash, now):
            mismatch_count = int(
                conn.execute(
                    """
                    SELECT COUNT(*) c
                    FROM events
                    WHERE action='license_check' AND machine_id=? AND status='failed'
                      AND detail LIKE 'machine_id_mismatch%' AND ts>=?
                    """,
                    (hwid_hash, now - window_seconds),
                ).fetchone()["c"]
            )
            if mismatch_count >= mismatch_limit:
                conn.execute(
                    "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                    (hwid_hash, f"auto_ban_hwid_spoof:{mismatch_count}", now, now + ban_seconds),
                )
                _insert_event_conn(
                    conn,
                    "auto_ban_hwid",
                    ip=ip,
                    machine_id=hwid_hash,
                    status="ok",
                    detail=f"rule=hwid_mismatch;events={mismatch_count};window={window_seconds};ban={ban_seconds}",
                )
                wrote = True

    # Cùng IP, quá nhiều HWID khác nhau trong các lần failed → nghi xoay HWID / spoof
    if ip and _is_true_value(settings.get("auto_ban_rule_multi_hwid_ip", "0")):
        if not _ip_currently_banned(conn, ip, now):
            mwin = _setting_int(settings, "multi_hwid_ip_window_seconds", 900, 60, 86400)
            mlim = _setting_int(settings, "multi_hwid_ip_limit", 15, 3, 500)
            distinct_hw = int(
                conn.execute(
                    """
                    SELECT COUNT(DISTINCT machine_id) c
                    FROM events
                    WHERE action='license_check' AND ip=? AND status='failed'
                      AND machine_id<>'' AND ts>=?
                    """,
                    (ip, now - mwin),
                ).fetchone()["c"]
            )
            if distinct_hw >= mlim:
                conn.execute(
                    "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                    (ip, f"auto_ban_multi_hwid_ip:{distinct_hw}", now, now + ban_seconds),
                )
                _insert_event_conn(
                    conn,
                    "auto_ban_ip",
                    ip=ip,
                    status="ok",
                    detail=f"rule=multi_hwid_ip;distinct={distinct_hw};window={mwin};ban={ban_seconds}",
                )
                wrote = True

    # Flood chữ ký / replay / nonce yếu (hành vi giả mạo request)
    if ip and _is_true_value(settings.get("auto_ban_rule_invalid_signature", "1")):
        if not _ip_currently_banned(conn, ip, now):
            iwin = _setting_int(settings, "invalid_sig_window_seconds", 600, 60, 86400)
            ilim = _setting_int(settings, "invalid_sig_ban_limit", 18, 5, 500)
            sig_fails = int(
                conn.execute(
                    """
                    SELECT COUNT(*) c
                    FROM events
                    WHERE action='license_check' AND ip=? AND status='failed' AND ts>=?
                      AND detail IN (
                        'invalid_request_signature',
                        'replay_or_duplicate_nonce',
                        'missing_request_signature',
                        'weak_nonce',
                        'missing_nonce'
                      )
                    """,
                    (ip, now - iwin),
                ).fetchone()["c"]
            )
            if sig_fails >= ilim:
                conn.execute(
                    "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                    (ip, f"auto_ban_invalid_sig_flood:{sig_fails}", now, now + ban_seconds),
                )
                _insert_event_conn(
                    conn,
                    "auto_ban_ip",
                    ip=ip,
                    status="ok",
                    detail=f"rule=invalid_signature_flood;count={sig_fails};window={iwin};ban={ban_seconds}",
                )
                wrote = True

    if wrote:
        conn.commit()


def _apply_hwid_swap_ban(conn: sqlite3.Connection, license_key_hash: str, ip: str) -> None:
    """Cùng một key thử quá nhiều HWID khác nhau (mismatch) trong cửa sổ thời gian -> ban key."""
    settings = _settings_map_conn(conn)
    if not _is_true_value(settings.get("hwid_swap_auto_ban_enabled", "1")):
        return
    limit = _setting_int(settings, "hwid_swap_fail_limit", 5, 2, 100)
    window_seconds = _setting_int(settings, "hwid_swap_window_seconds", 3600, 60, 86400)
    ban_seconds = _setting_int(settings, "auto_ban_duration_seconds", 3600, 60, 604800)
    detail_marker = f"machine_id_mismatch|key_hash={license_key_hash}"
    now = now_ts()
    cnt = int(
        conn.execute(
            """
            SELECT COUNT(*) c FROM events
            WHERE action='license_check' AND status='failed' AND detail=? AND ts>=?
            """,
            (detail_marker, now - window_seconds),
        ).fetchone()["c"]
    )
    if cnt < limit:
        return
    conn.execute("UPDATE licenses SET status='banned' WHERE key_hash=? OR license_key=?", (license_key_hash, license_key_hash))
    _insert_event_conn(
        conn,
        "auto_ban_license_hwid_swap",
        ip=ip,
        status="ok",
        detail=f"swap_mismatches={cnt};window={window_seconds};ban_key_seconds={ban_seconds}",
    )
    conn.commit()


def insert_event(action: str, ip: str = "", license_key: str = "", machine_id: str = "", status: str = "", detail: str = "") -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO events(ts, action, ip, license_key, machine_id, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now_ts(), action, ip, license_key, machine_id, status, detail),
        )
        conn.commit()
    finally:
        conn.close()


def _record_failed_license_check(
    ip: str,
    license_key: str,
    machine_id_plain: str,
    detail: str,
    *,
    license_key_hash: str = "",
) -> None:
    """Ghi log thất bại; machine_id trong events là hash HWID (không plaintext)."""
    hwid_h = normalize_hwid_hash(machine_id_plain) if machine_id_plain else ""
    if detail == "machine_id_mismatch" and license_key_hash:
        detail = f"machine_id_mismatch|key_hash={license_key_hash}"
    insert_event("license_check", ip, license_key=mask_license(license_key), machine_id=hwid_h, status="failed", detail=detail)
    conn = db_connect()
    try:
        _apply_auto_ban_rules(conn, ip, hwid_h)
        if detail.startswith("machine_id_mismatch|key_hash=") and license_key_hash:
            _apply_hwid_swap_ban(conn, license_key_hash, ip)
    finally:
        conn.close()


def _resolve_license_ref(body: dict[str, Any]) -> str:
    license_ref = str(body.get("license_ref", "")).strip()
    if _is_hex64(license_ref):
        return license_ref.lower()
    raw_key = str(body.get("license_key", "")).strip()
    if _is_hex64(raw_key):
        return raw_key.lower()
    if not raw_key:
        return ""
    return hash_license_key(raw_key)


def normalize_ip(handler: "AdminHandler") -> str:
    xff = str(handler.headers.get("X-Forwarded-For", "")).strip()
    if xff:
        return xff.split(",")[0].strip()
    if handler.client_address and handler.client_address[0]:
        return str(handler.client_address[0]).strip()
    return ""


def json_response(
    handler: "AdminHandler",
    payload: dict[str, Any],
    status: int = HTTPStatus.OK,
    extra_headers: dict[str, str] | None = None,
) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    if extra_headers:
        for hk, hv in extra_headers.items():
            handler.send_header(hk, str(hv))
    handler.end_headers()
    handler.wfile.write(raw)


def _bump_setting(conn: sqlite3.Connection, key: str, delta: int = 1) -> None:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    cur_v = 0
    try:
        cur_v = int(str(row["value"] or "0")) if row else 0
    except Exception:
        cur_v = 0
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(cur_v + int(delta))),
    )


def _handle_public_api_rate_violation(handler: "AdminHandler", ip: str, reason: str, retry_after_sec: int) -> None:
    insert_event("api_rate_limit", ip, status="failed", detail=reason)
    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
        _bump_setting(conn, "api_rate_rejections", 1)
        if _is_true_value(settings.get("api_auto_ban_on_rate_violations", "1")):
            thr = _setting_int(settings, "api_rate_violation_ban_threshold", 25, 5, 1000)
            win = _setting_int(settings, "api_rate_violation_ban_window_sec", 600, 60, 86400)
            ban_sec = _setting_int(settings, "auto_ban_duration_seconds", 3600, 60, 604800)
            if api_security.record_rate_violation(ip, win, thr):
                now = now_ts()
                conn.execute(
                    "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                    (ip, f"api_rate_abuse:{reason}", now, now + ban_sec),
                )
                _insert_event_conn(
                    conn,
                    "auto_ban_ip_rate_abuse",
                    ip=ip,
                    status="ok",
                    detail=f"reason={reason};thr={thr};win={win}",
                )
        conn.commit()
    finally:
        conn.close()
    json_response(
        handler,
        {"ok": False, "ACTIVE": False, "error": reason, "reason": reason},
        HTTPStatus.TOO_MANY_REQUESTS,
        {"Retry-After": str(max(1, retry_after_sec))},
    )


def _guard_license_public_api(handler: "AdminHandler", body: dict[str, Any]) -> bool:
    """
    Xác thực API key, Origin, rate limit; tăng bộ đếm khi cho phép.
    Trả True nếu đã gửi response lỗi (caller return). Trả False nếu tiếp tục xử lý.
    """
    ip = normalize_ip(handler)
    if not api_security.validate_public_api_key(handler):
        json_response(
            handler,
            {"ok": False, "ACTIVE": False, "error": "missing_or_invalid_api_key", "reason": "unauthorized"},
            HTTPStatus.UNAUTHORIZED,
        )
        return True

    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
    finally:
        conn.close()

    extra_origins = str(settings.get("api_allowed_origins", "") or "")
    if not api_security.origin_allowed(handler, extra_origins):
        json_response(
            handler,
            {"ok": False, "ACTIVE": False, "error": "origin_not_allowed", "reason": "forbidden"},
            HTTPStatus.FORBIDDEN,
        )
        return True

    window = _setting_int(settings, "api_rate_window_seconds", 60, 1, 3600)
    lim_ip = _setting_int(settings, "api_rate_ip_per_minute", 120, 1, 100000)
    lim_key = _setting_int(settings, "api_rate_key_per_minute", 60, 1, 100000)

    license_key = str(body.get("license_key", "") or "").strip()
    key_fp = hash_license_key(license_key) if license_key else ""

    ok, rreason = api_security.rate_limit_allow(
        ip,
        key_fp,
        window_sec=window,
        limit_ip=lim_ip,
        limit_key=lim_key if key_fp else lim_ip,
    )
    if not ok:
        _handle_public_api_rate_violation(handler, ip, rreason, window)
        return True

    conn = db_connect()
    try:
        _bump_setting(conn, "api_total_requests", 1)
        conn.commit()
    finally:
        conn.close()
    return False


def _guard_ping_public_api(handler: "AdminHandler") -> bool:
    """True = đã trả response (lỗi)."""
    ip = normalize_ip(handler)
    if not api_security.validate_public_api_key(handler):
        json_response(
            handler,
            {"ok": False, "error": "missing_or_invalid_api_key"},
            HTTPStatus.UNAUTHORIZED,
        )
        return True
    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
    finally:
        conn.close()
    extra_origins = str(settings.get("api_allowed_origins", "") or "")
    if not api_security.origin_allowed(handler, extra_origins):
        json_response(handler, {"ok": False, "error": "origin_not_allowed"}, HTTPStatus.FORBIDDEN)
        return True
    window = _setting_int(settings, "api_rate_window_seconds", 60, 1, 3600)
    lim_ip = _setting_int(settings, "api_rate_ip_per_minute", 120, 1, 100000)
    ok, rreason = api_security.rate_limit_allow(ip, "", window_sec=window, limit_ip=lim_ip, limit_key=10**9)
    if not ok:
        _handle_public_api_rate_violation(handler, ip, rreason, window)
        return True
    conn = db_connect()
    try:
        _bump_setting(conn, "api_total_requests", 1)
        conn.commit()
    finally:
        conn.close()
    return False


def _enforce_license_hmac_and_nonce_replay(
    *,
    license_key: str,
    license_key_hash: str,
    machine_id: str,
    ts: int,
    nonce: str,
    request_sig: str,
    app_version: str,
    settings: dict[str, str],
) -> str | None:
    """
    Xác thực HMAC request, timestamp, chống replay nonce.
    Trả về mã lỗi (reason) nếu từ chối; None nếu cho qua.
    """
    sig_req = _is_true_value(settings.get("license_signature_required", "1"))
    if not sig_req:
        if ts > 0 and abs(now_ts() - int(ts)) > 3600:
            return "invalid_ts"
        return None

    if not request_sig:
        return "missing_request_signature"
    if not nonce:
        return "missing_nonce"
    nmin = _setting_int(settings, "license_nonce_min_length", 16, 8, 128)
    if len(nonce) < nmin:
        return "weak_nonce"
    if int(ts or 0) <= 0:
        return "invalid_ts"
    skew = _setting_int(settings, "license_clock_skew_seconds", 300, 30, 7200)
    if abs(now_ts() - int(ts)) > skew:
        return "invalid_ts"

    av = str(app_version or "")
    expected = sign_hmac_hex(LICENSE_SECRET, canonical_request(license_key, machine_id, ts, nonce, av))
    ok_sig = hmac.compare_digest(expected, request_sig)
    if not ok_sig and _is_true_value(settings.get("license_signature_allow_legacy", "1")):
        leg = canonical_request_legacy(license_key, machine_id, ts, nonce)
        expected_leg = sign_hmac_hex(LICENSE_SECRET, leg)
        ok_sig = hmac.compare_digest(expected_leg, request_sig)
    if not ok_sig:
        return "invalid_request_signature"

    fp = license_request_nonce_fingerprint(nonce, license_key_hash, int(ts))
    retain = _setting_int(settings, "license_nonce_retain_seconds", 172800, skew * 2, 2592000)
    now = now_ts()
    conn = db_connect()
    try:
        conn.execute("DELETE FROM license_used_nonces WHERE used_at < ?", (now - retain,))
        try:
            conn.execute("INSERT INTO license_used_nonces(nonce_fp, used_at) VALUES (?, ?)", (fp, now))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return "replay_or_duplicate_nonce"
    finally:
        conn.close()
    return None


def read_json_body(handler: "AdminHandler") -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def mask_license(k: str) -> str:
    text = str(k or "")
    if len(text) < 10:
        return text
    return f"{text[:6]}...{text[-4:]}"


def _fingerprint_ua(handler: "AdminHandler") -> str:
    ua = str(handler.headers.get("User-Agent", "") or "").strip()
    if not ua:
        return ""
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()


def _hash_refresh_token(refresh_token: str) -> str:
    raw = f"{LICENSE_SECRET}|REFRESH|{str(refresh_token or '').strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _user_row_conn(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT username, password_hash, role, is_active, totp_secret, totp_enabled FROM users WHERE username=?",
        (_normalize_username(username),),
    ).fetchone()


def _issue_access_token(username: str, role: str, session_id: str, ttl_seconds: int) -> str:
    now = now_ts()
    payload = {
        "typ": "access",
        "sub": str(username or ""),
        "role": str(role or "mod"),
        "sid": str(session_id or ""),
        "iat": now,
        "exp": now + int(ttl_seconds),
        "jti": uuid.uuid4().hex,
    }
    return _issue_jwt(payload)


def _issue_refresh_token(username: str, session_id: str, ttl_seconds: int) -> str:
    now = now_ts()
    payload = {
        "typ": "refresh",
        "sub": str(username or ""),
        "sid": str(session_id or ""),
        "iat": now,
        "exp": now + int(ttl_seconds),
        "jti": uuid.uuid4().hex,
    }
    return _issue_jwt(payload)


def _create_auth_session(user: str, ip: str, ua_fp: str) -> tuple[str, str, int]:
    now = now_ts()
    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
        access_ttl = _setting_int(settings, "auth_access_token_ttl_seconds", ACCESS_TOKEN_TTL_SECONDS, 120, 86400)
        refresh_ttl = _setting_int(settings, "auth_refresh_token_ttl_seconds", REFRESH_TOKEN_TTL_SECONDS, 3600, 2592000)
        row = _user_row_conn(conn, user)
        role = str(row["role"] if row else "admin")
        session_id = uuid.uuid4().hex
        access_token = _issue_access_token(user, role, session_id, access_ttl)
        refresh_token = _issue_refresh_token(user, session_id, refresh_ttl)
        refresh_hash = _hash_refresh_token(refresh_token)
        conn.execute(
            """
            INSERT INTO auth_sessions(session_id, user, refresh_hash, created_at, expires_at, revoked_at, last_seen_at, last_ip, last_ua, suspicious_count)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 0)
            """,
            (session_id, user, refresh_hash, now, now + refresh_ttl, now, ip, ua_fp),
        )
        conn.commit()
    finally:
        conn.close()
    return access_token, refresh_token, access_ttl


def _revoke_session_id(session_id: str) -> None:
    now = now_ts()
    conn = db_connect()
    try:
        conn.execute("UPDATE auth_sessions SET revoked_at=? WHERE session_id=? AND revoked_at=0", (now, session_id))
        conn.commit()
    finally:
        conn.close()


def _session_claims(handler: "AdminHandler") -> dict[str, Any] | None:
    auth = str(handler.headers.get("Authorization", "")).strip()
    if not auth.startswith("Bearer "):
        return None
    token = auth.replace("Bearer ", "", 1).strip()
    claims, err = _verify_jwt(token, "access")
    if err or not claims:
        return None
    sid = str(claims.get("sid", "") or "")
    sub = str(claims.get("sub", "") or "")
    if not sid or not sub:
        return None

    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT user, revoked_at, expires_at FROM auth_sessions WHERE session_id=?",
            (sid,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    now = now_ts()
    if int(row["revoked_at"] or 0) > 0 or now >= int(row["expires_at"] or 0) or str(row["user"] or "") != sub:
        return None
    # cập nhật hoạt động session + phát hiện thay đổi bất thường
    conn2 = db_connect()
    try:
        settings = _settings_map_conn(conn2)
        ip = normalize_ip(handler)
        ua_fp = _fingerprint_ua(handler)
        r2 = conn2.execute(
            "SELECT last_ip, last_ua, suspicious_count FROM auth_sessions WHERE session_id=?",
            (sid,),
        ).fetchone()
        suspicious_add = 0
        if r2:
            if str(r2["last_ip"] or "") and str(r2["last_ip"] or "") != ip:
                suspicious_add += 1
            if str(r2["last_ua"] or "") and str(r2["last_ua"] or "") != ua_fp:
                suspicious_add += 1
            new_susp = int(r2["suspicious_count"] or 0) + suspicious_add
            lim = max(
                _setting_int(settings, "session_suspicious_ip_change_limit", 3, 1, 100),
                _setting_int(settings, "session_suspicious_ua_change_limit", 3, 1, 100),
            )
            if suspicious_add > 0:
                _insert_event_conn(conn2, "suspicious_session", ip=ip, status="warn", detail=f"sid={sid};delta={suspicious_add}")
            if _is_true_value(settings.get("session_auto_revoke_on_suspicious", "1")) and new_susp >= lim:
                conn2.execute("UPDATE auth_sessions SET revoked_at=?, suspicious_count=? WHERE session_id=?", (now, new_susp, sid))
                conn2.commit()
                return None
            conn2.execute(
                "UPDATE auth_sessions SET last_seen_at=?, last_ip=?, last_ua=?, suspicious_count=? WHERE session_id=?",
                (now, ip, ua_fp, new_susp, sid),
            )
            conn2.commit()
            urow = _user_row_conn(conn2, sub)
            if not urow or int(urow["is_active"] or 0) != 1:
                return None
            return {
                "user": str(urow["username"] or sub),
                "role": str(urow["role"] or "mod"),
                "sid": sid,
            }
    finally:
        conn2.close()
    return None


def session_user(handler: "AdminHandler") -> str | None:
    claims = _session_claims(handler)
    if not claims:
        return None
    return str(claims.get("user") or "")


def require_auth(handler: "AdminHandler") -> bool:
    claims = getattr(handler, "_auth_claims", None)
    if not claims:
        claims = _session_claims(handler)
    if not claims:
        json_response(handler, {"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
        return False
    setattr(handler, "_auth_claims", claims)
    return True


def require_role(handler: "AdminHandler", roles: set[str]) -> bool:
    claims = getattr(handler, "_auth_claims", None)
    if not claims:
        claims = _session_claims(handler)
        if not claims:
            json_response(handler, {"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return False
        setattr(handler, "_auth_claims", claims)
    role = str(claims.get("role") or "mod")
    if role not in set(roles):
        json_response(handler, {"ok": False, "error": "forbidden"}, HTTPStatus.FORBIDDEN)
        return False
    return True


def _refresh_session_tokens(handler: "AdminHandler", refresh_token: str) -> tuple[dict[str, Any] | None, int]:
    ip = normalize_ip(handler)
    ua_fp = _fingerprint_ua(handler)
    claims, tok_err = _verify_jwt(refresh_token, "refresh")
    if tok_err or not claims:
        return {"ok": False, "error": tok_err or "invalid_refresh_token"}, HTTPStatus.UNAUTHORIZED
    sid_claim = str(claims.get("sid") or "")
    sub_claim = str(claims.get("sub") or "")
    if not sid_claim or not sub_claim:
        return {"ok": False, "error": "invalid_refresh_token"}, HTTPStatus.UNAUTHORIZED
    rh = _hash_refresh_token(refresh_token)
    now = now_ts()
    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
        row = conn.execute(
            """
            SELECT session_id, user, expires_at, revoked_at, last_ip, last_ua, suspicious_count
            FROM auth_sessions WHERE refresh_hash=? AND session_id=?
            """,
            (rh, sid_claim),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "invalid_refresh_token"}, HTTPStatus.UNAUTHORIZED
        if str(row["user"] or "") != sub_claim:
            return {"ok": False, "error": "invalid_refresh_token"}, HTTPStatus.UNAUTHORIZED
        if int(row["revoked_at"] or 0) > 0:
            return {"ok": False, "error": "refresh_token_revoked"}, HTTPStatus.UNAUTHORIZED
        if now >= int(row["expires_at"] or 0):
            return {"ok": False, "error": "refresh_token_expired"}, HTTPStatus.UNAUTHORIZED

        suspicious = 0
        reason_parts: list[str] = []
        if str(row["last_ip"] or "") and str(row["last_ip"] or "") != ip:
            suspicious += 1
            reason_parts.append("ip_changed")
        if str(row["last_ua"] or "") and str(row["last_ua"] or "") != ua_fp:
            suspicious += 1
            reason_parts.append("ua_changed")
        new_susp = int(row["suspicious_count"] or 0) + suspicious
        lim_ip = _setting_int(settings, "session_suspicious_ip_change_limit", 3, 1, 100)
        lim_ua = _setting_int(settings, "session_suspicious_ua_change_limit", 3, 1, 100)
        lim_max = max(lim_ip, lim_ua)
        auto_revoke = _is_true_value(settings.get("session_auto_revoke_on_suspicious", "1"))

        if suspicious > 0:
            _insert_event_conn(
                conn,
                "suspicious_session",
                ip=ip,
                status="warn",
                detail=";".join(reason_parts) + f";session={row['session_id']}",
            )

        if auto_revoke and new_susp >= lim_max:
            conn.execute("UPDATE auth_sessions SET revoked_at=?, suspicious_count=? WHERE session_id=?", (now, new_susp, row["session_id"]))
            conn.commit()
            _revoke_session_id(str(row["session_id"]))
            return {"ok": False, "error": "session_revoked_suspicious"}, HTTPStatus.UNAUTHORIZED

        urow = _user_row_conn(conn, str(row["user"] or ""))
        if not urow or int(urow["is_active"] or 0) != 1:
            return {"ok": False, "error": "user_disabled"}, HTTPStatus.UNAUTHORIZED

        access_ttl = _setting_int(settings, "auth_access_token_ttl_seconds", ACCESS_TOKEN_TTL_SECONDS, 120, 86400)
        refresh_ttl = _setting_int(settings, "auth_refresh_token_ttl_seconds", REFRESH_TOKEN_TTL_SECONDS, 3600, 2592000)
        sid = str(row["session_id"] or "")
        role = str(urow["role"] or "mod")
        user = str(row["user"] or ADMIN_USER)
        new_access = _issue_access_token(user, role, sid, access_ttl)
        new_refresh = _issue_refresh_token(user, sid, refresh_ttl)
        new_refresh_hash = _hash_refresh_token(new_refresh)
        conn.execute(
            """
            UPDATE auth_sessions
            SET refresh_hash=?, expires_at=?, last_seen_at=?, last_ip=?, last_ua=?, suspicious_count=?
            WHERE session_id=?
            """,
            (new_refresh_hash, now + refresh_ttl, now, ip, ua_fp, new_susp, row["session_id"]),
        )
        conn.commit()
        return {
            "ok": True,
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token": new_access,
            "expires_in": access_ttl,
            "session_suspicious_count": new_susp,
        }, HTTPStatus.OK
    finally:
        conn.close()


def to_iso(ts: int) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ts)).isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def _stream_xor_crypt(data: bytes, key_material: str, nonce: bytes) -> bytes:
    """Mã hóa đối xứng nhẹ cho file backup (XOR keystream SHA-256)."""
    key = hashlib.sha256((LICENSE_SECRET + "|" + str(key_material or "")).encode("utf-8")).digest()
    out = bytearray(len(data))
    ctr = 0
    pos = 0
    while pos < len(data):
        block = hashlib.sha256(key + nonce + ctr.to_bytes(8, "big")).digest()
        n = min(len(block), len(data) - pos)
        for i in range(n):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += n
        ctr += 1
    return bytes(out)


def _write_encrypted_backup(snapshot_path: Path, out_path: Path, enc_key: str) -> str:
    raw = snapshot_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    comp = gzip.compress(raw, compresslevel=6)
    nonce = secrets.token_bytes(16)
    cipher = _stream_xor_crypt(comp, enc_key, nonce)
    payload = {
        "v": 1,
        "alg": "xor-sha256-stream+gzip",
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "sha256": digest,
    }
    body = _b64u_encode_json(payload).encode("ascii") + b"\n" + cipher
    out_path.write_bytes(body)
    return digest


def _run_integrity_check() -> None:
    conn = db_connect()
    try:
        row = conn.execute("PRAGMA quick_check").fetchone()
        result = str(row[0]) if row and len(row.keys()) > 0 else "unknown"
    finally:
        conn.close()
    status = "ok" if result.lower() == "ok" else "failed"
    insert_event("db_integrity_check", status=status, detail=result[:250])


def _run_backup_once() -> None:
    conn = db_connect()
    try:
        settings = _settings_map_conn(conn)
    finally:
        conn.close()
    if not _is_true_value(settings.get("db_backup_enabled", "1")):
        return
    enc_key = (
        str(settings.get("db_backup_encryption_key", "") or "").strip()
        or str(os.getenv("DB_BACKUP_ENCRYPTION_KEY", "")).strip()
        or LICENSE_SECRET
    )
    if not enc_key:
        insert_event("db_backup", status="failed", detail="missing_backup_encryption_key")
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = now_ts()
    snapshot = BACKUP_DIR / f"snapshot-{ts}.db"
    out_file = BACKUP_DIR / f"backup-{ts}.db.enc"
    conn_src = db_connect()
    conn_dst = sqlite3.connect(str(snapshot))
    try:
        conn_src.backup(conn_dst)
        conn_dst.commit()
    finally:
        conn_dst.close()
        conn_src.close()
    try:
        digest = _write_encrypted_backup(snapshot, out_file, enc_key)
        insert_event("db_backup", status="ok", detail=f"file={out_file.name};sha256={digest[:16]}")
    except Exception as exc:
        insert_event("db_backup", status="failed", detail=f"err={str(exc)[:180]}")
    finally:
        try:
            snapshot.unlink(missing_ok=True)
        except Exception:
            pass

    # cleanup theo retention
    days = _setting_int(settings, "db_backup_retention_days", 14, 1, 3650)
    cutoff = now_ts() - days * 86400
    for p in BACKUP_DIR.glob("backup-*.db.enc"):
        m = re.search(r"backup-(\d+)\.db\.enc$", p.name)
        if not m:
            continue
        try:
            pts = int(m.group(1))
        except Exception:
            continue
        if pts < cutoff:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


def _maintenance_loop() -> None:
    last_backup = 0
    last_integrity = 0
    while True:
        try:
            conn = db_connect()
            try:
                settings = _settings_map_conn(conn)
            finally:
                conn.close()
            now = now_ts()
            backup_iv = _setting_int(settings, "db_backup_interval_seconds", 3600, 60, 86400)
            integ_iv = _setting_int(settings, "db_integrity_check_interval_seconds", 1800, 60, 86400)
            if now - last_integrity >= integ_iv:
                _run_integrity_check()
                last_integrity = now
            if now - last_backup >= backup_iv:
                _run_backup_once()
                last_backup = now
            # dọn session/token hết hạn
            conn_gc = db_connect()
            try:
                conn_gc.execute(
                    "DELETE FROM auth_sessions WHERE (revoked_at>0 AND revoked_at<?) OR expires_at<?",
                    (now - 7 * 86400, now - 86400),
                )
                conn_gc.commit()
            finally:
                conn_gc.close()
            dead_tokens = [tk for tk, info in sessions.items() if now >= int(info.get("exp", 0) or 0)]
            for tk in dead_tokens:
                sessions.pop(tk, None)
            time.sleep(15)
        except Exception as exc:
            insert_event("db_maintenance", status="failed", detail=f"err={str(exc)[:180]}")
            time.sleep(30)


class AdminHandler(SimpleHTTPRequestHandler):
    def _query_param(self, query: dict[str, list[str]], key: str, default: str = "") -> str:
        val = query.get(key, [default])
        if not val:
            return default
        return str(val[0] or default).strip()

    def end_headers(self) -> None:
        # Force fresh static/assets so UI changes show immediately.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def translate_path(self, path: str) -> str:
        parsed = urlparse(path)
        req_path = parsed.path
        if req_path == "/":
            return str(STATIC_DIR / "index.html")
        if req_path.startswith("/static/"):
            rel = req_path.replace("/static/", "", 1)
            return str(STATIC_DIR / rel)
        return super().translate_path(path)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query or "")

        if path == "/api/ping":
            if _guard_ping_public_api(self):
                return
            return json_response(self, {"ok": True, "ts": now_ts()})
        protected_get_mod = {"/api/dashboard", "/api/licenses", "/api/bans", "/api/events", "/api/devices"}
        protected_get_admin = {"/api/settings", "/api/users", "/api/users/sessions"}
        if path in protected_get_mod:
            if not require_role(self, {"admin", "mod"}):
                return
        if path in protected_get_admin:
            if not require_role(self, {"admin"}):
                return
        if path == "/api/dashboard":
            return self._api_dashboard()
        if path == "/api/licenses":
            return self._api_list_licenses()
        if path == "/api/bans":
            return self._api_list_bans()
        if path == "/api/events":
            return self._api_list_events(query)
        if path == "/api/devices":
            return self._api_list_devices()
        if path == "/api/settings":
            return self._api_get_settings()
        if path == "/api/users":
            return self._api_list_users()
        if path == "/api/users/sessions":
            return self._api_list_user_sessions(query)

        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        protected_post_mod = {
            "/api/bans/ip",
            "/api/bans/hwid",
            "/api/bans/ip/update",
            "/api/bans/hwid/update",
            "/api/bans/ip/remove",
            "/api/bans/hwid/remove",
            "/api/devices/unbind",
            "/api/devices/ban",
            "/api/devices/kick",
        }
        protected_post_admin = {
            "/api/licenses/create",
            "/api/licenses/update",
            "/api/licenses/delete",
            "/api/licenses/extend",
            "/api/licenses/revoke",
            "/api/licenses/unrevoke",
            "/api/settings/update",
            "/api/users/create",
            "/api/users/role",
            "/api/users/disable",
            "/api/users/reset_password",
            "/api/users/revoke_all_sessions",
            "/api/users/revoke_active_sessions",
            "/api/users/revoke_session",
            "/api/2fa/setup",
            "/api/2fa/enable",
            "/api/2fa/disable",
        }
        if path in protected_post_mod:
            if not require_role(self, {"admin", "mod"}):
                return
        if path in protected_post_admin:
            if not require_role(self, {"admin"}):
                return

        if path == "/api/login":
            return self._api_login()
        if path == "/api/token/refresh":
            return self._api_refresh_token()
        if path == "/api/token/revoke":
            return self._api_revoke_token()
        if path == "/api/licenses/create":
            return self._api_create_licenses()
        if path == "/api/licenses/update":
            return self._api_update_license()
        if path == "/api/licenses/delete":
            return self._api_delete_license()
        if path == "/api/licenses/extend":
            return self._api_extend_license()
        if path == "/api/licenses/revoke":
            return self._api_revoke_license()
        if path == "/api/licenses/unrevoke":
            return self._api_unrevoke_license()
        if path == "/api/bans/ip":
            return self._api_ban_ip()
        if path == "/api/bans/hwid":
            return self._api_ban_hwid()
        if path == "/api/bans/ip/update":
            return self._api_update_ip_ban()
        if path == "/api/bans/hwid/update":
            return self._api_update_hwid_ban()
        if path == "/api/bans/ip/remove":
            return self._api_unban_ip()
        if path == "/api/bans/hwid/remove":
            return self._api_unban_hwid()
        if path == "/api/devices/unbind":
            return self._api_unbind_device()
        if path == "/api/devices/ban":
            return self._api_ban_device()
        if path == "/api/devices/kick":
            return self._api_kick_device()
        if path == "/api/settings/update":
            return self._api_update_settings()
        if path == "/api/users/create":
            return self._api_create_user()
        if path == "/api/users/role":
            return self._api_set_user_role()
        if path == "/api/users/disable":
            return self._api_set_user_active()
        if path == "/api/users/reset_password":
            return self._api_reset_user_password()
        if path == "/api/users/revoke_all_sessions":
            return self._api_revoke_all_user_sessions()
        if path == "/api/users/revoke_active_sessions":
            return self._api_revoke_active_user_sessions()
        if path == "/api/users/revoke_session":
            return self._api_revoke_single_session()
        if path == "/api/2fa/setup":
            return self._api_2fa_setup()
        if path == "/api/2fa/enable":
            return self._api_2fa_enable()
        if path == "/api/2fa/disable":
            return self._api_2fa_disable()
        if path == "/api/check":
            return self._api_check_license()
        if path == "/api/proof/verify":
            return self._api_verify_license_proof()
        if path == "/api/client/security_event":
            return self._api_client_security_event()

        json_response(self, {"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)

    def _api_login(self) -> None:
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")).strip())
        password = str(body.get("password", "")).strip()
        totp_code = str(body.get("totp_code", "")).strip()
        if not username or not password:
            insert_event("admin_login", normalize_ip(self), status="failed", detail="missing_credentials")
            return json_response(self, {"ok": False, "error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
        if not _is_valid_username(username):
            insert_event("admin_login", normalize_ip(self), status="failed", detail="invalid_username_format")
            return json_response(self, {"ok": False, "error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
        conn = db_connect()
        try:
            urow = _user_row_conn(conn, username)
        finally:
            conn.close()
        if not urow or int(urow["is_active"] or 0) != 1:
            insert_event("admin_login", normalize_ip(self), status="failed", detail="user_not_found_or_disabled")
            return json_response(self, {"ok": False, "error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
        if not _bcrypt_verify_password(password, str(urow["password_hash"] or "")):
            insert_event("admin_login", normalize_ip(self), status="failed", detail="bad_password")
            return json_response(self, {"ok": False, "error": "invalid_credentials"}, HTTPStatus.UNAUTHORIZED)
        if int(urow["totp_enabled"] or 0) == 1:
            secret = str(urow["totp_secret"] or "")
            if not _verify_totp(secret, totp_code):
                insert_event("admin_login", normalize_ip(self), status="failed", detail="totp_required_or_invalid")
                return json_response(self, {"ok": False, "error": "totp_required"}, HTTPStatus.UNAUTHORIZED)

        ip = normalize_ip(self)
        ua_fp = _fingerprint_ua(self)
        user_name = str(urow["username"] or username)
        access_token, refresh_token, ttl = _create_auth_session(user_name, ip, ua_fp)
        insert_event("admin_login", normalize_ip(self), status="ok")
        json_response(
            self,
            {
                "ok": True,
                "token": access_token,  # compat cũ
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": ttl,
                "role": str(urow["role"] or "mod"),
                "username": user_name,
            },
        )

    def _api_refresh_token(self) -> None:
        body = read_json_body(self)
        refresh_token = str(body.get("refresh_token", "")).strip()
        if not refresh_token:
            return json_response(self, {"ok": False, "error": "missing_refresh_token"}, HTTPStatus.BAD_REQUEST)
        payload, status = _refresh_session_tokens(self, refresh_token)
        json_response(self, payload or {"ok": False, "error": "refresh_failed"}, status)

    def _api_revoke_token(self) -> None:
        # hỗ trợ revoke current access token hoặc refresh token
        body = read_json_body(self)
        refresh_token = str(body.get("refresh_token", "")).strip()
        if refresh_token:
            rh = _hash_refresh_token(refresh_token)
            conn = db_connect()
            sid = ""
            try:
                row = conn.execute("SELECT session_id FROM auth_sessions WHERE refresh_hash=?", (rh,)).fetchone()
                if row:
                    sid = str(row["session_id"] or "")
            finally:
                conn.close()
            if sid:
                _revoke_session_id(sid)
                insert_event("token_revoke", normalize_ip(self), status="ok", detail="by_refresh")
                return json_response(self, {"ok": True})

        auth = str(self.headers.get("Authorization", "")).strip()
        token = auth.replace("Bearer ", "", 1).strip() if auth.startswith("Bearer ") else ""
        sid = ""
        if token:
            claims, err = _verify_jwt(token, "access")
            if not err and claims:
                sid = str(claims.get("sid") or "")
        if sid:
            _revoke_session_id(sid)
            insert_event("token_revoke", normalize_ip(self), status="ok", detail="by_access")
            return json_response(self, {"ok": True})
        return json_response(self, {"ok": False, "error": "session_not_found"}, HTTPStatus.NOT_FOUND)

    def _api_dashboard(self) -> None:
        if not require_auth(self):
            return
        conn = db_connect()
        try:
            cur = conn.cursor()
            total_keys = cur.execute("SELECT COUNT(*) c FROM licenses").fetchone()["c"]
            active_keys = cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at>?", (now_ts(),)).fetchone()["c"]
            revoked_keys = cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='revoked'").fetchone()["c"]
            expired_keys = cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at<=?", (now_ts(),)).fetchone()["c"]
            banned_ip = cur.execute("SELECT COUNT(*) c FROM banned_ips").fetchone()["c"]
            banned_hwid = cur.execute("SELECT COUNT(*) c FROM banned_hwids").fetchone()["c"]
            total_events = cur.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            active_users = cur.execute(
                "SELECT COUNT(DISTINCT machine_id) c FROM events WHERE machine_id<>'' AND ts>?",
                (now_ts() - 86400,),
            ).fetchone()["c"]
            usage_rows = cur.execute(
                """
                SELECT strftime('%m-%d', datetime(created_at, 'unixepoch', 'localtime')) AS day,
                       COUNT(*) AS c
                FROM licenses
                WHERE created_at >= ?
                GROUP BY day
                ORDER BY day
                """,
                (now_ts() - 7 * 86400,),
            ).fetchall()
            active_rows = cur.execute(
                """
                SELECT strftime('%m-%d', datetime(ts, 'unixepoch', 'localtime')) AS day,
                       COUNT(DISTINCT machine_id) AS c
                FROM events
                WHERE machine_id<>'' AND ts >= ?
                GROUP BY day
                ORDER BY day
                """,
                (now_ts() - 7 * 86400,),
            ).fetchall()
            st_map = _settings_map_conn(conn)
        finally:
            conn.close()
        json_response(
            self,
            {
                "ok": True,
                "data": {
                    "total_keys": int(total_keys),
                    "active_keys": int(active_keys),
                    "revoked_keys": int(revoked_keys),
                    "expired_keys": int(expired_keys),
                    "banned_ip": int(banned_ip),
                    "banned_hwid": int(banned_hwid),
                    "total_events": int(total_events),
                    "active_users": int(active_users),
                    "api_total_requests": int(str(st_map.get("api_total_requests", "0") or "0") or 0),
                    "api_rate_rejections": int(str(st_map.get("api_rate_rejections", "0") or "0") or 0),
                    "api_public_key_configured": api_security.public_api_key_configured(),
                    "usage_7d": [{"day": r["day"], "count": int(r["c"])} for r in usage_rows],
                    "active_users_7d": [{"day": r["day"], "count": int(r["c"])} for r in active_rows],
                },
            },
        )

    def _api_create_licenses(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        duration_days = int(body.get("duration_days", 0) or 0)
        qty = int(body.get("quantity", 1) or 1)
        note = str(body.get("note", "")).strip()
        prefix = normalize_prefix(str(body.get("prefix", "VE03")).strip().upper() or "VE03")
        manual_key = str(body.get("manual_key", "")).strip().upper()

        if duration_days not in {7, 30}:
            return json_response(self, {"ok": False, "error": "duration_days_must_be_7_or_30"}, HTTPStatus.BAD_REQUEST)
        if qty < 1 or qty > 200:
            return json_response(self, {"ok": False, "error": "quantity_must_be_1_to_200"}, HTTPStatus.BAD_REQUEST)

        created = []
        conn = db_connect()
        try:
            cur = conn.cursor()
            created_at = now_ts()
            expires_at = created_at + duration_days * 86400
            for _ in range(qty):
                key = ""
                key_hash = ""
                inserted = False
                if manual_key:
                    if qty != 1:
                        return json_response(self, {"ok": False, "error": "manual_key_requires_quantity_1"}, HTTPStatus.BAD_REQUEST)
                    key = manual_key
                    key_hash = hash_license_key(key)
                    try:
                        cur.execute(
                            """
                            INSERT INTO licenses(
                                license_key, key_hash, key_prefix, key_mask,
                                duration_days, created_at, expires_at, status, machine_id, note, last_used_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', '', ?, 0)
                            """,
                            (key_hash, key_hash, prefix, mask_license(key), duration_days, created_at, expires_at, note),
                        )
                        inserted = True
                    except sqlite3.IntegrityError:
                        return json_response(self, {"ok": False, "error": "manual_key_already_exists"}, HTTPStatus.CONFLICT)
                # Retry to avoid rare primary-key collisions.
                if not inserted:
                    for _attempt in range(30):
                        key = make_secure_license_key(prefix)
                        key_hash = hash_license_key(key)
                        try:
                            cur.execute(
                                """
                                INSERT INTO licenses(
                                    license_key, key_hash, key_prefix, key_mask,
                                    duration_days, created_at, expires_at, status, machine_id, note, last_used_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', '', ?, 0)
                                """,
                                (key_hash, key_hash, prefix, mask_license(key), duration_days, created_at, expires_at, note),
                            )
                            inserted = True
                            break
                        except sqlite3.IntegrityError:
                            continue
                if not inserted:
                    conn.rollback()
                    return json_response(self, {"ok": False, "error": "cannot_generate_unique_key"}, HTTPStatus.CONFLICT)
                created.append(
                    {
                        "license_ref": key_hash,
                        "license_key": key,
                        "duration_days": duration_days,
                        "created_at": created_at,
                        "expires_at": expires_at,
                    }
                )
            conn.commit()
        finally:
            conn.close()

        insert_event("license_create", normalize_ip(self), status="ok", detail=f"qty={qty},duration={duration_days}")
        json_response(self, {"ok": True, "data": created})

    def _api_list_licenses(self) -> None:
        if not require_auth(self):
            return
        conn = db_connect()
        try:
            rows = conn.execute(
                """
                SELECT l.license_key, l.key_hash, l.key_prefix, l.key_mask, l.duration_days, l.created_at, l.expires_at,
                       l.status, l.machine_id, l.note, l.last_used_at,
                       (SELECT COUNT(*) FROM license_hwid_bindings b WHERE b.key_hash = l.key_hash) AS bind_count
                FROM licenses l
                ORDER BY l.created_at DESC LIMIT 5000
                """
            ).fetchall()
        finally:
            conn.close()
        data = []
        for r in rows:
            key_ref = str(r["key_hash"] or r["license_key"] or "")
            key_mask = str(r["key_mask"] or "") or mask_license(str(r["license_key"] or ""))
            data.append(
                {
                    "license_ref": key_ref,
                    "license_key": key_ref,
                    "license_key_masked": key_mask,
                    "key_prefix": str(r["key_prefix"] or ""),
                    "duration_days": int(r["duration_days"]),
                    "created_at": int(r["created_at"]),
                    "created_at_text": to_iso(int(r["created_at"])),
                    "expires_at": int(r["expires_at"]),
                    "expires_at_text": to_iso(int(r["expires_at"])),
                    "status": r["status"],
                    "machine_id": r["machine_id"],
                    "machine_id_masked": mask_hwid_hash(str(r["machine_id"] or "")),
                    "hwid_bindings_count": int(r["bind_count"] or 0),
                    "note": r["note"],
                    "last_used_at": int(r["last_used_at"]) if "last_used_at" in r.keys() else 0,
                    "last_used_at_text": to_iso(int(r["last_used_at"])) if "last_used_at" in r.keys() and int(r["last_used_at"] or 0) > 0 else "",
                }
            )
        json_response(self, {"ok": True, "data": data})

    def _api_extend_license(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        license_ref = _resolve_license_ref(body)
        days = int(body.get("days", 0) or 0)
        if not license_ref or days <= 0:
            return json_response(self, {"ok": False, "error": "missing_license_key_or_days"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE licenses SET expires_at = expires_at + (? * 86400) WHERE key_hash=? OR license_key=?",
                (days, license_ref, license_ref),
            )
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return json_response(self, {"ok": False, "error": "license_not_found"}, HTTPStatus.NOT_FOUND)
        insert_event("license_extend", normalize_ip(self), license_key=mask_license(license_ref), status="ok", detail=f"days={days}")
        json_response(self, {"ok": True})

    def _api_revoke_license(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        license_ref = _resolve_license_ref(body)
        if not license_ref:
            return json_response(self, {"ok": False, "error": "missing_license_key"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE licenses SET status='revoked' WHERE key_hash=? OR license_key=?", (license_ref, license_ref))
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return json_response(self, {"ok": False, "error": "license_not_found"}, HTTPStatus.NOT_FOUND)
        insert_event("license_revoke", normalize_ip(self), license_key=mask_license(license_ref), status="ok")
        json_response(self, {"ok": True})

    def _api_update_license(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        license_ref = _resolve_license_ref(body)
        if not license_ref:
            return json_response(self, {"ok": False, "error": "missing_license_key"}, HTTPStatus.BAD_REQUEST)

        note = str(body.get("note", "")).strip()
        status = str(body.get("status", "")).strip().lower()
        machine_id = str(body.get("machine_id", "")).strip()
        clear_machine = bool(body.get("clear_machine", False))
        duration_days_raw = body.get("duration_days", None)

        updates: list[str] = []
        params: list[Any] = []

        if duration_days_raw is not None and str(duration_days_raw).strip() != "":
            duration_days = int(duration_days_raw)
            if duration_days not in {7, 30}:
                return json_response(self, {"ok": False, "error": "duration_days_must_be_7_or_30"}, HTTPStatus.BAD_REQUEST)
            updates.append("duration_days=?")
            updates.append("expires_at=created_at + (? * 86400)")
            params.extend([duration_days, duration_days])

        if status:
            if status not in {"active", "revoked", "banned"}:
                return json_response(self, {"ok": False, "error": "status_must_be_active_revoked_or_banned"}, HTTPStatus.BAD_REQUEST)
            updates.append("status=?")
            params.append(status)

        updates.append("note=?")
        params.append(note)

        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                f"UPDATE licenses SET {', '.join(updates)} WHERE key_hash=? OR license_key=?",
                (*params, license_ref, license_ref),
            )
            changed = cur.rowcount
            if changed > 0:
                if clear_machine:
                    cur.execute("DELETE FROM license_hwid_bindings WHERE key_hash=?", (license_ref,))
                    cur.execute("UPDATE licenses SET machine_id='' WHERE key_hash=? OR license_key=?", (license_ref, license_ref))
                elif machine_id:
                    hh = normalize_hwid_hash(machine_id)
                    cur.execute("DELETE FROM license_hwid_bindings WHERE key_hash=?", (license_ref,))
                    cur.execute(
                        "INSERT INTO license_hwid_bindings(key_hash, hwid_hash, created_at) VALUES (?, ?, ?)",
                        (license_ref, hh, now_ts()),
                    )
                    cur.execute(
                        "UPDATE licenses SET machine_id=? WHERE key_hash=? OR license_key=?",
                        (hh, license_ref, license_ref),
                    )
            conn.commit()
        finally:
            conn.close()

        if changed <= 0:
            return json_response(self, {"ok": False, "error": "license_not_found"}, HTTPStatus.NOT_FOUND)

        insert_event("license_update", normalize_ip(self), license_key=mask_license(license_ref), status="ok", detail="updated_fields")
        json_response(self, {"ok": True})

    def _api_delete_license(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        license_ref = _resolve_license_ref(body)
        if not license_ref:
            return json_response(self, {"ok": False, "error": "missing_license_key"}, HTTPStatus.BAD_REQUEST)

        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM license_hwid_bindings WHERE key_hash=?", (license_ref,))
            cur.execute("DELETE FROM licenses WHERE key_hash=? OR license_key=?", (license_ref, license_ref))
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return json_response(self, {"ok": False, "error": "license_not_found"}, HTTPStatus.NOT_FOUND)
        insert_event("license_delete", normalize_ip(self), license_key=mask_license(license_ref), status="ok")
        json_response(self, {"ok": True})

    def _api_unrevoke_license(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        license_ref = _resolve_license_ref(body)
        if not license_ref:
            return json_response(self, {"ok": False, "error": "missing_license_key"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE licenses SET status='active' WHERE key_hash=? OR license_key=?", (license_ref, license_ref))
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return json_response(self, {"ok": False, "error": "license_not_found"}, HTTPStatus.NOT_FOUND)
        insert_event("license_unrevoke", normalize_ip(self), license_key=mask_license(license_ref), status="ok")
        json_response(self, {"ok": True})

    def _api_ban_ip(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        ip = str(body.get("ip", "")).strip()
        reason = str(body.get("reason", "")).strip()
        expire_at = _parse_optional_ts(body.get("expire_at"))
        if not ip:
            return json_response(self, {"ok": False, "error": "missing_ip"}, HTTPStatus.BAD_REQUEST)
        if not _validate_ip(ip):
            return json_response(self, {"ok": False, "error": "invalid_ip_format"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                (ip, reason, now_ts(), expire_at),
            )
            conn.commit()
        finally:
            conn.close()
        insert_event("ip_ban", normalize_ip(self), status="ok", detail=ip)
        json_response(self, {"ok": True})

    def _api_unban_ip(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        ip = str(body.get("ip", "")).strip()
        if not ip:
            return json_response(self, {"ok": False, "error": "missing_ip"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
            conn.commit()
        finally:
            conn.close()
        insert_event("ip_unban", normalize_ip(self), status="ok", detail=ip)
        json_response(self, {"ok": True})

    def _api_update_ip_ban(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        old_ip = str(body.get("old_ip", "")).strip()
        new_ip = str(body.get("new_ip", "")).strip()
        reason = str(body.get("reason", "")).strip()
        expire_at = _parse_optional_ts(body.get("expire_at"))
        if not old_ip or not new_ip:
            return json_response(self, {"ok": False, "error": "missing_ip"}, HTTPStatus.BAD_REQUEST)
        if not _validate_ip(new_ip):
            return json_response(self, {"ok": False, "error": "invalid_ip_format"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM banned_ips WHERE ip=?", (old_ip,))
            cur.execute("INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)", (new_ip, reason, now_ts(), expire_at))
            conn.commit()
        finally:
            conn.close()
        insert_event("ip_ban_update", normalize_ip(self), status="ok", detail=f"{old_ip}->{new_ip}")
        json_response(self, {"ok": True})

    def _api_ban_hwid(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        hwid = str(body.get("hwid", "")).strip()
        reason = str(body.get("reason", "")).strip()
        expire_at = _parse_optional_ts(body.get("expire_at"))
        if not hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        hh = normalize_hwid_hash(hwid)
        conn = db_connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                (hh, reason, now_ts(), expire_at),
            )
            conn.commit()
        finally:
            conn.close()
        insert_event("hwid_ban", normalize_ip(self), status="ok", detail=mask_hwid_hash(hh))
        json_response(self, {"ok": True})

    def _api_unban_hwid(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        hwid = str(body.get("hwid", "")).strip()
        if not hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        hh = normalize_hwid_hash(hwid)
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_hwids WHERE hwid=?", (hh,))
            conn.commit()
        finally:
            conn.close()
        insert_event("hwid_unban", normalize_ip(self), status="ok", detail=mask_hwid_hash(hh))
        json_response(self, {"ok": True})

    def _api_update_hwid_ban(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        old_hwid = str(body.get("old_hwid", "")).strip()
        new_hwid = str(body.get("new_hwid", "")).strip()
        reason = str(body.get("reason", "")).strip()
        expire_at = _parse_optional_ts(body.get("expire_at"))
        if not old_hwid or not new_hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        old_h = normalize_hwid_hash(old_hwid)
        new_h = normalize_hwid_hash(new_hwid)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM banned_hwids WHERE hwid=?", (old_h,))
            cur.execute(
                "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                (new_h, reason, now_ts(), expire_at),
            )
            conn.commit()
        finally:
            conn.close()
        insert_event("hwid_ban_update", normalize_ip(self), status="ok", detail=f"{mask_hwid_hash(old_h)}->{mask_hwid_hash(new_h)}")
        json_response(self, {"ok": True})

    def _api_list_bans(self) -> None:
        if not require_auth(self):
            return
        conn = db_connect()
        try:
            ip_rows = conn.execute("SELECT ip, reason, created_at, expire_at FROM banned_ips ORDER BY created_at DESC").fetchall()
            hwid_rows = conn.execute("SELECT hwid, reason, created_at, expire_at FROM banned_hwids ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()
        json_response(
            self,
            {
                "ok": True,
                "data": {
                    "ips": [
                        {
                            "ip": r["ip"],
                            "reason": r["reason"],
                            "created_at": int(r["created_at"]),
                            "created_at_text": to_iso(int(r["created_at"])),
                            "expire_at": int(r["expire_at"] or 0),
                            "expire_at_text": to_iso(int(r["expire_at"])) if int(r["expire_at"] or 0) > 0 else "",
                            "status": _ban_status(int(r["expire_at"] or 0)),
                        }
                        for r in ip_rows
                    ],
                    "hwids": [
                        {
                            "hwid": r["hwid"],
                            "hwid_masked": mask_hwid_hash(str(r["hwid"] or "")),
                            "reason": r["reason"],
                            "created_at": int(r["created_at"]),
                            "created_at_text": to_iso(int(r["created_at"])),
                            "expire_at": int(r["expire_at"] or 0),
                            "expire_at_text": to_iso(int(r["expire_at"])) if int(r["expire_at"] or 0) > 0 else "",
                            "status": _ban_status(int(r["expire_at"] or 0)),
                        }
                        for r in hwid_rows
                    ],
                },
            },
        )

    def _api_list_events(self, query: dict[str, list[str]] | None = None) -> None:
        if not require_auth(self):
            return
        query = query or {}
        q = self._query_param(query, "q", "").lower()
        event_type = self._query_param(query, "type", "")
        from_ts = _parse_optional_ts(self._query_param(query, "from_ts", "0"))
        to_ts = _parse_optional_ts(self._query_param(query, "to_ts", "0"))
        conn = db_connect()
        try:
            sql = "SELECT id, ts, action, ip, license_key, machine_id, status, detail FROM events WHERE 1=1"
            args: list[Any] = []
            if event_type:
                sql += " AND action=?"
                args.append(event_type)
            if from_ts > 0:
                sql += " AND ts>=?"
                args.append(from_ts)
            if to_ts > 0:
                sql += " AND ts<=?"
                args.append(to_ts)
            sql += " ORDER BY id DESC LIMIT 5000"
            rows = conn.execute(sql, args).fetchall()
        finally:
            conn.close()
        data = []
        for r in rows:
            if q:
                hay = f"{r['action']} {r['ip']} {r['license_key']} {r['machine_id']} {r['status']} {r['detail']}".lower()
                if q not in hay:
                    continue
            data.append(
                {
                    "id": int(r["id"]),
                    "ts": int(r["ts"]),
                    "time": to_iso(int(r["ts"])),
                    "action": r["action"],
                    "ip": r["ip"],
                    "license_key": r["license_key"],
                    "machine_id": r["machine_id"],
                    "status": r["status"],
                    "detail": r["detail"],
                }
            )
        json_response(self, {"ok": True, "data": data})

    def _api_list_devices(self) -> None:
        if not require_auth(self):
            return
        conn = db_connect()
        try:
            rows = conn.execute(
                """
                SELECT machine_id,
                       MAX(ip) AS ip_address,
                       MAX(license_key) AS linked_key,
                       MAX(ts) AS last_active,
                       COUNT(DISTINCT ip) AS ip_variants,
                       COUNT(DISTINCT license_key) AS key_variants
                FROM events
                WHERE machine_id <> ''
                GROUP BY machine_id
                ORDER BY last_active DESC
                LIMIT 5000
                """
            ).fetchall()
        finally:
            conn.close()
        data = []
        for r in rows:
            suspicious = int(r["ip_variants"] or 0) > 2 or int(r["key_variants"] or 0) > 1
            data.append(
                {
                    "hwid": r["machine_id"],
                    "ip_address": r["ip_address"],
                    "linked_key": r["linked_key"],
                    "last_active": int(r["last_active"] or 0),
                    "last_active_text": to_iso(int(r["last_active"] or 0)),
                    "status": "suspicious" if suspicious else "normal",
                    "ip_variants": int(r["ip_variants"] or 0),
                    "key_variants": int(r["key_variants"] or 0),
                }
            )
        json_response(self, {"ok": True, "data": data})

    def _api_unbind_device(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        hwid = str(body.get("hwid", "")).strip()
        if not hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        hh = normalize_hwid_hash(hwid)
        conn = db_connect()
        try:
            conn.execute("DELETE FROM license_hwid_bindings WHERE hwid_hash=?", (hh,))
            conn.execute("UPDATE licenses SET machine_id='' WHERE machine_id=?", (hh,))
            conn.commit()
        finally:
            conn.close()
        insert_event("device_unbind", normalize_ip(self), machine_id=hh, status="ok")
        json_response(self, {"ok": True})

    def _api_ban_device(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        hwid = str(body.get("hwid", "")).strip()
        reason = str(body.get("reason", "")).strip() or "ban_from_device_panel"
        expire_at = _parse_optional_ts(body.get("expire_at"))
        if not hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        hh = normalize_hwid_hash(hwid)
        conn = db_connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                (hh, reason, now_ts(), expire_at),
            )
            conn.commit()
        finally:
            conn.close()
        insert_event("device_ban", normalize_ip(self), machine_id=hh, status="ok", detail=reason)
        json_response(self, {"ok": True})

    def _api_kick_device(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        hwid = str(body.get("hwid", "")).strip()
        if not hwid:
            return json_response(self, {"ok": False, "error": "missing_hwid"}, HTTPStatus.BAD_REQUEST)
        hh = normalize_hwid_hash(hwid)
        insert_event("device_kick", normalize_ip(self), machine_id=hh, status="ok")
        json_response(self, {"ok": True})

    def _api_get_settings(self) -> None:
        if not require_auth(self):
            return
        conn = db_connect()
        try:
            rows = conn.execute("SELECT key, value FROM settings ORDER BY key ASC").fetchall()
        finally:
            conn.close()
        data = {str(r["key"]): str(r["value"]) for r in rows}
        json_response(self, {"ok": True, "data": data})

    def _api_update_settings(self) -> None:
        if not require_auth(self):
            return
        body = read_json_body(self)
        items = body.get("items", {})
        if not isinstance(items, dict):
            return json_response(self, {"ok": False, "error": "invalid_items"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            for k, v in items.items():
                key = str(k).strip()
                val = str(v)
                if not key:
                    continue
                cur.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, val))
            conn.commit()
        finally:
            conn.close()
        insert_event("settings_update", normalize_ip(self), status="ok", detail=f"count={len(items)}")
        json_response(self, {"ok": True})

    def _api_list_users(self) -> None:
        if not require_role(self, {"admin"}):
            return
        conn = db_connect()
        try:
            rows = conn.execute(
                """
                SELECT username, role, is_active, totp_enabled, created_at, updated_at
                FROM users
                ORDER BY username ASC
                """
            ).fetchall()
        finally:
            conn.close()
        data = [
            {
                "username": str(r["username"]),
                "role": str(r["role"]),
                "is_active": int(r["is_active"] or 0),
                "totp_enabled": int(r["totp_enabled"] or 0),
                "created_at": int(r["created_at"] or 0),
                "updated_at": int(r["updated_at"] or 0),
                "created_at_text": to_iso(int(r["created_at"] or 0)),
                "updated_at_text": to_iso(int(r["updated_at"] or 0)),
            }
            for r in rows
        ]
        json_response(self, {"ok": True, "data": data})

    def _api_create_user(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        password = str(body.get("password", "") or "")
        role = str(body.get("role", "mod") or "mod").strip().lower()
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        if not _is_valid_role(role):
            return json_response(self, {"ok": False, "error": "invalid_role"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            st = _settings_map_conn(conn)
        finally:
            conn.close()
        perr = _validate_password_by_policy(password, st)
        if perr:
            return json_response(self, {"ok": False, "error": perr}, HTTPStatus.BAD_REQUEST)
        now = now_ts()
        conn = db_connect()
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    """
                    INSERT INTO users(username, password_hash, role, is_active, totp_secret, totp_enabled, created_at, updated_at)
                    VALUES (?, ?, ?, 1, '', 0, ?, ?)
                    """,
                    (username, _bcrypt_hash_password(password), role, now, now),
                )
            except sqlite3.IntegrityError:
                return json_response(self, {"ok": False, "error": "user_exists"}, HTTPStatus.CONFLICT)
            conn.commit()
        finally:
            conn.close()
        insert_event("user_create", normalize_ip(self), status="ok", detail=f"user={username};role={role}")
        json_response(self, {"ok": True})

    def _api_set_user_role(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        role = str(body.get("role", "")).strip().lower()
        if not _is_valid_username(username) or not _is_valid_role(role):
            return json_response(self, {"ok": False, "error": "invalid_input"}, HTTPStatus.BAD_REQUEST)
        if username == _normalize_username(ADMIN_USER) and role != "admin":
            return json_response(self, {"ok": False, "error": "cannot_downgrade_bootstrap_admin"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET role=?, updated_at=? WHERE username=?", (role, now_ts(), username))
            if cur.rowcount <= 0:
                return json_response(self, {"ok": False, "error": "user_not_found"}, HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        insert_event("user_set_role", normalize_ip(self), status="ok", detail=f"user={username};role={role}")
        json_response(self, {"ok": True})

    def _api_set_user_active(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        raw_active = body.get("is_active", True)
        active = 1 if str(raw_active).strip().lower() in {"1", "true", "yes", "on"} else 0
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        if username == _normalize_username(ADMIN_USER) and active == 0:
            return json_response(self, {"ok": False, "error": "cannot_disable_bootstrap_admin"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_active=?, updated_at=? WHERE username=?", (active, now_ts(), username))
            if cur.rowcount <= 0:
                return json_response(self, {"ok": False, "error": "user_not_found"}, HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        if active == 0:
            self._revoke_all_sessions_for_user(username)
        insert_event("user_set_active", normalize_ip(self), status="ok", detail=f"user={username};active={active}")
        json_response(self, {"ok": True})

    def _api_reset_user_password(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        new_password = str(body.get("new_password", "") or "")
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        conn0 = db_connect()
        try:
            st = _settings_map_conn(conn0)
        finally:
            conn0.close()
        perr = _validate_password_by_policy(new_password, st)
        if perr:
            return json_response(self, {"ok": False, "error": perr}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET password_hash=?, updated_at=? WHERE username=?",
                (_bcrypt_hash_password(new_password), now_ts(), username),
            )
            if cur.rowcount <= 0:
                return json_response(self, {"ok": False, "error": "user_not_found"}, HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        self._revoke_all_sessions_for_user(username)
        insert_event("user_reset_password", normalize_ip(self), status="ok", detail=f"user={username}")
        json_response(self, {"ok": True})

    def _api_revoke_all_user_sessions(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        n = self._revoke_all_sessions_for_user(username, active_only=False)
        insert_event("user_revoke_sessions", normalize_ip(self), status="ok", detail=f"user={username};count={n}")
        json_response(self, {"ok": True, "revoked": n})

    def _api_revoke_active_user_sessions(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        username = _normalize_username(str(body.get("username", "")))
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        n = self._revoke_all_sessions_for_user(username, active_only=True)
        insert_event("user_revoke_active_sessions", normalize_ip(self), status="ok", detail=f"user={username};count={n}")
        json_response(self, {"ok": True, "revoked": n})

    def _api_list_user_sessions(self, query: dict[str, list[str]]) -> None:
        if not require_role(self, {"admin"}):
            return
        username = _normalize_username(self._query_param(query, "username", ""))
        if not username:
            return json_response(self, {"ok": False, "error": "missing_username"}, HTTPStatus.BAD_REQUEST)
        include_revoked = _is_true_value(self._query_param(query, "include_revoked", "0"))
        status_filter = str(self._query_param(query, "status", "")).strip().lower()
        ip_filter = str(self._query_param(query, "ip", "")).strip()
        conn = db_connect()
        try:
            where = "WHERE user=?"
            params: list[Any] = [username]
            if not include_revoked:
                where += " AND revoked_at=0"
            rows = conn.execute(
                f"""
                SELECT session_id, user, created_at, expires_at, revoked_at, last_seen_at, last_ip, last_ua, suspicious_count
                FROM auth_sessions
                {where}
                ORDER BY created_at DESC
                LIMIT 500
                """,
                params,
            ).fetchall()
        finally:
            conn.close()
        now = now_ts()
        data = []
        for r in rows:
            revoked_at = int(r["revoked_at"] or 0)
            expires_at = int(r["expires_at"] or 0)
            status = "revoked" if revoked_at > 0 else ("expired" if now >= expires_at else "active")
            last_ip = str(r["last_ip"] or "")
            if status_filter and status_filter in {"active", "expired", "revoked"} and status != status_filter:
                continue
            if ip_filter and ip_filter not in last_ip:
                continue
            data.append(
                {
                    "session_id": str(r["session_id"]),
                    "user": str(r["user"]),
                    "created_at": int(r["created_at"] or 0),
                    "created_at_text": to_iso(int(r["created_at"] or 0)),
                    "expires_at": expires_at,
                    "expires_at_text": to_iso(expires_at),
                    "revoked_at": revoked_at,
                    "revoked_at_text": to_iso(revoked_at) if revoked_at > 0 else "",
                    "last_seen_at": int(r["last_seen_at"] or 0),
                    "last_seen_at_text": to_iso(int(r["last_seen_at"] or 0)),
                    "last_ip": last_ip,
                    "suspicious_count": int(r["suspicious_count"] or 0),
                    "status": status,
                }
            )
        json_response(self, {"ok": True, "data": data})

    def _api_revoke_single_session(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        session_id = str(body.get("session_id", "")).strip()
        if not session_id:
            return json_response(self, {"ok": False, "error": "missing_session_id"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            row = conn.execute("SELECT user FROM auth_sessions WHERE session_id=?", (session_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return json_response(self, {"ok": False, "error": "session_not_found"}, HTTPStatus.NOT_FOUND)
        _revoke_session_id(session_id)
        insert_event("user_revoke_session", normalize_ip(self), status="ok", detail=f"user={row['user']};sid={session_id[:12]}")
        json_response(self, {"ok": True})

    def _api_2fa_setup(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        claims = getattr(self, "_auth_claims", {}) or {}
        username = _normalize_username(str(body.get("username", "") or claims.get("user", "")))
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        secret = _totp_generate_secret(32)
        issuer = str(body.get("issuer", "AdminPortal") or "AdminPortal").strip()
        account = username
        otp_uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        # Không lưu ngay; chỉ enable sau khi verify code.
        json_response(self, {"ok": True, "secret": secret, "otpauth_uri": otp_uri})

    def _api_2fa_enable(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        claims = getattr(self, "_auth_claims", {}) or {}
        username = _normalize_username(str(body.get("username", "") or claims.get("user", "")))
        secret = _totp_normalize_secret(str(body.get("secret", "") or ""))
        code = str(body.get("code", "") or "")
        if not _is_valid_username(username) or not secret:
            return json_response(self, {"ok": False, "error": "invalid_input"}, HTTPStatus.BAD_REQUEST)
        if not _verify_totp(secret, code):
            return json_response(self, {"ok": False, "error": "invalid_totp_code"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE username=?",
                (secret, now_ts(), username),
            )
            if cur.rowcount <= 0:
                return json_response(self, {"ok": False, "error": "user_not_found"}, HTTPStatus.NOT_FOUND)
            conn.commit()
        finally:
            conn.close()
        self._revoke_all_sessions_for_user(username)
        insert_event("user_2fa_enable", normalize_ip(self), status="ok", detail=f"user={username}")
        json_response(self, {"ok": True})

    def _api_2fa_disable(self) -> None:
        if not require_role(self, {"admin"}):
            return
        body = read_json_body(self)
        claims = getattr(self, "_auth_claims", {}) or {}
        username = _normalize_username(str(body.get("username", "") or claims.get("user", "")))
        actor = _normalize_username(str(claims.get("user", "") or ""))
        code = str(body.get("code", "") or "")
        if not _is_valid_username(username):
            return json_response(self, {"ok": False, "error": "invalid_username"}, HTTPStatus.BAD_REQUEST)
        conn = db_connect()
        try:
            row = _user_row_conn(conn, username)
            if not row:
                return json_response(self, {"ok": False, "error": "user_not_found"}, HTTPStatus.NOT_FOUND)
            # Nếu admin disable cho user khác: cho phép không cần mã của user đó.
            need_code = int(row["totp_enabled"] or 0) == 1 and actor == username
            if need_code:
                if not _verify_totp(str(row["totp_secret"] or ""), code):
                    return json_response(self, {"ok": False, "error": "invalid_totp_code"}, HTTPStatus.BAD_REQUEST)
            conn.execute(
                "UPDATE users SET totp_secret='', totp_enabled=0, updated_at=? WHERE username=?",
                (now_ts(), username),
            )
            conn.commit()
        finally:
            conn.close()
        self._revoke_all_sessions_for_user(username)
        insert_event("user_2fa_disable", normalize_ip(self), status="ok", detail=f"user={username}")
        json_response(self, {"ok": True})

    def _revoke_all_sessions_for_user(self, username: str, active_only: bool = False) -> int:
        uname = _normalize_username(username)
        now = now_ts()
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE auth_sessions
                SET revoked_at=?
                WHERE user=? AND revoked_at=0
                  AND (?=0 OR expires_at>?)
                """,
                (now, uname, 1 if active_only else 0, now),
            )
            changed = int(cur.rowcount or 0)
            conn.commit()
        finally:
            conn.close()
        return changed

    def _api_client_security_event(self) -> None:
        body = read_json_body(self)
        if _guard_license_public_api(self, body):
            return
        ip = normalize_ip(self)
        license_key = str(body.get("license_key", "") or "").strip()
        machine_id = str(body.get("machine_id", "") or "").strip()
        key_hash = hash_license_key(license_key) if license_key else ""
        hwid_hash = normalize_hwid_hash(machine_id) if machine_id else ""
        signal_type = str(body.get("signal_type", "") or "").strip().lower()
        detail = str(body.get("detail", "") or "").strip()[:250]
        score_raw = int(body.get("score", 0) or 0)
        map_score = {
            "debugger_detected": 30,
            "vm_detected": 25,
            "tamper_detected": 45,
            "hook_detected": 35,
            "binary_modified": 45,
            "runtime_patch_detected": 40,
        }
        score = max(1, min(100, score_raw or map_score.get(signal_type, 20)))
        if not signal_type:
            return json_response(self, {"ok": False, "error": "missing_signal_type"}, HTTPStatus.BAD_REQUEST)

        conn = db_connect()
        try:
            now = now_ts()
            conn.execute(
                """
                INSERT INTO client_security_signals(ts, ip, key_hash, hwid_hash, signal_type, score, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, ip, key_hash, hwid_hash, signal_type, score, detail),
            )
            settings = _settings_map_conn(conn)
            if _is_true_value(settings.get("client_security_signal_auto_ban", "1")):
                win = _setting_int(settings, "client_security_signal_window_seconds", 3600, 60, 86400)
                thr = _setting_int(settings, "client_security_signal_ban_threshold", 80, 20, 10000)
                ban_sec = _setting_int(settings, "auto_ban_duration_seconds", 3600, 60, 604800)
                total_score = int(
                    conn.execute(
                        """
                        SELECT COALESCE(SUM(score), 0) AS s
                        FROM client_security_signals
                        WHERE ts>=? AND (ip=? OR (key_hash<>'' AND key_hash=?))
                        """,
                        (now - win, ip, key_hash),
                    ).fetchone()["s"]
                )
                if total_score >= thr:
                    if ip:
                        conn.execute(
                            "INSERT OR REPLACE INTO banned_ips(ip, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                            (ip, f"auto_ban_client_tamper:{total_score}", now, now + ban_sec),
                        )
                    if hwid_hash:
                        conn.execute(
                            "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at, expire_at) VALUES (?, ?, ?, ?)",
                            (hwid_hash, f"auto_ban_client_tamper:{total_score}", now, now + ban_sec),
                        )
                    _insert_event_conn(
                        conn,
                        "auto_ban_client_tamper",
                        ip=ip,
                        machine_id=hwid_hash,
                        status="ok",
                        detail=f"score={total_score};window={win}",
                    )
            conn.commit()
        finally:
            conn.close()
        insert_event("client_security_event", ip, license_key=mask_license(license_key), machine_id=hwid_hash, status="ok", detail=f"{signal_type}:{score}")
        json_response(self, {"ok": True})

    def _api_verify_license_proof(self) -> None:
        body = read_json_body(self)
        # endpoint public: vẫn đi qua guard API key/origin/rate-limit
        if _guard_ping_public_api(self):
            return

        proof = str(body.get("license_proof", "") or "").strip()
        machine_id = str(body.get("machine_id", "") or "").strip()
        ip = normalize_ip(self)
        if not proof:
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": "missing_license_proof"}, HTTPStatus.BAD_REQUEST)
        if not machine_id:
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": "missing_machine_id"}, HTTPStatus.BAD_REQUEST)

        payload, perr = verify_license_proof_token(proof)
        if perr or not payload:
            insert_event("license_proof_verify", ip, machine_id=normalize_hwid_hash(machine_id), status="failed", detail=perr or "invalid_proof")
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": perr or "invalid_proof"}, HTTPStatus.UNAUTHORIZED)

        key_hash = str(payload.get("kh") or "")
        proof_hwid_hash = str(payload.get("hh") or "")
        hwid_hash = normalize_hwid_hash(machine_id)
        if proof_hwid_hash != hwid_hash:
            insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="proof_machine_mismatch")
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": "machine_id_mismatch"}, HTTPStatus.UNAUTHORIZED)

        now = now_ts()
        conn = db_connect()
        try:
            row = conn.execute(
                "SELECT key_hash, license_key, expires_at, status, machine_id FROM licenses WHERE key_hash=? OR license_key=?",
                (key_hash, key_hash),
            ).fetchone()
            if not row:
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="license_not_found")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "license_not_found"}, HTTPStatus.UNAUTHORIZED)
            if str(row["status"]) != "active":
                status_text = str(row["status"] or "invalid")
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail=status_text)
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": status_text}, HTTPStatus.UNAUTHORIZED)
            expires_at = int(row["expires_at"] or 0)
            if now >= expires_at:
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="expired")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "expired", "expires_at": expires_at}, HTTPStatus.UNAUTHORIZED)
            ban_ip = conn.execute("SELECT ip FROM banned_ips WHERE ip=? AND (expire_at<=0 OR expire_at>?)", (ip, now)).fetchone()
            if ban_ip:
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="ip_banned")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "ip_banned"}, HTTPStatus.UNAUTHORIZED)
            ban_hwid = conn.execute("SELECT hwid FROM banned_hwids WHERE hwid=? AND (expire_at<=0 OR expire_at>?)", (hwid_hash, now)).fetchone()
            if ban_hwid:
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="hwid_banned")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "hwid_banned"}, HTTPStatus.UNAUTHORIZED)

            # đảm bảo key vẫn đang bind với HWID hiện tại
            bind_row = conn.execute(
                "SELECT 1 FROM license_hwid_bindings WHERE key_hash=? AND hwid_hash=? LIMIT 1",
                (key_hash, hwid_hash),
            ).fetchone()
            if not bind_row and _is_true_value(_settings_map_conn(conn).get("enable_hwid_binding", "1")):
                insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="failed", detail="proof_not_bound")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "machine_id_mismatch"}, HTTPStatus.UNAUTHORIZED)
        finally:
            conn.close()

        server_ts = now_ts()
        server_nonce = secrets.token_hex(8)
        core_msg = f"ok=true&proof=valid&machine_id={machine_id}&server_ts={server_ts}&nonce={server_nonce}"
        verify_sig = sign_hmac_hex(LICENSE_SECRET, core_msg)
        insert_event("license_proof_verify", ip, machine_id=hwid_hash, status="ok")
        return json_response(
            self,
            {
                "ok": True,
                "ACTIVE": True,
                "reason": "valid",
                "machine_id": machine_id,
                "server_ts": server_ts,
                "nonce": server_nonce,
                "verify_sig": verify_sig,
            },
        )

    def _api_check_license(self) -> None:
        body = read_json_body(self)
        if _guard_license_public_api(self, body):
            return

        ip = normalize_ip(self)

        license_key = str(body.get("license_key", "")).strip()
        license_key_hash = hash_license_key(license_key) if license_key else ""
        machine_id = str(body.get("machine_id", "")).strip()
        ts = int(body.get("ts", 0) or 0)
        nonce = str(body.get("nonce", "")).strip()
        request_sig = str(body.get("request_sig", "")).strip()

        if not license_key or not machine_id:
            _record_failed_license_check(ip, license_key, machine_id, "missing_fields")
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": "missing_fields"}, HTTPStatus.BAD_REQUEST)

        conn_st = db_connect()
        try:
            settings_chk = _settings_map_conn(conn_st)
        finally:
            conn_st.close()

        app_version = str(body.get("app_version", "") or "")
        verr = _enforce_license_hmac_and_nonce_replay(
            license_key=license_key,
            license_key_hash=license_key_hash,
            machine_id=machine_id,
            ts=ts,
            nonce=nonce,
            request_sig=request_sig,
            app_version=app_version,
            settings=settings_chk,
        )
        if verr:
            _record_failed_license_check(ip, license_key, machine_id, verr)
            return json_response(self, {"ok": False, "ACTIVE": False, "reason": verr}, HTTPStatus.BAD_REQUEST)

        hwid_hash = normalize_hwid_hash(machine_id)

        conn = db_connect()
        try:
            _apply_auto_ban_rules(conn, ip, hwid_hash)
            ban_ip = conn.execute(
                "SELECT ip FROM banned_ips WHERE ip=? AND (expire_at<=0 OR expire_at>?)",
                (ip, now_ts()),
            ).fetchone()
            if ban_ip:
                _record_failed_license_check(ip, license_key, machine_id, "ip_banned")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "ip_banned"})

            ban_hwid = conn.execute(
                "SELECT hwid FROM banned_hwids WHERE hwid=? AND (expire_at<=0 OR expire_at>?)",
                (hwid_hash, now_ts()),
            ).fetchone()
            if ban_hwid:
                _record_failed_license_check(ip, license_key, machine_id, "hwid_banned")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "hwid_banned"})

            row = conn.execute(
                "SELECT license_key, key_hash, duration_days, created_at, expires_at, status, machine_id, note FROM licenses WHERE key_hash=? OR license_key=?",
                (license_key_hash, license_key_hash),
            ).fetchone()
            if not row:
                _record_failed_license_check(ip, license_key, machine_id, "license_not_found")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "license_not_found"})

            if str(row["status"]) != "active":
                status_text = str(row["status"])
                _record_failed_license_check(ip, license_key, machine_id, status_text)
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": status_text})

            expires_at = int(row["expires_at"])
            if now_ts() >= expires_at:
                _record_failed_license_check(ip, license_key, machine_id, "expired")
                return json_response(self, {"ok": False, "ACTIVE": False, "reason": "expired", "expires_at": expires_at})

            lic_kh = str(row["key_hash"] or row["license_key"] or license_key_hash)
            settings = _settings_map_conn(conn)
            max_devices = _setting_int(settings, "max_devices_per_key", 1, 1, 50)
            enable_bind = _is_true_value(settings.get("enable_hwid_binding", "1"))

            if enable_bind:
                cur_rows = conn.execute(
                    "SELECT hwid_hash FROM license_hwid_bindings WHERE key_hash=?",
                    (lic_kh,),
                ).fetchall()
                bound_hashes = {str(x["hwid_hash"]) for x in cur_rows}
                if hwid_hash not in bound_hashes:
                    if len(bound_hashes) < max_devices:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO license_hwid_bindings(key_hash, hwid_hash, created_at)
                            VALUES (?, ?, ?)
                            """,
                            (lic_kh, hwid_hash, now_ts()),
                        )
                    else:
                        _record_failed_license_check(
                            ip,
                            license_key,
                            machine_id,
                            "machine_id_mismatch",
                            license_key_hash=lic_kh,
                        )
                        return json_response(self, {"ok": False, "ACTIVE": False, "reason": "machine_id_mismatch"})

            conn.execute(
                "UPDATE licenses SET machine_id=?, last_used_at=? WHERE key_hash=? OR license_key=?",
                (hwid_hash, now_ts(), lic_kh, lic_kh),
            )
            conn.commit()
        finally:
            conn.close()

        server_ts = now_ts()
        server_nonce = nonce or secrets.token_hex(8)
        features_obj = {"name": "Licensed User", "sdt": "0000000000"}
        features = json.dumps(features_obj, ensure_ascii=False, separators=(",", ":"))

        core_msg = canonical_response_core(True, license_key, machine_id, expires_at, server_ts, server_nonce)
        server_sig = sign_hmac_hex(LICENSE_SECRET, core_msg)
        proof_ttl = _setting_int(settings_chk, "license_proof_ttl_seconds", 120, 30, 3600)
        license_proof, proof_expires_at = issue_license_proof_token(lic_kh, hwid_hash, proof_ttl)

        insert_event("license_check", ip, license_key=mask_license(license_key), machine_id=hwid_hash, status="ok")
        payload = {
            "ok": True,
            "ACTIVE": True,
            "license_key": license_key,
            "machine_id": machine_id,
            "expires_at": expires_at,
            "features": features,
            "server_ts": server_ts,
            "nonce": server_nonce,
            "server_sig": server_sig,
            "license_proof": license_proof,
            "proof_expires_at": proof_expires_at,
        }
        json_response(self, payload)


def main() -> None:
    init_db()
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_maintenance_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), AdminHandler)
    url = f"http://{HOST}:{PORT}"
    print(f"[admin_portal] Running on {url}")
    print(f"[admin_portal] Admin user: {ADMIN_USER}")
    print("[admin_portal] Change ADMIN_PASS in environment before production.")
    if str(os.getenv("ADMIN_OPEN_BROWSER", "1")).strip().lower() not in {"0", "false", "no"}:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
