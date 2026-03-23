"""
Lớp bảo mật cho API công khai (license check / ping):
- Xác thực API key (Authorization: Bearer hoặc X-Api-Key)
- Giới hạn tốc độ theo IP và theo key (sliding window trong RAM)
- Kiểm tra Origin khi có Allowlist (trình duyệt); client native không gửi Origin vẫn được nếu có API key
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any

_public_key = os.getenv("LICENSE_PUBLIC_API_KEY", "").strip()
_allowed_origins_env = os.getenv("LICENSE_ALLOWED_ORIGINS", "").strip()

_lock = threading.Lock()
_ip_window: dict[str, deque[float]] = defaultdict(lambda: deque())
_key_window: dict[str, deque[float]] = defaultdict(lambda: deque())
_violation_window: dict[str, deque[float]] = defaultdict(lambda: deque())


def public_api_key_configured() -> bool:
    return bool(_public_key)


def validate_public_api_key(handler: Any) -> bool:
    """Trả True nếu không cấu hình key, hoặc key khớp (timing-safe)."""
    if not _public_key:
        return True
    key = extract_public_api_key(handler)
    if not key:
        return False
    try:
        return hmac.compare_digest(key.encode("utf-8"), _public_key.encode("utf-8"))
    except Exception:
        return hmac.compare_digest(key, _public_key)


def extract_public_api_key(handler: Any) -> str:
    auth = str(handler.headers.get("Authorization", "") or "").strip()
    low = auth[:7].lower()
    if low == "bearer ":
        return auth[7:].strip()
    return str(handler.headers.get("X-Api-Key", "") or "").strip()


def merge_allowed_origins(extra_csv: str) -> str:
    parts = [p.strip() for p in (_allowed_origins_env, str(extra_csv or "").strip()) if p.strip()]
    return ",".join(parts)


def origin_allowed(handler: Any, extra_origins_csv: str = "") -> bool:
    """
    Nếu có allowlist: khi Origin có mặt thì phải khớp một mục (prefix).
    Không có Origin (curl/app desktop): cho phép (dựa vào API key + rate limit).
    """
    raw = merge_allowed_origins(extra_origins_csv)
    if not raw:
        return True
    allowed = [x.strip().rstrip("/") for x in raw.split(",") if x.strip()]
    if not allowed:
        return True
    origin = str(handler.headers.get("Origin", "") or "").strip().rstrip("/")
    if not origin:
        return True
    for a in allowed:
        if origin == a or origin.startswith(a + "/"):
            return True
    return False


def _prune(q: deque[float], window_sec: float, now: float) -> None:
    while q and now - q[0] > window_sec:
        q.popleft()


def rate_limit_allow(ip: str, key_fingerprint: str, *, window_sec: int, limit_ip: int, limit_key: int) -> tuple[bool, str]:
    """
    Giới hạn số request trong cửa sổ window_sec.
    key_fingerprint rỗng => chỉ áp dụng giới hạn IP (dùng cho /api/ping).
    """
    now = time.time()
    w = float(max(1, window_sec))
    with _lock:
        iq = _ip_window[ip]
        _prune(iq, w, now)
        if len(iq) >= limit_ip:
            return False, "rate_limit_ip"
        if key_fingerprint:
            kq = _key_window[key_fingerprint]
            _prune(kq, w, now)
            if len(kq) >= limit_key:
                return False, "rate_limit_key"
        iq.append(now)
        if key_fingerprint:
            _key_window[key_fingerprint].append(now)
    return True, ""


def record_rate_violation(ip: str, window_sec: int, threshold: int) -> bool:
    """Đếm số lần vượt rate trong window; True nếu >= threshold (nên auto-ban IP)."""
    now = time.time()
    w = float(max(1, window_sec))
    with _lock:
        vq = _violation_window[ip]
        _prune(vq, w, now)
        vq.append(now)
        return len(vq) >= threshold


def violation_count(ip: str, window_sec: int) -> int:
    now = time.time()
    w = float(max(1, window_sec))
    with _lock:
        vq = _violation_window[ip]
        _prune(vq, w, now)
        return len(vq)
