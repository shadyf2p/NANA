import base64
import hashlib
import hmac
import json
import os
import platform
import random
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VERIFY_URL = os.getenv("LICENSE_VERIFY_URL", "http://127.0.0.1:8081/api/key/verify").strip()
LICENSE_KEY = os.getenv("LICENSE_KEY", "").strip().upper()
COMM_AES_KEY_B64 = os.getenv("COMM_AES_KEY_B64", "").strip()
COMM_HMAC_SECRET = os.getenv("COMM_HMAC_SECRET", "").strip()
COMM_ACTIVE_KID = os.getenv("COMM_ACTIVE_KID", "v1").strip() or "v1"
COMM_AES_KEYS_JSON = os.getenv("COMM_AES_KEYS_JSON", "").strip()
COMM_HMAC_KEYS_JSON = os.getenv("COMM_HMAC_KEYS_JSON", "").strip()
VERIFY_INTERVAL_SECONDS = int(os.getenv("VERIFY_INTERVAL_SECONDS", "120"))

# Optional local integrity pin. Generate once in build pipeline.
EXPECTED_SELF_SHA256 = os.getenv("EXPECTED_SELF_SHA256", "").strip().lower()

_LOCK = threading.RLock()
_STATE_CELLS: Dict[str, Dict[str, str]] = {}
_FN_SNAPSHOT: Dict[str, str] = {}
_LAST_SERVER_TS = 0


def _load_keyring() -> Tuple[str, Dict[str, bytes], Dict[str, str]]:
    aes_map: Dict[str, bytes] = {}
    hmac_map: Dict[str, str] = {}

    if COMM_AES_KEYS_JSON:
        try:
            raw = json.loads(COMM_AES_KEYS_JSON)
            for kid, val in raw.items():
                aes_map[str(kid)] = base64.b64decode(str(val).encode("ascii"))
        except Exception:
            raise SecurityAbort("invalid_comm_aes_keys_json")
    elif COMM_AES_KEY_B64:
        aes_map[COMM_ACTIVE_KID] = base64.b64decode(COMM_AES_KEY_B64.encode("ascii"))

    if COMM_HMAC_KEYS_JSON:
        try:
            raw = json.loads(COMM_HMAC_KEYS_JSON)
            for kid, val in raw.items():
                hmac_map[str(kid)] = str(val)
        except Exception:
            raise SecurityAbort("invalid_comm_hmac_keys_json")
    elif COMM_HMAC_SECRET:
        hmac_map[COMM_ACTIVE_KID] = COMM_HMAC_SECRET

    if COMM_ACTIVE_KID not in aes_map or COMM_ACTIVE_KID not in hmac_map:
        raise SecurityAbort("active_kid_missing_in_keyring")
    for kid, key in aes_map.items():
        if len(key) != 32:
            raise SecurityAbort(f"invalid_aes_key_len:{kid}")
    return COMM_ACTIVE_KID, aes_map, hmac_map


class SecurityAbort(Exception):
    pass


@dataclass
class VerifyResult:
    valid: bool
    message: str
    payload: Dict[str, Any]


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hmac_hex(secret: str, text: str) -> str:
    return hmac.new(secret.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def _random_noise_branch(seed: Optional[int] = None) -> int:
    # Non-constant branch noise to complicate static patching.
    r = random.Random(seed if seed is not None else int(time.time() * 1000) ^ os.getpid())
    v = 0
    for _ in range(r.randint(7, 19)):
        n = r.randint(1, 1_000_000)
        if n & 1:
            v ^= (n * 17) & 0xFFFF
        else:
            v ^= (n * 29) & 0xFFFF
    return v


def _encrypt_payload(data: Dict[str, Any], aes_key: bytes) -> str:
    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    plain = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    encrypted = aes.encrypt(nonce, plain, None)  # ciphertext + tag
    return base64.b64encode(nonce + encrypted).decode("ascii")


def _decrypt_payload(payload_b64: str, aes_key: bytes) -> Dict[str, Any]:
    blob = base64.b64decode(payload_b64.encode("ascii"))
    if len(blob) < 12 + 16 + 1:
        raise SecurityAbort("invalid_encrypted_blob")
    nonce = blob[:12]
    ciphertext_and_tag = blob[12:]
    aes = AESGCM(aes_key)
    plain = aes.decrypt(nonce, ciphertext_and_tag, None)
    return json.loads(plain.decode("utf-8"))


def _verify_signature(payload: str, timestamp: int, nonce: str, signature: str, hmac_secret: str) -> bool:
    expected = _hmac_hex(hmac_secret, f"{payload}.{timestamp}.{nonce}")
    return hmac.compare_digest(expected, signature)


def _random_delay_guard() -> None:
    # Low-impact jitter: makes deterministic patching harder.
    time.sleep(random.uniform(0.05, 0.25))


def _timing_guard() -> None:
    t0 = time.perf_counter()
    s = 0
    for i in range(25000):
        s ^= (i * 17) & 0xFFFF
    dt = time.perf_counter() - t0
    if dt > 0.25:  # suspiciously slow for tiny loop
        raise SecurityAbort("timing_anomaly_detected")
    _ = s


def _debugger_guard() -> None:
    if sys.gettrace() is not None:
        raise SecurityAbort("debugger_detected")


def _tool_scan_guard() -> None:
    if os.name != "nt":
        return
    try:
        out = subprocess.check_output(
            ["tasklist"], text=True, errors="ignore", timeout=2
        ).lower()
    except Exception:
        return
    bad = ("x64dbg", "ida", "ida64", "ollydbg", "cheat engine")
    if any(x in out for x in bad):
        raise SecurityAbort("reverse_tool_detected")


def _runtime_fingerprint() -> str:
    parts = [
        VERIFY_URL,
        LICENSE_KEY,
        sys.executable,
        platform.platform(),
        str(os.getpid()),
        os.getenv("COMPUTERNAME", ""),
    ]
    return _sha256_hex("|".join(parts))


def _self_integrity_guard() -> None:
    if not EXPECTED_SELF_SHA256:
        return
    try:
        path = os.path.abspath(__file__)
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest().lower()
    except Exception:
        raise SecurityAbort("self_integrity_check_failed")
    if digest != EXPECTED_SELF_SHA256:
        raise SecurityAbort("binary_tamper_detected")


def _capture_fn_snapshot() -> None:
    global _FN_SNAPSHOT
    critical = [
        _encrypt_payload,
        _decrypt_payload,
        _verify_signature,
        _make_hwid,
        verify_once,
    ]
    snap: Dict[str, str] = {}
    for fn in critical:
        code = fn.__code__.co_code
        const = repr(fn.__code__.co_consts).encode("utf-8")
        snap[fn.__name__] = hashlib.sha256(code + const).hexdigest()
    _FN_SNAPSHOT = snap


def _verify_fn_snapshot() -> None:
    if not _FN_SNAPSHOT:
        raise SecurityAbort("missing_fn_snapshot")
    for name, baseline in _FN_SNAPSHOT.items():
        fn = globals().get(name)
        if not callable(fn):
            raise SecurityAbort("fn_pointer_tampered")
        code = fn.__code__.co_code
        const = repr(fn.__code__.co_consts).encode("utf-8")
        current = hashlib.sha256(code + const).hexdigest()
        if current != baseline:
            raise SecurityAbort("fn_code_tampered")


def _make_hwid() -> str:
    parts = [
        platform.system(),
        platform.release(),
        platform.machine(),
        platform.node(),
        os.getenv("PROCESSOR_IDENTIFIER", ""),
        os.getenv("COMPUTERNAME", ""),
    ]
    raw = "|".join([p.strip().lower() for p in parts if p and p.strip()])
    return _sha256_hex(raw)


def _state_digest(name: str, value: str, mirror: str) -> str:
    return _sha256_hex(f"{name}|{value}|{mirror}|{_runtime_fingerprint()}")


def _set_state_cell(name: str, value: str) -> None:
    with _LOCK:
        mirror = value[::-1]
        _STATE_CELLS[name] = {
            "value": value,
            "mirror": mirror,
            "digest": _state_digest(name, value, mirror),
        }


def _check_state_cells() -> None:
    with _LOCK:
        if not _STATE_CELLS:
            raise SecurityAbort("missing_state_cells")
        for name, cell in _STATE_CELLS.items():
            value = str(cell.get("value", ""))
            mirror = str(cell.get("mirror", ""))
            digest = str(cell.get("digest", ""))
            if mirror != value[::-1]:
                raise SecurityAbort("memory_patch_detected")
            if digest != _state_digest(name, value, mirror):
                raise SecurityAbort("state_digest_mismatch")


def _random_integrity_probe() -> None:
    # Randomized integrity checks reduce deterministic bypass.
    choice = random.randint(0, 4)
    if choice == 0:
        _verify_fn_snapshot()
    elif choice == 1:
        _check_state_cells()
    elif choice == 2:
        _timing_guard()
    elif choice == 3:
        _debugger_guard()
    else:
        _tool_scan_guard()


def _secure_loader() -> None:
    _random_delay_guard()
    _random_noise_branch()
    _debugger_guard()
    _timing_guard()
    _tool_scan_guard()
    _self_integrity_guard()
    _capture_fn_snapshot()
    _set_state_cell("license_hash", _sha256_hex(LICENSE_KEY or "missing"))
    keyring_fingerprint = _sha256_hex(
        f"{COMM_ACTIVE_KID}|{COMM_AES_KEYS_JSON or COMM_AES_KEY_B64}|{COMM_HMAC_KEYS_JSON or COMM_HMAC_SECRET}"
    )
    _set_state_cell("comm_secret_hash", keyring_fingerprint)
    _set_state_cell("boot_fingerprint", _runtime_fingerprint())
    _check_state_cells()


def verify_once() -> VerifyResult:
    global _LAST_SERVER_TS
    if not LICENSE_KEY:
        raise SecurityAbort("missing_license_key")
    active_kid, aes_keys, hmac_keys = _load_keyring()
    aes_key = aes_keys[active_kid]
    hmac_secret = hmac_keys[active_kid]

    _random_delay_guard()
    _random_noise_branch()

    payload = {
        "license_key": LICENSE_KEY,
        "hwid": _make_hwid(),
        "client_meta": {
            "os": platform.system(),
            "ver": platform.version(),
            "py": platform.python_version(),
        }
    }
    encrypted_payload = _encrypt_payload(payload, aes_key)
    timestamp = int(time.time())
    nonce = uuid.uuid4().hex
    signature = _hmac_hex(hmac_secret, f"{encrypted_payload}.{timestamp}.{nonce}")

    body = {
        "kid": active_kid,
        "encrypted_payload": encrypted_payload,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature
    }

    try:
        resp = requests.post(VERIFY_URL, json=body, timeout=8)
        data = resp.json() if resp.content else {}
    except Exception as exc:
        return VerifyResult(False, f"verify_api_error:{exc}", {})

    srv_kid = str(data.get("kid", active_kid) or active_kid)
    srv_payload = str(data.get("encrypted_payload", ""))
    srv_ts = int(data.get("timestamp", 0) or 0)
    srv_nonce = str(data.get("nonce", ""))
    srv_sig = str(data.get("signature", ""))
    srv_hmac_secret = hmac_keys.get(srv_kid, "")
    if not srv_hmac_secret:
        raise SecurityAbort("unknown_server_kid")
    if not _verify_signature(srv_payload, srv_ts, srv_nonce, srv_sig, srv_hmac_secret):
        raise SecurityAbort("bad_server_signature")
    if srv_ts <= 0 or abs(int(time.time()) - srv_ts) > 300:
        raise SecurityAbort("bad_server_timestamp")
    if _LAST_SERVER_TS and srv_ts + 30 < _LAST_SERVER_TS:
        raise SecurityAbort("server_time_regression")
    _LAST_SERVER_TS = max(_LAST_SERVER_TS, srv_ts)

    srv_aes_key = aes_keys.get(srv_kid)
    if not srv_aes_key:
        raise SecurityAbort("unknown_server_aes_kid")
    decrypted = _decrypt_payload(srv_payload, srv_aes_key)
    ok = bool(decrypted.get("valid"))
    msg = str(decrypted.get("message", "unknown"))
    _set_state_cell("last_verify", _sha256_hex(f"{ok}|{msg}|{srv_ts}"))
    return VerifyResult(ok, msg, decrypted)


def _runtime_guard_loop(stop_evt: threading.Event) -> None:
    while not stop_evt.wait(random.uniform(20.0, 45.0)):
        try:
            _random_delay_guard()
            _debugger_guard()
            _timing_guard()
            _random_integrity_probe()
        except Exception:
            os._exit(1)


def _anti_memory_patch_loop(stop_evt: threading.Event) -> None:
    while not stop_evt.wait(random.uniform(8.0, 20.0)):
        try:
            _check_state_cells()
            _verify_fn_snapshot()
            # Redundant nonlinear branch check.
            if _random_noise_branch() < 0:
                raise SecurityAbort("control_flow_tampered")
        except Exception:
            os._exit(1)


def _periodic_verify_loop(stop_evt: threading.Event) -> None:
    while not stop_evt.wait(VERIFY_INTERVAL_SECONDS):
        try:
            vr = verify_once()
            if not vr.valid:
                os._exit(1)
        except Exception:
            os._exit(1)


def _hidden_verify_loop(stop_evt: threading.Event) -> None:
    # Hidden secondary verify loop with randomized cadence.
    while not stop_evt.wait(random.uniform(55.0, 140.0)):
        try:
            vr = verify_once()
            if not vr.valid:
                os._exit(1)
        except Exception:
            os._exit(1)


def start_protected_app() -> None:
    _secure_loader()
    first = verify_once()
    if not first.valid:
        raise SecurityAbort(f"license_rejected:{first.message}")

    # Example dynamic execution control from server:
    # instructions = first.payload.get("instructions", [])
    # apply your feature toggles from instructions here.

    stop_evt = threading.Event()
    threading.Thread(target=_runtime_guard_loop, args=(stop_evt,), daemon=True).start()
    threading.Thread(target=_anti_memory_patch_loop, args=(stop_evt,), daemon=True).start()
    threading.Thread(target=_periodic_verify_loop, args=(stop_evt,), daemon=True).start()
    threading.Thread(target=_hidden_verify_loop, args=(stop_evt,), daemon=True).start()

    print("License accepted. App can start.")
    # Replace with your real main logic entrypoint.
    while True:
        time.sleep(1.0)


if __name__ == "__main__":
    try:
        start_protected_app()
    except SecurityAbort as err:
        print(f"[SECURITY] Abort: {err}")
        sys.exit(1)
    except Exception as err:
        print(f"[FATAL] {err}")
        sys.exit(1)

