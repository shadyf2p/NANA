from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


APP_DIR = _app_dir()
DATA_GENERAL_DIR = APP_DIR / "data_general"
MANIFEST_PATH = DATA_GENERAL_DIR / "security_manifest.json"
USER_DATA_FILE = DATA_GENERAL_DIR / "user_data.txt"
_last_signal_sent: dict[str, float] = {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _is_debugger_present() -> bool:
    try:
        if sys.gettrace() is not None:
            return True
    except Exception:
        pass

    if os.name == "nt":
        try:
            import ctypes

            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            if bool(k32.IsDebuggerPresent()):
                return True
            has_dbg = ctypes.c_int(0)
            ok = k32.CheckRemoteDebuggerPresent(k32.GetCurrentProcess(), ctypes.byref(has_dbg))
            if bool(ok) and bool(has_dbg.value):
                return True
        except Exception:
            pass
    return False


def _find_suspicious_tools() -> list[str]:
    names = {
        "x64dbg.exe",
        "x32dbg.exe",
        "ida.exe",
        "ida64.exe",
        "ollydbg.exe",
        "cheatengine.exe",
        "dnspy.exe",
        "frida.exe",
        "frida-server.exe",
        "procmon.exe",
        "processhacker.exe",
        "httpdebuggerui.exe",
    }
    found: list[str] = []
    if os.name != "nt":
        return found
    try:
        out = subprocess.check_output(["tasklist"], text=True, timeout=3, errors="ignore")
        low = out.lower()
        for n in names:
            if n.lower() in low:
                found.append(n)
    except Exception:
        pass
    return found


def _detect_vm_hint() -> bool:
    if os.name != "nt":
        return False
    hints: list[str] = []
    try:
        out = subprocess.check_output(["wmic", "csproduct", "get", "uuid"], text=True, timeout=5, errors="ignore")
        hints.append(out.lower())
    except Exception:
        pass
    try:
        out2 = subprocess.check_output(["wmic", "computersystem", "get", "model"], text=True, timeout=5, errors="ignore")
        hints.append(out2.lower())
    except Exception:
        pass
    hay = " ".join(hints)
    return any(x in hay for x in ("vmware", "virtualbox", "kvm", "qemu", "hyper-v", "xen"))


def _load_manifest() -> dict[str, Any] | None:
    if not MANIFEST_PATH.exists():
        return None
    try:
        raw = MANIFEST_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _verify_manifest() -> tuple[bool, list[str]]:
    manifest = _load_manifest()
    if not manifest:
        return False, ["manifest_missing"]
    files = manifest.get("files")
    if not isinstance(files, dict):
        return False, ["manifest_invalid"]
    issues: list[str] = []
    for rel, expected_hash in files.items():
        p = APP_DIR / str(rel)
        if not p.exists():
            issues.append(f"missing:{rel}")
            continue
        try:
            actual = _sha256_file(p)
        except Exception:
            issues.append(f"read_error:{rel}")
            continue
        if str(actual).lower() != str(expected_hash).lower():
            issues.append(f"hash_mismatch:{rel}")
    return len(issues) == 0, issues


def _load_license_key() -> str:
    try:
        if USER_DATA_FILE.exists():
            return USER_DATA_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""


def _make_machine_id() -> str:
    parts = [
        os.name,
        os.getenv("COMPUTERNAME", ""),
        os.getenv("PROCESSOR_IDENTIFIER", ""),
        os.getenv("USERDOMAIN", ""),
    ]
    raw = "|".join([p.strip().lower() for p in parts if p and p.strip()])
    raw = re.sub(r"\s+", " ", raw)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _send_signal(signal_type: str, detail: str, score: int) -> None:
    now = time.time()
    key = f"{signal_type}|{detail[:48]}"
    # Chống spam telemetry cùng loại trong thời gian ngắn.
    if now - float(_last_signal_sent.get(key, 0.0)) < 300.0:
        return
    _last_signal_sent[key] = now
    try:
        import requests
    except Exception:
        return
    base_url = str(os.getenv("LICENSE_SERVER_URL", "http://127.0.0.1:8787/api/check")).strip()
    event_url = str(os.getenv("LICENSE_SECURITY_EVENT_URL", base_url.replace("/api/check", "/api/client/security_event"))).strip()
    api_key = str(os.getenv("LICENSE_PUBLIC_API_KEY", "")).strip()
    headers: dict[str, str] = {}
    if api_key:
        headers["X-Api-Key"] = api_key
    payload = {
        "license_key": _load_license_key(),
        "machine_id": _make_machine_id(),
        "signal_type": signal_type,
        "detail": detail[:180],
        "score": int(score),
    }
    try:
        requests.post(event_url, json=payload, headers=headers or None, timeout=4)
    except Exception:
        pass


def _verify_pe_signature_windows(file_path: Path) -> tuple[bool, str]:
    if os.name != "nt":
        return True, "not_windows"
    if not file_path.exists():
        return False, "missing_file"
    escaped_path = str(file_path).replace("'", "''")
    cmd = (
        "powershell -NoProfile -Command "
        f"\"$s=Get-AuthenticodeSignature -FilePath '{escaped_path}';"
        "Write-Output ($s.Status.ToString() + '|' + ($s.SignerCertificate.Subject -as [string]))\""
    )
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, timeout=8, errors="ignore").strip()
    except Exception:
        return False, "sig_check_error"
    status = str(out.split("|", 1)[0] if out else "").strip().lower()
    # valid: chữ ký hợp lệ; unknownerror/notsigned/hashmismatch là không an toàn
    if status == "valid":
        return True, "valid"
    if status == "notsigned":
        return False, "not_signed"
    return False, status or "invalid_signature"


def _collect_pe_targets() -> list[Path]:
    targets: list[Path] = []
    try:
        exe = Path(sys.executable).resolve()
        if exe.exists():
            targets.append(exe)
    except Exception:
        pass
    if APP_DIR.exists():
        for p in sorted(APP_DIR.glob("*.exe")):
            if p not in targets:
                targets.append(p)
        # giới hạn để tránh check quá nặng
        dlls = sorted(APP_DIR.glob("*.dll"))[:40]
        for p in dlls:
            if p not in targets:
                targets.append(p)
    return targets


@dataclass
class SecurityReport:
    mode: str  # normal | degraded | blocked
    risk: int
    reasons: list[str]


def evaluate_client_security(*, include_signature_check: bool = True) -> SecurityReport:
    """
    Đánh giá bảo mật client.
    - normal: chạy bình thường
    - degraded: khóa chức năng nhạy cảm nhưng vẫn mở app
    - blocked: mức rủi ro quá cao
    Mục tiêu: tăng chi phí bypass, không thay thế server-side validation.
    """
    risk = 0
    issues: list[tuple[str, str, int]] = []

    if _is_debugger_present():
        issues.append(("debugger_detected", "debugger_present", 45))
    tools = _find_suspicious_tools()
    if tools:
        issues.append(("hook_detected", ",".join(tools[:4]), 30))
    if _detect_vm_hint():
        issues.append(("vm_detected", "vm_hint", 20))

    ok_manifest, manifest_issues = _verify_manifest()
    if not ok_manifest:
        # Manifest missing chỉ cảnh báo nhẹ; mismatch thì nặng hơn.
        score = 10 if manifest_issues == ["manifest_missing"] else 60
        issues.append(("tamper_detected", ";".join(manifest_issues[:4]), score))

    if include_signature_check:
        strict_sig = str(os.getenv("CLIENT_SECURITY_SIGNATURE_STRICT", "0")).strip() in {"1", "true", "yes", "on"}
        for p in _collect_pe_targets():
            ok_sig, sig_reason = _verify_pe_signature_windows(p)
            if not ok_sig:
                score = 35 if strict_sig else 15
                issues.append(("binary_signature_invalid", f"{p.name}:{sig_reason}", score))
                # tránh cộng quá nhiều nếu thư mục có nhiều dll unsigned
                if len([x for x in issues if x[0] == "binary_signature_invalid"]) >= 4:
                    break

    for t, d, s in issues:
        risk += s
        _send_signal(t, d, s)

    # anti-hook timing simple check
    t0 = time.perf_counter()
    time.sleep(0.05)
    delta_ms = (time.perf_counter() - t0) * 1000.0
    if delta_ms > 400.0:
        risk += 20
        _send_signal("runtime_patch_detected", f"sleep_drift_ms={delta_ms:.1f}", 20)

    block_threshold = int(str(os.getenv("CLIENT_SECURITY_BLOCK_THRESHOLD", "110")).strip() or "110")
    degrade_threshold = int(str(os.getenv("CLIENT_SECURITY_DEGRADE_THRESHOLD", "60")).strip() or "60")
    mode = "normal"
    if risk >= max(1, block_threshold):
        mode = "blocked"
    elif risk >= max(1, degrade_threshold):
        mode = "degraded"
    reasons = [f"{t}:{d}" for t, d, _s in issues]
    return SecurityReport(mode=mode, risk=risk, reasons=reasons[:8])


def enforce_client_security() -> bool:
    """
    Backward-compat: trả False khi blocked/degraded.
    """
    rep = evaluate_client_security(include_signature_check=True)
    return rep.mode == "normal"

