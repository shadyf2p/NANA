import time, uuid, hmac, hashlib, requests, platform, subprocess, re, sys, json, atexit, msvcrt, os
import tkinter as tk
from tkinter import messagebox
from pathlib import Path


def _resolve_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = _resolve_app_dir()
DATA_GENERAL_DIR = APP_DIR / "data_general"
from branding_config import (
    APP_VERSION,
    LICENSE_ACTIVATION_TEXT_SHORT,
    LICENSE_FOOTER_TEXT,
    DEFAULT_OWNER_NAME,
    DEFAULT_OWNER_PHONE,
    save_runtime_owner,
)

# ===== CONFIG =====
URL = os.getenv(
    "LICENSE_SERVER_URL",
    "http://127.0.0.1:8787/api/check",
)
LICENSE_SECRET = os.getenv(
    "LICENSE_SERVER_SECRET",
    "7c1e4b9a2f6d8c3e1a9f5b2d7c4e8a1f6b3d9c2e7a5f1b4c8d6e2a9f",
)  # phải trùng SECRET phía server

# API công khai: nếu server bật LICENSE_PUBLIC_API_KEY thì phải gửi cùng giá trị (header X-Api-Key hoặc Bearer).
LICENSE_PUBLIC_API_KEY = os.getenv("LICENSE_PUBLIC_API_KEY", "").strip()
SECURITY_EVENT_URL = os.getenv(
    "LICENSE_SECURITY_EVENT_URL",
    URL.replace("/api/check", "/api/client/security_event"),
)

APP_SALT = "veo3_salt_v1"
USER_DATA_FILE = DATA_GENERAL_DIR / "user_data.txt"
LICENSE_STATE_FILE = DATA_GENERAL_DIR / "license_state.json"  # lưu info (features, expires,...) để app đọc nếu cần
LOCK_FILE = DATA_GENERAL_DIR / "license_checker.lock"
_lock_fp = None


def _parse_owner_from_features(features_value):
    payload = None
    if isinstance(features_value, dict):
        payload = features_value
    elif isinstance(features_value, str):
        text = features_value.strip()
        if text:
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                payload = None

    if not isinstance(payload, dict):
        return None

    owner_name = str(payload.get("name", "")).strip()
    owner_phone = str(payload.get("sdt", "")).strip()
    if not owner_name or not owner_phone:
        return None
    return {
        "name": owner_name,
        "sdt": owner_phone,
    }


def _extract_owner_info(response_data):
    if not isinstance(response_data, dict):
        return None

    owner_info = _parse_owner_from_features(response_data.get("features"))
    if owner_info:
        return owner_info

    direct_name = str(response_data.get("name", "")).strip()
    direct_phone = str(response_data.get("sdt", "")).strip()
    if direct_name and direct_phone:
        return {"name": direct_name, "sdt": direct_phone}

    return None


def _write_owner_to_branding_config(owner_name, owner_phone):
    """Cập nhật owner runtime để app/exe đọc đúng ngay trong lần chạy hiện tại."""
    try:
        return bool(save_runtime_owner(owner_name, owner_phone))
    except Exception:
        return False

# ---------- Machine ID ----------
def _win_machine_guid() -> str:
    if platform.system() != "Windows":
        return ""
    try:
        import winreg  # type: ignore
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        v, _ = winreg.QueryValueEx(k, "MachineGuid")
        return str(v)
    except Exception:
        return ""

def _win_system_uuid() -> str:
    if platform.system() != "Windows":
        return ""
    try:
        out = subprocess.check_output(["wmic", "csproduct", "get", "uuid"], text=True, timeout=10)
        lines = [x.strip() for x in out.splitlines() if x.strip() and "UUID" not in x.upper()]
        return lines[0] if lines else ""
    except Exception:
        return ""

def _linux_machine_id() -> str:
    if platform.system() != "Linux":
        return ""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

def _mac_addr() -> str:
    import uuid as _uuid
    return hex(_uuid.getnode())

def make_machine_id() -> str:
    parts = [
        platform.system(),
        platform.release(),
        platform.machine(),
        _win_machine_guid(),
        _win_system_uuid(),
        _linux_machine_id(),
        _mac_addr(),
    ]
    raw = "|".join([p.strip().lower() for p in parts if p and p.strip()])
    raw = re.sub(r"\s+", " ", raw)
    raw = raw + "|" + APP_SALT
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _detect_debugger() -> bool:
    try:
        if sys.gettrace() is not None:
            return True
    except Exception:
        pass
    # Một số môi trường crack/debug set biến này
    if str(os.getenv("PYTHONINSPECT", "")).strip() == "1":
        return True
    return False


def _detect_vm() -> bool:
    hints = []
    try:
        hints.append(_win_system_uuid().lower())
    except Exception:
        pass
    try:
        hints.append(str(os.getenv("PROCESSOR_IDENTIFIER", "")).lower())
    except Exception:
        pass
    hay = " ".join(hints)
    vm_markers = ("vmware", "virtualbox", "kvm", "xen", "hyper-v", "qemu")
    return any(m in hay for m in vm_markers)


def _send_security_signal(license_key: str, machine_id: str, signal_type: str, detail: str = "", score: int = 0) -> None:
    headers = {}
    if LICENSE_PUBLIC_API_KEY:
        headers["X-Api-Key"] = LICENSE_PUBLIC_API_KEY
    payload = {
        "license_key": license_key,
        "machine_id": machine_id,
        "signal_type": signal_type,
        "detail": detail[:180],
        "score": int(score or 0),
    }
    try:
        requests.post(SECURITY_EVENT_URL, json=payload, headers=headers or None, timeout=6)
    except Exception:
        pass

# ---------- Signing (HMAC) ----------
def canonical_request(license_key: str, machine_id: str, ts: int, nonce: str, app_version: str = "") -> str:
    # MUST match admin_portal server canonical_request() (HMAC request)
    av = re.sub(r"[^\w.\-]", "", str(app_version or ""))[:64]
    return f"license_key={license_key}&machine_id={machine_id}&ts={int(ts)}&nonce={nonce}&app_version={av}"

def canonical_response(ok: bool, license_key: str, machine_id: str, expires_at: int, features: str, server_ts: int, nonce: str) -> str:
    # MUST match Apps Script canonicalResponse()
    ok_str = "true" if ok else "false"
    return f"ok={ok_str}&license_key={license_key}&machine_id={machine_id}&expires_at={int(expires_at)}&features={features}&server_ts={int(server_ts)}&nonce={nonce}"


def canonical_response_core(ok: bool, license_key: str, machine_id: str, expires_at: int, server_ts: int, nonce: str) -> str:
    """Canonical response bỏ qua features để tránh fail do format JSON features."""
    ok_str = "true" if ok else "false"
    return (
        f"ok={ok_str}&license_key={license_key}&machine_id={machine_id}"
        f"&expires_at={int(expires_at)}&server_ts={int(server_ts)}&nonce={nonce}"
    )

def sign_hmac_hex(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

# ---------- Local storage ----------
def _save_license(license_key: str):
    DATA_GENERAL_DIR.mkdir(parents=True, exist_ok=True)
    USER_DATA_FILE.write_text(license_key.strip(), encoding="utf-8")
    try:
        print(f"[LICENSE] saved_key path={USER_DATA_FILE}")
    except Exception:
        pass

def _load_license() -> str:
    if not USER_DATA_FILE.exists():
        try:
            print(f"[LICENSE] no_saved_key path={USER_DATA_FILE}")
        except Exception:
            pass
        return ""
    try:
        key = USER_DATA_FILE.read_text(encoding="utf-8").strip()
        try:
            masked = f"{key[:6]}...{key[-4:]}" if len(key) > 12 else "***"
            print(f"[LICENSE] loaded_saved_key path={USER_DATA_FILE} key={masked}")
        except Exception:
            pass
        return key
    except Exception:
        return ""


def _clear_saved_license() -> None:
    try:
        if USER_DATA_FILE.exists():
            USER_DATA_FILE.unlink()
            print(f"[LICENSE] cleared_saved_key path={USER_DATA_FILE}")
    except Exception:
        pass

def _save_license_state(state: dict):
    DATA_GENERAL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        LICENSE_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------- Single instance lock ----------
def _acquire_lock() -> bool:
    global _lock_fp
    try:
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        _lock_fp = open(LOCK_FILE, "a+")
        try:
            msvcrt.locking(_lock_fp.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        _lock_fp.seek(0)
        _lock_fp.truncate()
        _lock_fp.write(str(os.getpid()))
        _lock_fp.flush()
        return True
    except Exception:
        return False  # nếu lock lỗi thì không chặn thêm instance


def _release_lock():
    global _lock_fp
    if _lock_fp:
        try:
            _lock_fp.seek(0)
            _lock_fp.truncate()
            msvcrt.locking(_lock_fp.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            _lock_fp.close()
        except Exception:
            pass
        _lock_fp = None


atexit.register(_release_lock)


# ---------- License check (NEW: request_sig + verify server_sig) ----------
def _check_license(license_key: str):
    machine_id = make_machine_id()
    if _detect_debugger():
        _send_security_signal(license_key, machine_id, "debugger_detected", "sys.gettrace_active", 30)
    if _detect_vm():
        _send_security_signal(license_key, machine_id, "vm_detected", "vm_hint_detected", 25)
    nonce = uuid.uuid4().hex
    ts = int(time.time())

    def _to_int(value, default=0):
        try:
            return int(value)
        except Exception:
            return default

    req_msg = canonical_request(license_key, machine_id, ts, nonce, APP_VERSION)
    req_sig = sign_hmac_hex(LICENSE_SECRET, req_msg)

    payload = {
        "license_key": license_key,
        "machine_id": machine_id,
        "ts": ts,
        "nonce": nonce,
        "request_sig": req_sig,
        "app_version": APP_VERSION,
    }

    start = time.time()
    status_code = 0
    elapsed = 0.0
    response_data = None
    request_error = None

    req_headers = {}
    if LICENSE_PUBLIC_API_KEY:
        req_headers["X-Api-Key"] = LICENSE_PUBLIC_API_KEY

    # Ưu tiên POST JSON; fallback GET query cho backend cũ.
    try:
        resp = requests.post(URL, json=payload, headers=req_headers or None, timeout=25)
        status_code = int(resp.status_code)
        elapsed = time.time() - start
        try:
            response_data = resp.json()
        except Exception:
            response_data = {"ok": False, "ACTIVE": False, "reason": "invalid_json_response", "raw": resp.text[:500]}
    except Exception as exc:
        request_error = str(exc)

    if response_data is None:
        try:
            resp = requests.get(URL, params=payload, headers=req_headers or None, timeout=25)
            status_code = int(resp.status_code)
            elapsed = time.time() - start
            try:
                response_data = resp.json()
            except Exception:
                response_data = {"ok": False, "ACTIVE": False, "reason": "invalid_json_response", "raw": resp.text[:500]}
        except Exception as exc:
            elapsed = time.time() - start
            err = request_error or str(exc)
            return 0, {"ok": False, "ACTIVE": False, "reason": f"network_error: {err}"}, elapsed

    if not isinstance(response_data, dict):
        return status_code, {"ok": False, "ACTIVE": False, "reason": "invalid_response_payload"}, elapsed

    data = response_data.get("data") if isinstance(response_data.get("data"), dict) else response_data
    if not isinstance(data, dict):
        return status_code, {"ok": False, "ACTIVE": False, "reason": "invalid_response_data"}, elapsed

    ok = bool(data.get("ok") or data.get("ACTIVE"))
    data["ok"] = ok
    data["ACTIVE"] = ok

    server_license_key = str(data.get("license_key", "") or "")
    server_machine_id = str(data.get("machine_id", "") or "")
    server_expires_at = _to_int(data.get("expires_at"), 0)
    server_ts = _to_int(data.get("server_ts"), 0)
    server_nonce = str(data.get("nonce", "") or "")
    server_sig = str(data.get("server_sig", "") or "")
    license_proof = str(data.get("license_proof", "") or "")
    proof_expires_at = _to_int(data.get("proof_expires_at"), 0)
    features = data.get("features", "")

    # 1) Bắt buộc verify chữ ký response cho kết quả ACTIVE để chống fake success.
    if ok and not server_sig:
        return status_code, {"ok": False, "ACTIVE": False, "reason": "missing_server_signature"}, elapsed
    if server_sig:
        core_msg = canonical_response_core(
            ok,
            server_license_key or license_key,
            server_machine_id or machine_id,
            server_expires_at,
            server_ts,
            server_nonce or nonce,
        )
        expected_core_sig = sign_hmac_hex(LICENSE_SECRET, core_msg)
        sig_valid = hmac.compare_digest(expected_core_sig, server_sig)

        if not sig_valid:
            if isinstance(features, str):
                features_str = features
            else:
                try:
                    features_str = json.dumps(features, ensure_ascii=False, separators=(",", ":"))
                except Exception:
                    features_str = str(features)
            full_msg = canonical_response(
                ok,
                server_license_key or license_key,
                server_machine_id or machine_id,
                server_expires_at,
                features_str,
                server_ts,
                server_nonce or nonce,
            )
            expected_full_sig = sign_hmac_hex(LICENSE_SECRET, full_msg)
            sig_valid = hmac.compare_digest(expected_full_sig, server_sig)

        if not sig_valid:
            return status_code, {"ok": False, "ACTIVE": False, "reason": "invalid_server_signature"}, elapsed

    # 1b) Ràng buộc thời gian/nonce từ server để tránh replay response.
    if ok:
        now = int(time.time())
        if server_ts <= 0 or abs(now - server_ts) > 600:
            return status_code, {"ok": False, "ACTIVE": False, "reason": "stale_server_response"}, elapsed
        if server_nonce and server_nonce != nonce:
            return status_code, {"ok": False, "ACTIVE": False, "reason": "response_nonce_mismatch"}, elapsed

    # 2) Verify ràng buộc key + machine.
    if server_license_key and server_license_key != license_key:
        return status_code, {"ok": False, "ACTIVE": False, "reason": "license_key_mismatch"}, elapsed
    if server_machine_id and server_machine_id != machine_id:
        return status_code, {"ok": False, "ACTIVE": False, "reason": "machine_id_mismatch"}, elapsed

    # 3) Verify hạn dùng theo server.
    if server_expires_at > 0 and int(time.time()) >= int(server_expires_at):
        return status_code, {"ok": False, "ACTIVE": False, "reason": "expired", "expires_at": server_expires_at}, elapsed

    if ok and (not license_proof or proof_expires_at <= 0):
        return status_code, {"ok": False, "ACTIVE": False, "reason": "missing_license_proof"}, elapsed

    if ok:
        owner_info = _extract_owner_info(data)
        if owner_info:
            _write_owner_to_branding_config(owner_info.get("name"), owner_info.get("sdt"))
        _save_license_state(
            {
                "ok": True,
                "ACTIVE": True,
                "license_key": license_key,
                "machine_id": machine_id,
                "expires_at": server_expires_at,
                "server_ts": server_ts,
                "nonce": server_nonce or nonce,
                "features": features,
                "license_proof": license_proof,
                "proof_expires_at": proof_expires_at,
                "checked_at": int(time.time()),
            }
        )

    return status_code, data, elapsed


# ---------- Run app ----------
def _run_app():
    if getattr(sys, "frozen", False):
        try:
            import main as main_module
            if hasattr(main_module, "main"):
                main_module.main()
            else:
                raise RuntimeError("Không tìm thấy hàm main() trong module main")
            return
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể chạy app trong chế độ build: {e}")
            return

    app_py = APP_DIR / "main.py"
    python_exe = APP_DIR / "venv" / "Scripts" / "python.exe"
    if not python_exe.exists():
        python_exe = Path(sys.executable)

    try:
        subprocess.Popen([str(python_exe), "-c", "import main; main.main()"], cwd=str(APP_DIR))
        return
    except Exception:
        pass

    if not app_py.exists():
        messagebox.showerror("Lỗi", f"Không tìm thấy module main hoặc main.py tại: {APP_DIR}")
        return

    subprocess.Popen([str(python_exe), str(app_py)], cwd=str(app_py.parent))

# ---------- UI ----------
def _show_checking_window():
    root = tk.Tk()
    root.title(f"Checking License {APP_VERSION}")
    root.geometry("460x190")
    root.resizable(False, False)
    root.configure(bg="#060b18")

    panel = tk.Frame(root, bg="#0f1a34", bd=1, relief="solid", highlightthickness=1, highlightbackground="#2c4f9e")
    panel.pack(fill="both", expand=True, padx=16, pady=16)

    tk.Label(
        panel,
        text="Dang check license...",
        font=("Segoe UI", 14, "bold"),
        fg="#dbe8ff",
        bg="#0f1a34",
    ).pack(pady=(24, 8))

    status_label = tk.Label(
        panel,
        text="Vui long cho phan hoi tu server",
        font=("Segoe UI", 10),
        fg="#9fb8ea",
        bg="#0f1a34",
    )
    status_label.pack(pady=4)

    pulse = tk.Label(panel, text="● ● ●", font=("Segoe UI", 10, "bold"), fg="#61a0ff", bg="#0f1a34")
    pulse.pack(pady=(8, 0))

    def _animate(step=0):
        dots = ["● ○ ○", "○ ● ○", "○ ○ ●"]
        pulse.config(text=dots[step % 3])
        if root.winfo_exists():
            root.after(240, lambda: _animate(step + 1))

    _animate()
    return root, status_label

def _show_first_run_window():
    machine_id = make_machine_id()

    root = tk.Tk()
    root.title(f"Check License tool AUTO VEO3 {APP_VERSION}")
    root.geometry("900x520")
    root.resizable(False, False)
    root.configure(bg="#070d1c")

    colors = {
        "bg": "#070d1c",
        "panel": "#0f1d3a",
        "panel_alt": "#121a31",
        "text": "#e9f1ff",
        "muted": "#98b0dc",
        "accent": "#7e5dff",
        "accent_2": "#55b2ff",
        "label": "#9fc2ff",
        "entry_bg": "#0c1529",
        "entry_fg": "#f1f6ff",
        "btn_primary": "#2f88ff",
        "btn_primary_active": "#246fce",
        "btn_secondary": "#1f3f74",
        "btn_secondary_active": "#17325b",
        "error": "#ff89a6",
        "ok": "#6be2b6",
        "line": "#2a4779",
        "line_soft": "#1b2e51",
    }

    outer = tk.Frame(root, bg=colors["bg"])
    outer.pack(fill="both", expand=True, padx=18, pady=18)

    shell = tk.Frame(
        outer,
        bg=colors["panel_alt"],
        bd=1,
        relief="solid",
        highlightthickness=1,
        highlightbackground=colors["line"],
    )
    shell.pack(fill="both", expand=True)

    left = tk.Frame(shell, bg=colors["panel"], width=320)
    left.pack(side="left", fill="y")
    left.pack_propagate(False)

    right = tk.Frame(shell, bg=colors["panel_alt"])
    right.pack(side="left", fill="both", expand=True)

    tk.Label(
        left,
        text="ADMIN PORTAL",
        font=("Segoe UI", 10, "bold"),
        fg=colors["accent_2"],
        bg=colors["panel"],
    ).pack(anchor="w", padx=22, pady=(24, 4))

    tk.Label(
        left,
        text="Kích hoạt License",
        font=("Segoe UI", 22, "bold"),
        fg=colors["text"],
        bg=colors["panel"],
        wraplength=270,
        justify="left",
    ).pack(anchor="w", padx=22, pady=(2, 10))

    tk.Label(
        left,
        text=LICENSE_ACTIVATION_TEXT_SHORT,
        font=("Segoe UI", 10),
        fg=colors["muted"],
        bg=colors["panel"],
        wraplength=272,
        justify="left",
    ).pack(anchor="w", padx=22)

    feature_box = tk.Frame(left, bg=colors["panel"], highlightthickness=1, highlightbackground=colors["line_soft"])
    feature_box.pack(fill="x", padx=22, pady=(18, 0))
    for item in [
        "• Kích hoạt nhanh theo key server",
        "• Tự động bind Machine ID",
        "• Kiểm tra hạn dùng 7 / 30 ngày",
    ]:
        tk.Label(
            feature_box,
            text=item,
            font=("Segoe UI", 9),
            fg="#c9dcff",
            bg=colors["panel"],
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=10, pady=6)

    tk.Label(
        left,
        text=LICENSE_FOOTER_TEXT,
        font=("Segoe UI", 8),
        fg=colors["muted"],
        bg=colors["panel"],
        wraplength=272,
        justify="left",
    ).pack(anchor="w", padx=22, pady=(18, 0))

    content = tk.Frame(right, bg=colors["panel_alt"])
    content.pack(fill="both", expand=True, padx=24, pady=24)

    tk.Label(
        content,
        text="Nhập thông tin kích hoạt",
        font=("Segoe UI", 16, "bold"),
        fg=colors["text"],
        bg=colors["panel_alt"],
    ).pack(anchor="w")
    tk.Label(
        content,
        text="Dán key do Admin cấp để mở toàn bộ chức năng.",
        font=("Segoe UI", 10),
        fg=colors["muted"],
        bg=colors["panel_alt"],
    ).pack(anchor="w", pady=(4, 14))

    tk.Label(
        content,
        text="MACHINE ID",
        font=("Segoe UI", 10, "bold"),
        fg=colors["label"],
        bg=colors["panel_alt"],
    ).pack(anchor="w", pady=(0, 6))
    frame_mid = tk.Frame(content, bg=colors["panel_alt"])
    frame_mid.pack(fill="x")

    machine_entry = tk.Entry(
        frame_mid,
        width=64,
        relief="flat",
        bg=colors["entry_bg"],
        fg=colors["entry_fg"],
        insertbackground=colors["entry_fg"],
        readonlybackground=colors["entry_bg"],
        highlightthickness=1,
        highlightbackground=colors["line"],
        highlightcolor=colors["accent_2"],
        font=("Consolas", 11),
    )
    machine_entry.insert(0, machine_id)
    machine_entry.configure(state="readonly")
    machine_entry.pack(side="left", fill="x", expand=True, ipady=10)

    status_label = tk.Label(content, text="", fg=colors["error"], bg=colors["panel_alt"], font=("Segoe UI", 9, "bold"))
    status_label.pack(anchor="w", pady=(10, 0))

    def copy_machine_id():
        root.clipboard_clear()
        root.clipboard_append(machine_id)
        status_label.config(text="Đã copy MACHINE ID", fg=colors["ok"])
        root.after(1300, lambda: status_label.config(text="", fg=colors["error"]))

    tk.Button(
        frame_mid,
        text="Copy",
        command=copy_machine_id,
        width=10,
        height=1,
        bg=colors["btn_secondary"],
        fg=colors["text"],
        activebackground=colors["btn_secondary_active"],
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        cursor="hand2",
    ).pack(side="left", padx=8)

    tk.Label(
        content,
        text="LICENSE KEY",
        font=("Segoe UI", 10, "bold"),
        fg=colors["label"],
        bg=colors["panel_alt"],
    ).pack(anchor="w", pady=(18, 6))
    license_entry = tk.Entry(
        content,
        width=64,
        relief="flat",
        bg=colors["entry_bg"],
        fg=colors["entry_fg"],
        insertbackground=colors["entry_fg"],
        highlightthickness=1,
        highlightbackground=colors["line"],
        highlightcolor=colors["accent"],
        font=("Consolas", 12),
    )
    license_entry.pack(fill="x", ipady=11)

    helper_row = tk.Frame(content, bg=colors["panel_alt"])
    helper_row.pack(fill="x", pady=(10, 0))

    def paste_license():
        try:
            text = root.clipboard_get().strip()
        except Exception:
            text = ""
        if text:
            license_entry.delete(0, tk.END)
            license_entry.insert(0, text)
            status_label.config(text="Đã paste license key", fg=colors["ok"])
            root.after(1300, lambda: status_label.config(text="", fg=colors["error"]))

    tk.Button(
        helper_row,
        text="Paste",
        command=paste_license,
        width=10,
        bg=colors["btn_secondary"],
        fg=colors["text"],
        activebackground=colors["btn_secondary_active"],
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        cursor="hand2",
    ).pack(side="left")

    tip = tk.Label(
        helper_row,
        text="Nhấn Enter để kích hoạt nhanh",
        fg=colors["muted"],
        bg=colors["panel_alt"],
        font=("Segoe UI", 9),
    )
    tip.pack(side="right")

    def _clear_status(*_):
        status_label.config(text="")

    license_entry.bind("<KeyRelease>", _clear_status)

    def on_confirm():
        # Ngăn double-click khi đang gửi request
        if getattr(on_confirm, "_busy", False):
            return
        on_confirm._busy = True
        status_label.config(text="")
        license_key = license_entry.get().strip()
        if not license_key:
            status_label.config(text="Vui lòng nhập license key")
            on_confirm._busy = False
            return
        status_label.config(text="Đang kiểm tra license...", fg=colors["label"])
        btn_confirm.config(text="Đang kích hoạt...", state="disabled")
        root.update_idletasks()

        status_code, data, _ = _check_license(license_key)
        active = bool(data.get("ACTIVE") or data.get("ok")) if isinstance(data, dict) else False
        if active:
            _save_license(license_key)
            root.destroy()
            _run_app()
        else:
            err = (data.get("reason") or data.get("error") or "unknown") if isinstance(data, dict) else "unknown"
            status_label.config(text=f"License không hợp lệ ({err}). Liên hệ Admin để kích hoạt.", fg=colors["error"])
            btn_confirm.config(text="Kích hoạt", state="normal")
        on_confirm._busy = False

    btn_row = tk.Frame(content, bg=colors["panel_alt"])
    btn_row.pack(fill="x", pady=(22, 0))

    def clear_license():
        license_entry.delete(0, tk.END)
        license_entry.focus_set()
        status_label.config(text="")

    tk.Button(
        btn_row,
        text="Xóa",
        command=clear_license,
        width=11,
        height=1,
        bg=colors["btn_secondary"],
        fg=colors["text"],
        activebackground=colors["btn_secondary_active"],
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        cursor="hand2",
    ).pack(side="left")

    btn_confirm = tk.Button(
        btn_row,
        text="Kích hoạt",
        command=on_confirm,
        width=18,
        height=2,
        bg=colors["btn_primary"],
        fg="#ffffff",
        activebackground=colors["btn_primary_active"],
        relief="flat",
        font=("Segoe UI", 11, "bold"),
        cursor="hand2",
    )
    btn_confirm.pack(side="right")

    license_entry.focus_set()
    root.bind("<Return>", lambda _e: on_confirm())
    root.mainloop()

def main():
    if not _acquire_lock():
        messagebox.showerror("Đang chạy", "Công cụ check license đang được mở. Vui lòng không mở thêm.")
        return

    # Basic config guard
    if "REPLACE_" in URL:
        messagebox.showerror("Thiếu URL", "Bạn chưa cấu hình URL Apps Script (Web App).")
        return
    if not LICENSE_SECRET or "REPLACE_" in LICENSE_SECRET:
        messagebox.showerror("Thiếu SECRET", "Bạn chưa cấu hình LICENSE_SECRET (trùng SECRET ở Apps Script).")
        return

    license_key = _load_license()
    if not license_key:
        _show_first_run_window()
        return

    root, status_label = _show_checking_window()

    def check_now():
        status_code, data, _ = _check_license(license_key)
        active = bool(data.get("ACTIVE") or data.get("ok")) if isinstance(data, dict) else False
        if active:
            root.destroy()
            _run_app()
        else:
            err = (data.get("reason") or data.get("error") or "unknown") if isinstance(data, dict) else "unknown"
            status_label.config(text=f"License không hợp lệ ({err}). Mở lại màn hình nhập key...")
            root.update_idletasks()
            _clear_saved_license()
            root.after(300, lambda: (root.destroy(), _show_first_run_window()))

    root.after(100, check_now)
    root.mainloop()

if __name__ == "__main__":
    main()
