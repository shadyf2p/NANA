from __future__ import annotations

import datetime as dt
import os
import secrets
import sqlite3
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BASE_DIR = app_dir()


def resolve_db_path() -> Path:
    # 1) Explicit override so server/desktop can share exactly one DB.
    raw = os.getenv("ADMIN_DB_PATH", "").strip()
    if raw:
        return Path(raw).resolve()

    # 2) Source run (python admin_portal/admin_desktop.py).
    source_default = BASE_DIR / "data" / "admin.db"
    if source_default.parent.exists():
        return source_default

    # 3) EXE in dist/ -> use project-level admin_portal/data/admin.db.
    dist_shared = BASE_DIR.parent / "admin_portal" / "data" / "admin.db"
    if dist_shared.parent.exists():
        return dist_shared

    # 4) Fallback create DB beside exe.
    if getattr(sys, "frozen", False):
        return BASE_DIR / "admin_data" / "admin.db"

    return source_default


DB_PATH = resolve_db_path()
DATA_DIR = DB_PATH.parent

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"
FONT_FAMILY = "Segoe UI"
BUILD_TAG = "DESKTOP-BUILD-20260323-1402"

THEME = {
    "bg": "#060a14",
    "bg_2": "#0a1226",
    "bg_3": "#0f1f3f",
    "panel": "#101a31",
    "panel_2": "#0d162a",
    "fg": "#e6eeff",
    "muted": "#9db2d9",
    "accent": "#2f6bff",
    "accent_2": "#7a4dff",
    "success": "#34d399",
    "warn": "#f59e0b",
    "danger": "#ef4444",
    "line": "#2a3d63",
    "glow": "#2d5de0",
}


def now_ts() -> int:
    return int(time.time())


def to_text(ts: int) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


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
                note TEXT NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS banned_hwids (
                hwid TEXT PRIMARY KEY,
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
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
        conn.commit()
    finally:
        conn.close()


def log_event(action: str, status: str = "", detail: str = "", license_key: str = "", machine_id: str = "", ip: str = "") -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO events(ts, action, ip, license_key, machine_id, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now_ts(), action, ip, license_key, machine_id, status, detail),
        )
        conn.commit()
    finally:
        conn.close()


def make_key(prefix: str = "VEO3") -> str:
    blocks = [secrets.token_hex(2).upper() for _ in range(4)]
    return f"{prefix}-{'-'.join(blocks)}"


def apply_theme(root: tk.Tk) -> ttk.Style:
    root.configure(bg=THEME["bg"])
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    root.option_add("*TCombobox*Listbox*Background", THEME["panel_2"])
    root.option_add("*TCombobox*Listbox*Foreground", THEME["fg"])
    root.option_add("*TCombobox*Listbox*selectBackground", "#2a4780")
    root.option_add("*TCombobox*Listbox*selectForeground", "#ffffff")

    style.configure(".", font=(FONT_FAMILY, 10))
    style.configure("TFrame", background=THEME["bg"])
    style.configure("App.TFrame", background=THEME["bg"])
    style.configure("Card.TFrame", background=THEME["panel"])
    style.configure("Card2.TFrame", background=THEME["panel_2"])
    style.configure("Glass.TFrame", background=THEME["panel"], borderwidth=1, relief="solid")
    style.configure("GlassHover.TFrame", background="#172a54", borderwidth=1, relief="solid")
    style.configure("GlassSoft.TFrame", background=THEME["panel_2"], borderwidth=1, relief="solid")
    style.configure("TLabel", background=THEME["bg"], foreground=THEME["fg"])
    style.configure("Muted.TLabel", background=THEME["bg"], foreground=THEME["muted"])
    style.configure("Title.TLabel", background=THEME["panel"], foreground=THEME["fg"], font=(FONT_FAMILY, 22, "bold"))
    style.configure("H2.TLabel", background=THEME["bg"], foreground=THEME["fg"], font=(FONT_FAMILY, 12, "bold"))
    style.configure("CardTitle.TLabel", background=THEME["panel"], foreground=THEME["muted"], font=(FONT_FAMILY, 9, "bold"))
    style.configure("CardValue.TLabel", background=THEME["panel"], foreground=THEME["fg"], font=(FONT_FAMILY, 22, "bold"))
    style.configure("CardTrend.TLabel", background=THEME["panel"], foreground="#80b6ff", font=(FONT_FAMILY, 9))
    style.configure("CardIcon.TLabel", background=THEME["panel"], foreground="#a9cbff", font=(FONT_FAMILY, 10, "bold"))
    style.configure("Badge.TLabel", background="#1a2a4d", foreground="#dbe8ff", font=(FONT_FAMILY, 9, "bold"))
    style.configure("StatusOk.TLabel", background=THEME["panel"], foreground=THEME["success"], font=(FONT_FAMILY, 9, "bold"))
    style.configure("StatusWarn.TLabel", background=THEME["panel"], foreground=THEME["warn"], font=(FONT_FAMILY, 9, "bold"))
    style.configure("TEntry", fieldbackground=THEME["panel_2"], foreground=THEME["fg"], bordercolor=THEME["line"])
    style.configure("TCombobox", fieldbackground=THEME["panel_2"], foreground=THEME["fg"], bordercolor=THEME["line"])
    style.map("TButton", background=[("active", "#3f7bff")], foreground=[("active", "#ffffff")])
    style.configure("TButton", padding=(11, 7), borderwidth=0)
    style.configure("Primary.TButton", padding=(14, 8), font=(FONT_FAMILY, 10, "bold"))
    style.map("Primary.TButton", background=[("!disabled", THEME["accent"]), ("active", "#4d7fff")], foreground=[("!disabled", "#ffffff")])
    style.configure("Soft.TButton", padding=(12, 7), font=(FONT_FAMILY, 9, "bold"))
    style.map("Soft.TButton", background=[("!disabled", "#1e315c"), ("active", "#26427b")], foreground=[("!disabled", "#d8e6ff")])
    style.configure("Danger.TButton", padding=(12, 7), font=(FONT_FAMILY, 9, "bold"))
    style.map("Danger.TButton", background=[("!disabled", "#6a2034"), ("active", "#823047")], foreground=[("!disabled", "#ffe0e7")])
    style.configure("Nav.TButton", padding=(12, 10), font=(FONT_FAMILY, 10, "bold"))
    style.map("Nav.TButton", background=[("!disabled", "#13284d"), ("active", "#21437f")], foreground=[("!disabled", "#dce8ff")])
    style.configure("LoginPanel.TFrame", background=THEME["panel"])
    style.configure("LoginHero.TFrame", background="#122240")
    style.configure("LoginTitle.TLabel", background="#122240", foreground="#f3f7ff", font=(FONT_FAMILY, 23, "bold"))
    style.configure("LoginSub.TLabel", background="#122240", foreground="#b6c8ef", font=(FONT_FAMILY, 10))
    style.configure("LoginBadge.TLabel", background="#1e3a74", foreground="#dbe8ff", font=(FONT_FAMILY, 9, "bold"))
    style.configure("LoginFieldLabel.TLabel", background=THEME["panel"], foreground="#dce7ff", font=(FONT_FAMILY, 10, "bold"))
    style.configure("LoginMsg.TLabel", background=THEME["panel"], foreground=THEME["muted"])

    style.configure(
        "Treeview",
        background=THEME["panel_2"],
        foreground=THEME["fg"],
        fieldbackground=THEME["panel_2"],
        rowheight=28,
        bordercolor=THEME["line"],
        borderwidth=1,
    )
    style.configure(
        "Treeview.Heading",
        background="#16253f",
        foreground=THEME["fg"],
        relief="flat",
        font=(FONT_FAMILY, 10, "bold"),
        padding=(6, 6),
    )
    style.map("Treeview", background=[("selected", "#1f3f78")], foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", "#1c3155")])
    style.configure(
        "TNotebook",
        background=THEME["bg_2"],
        borderwidth=0,
        tabmargins=[2, 4, 2, 0],
    )
    style.configure("TNotebook.Tab", background="#101f3b", foreground=THEME["muted"], padding=(18, 10), borderwidth=0)
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#294b87"), ("active", "#173056")],
        foreground=[("selected", "#ffffff"), ("active", "#dbe8ff")],
    )
    return style


class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Admin Login • {BUILD_TAG}")
        self.geometry("760x430")
        self.resizable(False, False)
        apply_theme(self)
        self._center_window()
        self.bind("<Return>", lambda _e: self.do_login())

        wrap = ttk.Frame(self, style="LoginPanel.TFrame", padding=0)
        wrap.place(relx=0.5, rely=0.5, anchor="center", width=700, height=360)
        wrap.columnconfigure(0, weight=1)
        wrap.columnconfigure(1, weight=1)
        wrap.rowconfigure(0, weight=1)

        hero = ttk.Frame(wrap, style="LoginHero.TFrame", padding=(26, 24))
        hero.grid(row=0, column=0, sticky="nsew")
        ttk.Label(hero, text="ADMIN\nPORTAL", style="LoginTitle.TLabel", justify="left").pack(anchor="w")
        ttk.Label(
            hero,
            text="Quan tri key 7/30 ngay\nBan IP/HWID\nTheo doi nguoi dung va su kien",
            style="LoginSub.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(8, 14))
        ttk.Label(hero, text=f"SECURE ACCESS • {BUILD_TAG}", style="LoginBadge.TLabel").pack(anchor="w")

        form = ttk.Frame(wrap, style="LoginPanel.TFrame", padding=(26, 24))
        form.grid(row=0, column=1, sticky="nsew")
        form.columnconfigure(0, weight=1)

        ttk.Label(form, text="Dang nhap quan tri", style="H2.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Nhap thong tin de tiep tuc", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 16))

        ttk.Label(form, text="Username", style="LoginFieldLabel.TLabel").grid(row=2, column=0, sticky="w")
        self.user = ttk.Entry(form)
        self.user.grid(row=3, column=0, sticky="ew", pady=(6, 10), ipady=4)
        self.user.insert(0, "admin")

        ttk.Label(form, text="Password", style="LoginFieldLabel.TLabel").grid(row=4, column=0, sticky="w")
        self.pwd = ttk.Entry(form, show="*")
        self.pwd.grid(row=5, column=0, sticky="ew", pady=(6, 8), ipady=4)

        self.msg = ttk.Label(form, text="", style="LoginMsg.TLabel")
        self.msg.grid(row=6, column=0, sticky="w", pady=(2, 12))

        ttk.Button(form, text="Dang nhap", style="Primary.TButton", command=self.do_login).grid(row=7, column=0, sticky="ew")
        self.user.focus_set()

    def _center_window(self) -> None:
        self.update_idletasks()
        width, height = 760, 430
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = max((screen_w - width) // 2, 0)
        y = max((screen_h - height) // 2, 0)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def do_login(self) -> None:
        u = self.user.get().strip()
        p = self.pwd.get().strip()
        if u == ADMIN_USER and p == ADMIN_PASS:
            log_event("admin_login", "ok")
            self.destroy()
            app = AdminApp()
            app.mainloop()
            return
        log_event("admin_login", "failed", "bad_credentials")
        self.msg.config(text="Sai tai khoan/mat khau", foreground=THEME["danger"])


class AdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Admin Desktop Portal • {BUILD_TAG}")
        self.geometry("1280x820")
        self.minsize(1180, 740)
        apply_theme(self)
        self.status_var = tk.StringVar(value="San sang")
        self.last_refresh_var = tk.StringVar(value="Last refresh: -")
        self._spin_tokens = ["|", "/", "-", "\\"]
        self._spin_idx = 0
        self._refresh_anim = False

        root = ttk.Frame(self, padding=12, style="App.TFrame")
        root.pack(fill="both", expand=True)
        self._build_background_gradient(root)
        self.attributes("-alpha", 0.98)

        header = ttk.Frame(root, style="Glass.TFrame", padding=(14, 12))
        header.pack(fill="x", pady=(0, 10))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=0)

        left = ttk.Frame(header, style="Glass.TFrame")
        left.grid(row=0, column=0, sticky="w")
        ttk.Label(left, text=f"Admin Portal [{BUILD_TAG}]", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            left,
            text=f"Premium license control center • DB: {DB_PATH}",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        right = ttk.Frame(header, style="Glass.TFrame")
        right.grid(row=0, column=1, sticky="e")
        ttk.Label(right, text="[AD]", style="Badge.TLabel").grid(row=0, column=0, rowspan=2, padx=(0, 10))
        ttk.Label(right, text="admin", style="H2.TLabel").grid(row=0, column=1, sticky="w")
        self.lbl_live_status = ttk.Label(right, text="ONLINE", style="StatusOk.TLabel")
        self.lbl_live_status.grid(row=0, column=2, sticky="w", padx=(8, 0))
        self.lbl_refresh_badge = ttk.Label(right, textvariable=self.last_refresh_var, style="Badge.TLabel")
        self.lbl_refresh_badge.grid(row=1, column=1, columnspan=2, sticky="w", pady=(4, 0))

        body = ttk.Frame(root, style="TFrame")
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self.sidebar_expanded = True
        self.sidebar = ttk.Frame(body, style="Glass.TFrame", padding=8)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(0, 10))
        self.main_wrap = ttk.Frame(body, style="TFrame")
        self.main_wrap.grid(row=0, column=1, sticky="nsew")
        self.main_wrap.rowconfigure(0, weight=1)
        self.main_wrap.columnconfigure(0, weight=1)

        ttk.Button(self.sidebar, text="☰ Menu", style="Soft.TButton", command=self._toggle_sidebar).pack(fill="x", pady=(0, 8))

        self.note = ttk.Notebook(self.main_wrap, style="TNotebook")
        self.note.grid(row=0, column=0, sticky="nsew")

        self.tab_dash = ttk.Frame(self.note, padding=10)
        self.tab_key = ttk.Frame(self.note, padding=10)
        self.tab_devices = ttk.Frame(self.note, padding=10)
        self.tab_ban = ttk.Frame(self.note, padding=10)
        self.tab_events = ttk.Frame(self.note, padding=10)
        self.tab_settings = ttk.Frame(self.note, padding=10)
        self.note.add(self.tab_dash, text="Dashboard")
        self.note.add(self.tab_key, text="Key Management")
        self.note.add(self.tab_devices, text="Users / Devices")
        self.note.add(self.tab_ban, text="HWID & IP Ban")
        self.note.add(self.tab_events, text="Logs")
        self.note.add(self.tab_settings, text="Settings")

        self.nav_items = [
            ("🏠 Dashboard", self.tab_dash),
            ("🔑 Key Management", self.tab_key),
            ("🖥 Users / Devices", self.tab_devices),
            ("🧬 HWID Management", self.tab_ban),
            ("🌐 IP Ban", self.tab_ban),
            ("📋 Logs", self.tab_events),
            ("⚙ Settings", self.tab_settings),
        ]
        self._build_sidebar_buttons()

        self._build_dashboard()
        self._build_license_tab()
        self._build_devices_tab()
        self._build_ban_tab()
        self._build_events_tab()
        self._build_settings_tab()

        status_bar = ttk.Frame(root, style="GlassSoft.TFrame", padding=(8, 6))
        status_bar.pack(fill="x", pady=(8, 0))
        ttk.Label(status_bar, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        ttk.Label(status_bar, text="SYSTEM: STABLE", style="StatusWarn.TLabel").pack(side="right")
        self.refresh_all()
        self._start_metric_pulse()
        self._fade_in()

    def _build_background_gradient(self, root: ttk.Frame) -> None:
        bar = tk.Canvas(root, height=62, highlightthickness=0, bd=0, background=THEME["bg"])
        bar.pack(fill="x", pady=(0, 8))
        width = 1200
        steps = 220
        c1 = (8, 12, 28)
        c2 = (32, 53, 112)
        for i in range(steps):
            r = c1[0] + (c2[0] - c1[0]) * i // steps
            g = c1[1] + (c2[1] - c1[1]) * i // steps
            b = c1[2] + (c2[2] - c1[2]) * i // steps
            color = f"#{r:02x}{g:02x}{b:02x}"
            x0 = int(i * width / steps)
            x1 = int((i + 1) * width / steps) + 1
            bar.create_rectangle(x0, 0, x1, 62, outline="", fill=color)
        bar.create_oval(width - 250, -140, width + 140, 170, outline="", fill="#162d66")
        bar.create_oval(width - 150, -100, width + 180, 200, outline="", fill="#263d82")
        bar.create_text(24, 32, text="CONTROL SURFACE", fill="#b5c9f4", anchor="w", font=(FONT_FAMILY, 10, "bold"))

    def _build_sidebar_buttons(self) -> None:
        for text, target in self.nav_items:
            ttk.Button(
                self.sidebar,
                text=text,
                style="Nav.TButton",
                command=lambda t=target: self._goto_tab(t),
            ).pack(fill="x", pady=3)

    def _goto_tab(self, tab: ttk.Frame) -> None:
        self.note.select(tab)

    def _toggle_sidebar(self) -> None:
        if self.sidebar_expanded:
            self.sidebar.grid_remove()
            self.sidebar_expanded = False
        else:
            self.sidebar.grid()
            self.sidebar_expanded = True

    def _build_dashboard(self) -> None:
        bar = ttk.Frame(self.tab_dash, style="Glass.TFrame", padding=10)
        bar.pack(fill="x")
        self.btn_refresh_dash = ttk.Button(bar, text="Refresh", style="Primary.TButton", command=self._refresh_with_animation)
        self.btn_refresh_dash.pack(side="left")
        ttk.Label(bar, text="Realtime metrics and activity intelligence", style="Muted.TLabel").pack(side="left", padx=(10, 0))
        ttk.Label(bar, textvariable=self.last_refresh_var, style="Badge.TLabel").pack(side="right")

        grid = ttk.Frame(self.tab_dash)
        grid.pack(fill="x", pady=(12, 0))
        grid.columnconfigure((0, 1, 2), weight=1)
        self.metric_vars = {
            "total": tk.StringVar(value="0"),
            "active": tk.StringVar(value="0"),
            "revoked": tk.StringVar(value="0"),
            "ip": tk.StringVar(value="0"),
            "hwid": tk.StringVar(value="0"),
            "events": tk.StringVar(value="0"),
        }
        self.metric_trend_vars = {
            "total": tk.StringVar(value="inventory"),
            "active": tk.StringVar(value="+0%"),
            "revoked": tk.StringVar(value="0 risk"),
            "ip": tk.StringVar(value="blocked nodes"),
            "hwid": tk.StringVar(value="blocked devices"),
            "events": tk.StringVar(value="event stream"),
        }
        self.metric_value_labels: list[ttk.Label] = []

        cards = [
            ("KEY", "Tong keys", self.metric_vars["total"], self.metric_trend_vars["total"]),
            ("LIVE", "Key active", self.metric_vars["active"], self.metric_trend_vars["active"]),
            ("RISK", "Key revoked", self.metric_vars["revoked"], self.metric_trend_vars["revoked"]),
            ("NET", "IP da ban", self.metric_vars["ip"], self.metric_trend_vars["ip"]),
            ("HWID", "HWID da ban", self.metric_vars["hwid"], self.metric_trend_vars["hwid"]),
            ("LOG", "Tong logs", self.metric_vars["events"], self.metric_trend_vars["events"]),
        ]
        for i, (icon, title, var, trend_var) in enumerate(cards):
            card = ttk.Frame(grid, style="Glass.TFrame", padding=12)
            card.grid(row=i // 3, column=i % 3, sticky="nsew", padx=7, pady=7)
            self._bind_card_hover(card)
            top = ttk.Frame(card, style="Glass.TFrame")
            top.pack(fill="x")
            ttk.Label(top, text=icon, style="CardIcon.TLabel").pack(side="left")
            ttk.Label(top, text=title, style="CardTitle.TLabel").pack(side="left", padx=(8, 0))
            val_lbl = ttk.Label(card, textvariable=var, style="CardValue.TLabel")
            val_lbl.pack(anchor="w", pady=(6, 2))
            self.metric_value_labels.append(val_lbl)
            ttk.Label(card, textvariable=trend_var, style="CardTrend.TLabel").pack(anchor="w")

        lower = ttk.Frame(self.tab_dash)
        lower.pack(fill="both", expand=True, pady=(10, 0))
        lower.columnconfigure(0, weight=2)
        lower.columnconfigure(1, weight=1)

        usage_box = ttk.Frame(lower, style="GlassSoft.TFrame", padding=10)
        usage_box.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ttk.Label(usage_box, text="Key Usage (7d)", style="H2.TLabel").pack(anchor="w")
        ttk.Label(usage_box, text="Created keys by day", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.canvas_usage = tk.Canvas(
            usage_box,
            height=220,
            highlightthickness=0,
            bd=0,
            background=THEME["panel_2"],
        )
        self.canvas_usage.pack(fill="both", expand=True)

        feed_box = ttk.Frame(lower, style="GlassSoft.TFrame", padding=10)
        feed_box.grid(row=0, column=1, sticky="nsew")
        ttk.Label(feed_box, text="Activity Feed", style="H2.TLabel").pack(anchor="w")
        ttk.Label(feed_box, text="Recent admin actions", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.tree_feed = ttk.Treeview(feed_box, columns=("time", "action", "status"), show="headings", height=10)
        self.tree_feed.heading("time", text="time")
        self.tree_feed.heading("action", text="action")
        self.tree_feed.heading("status", text="status")
        self.tree_feed.column("time", width=130, anchor="w")
        self.tree_feed.column("action", width=160, anchor="w")
        self.tree_feed.column("status", width=90, anchor="w")
        self.tree_feed.pack(fill="both", expand=True)
        self.tree_feed.tag_configure("odd", background="#101b31")
        self.tree_feed.tag_configure("even", background="#0c162b")

    def _bind_card_hover(self, card: ttk.Frame) -> None:
        def on_enter(_e: tk.Event) -> None:
            card.configure(style="GlassHover.TFrame")

        def on_leave(_e: tk.Event) -> None:
            card.configure(style="Glass.TFrame")

        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)

    def _refresh_with_animation(self) -> None:
        if self._refresh_anim:
            return
        self._refresh_anim = True
        self._spin_idx = 0
        self._spin_refresh_label()
        self.after(80, self._do_refresh_work)

    def _spin_refresh_label(self) -> None:
        if not self._refresh_anim:
            self.btn_refresh_dash.config(text="Refresh")
            return
        token = self._spin_tokens[self._spin_idx % len(self._spin_tokens)]
        self._spin_idx += 1
        self.btn_refresh_dash.config(text=f"Refresh {token}")
        self.after(100, self._spin_refresh_label)

    def _do_refresh_work(self) -> None:
        try:
            self.refresh_all()
        finally:
            self._refresh_anim = False
            self.btn_refresh_dash.config(text="Refresh")

    def _start_metric_pulse(self) -> None:
        self._pulse_on = False
        self._pulse_metrics()

    def _pulse_metrics(self) -> None:
        self._pulse_on = not getattr(self, "_pulse_on", False)
        color = "#f2f7ff" if self._pulse_on else "#b5cdff"
        for lbl in self.metric_value_labels:
            lbl.configure(foreground=color)
        self.after(900, self._pulse_metrics)

    def _fade_in(self) -> None:
        alpha = float(self.attributes("-alpha"))
        if alpha >= 1.0:
            self.attributes("-alpha", 1.0)
            return
        self.attributes("-alpha", min(alpha + 0.02, 1.0))
        self.after(18, self._fade_in)

    def _refresh_activity_feed(self) -> None:
        for item in self.tree_feed.get_children():
            self.tree_feed.delete(item)
        conn = db_connect()
        try:
            rows = conn.execute("SELECT ts, action, status FROM events ORDER BY id DESC LIMIT 12").fetchall()
        finally:
            conn.close()
        for row in rows:
            idx = len(self.tree_feed.get_children())
            stripe = "even" if idx % 2 == 0 else "odd"
            self.tree_feed.insert("", "end", values=(to_text(int(row["ts"]))[11:], row["action"], row["status"]), tags=(stripe,))

    def _draw_usage_chart(self, points: list[tuple[str, int]]) -> None:
        canvas = self.canvas_usage
        canvas.delete("all")
        canvas.update_idletasks()
        w = max(canvas.winfo_width(), 420)
        h = max(canvas.winfo_height(), 220)
        canvas.create_rectangle(0, 0, w, h, outline="", fill=THEME["panel_2"])
        if not points:
            canvas.create_text(w // 2, h // 2, text="No data", fill=THEME["muted"], font=(FONT_FAMILY, 11))
            return
        max_val = max(v for _, v in points) or 1
        pad_x = 18
        bar_w = max((w - (pad_x * 2)) // (len(points) * 2), 16)
        gap = bar_w
        x = pad_x
        base_y = h - 30
        for day, value in points:
            bar_h = int((h - 55) * value / max_val)
            canvas.create_rectangle(x, base_y - bar_h, x + bar_w, base_y, outline="", fill=THEME["accent"])
            canvas.create_rectangle(x, base_y - bar_h, x + bar_w, base_y - bar_h + 2, outline="", fill=THEME["accent_2"])
            canvas.create_text(x + (bar_w // 2), base_y + 12, text=day, fill=THEME["muted"], font=(FONT_FAMILY, 8))
            canvas.create_text(x + (bar_w // 2), base_y - bar_h - 10, text=str(value), fill="#cfe0ff", font=(FONT_FAMILY, 8))
            x += bar_w + gap

    def _build_license_tab(self) -> None:
        top = ttk.Frame(self.tab_key, style="Glass.TFrame", padding=12)
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="Search").pack(side="left")
        self.key_search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.key_search_var, width=24)
        search_entry.pack(side="left", padx=(6, 10))
        self.key_search_var.trace_add("write", lambda *_: self.refresh_licenses())

        ttk.Label(top, text="Status").pack(side="left")
        self.key_status_var = tk.StringVar(value="all")
        ttk.Combobox(top, textvariable=self.key_status_var, values=["all", "active", "expired", "revoked"], width=10, state="readonly").pack(
            side="left", padx=(6, 10)
        )
        self.key_status_var.trace_add("write", lambda *_: self.refresh_licenses())

        ttk.Label(top, text="Duration").pack(side="left")
        self.duration_var = tk.StringVar(value="7")
        ttk.Combobox(top, textvariable=self.duration_var, values=["7", "30"], width=8, state="readonly").pack(side="left", padx=(6, 10))

        ttk.Label(top, text="So luong").pack(side="left")
        self.qty_var = tk.StringVar(value="1")
        ttk.Entry(top, textvariable=self.qty_var, width=8).pack(side="left", padx=(6, 10))

        ttk.Label(top, text="Ghi chu").pack(side="left")
        self.note_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.note_var, width=30).pack(side="left", padx=(6, 10))

        ttk.Button(top, text="+ Create Key", style="Primary.TButton", command=self.open_create_key_modal).pack(side="left")
        ttk.Button(top, text="Bulk Generate", style="Soft.TButton", command=self.open_bulk_generate_modal).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Reload", style="Soft.TButton", command=self.refresh_licenses).pack(side="left", padx=(8, 0))

        cols = ("license_key", "duration", "status", "created", "expires", "machine_id", "note")
        table_wrap = ttk.Frame(self.tab_key, style="GlassSoft.TFrame", padding=8)
        table_wrap.pack(fill="both", expand=True)
        self.tree_licenses = ttk.Treeview(table_wrap, columns=cols, show="headings", height=22)
        for c in cols:
            self.tree_licenses.heading(c, text=c)
            self.tree_licenses.column(c, width=140, anchor="w")
        self.tree_licenses.column("license_key", width=220)
        self.tree_licenses.column("machine_id", width=220)
        self.tree_licenses.pack(side="left", fill="both", expand=True)
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree_licenses.yview)
        yscroll.pack(side="right", fill="y")
        self.tree_licenses.configure(yscrollcommand=yscroll.set)
        self.tree_licenses.tag_configure("active", foreground=THEME["success"])
        self.tree_licenses.tag_configure("revoked", foreground=THEME["danger"])
        self.tree_licenses.tag_configure("expired", foreground=THEME["warn"])
        self.tree_licenses.tag_configure("odd", background="#101b31")
        self.tree_licenses.tag_configure("even", background="#0c162b")
        self.tree_licenses.bind("<<TreeviewSelect>>", self._on_license_selected)

        action = ttk.Frame(self.tab_key, style="Glass.TFrame", padding=8)
        action.pack(fill="x", pady=(8, 0))
        ttk.Button(action, text="✏️ Edit", style="Soft.TButton", command=self.open_edit_selected_key_modal).pack(side="left")
        ttk.Button(action, text="🗑️ Delete", style="Danger.TButton", command=self.delete_selected_license).pack(side="left", padx=(8, 0))
        ttk.Button(action, text="🚫 Ban", style="Danger.TButton", command=self.revoke_selected).pack(side="left", padx=(8, 0))
        ttk.Button(action, text="✅ Unban", style="Soft.TButton", command=self.unrevoke_selected).pack(side="left", padx=(8, 0))
        ttk.Button(action, text="📋 Copy Key", style="Soft.TButton", command=self.copy_selected_key).pack(side="left", padx=(8, 0))

        edit = ttk.Frame(self.tab_key, style="Glass.TFrame", padding=10)
        edit.pack(fill="x", pady=(8, 0))
        ttk.Label(edit, text="Sua license duoc chon", style="H2.TLabel").pack(anchor="w", pady=(0, 6))

        row1 = ttk.Frame(edit, style="Glass.TFrame")
        row1.pack(fill="x", pady=(0, 6))
        self.edit_key_var = tk.StringVar()
        self.edit_duration_var = tk.StringVar(value="7")
        self.edit_status_var = tk.StringVar(value="active")
        self.edit_machine_var = tk.StringVar()
        self.edit_note_var = tk.StringVar()
        ttk.Label(row1, text="Key").pack(side="left")
        ttk.Entry(row1, textvariable=self.edit_key_var, width=28, state="readonly").pack(side="left", padx=(6, 12))
        ttk.Label(row1, text="Ngay").pack(side="left")
        ttk.Combobox(row1, textvariable=self.edit_duration_var, values=["7", "30"], width=8, state="readonly").pack(side="left", padx=(6, 12))
        ttk.Label(row1, text="Status").pack(side="left")
        ttk.Combobox(row1, textvariable=self.edit_status_var, values=["active", "revoked"], width=10, state="readonly").pack(side="left", padx=(6, 0))

        row2 = ttk.Frame(edit, style="Glass.TFrame")
        row2.pack(fill="x")
        ttk.Label(row2, text="Machine ID").pack(side="left")
        ttk.Entry(row2, textvariable=self.edit_machine_var, width=32).pack(side="left", padx=(6, 12))
        ttk.Label(row2, text="Note").pack(side="left")
        ttk.Entry(row2, textvariable=self.edit_note_var, width=38).pack(side="left", padx=(6, 12))
        ttk.Button(row2, text="Luu sua", style="Primary.TButton", command=self.update_selected_license).pack(side="left")
        ttk.Button(row2, text="Xoa machine bind", style="Soft.TButton", command=self.clear_machine_selected_license).pack(side="left", padx=(8, 0))

    def _build_ban_tab(self) -> None:
        left = ttk.Frame(self.tab_ban, style="Glass.TFrame", padding=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = ttk.Frame(self.tab_ban, style="Glass.TFrame", padding=10)
        right.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Ban IP").pack(anchor="w")
        row1 = ttk.Frame(left, style="Glass.TFrame")
        row1.pack(fill="x", pady=(4, 8))
        self.ip_var = tk.StringVar()
        self.ip_reason = tk.StringVar()
        ttk.Entry(row1, textvariable=self.ip_var, width=22).pack(side="left")
        ttk.Entry(row1, textvariable=self.ip_reason, width=24).pack(side="left", padx=(6, 6))
        ttk.Button(row1, text="Ban", style="Danger.TButton", command=self.ban_ip).pack(side="left")
        ttk.Button(row1, text="Go ban", style="Soft.TButton", command=self.unban_ip).pack(side="left", padx=(6, 0))

        ttk.Label(left, text="Danh sach IP da ban").pack(anchor="w")
        ips_wrap = ttk.Frame(left, style="GlassSoft.TFrame", padding=6)
        ips_wrap.pack(fill="both", expand=True)
        self.tree_ips = ttk.Treeview(ips_wrap, columns=("ip", "reason", "created"), show="headings", height=20)
        for c in ("ip", "reason", "created"):
            self.tree_ips.heading(c, text=c)
            self.tree_ips.column(c, width=180, anchor="w")
        self.tree_ips.pack(side="left", fill="both", expand=True)
        ips_scroll = ttk.Scrollbar(ips_wrap, orient="vertical", command=self.tree_ips.yview)
        ips_scroll.pack(side="right", fill="y")
        self.tree_ips.configure(yscrollcommand=ips_scroll.set)
        self.tree_ips.tag_configure("odd", background="#101b31")
        self.tree_ips.tag_configure("even", background="#0c162b")
        self.tree_ips.bind("<<TreeviewSelect>>", self._on_ip_selected)

        ttk.Label(right, text="Ban HWID").pack(anchor="w")
        row2 = ttk.Frame(right, style="Glass.TFrame")
        row2.pack(fill="x", pady=(4, 8))
        self.hwid_var = tk.StringVar()
        self.hwid_reason = tk.StringVar()
        ttk.Entry(row2, textvariable=self.hwid_var, width=34).pack(side="left")
        ttk.Entry(row2, textvariable=self.hwid_reason, width=20).pack(side="left", padx=(6, 6))
        ttk.Button(row2, text="Ban", style="Danger.TButton", command=self.ban_hwid).pack(side="left")
        ttk.Button(row2, text="Go ban", style="Soft.TButton", command=self.unban_hwid).pack(side="left", padx=(6, 0))

        ttk.Label(right, text="Danh sach HWID da ban").pack(anchor="w")
        hwids_wrap = ttk.Frame(right, style="GlassSoft.TFrame", padding=6)
        hwids_wrap.pack(fill="both", expand=True)
        self.tree_hwids = ttk.Treeview(hwids_wrap, columns=("hwid", "reason", "created"), show="headings", height=20)
        for c in ("hwid", "reason", "created"):
            self.tree_hwids.heading(c, text=c)
            self.tree_hwids.column(c, width=210, anchor="w")
        self.tree_hwids.pack(side="left", fill="both", expand=True)
        hwids_scroll = ttk.Scrollbar(hwids_wrap, orient="vertical", command=self.tree_hwids.yview)
        hwids_scroll.pack(side="right", fill="y")
        self.tree_hwids.configure(yscrollcommand=hwids_scroll.set)
        self.tree_hwids.tag_configure("odd", background="#101b31")
        self.tree_hwids.tag_configure("even", background="#0c162b")
        self.tree_hwids.bind("<<TreeviewSelect>>", self._on_hwid_selected)

        bottom = ttk.Frame(self.tab_ban, style="Glass.TFrame", padding=8)
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Button(bottom, text="Reload ban lists", style="Soft.TButton", command=self.refresh_bans).pack(side="left")
        ttk.Button(bottom, text="Sua IP da chon", style="Primary.TButton", command=self.update_selected_ip).pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="Sua HWID da chon", style="Primary.TButton", command=self.update_selected_hwid).pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="Xoa IP da chon", style="Danger.TButton", command=self.delete_selected_ip).pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="Xoa HWID da chon", style="Danger.TButton", command=self.delete_selected_hwid).pack(side="left", padx=(8, 0))

    def _build_devices_tab(self) -> None:
        top = ttk.Frame(self.tab_devices, style="Glass.TFrame", padding=10)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Users / Devices", style="H2.TLabel").pack(side="left")
        ttk.Button(top, text="Reload devices", style="Soft.TButton", command=self.refresh_devices).pack(side="right")

        cols = ("machine_id", "linked_key", "ip", "last_active")
        wrap = ttk.Frame(self.tab_devices, style="GlassSoft.TFrame", padding=8)
        wrap.pack(fill="both", expand=True)
        self.tree_devices = ttk.Treeview(wrap, columns=cols, show="headings", height=24)
        for c in cols:
            self.tree_devices.heading(c, text=c)
            self.tree_devices.column(c, width=230, anchor="w")
        self.tree_devices.column("linked_key", width=260)
        self.tree_devices.pack(side="left", fill="both", expand=True)
        scr = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_devices.yview)
        scr.pack(side="right", fill="y")
        self.tree_devices.configure(yscrollcommand=scr.set)
        self.tree_devices.tag_configure("odd", background="#101b31")
        self.tree_devices.tag_configure("even", background="#0c162b")

        actions = ttk.Frame(self.tab_devices, style="Glass.TFrame", padding=8)
        actions.pack(fill="x", pady=(8, 0))
        ttk.Button(actions, text="Unbind HWID", style="Soft.TButton", command=self.unbind_selected_device).pack(side="left")
        ttk.Button(actions, text="Ban device", style="Danger.TButton", command=self.ban_selected_device).pack(side="left", padx=(8, 0))

    def _build_settings_tab(self) -> None:
        card = ttk.Frame(self.tab_settings, style="Glass.TFrame", padding=14)
        card.pack(fill="x")
        ttk.Label(card, text="Settings", style="H2.TLabel").pack(anchor="w")
        ttk.Label(card, text="Role-based access and realtime update placeholders", style="Muted.TLabel").pack(anchor="w", pady=(4, 10))
        self.dark_mode_var = tk.BooleanVar(value=True)
        self.realtime_var = tk.BooleanVar(value=False)
        self.role_var = tk.StringVar(value="Admin")
        ttk.Checkbutton(card, text="Dark mode", variable=self.dark_mode_var).pack(anchor="w")
        ttk.Checkbutton(card, text="Realtime updates", variable=self.realtime_var).pack(anchor="w", pady=(4, 0))
        role = ttk.Frame(card, style="Glass.TFrame")
        role.pack(fill="x", pady=(8, 0))
        ttk.Label(role, text="Role").pack(side="left")
        ttk.Combobox(role, textvariable=self.role_var, values=["Admin", "Mod"], state="readonly", width=12).pack(side="left", padx=(8, 0))

    def _build_events_tab(self) -> None:
        top = ttk.Frame(self.tab_events, style="Glass.TFrame", padding=10)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Reload logs", style="Soft.TButton", command=self.refresh_events).pack(side="left")

        cols = ("time", "action", "status", "ip", "license_key", "machine_id", "detail")
        events_wrap = ttk.Frame(self.tab_events, style="GlassSoft.TFrame", padding=8)
        events_wrap.pack(fill="both", expand=True)
        self.tree_events = ttk.Treeview(events_wrap, columns=cols, show="headings", height=26)
        for c in cols:
            self.tree_events.heading(c, text=c)
            self.tree_events.column(c, width=140, anchor="w")
        self.tree_events.column("detail", width=320)
        self.tree_events.pack(side="left", fill="both", expand=True)
        events_scroll = ttk.Scrollbar(events_wrap, orient="vertical", command=self.tree_events.yview)
        events_scroll.pack(side="right", fill="y")
        self.tree_events.configure(yscrollcommand=events_scroll.set)
        self.tree_events.tag_configure("odd", background="#101b31")
        self.tree_events.tag_configure("even", background="#0c162b")

    def refresh_all(self) -> None:
        self.refresh_dashboard()
        self.refresh_licenses()
        self.refresh_devices()
        self.refresh_bans()
        self.refresh_events()
        self.set_status("Da refresh toan bo du lieu")

    def set_status(self, text: str) -> None:
        self.status_var.set(str(text or "").strip() or "San sang")

    def show_toast(self, text: str, is_error: bool = False) -> None:
        popup = tk.Toplevel(self)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(bg="#2b1b2b" if is_error else "#13284d")
        x = self.winfo_rootx() + self.winfo_width() - 320
        y = self.winfo_rooty() + 72
        popup.geometry(f"290x46+{x}+{y}")
        lbl = tk.Label(
            popup,
            text=text,
            bg="#2b1b2b" if is_error else "#13284d",
            fg="#ffdce5" if is_error else "#dbe8ff",
            font=(FONT_FAMILY, 10, "bold"),
            anchor="w",
            padx=12,
        )
        lbl.pack(fill="both", expand=True)
        popup.after(1700, popup.destroy)

    def refresh_dashboard(self) -> None:
        conn = db_connect()
        try:
            c = conn.cursor()
            total = c.execute("SELECT COUNT(*) c FROM licenses").fetchone()["c"]
            active = c.execute("SELECT COUNT(*) c FROM licenses WHERE status='active' AND expires_at>?", (now_ts(),)).fetchone()["c"]
            revoked = c.execute("SELECT COUNT(*) c FROM licenses WHERE status='revoked'").fetchone()["c"]
            ban_ip = c.execute("SELECT COUNT(*) c FROM banned_ips").fetchone()["c"]
            ban_hwid = c.execute("SELECT COUNT(*) c FROM banned_hwids").fetchone()["c"]
            events = c.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            usage_rows = c.execute(
                """
                SELECT strftime('%m-%d', datetime(created_at, 'unixepoch', 'localtime')) AS d, COUNT(*) AS c
                FROM licenses
                WHERE created_at >= ?
                GROUP BY d
                ORDER BY d
                """,
                (now_ts() - 7 * 86400,),
            ).fetchall()
        finally:
            conn.close()
        self.metric_vars["total"].set(str(total))
        self.metric_vars["active"].set(str(active))
        self.metric_vars["revoked"].set(str(revoked))
        self.metric_vars["ip"].set(str(ban_ip))
        self.metric_vars["hwid"].set(str(ban_hwid))
        self.metric_vars["events"].set(str(events))
        active_pct = (active / total * 100.0) if total else 0.0
        revoked_pct = (revoked / total * 100.0) if total else 0.0
        self.metric_trend_vars["active"].set(f"+{active_pct:.1f}% healthy")
        self.metric_trend_vars["revoked"].set(f"{revoked_pct:.1f}% flagged")
        self.metric_trend_vars["events"].set(f"stream {events}")
        self.last_refresh_var.set(f"Last refresh: {to_text(now_ts())}")
        usage_points = [(str(r["d"]), int(r["c"])) for r in usage_rows]
        self._draw_usage_chart(usage_points[-7:])
        self._refresh_activity_feed()

    def _key_modal(self, title: str, mode: str, initial: dict[str, str] | None = None) -> None:
        data = initial or {}
        modal = tk.Toplevel(self)
        modal.title(title)
        modal.transient(self)
        modal.grab_set()
        modal.geometry("560x300")
        modal.configure(bg=THEME["panel"])

        frm = ttk.Frame(modal, style="Glass.TFrame", padding=12)
        frm.pack(fill="both", expand=True, padx=10, pady=10)
        frm.columnconfigure(1, weight=1)

        key_var = tk.StringVar(value=data.get("key", ""))
        duration_var = tk.StringVar(value=data.get("duration", "7"))
        status_var = tk.StringVar(value=data.get("status", "active"))
        machine_var = tk.StringVar(value=data.get("machine", ""))
        note_var = tk.StringVar(value=data.get("note", ""))

        ttk.Label(frm, text="Key").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(frm, textvariable=key_var).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Duration").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Combobox(frm, textvariable=duration_var, values=["7", "30"], state="readonly").grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Status").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Combobox(frm, textvariable=status_var, values=["active", "revoked"], state="readonly").grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Bind HWID").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(frm, textvariable=machine_var).grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Note").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(frm, textvariable=note_var).grid(row=4, column=1, sticky="ew", pady=5)

        def do_save() -> None:
            key = key_var.get().strip() or make_key("VEO3")
            try:
                duration = int(duration_var.get().strip())
            except Exception:
                return messagebox.showwarning("Canh bao", "Duration khong hop le")
            if duration not in {7, 30}:
                return messagebox.showwarning("Canh bao", "Chi cho phep 7 hoac 30 ngay")
            status = status_var.get().strip() or "active"
            machine = machine_var.get().strip()
            note = note_var.get().strip()
            conn = db_connect()
            try:
                if mode == "create":
                    created = now_ts()
                    expires = created + duration * 86400
                    conn.execute(
                        "INSERT INTO licenses(license_key, duration_days, created_at, expires_at, status, machine_id, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (key, duration, created, expires, status, machine, note),
                    )
                    log_event("license_create_modal", "ok", license_key=key)
                else:
                    conn.execute(
                        "UPDATE licenses SET duration_days=?, expires_at=created_at + (? * 86400), status=?, machine_id=?, note=? WHERE license_key=?",
                        (duration, duration, status, machine, note, key),
                    )
                    log_event("license_update_modal", "ok", license_key=key)
                conn.commit()
            except sqlite3.IntegrityError:
                return messagebox.showwarning("Canh bao", "Key da ton tai")
            finally:
                conn.close()
            modal.destroy()
            self.refresh_all()
            self.show_toast("Saved successfully")

        btn = ttk.Frame(frm, style="Glass.TFrame")
        btn.grid(row=5, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btn, text="Cancel", style="Soft.TButton", command=modal.destroy).pack(side="right")
        ttk.Button(btn, text="Save", style="Primary.TButton", command=do_save).pack(side="right", padx=(0, 8))

    def open_create_key_modal(self) -> None:
        self._key_modal("Create Key", "create")

    def open_edit_selected_key_modal(self) -> None:
        row = self._selected_license_row()
        if not row:
            return messagebox.showwarning("Canh bao", "Chon key can sua")
        self._key_modal(
            "Edit Key",
            "edit",
            {
                "key": str(row[0]),
                "duration": str(row[1]),
                "status": str(row[2]),
                "machine": str(row[5]),
                "note": str(row[6]),
            },
        )

    def open_bulk_generate_modal(self) -> None:
        modal = tk.Toplevel(self)
        modal.title("Bulk Generate")
        modal.transient(self)
        modal.grab_set()
        modal.geometry("420x220")
        modal.configure(bg=THEME["panel"])
        frm = ttk.Frame(modal, style="Glass.TFrame", padding=12)
        frm.pack(fill="both", expand=True, padx=10, pady=10)
        frm.columnconfigure(1, weight=1)
        duration = tk.StringVar(value="7")
        qty = tk.StringVar(value="10")
        note = tk.StringVar(value="")
        ttk.Label(frm, text="Duration").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Combobox(frm, textvariable=duration, values=["7", "30"], state="readonly").grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Quantity").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(frm, textvariable=qty).grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Label(frm, text="Note").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(frm, textvariable=note).grid(row=2, column=1, sticky="ew", pady=5)

        def run_bulk() -> None:
            self.duration_var.set(duration.get().strip())
            self.qty_var.set(qty.get().strip())
            self.note_var.set(note.get().strip())
            modal.destroy()
            self.create_keys()

        btn = ttk.Frame(frm, style="Glass.TFrame")
        btn.grid(row=3, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btn, text="Cancel", style="Soft.TButton", command=modal.destroy).pack(side="right")
        ttk.Button(btn, text="Generate", style="Primary.TButton", command=run_bulk).pack(side="right", padx=(0, 8))

    def create_keys(self) -> None:
        try:
            duration = int(self.duration_var.get().strip())
            qty = int(self.qty_var.get().strip())
        except Exception:
            return messagebox.showwarning("Canh bao", "Duration/So luong khong hop le")
        if duration not in {7, 30}:
            return messagebox.showwarning("Canh bao", "Chi cho phep 7 hoac 30 ngay")
        if qty < 1 or qty > 200:
            return messagebox.showwarning("Canh bao", "So luong 1..200")

        note = self.note_var.get().strip()
        created_at = now_ts()
        expires_at = created_at + duration * 86400
        keys = []
        conn = db_connect()
        try:
            cur = conn.cursor()
            for _ in range(qty):
                key = make_key("VEO3")
                cur.execute(
                    "INSERT INTO licenses(license_key, duration_days, created_at, expires_at, status, machine_id, note) VALUES (?, ?, ?, ?, 'active', '', ?)",
                    (key, duration, created_at, expires_at, note),
                )
                keys.append(key)
            conn.commit()
        finally:
            conn.close()
        log_event("license_create", "ok", f"qty={qty},duration={duration}")
        messagebox.showinfo("Thanh cong", f"Da tao {len(keys)} key.")
        self.refresh_all()
        self.set_status(f"Tao thanh cong {len(keys)} key ({duration} ngay)")

    def refresh_licenses(self) -> None:
        for it in self.tree_licenses.get_children():
            self.tree_licenses.delete(it)
        conn = db_connect()
        try:
            rows = conn.execute(
                "SELECT license_key, duration_days, status, created_at, expires_at, machine_id, note FROM licenses ORDER BY created_at DESC LIMIT 5000"
            ).fetchall()
        finally:
            conn.close()
        q = self.key_search_var.get().strip().lower() if hasattr(self, "key_search_var") else ""
        status_filter = self.key_status_var.get().strip().lower() if hasattr(self, "key_status_var") else "all"
        for i, r in enumerate(rows):
            exp = int(r["expires_at"])
            status = str(r["status"])
            if status == "revoked":
                tag = "revoked"
            elif now_ts() >= exp:
                tag = "expired"
            else:
                tag = "active"
            key_txt = str(r["license_key"]).lower()
            machine_txt = str(r["machine_id"]).lower()
            note_txt = str(r["note"]).lower()
            if q and q not in key_txt and q not in machine_txt and q not in note_txt:
                continue
            if status_filter and status_filter != "all" and tag != status_filter:
                continue
            stripe = "even" if i % 2 == 0 else "odd"
            self.tree_licenses.insert(
                "",
                "end",
                values=(
                    r["license_key"],
                    r["duration_days"],
                    r["status"],
                    to_text(int(r["created_at"])),
                    to_text(int(r["expires_at"])),
                    r["machine_id"],
                    r["note"],
                ),
                tags=(tag, stripe),
            )

    def copy_selected_key(self) -> None:
        key = self._selected_license()
        if not key:
            return messagebox.showwarning("Canh bao", "Chon key can copy")
        self.clipboard_clear()
        self.clipboard_append(key)
        self.show_toast("Copied key")

    def _selected_license(self) -> str:
        sel = self.tree_licenses.selection()
        if not sel:
            return ""
        row = self.tree_licenses.item(sel[0], "values")
        if not row:
            return ""
        return str(row[0])

    def _selected_license_row(self) -> tuple[str, ...]:
        sel = self.tree_licenses.selection()
        if not sel:
            return ()
        row = self.tree_licenses.item(sel[0], "values")
        return tuple(row) if row else ()

    def _on_license_selected(self, _event: tk.Event | None = None) -> None:
        row = self._selected_license_row()
        if not row:
            return
        self.edit_key_var.set(str(row[0]))
        self.edit_duration_var.set(str(row[1]))
        self.edit_status_var.set(str(row[2]))
        self.edit_machine_var.set(str(row[5]))
        self.edit_note_var.set(str(row[6]))

    def update_selected_license(self) -> None:
        key = self.edit_key_var.get().strip()
        if not key:
            return messagebox.showwarning("Canh bao", "Chon license can sua")
        try:
            duration = int(self.edit_duration_var.get().strip())
        except Exception:
            return messagebox.showwarning("Canh bao", "Duration khong hop le")
        if duration not in {7, 30}:
            return messagebox.showwarning("Canh bao", "Chi cho phep 7 hoac 30 ngay")
        status = self.edit_status_var.get().strip() or "active"
        if status not in {"active", "revoked"}:
            return messagebox.showwarning("Canh bao", "Status khong hop le")
        machine = self.edit_machine_var.get().strip()
        note = self.edit_note_var.get().strip()
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE licenses SET duration_days=?, expires_at=created_at + (? * 86400), status=?, machine_id=?, note=? WHERE license_key=?",
                (duration, duration, status, machine, note, key),
            )
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return messagebox.showwarning("Canh bao", "Khong tim thay license")
        log_event("license_update", "ok", license_key=key)
        self.refresh_all()
        self.set_status(f"Da cap nhat license: {key}")

    def clear_machine_selected_license(self) -> None:
        key = self.edit_key_var.get().strip()
        if not key:
            return messagebox.showwarning("Canh bao", "Chon license can xoa machine bind")
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE licenses SET machine_id='' WHERE license_key=?", (key,))
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return messagebox.showwarning("Canh bao", "Khong tim thay license")
        log_event("license_clear_machine", "ok", license_key=key)
        self.refresh_all()
        self.set_status(f"Da xoa machine bind: {key}")

    def delete_selected_license(self) -> None:
        key = self._selected_license()
        if not key:
            return messagebox.showwarning("Canh bao", "Chon license can xoa")
        if not messagebox.askyesno("Xac nhan", f"Xoa license {key}?"):
            return
        conn = db_connect()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM licenses WHERE license_key=?", (key,))
            changed = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if changed <= 0:
            return messagebox.showwarning("Canh bao", "Khong tim thay license")
        log_event("license_delete", "ok", license_key=key)
        self.refresh_all()
        self.set_status(f"Da xoa license: {key}")

    def revoke_selected(self) -> None:
        key = self._selected_license()
        if not key:
            return
        conn = db_connect()
        try:
            conn.execute("UPDATE licenses SET status='revoked' WHERE license_key=?", (key,))
            conn.commit()
        finally:
            conn.close()
        log_event("license_revoke", "ok", license_key=key)
        self.refresh_all()
        self.set_status(f"Da revoke key: {key}")

    def unrevoke_selected(self) -> None:
        key = self._selected_license()
        if not key:
            return
        conn = db_connect()
        try:
            conn.execute("UPDATE licenses SET status='active' WHERE license_key=?", (key,))
            conn.commit()
        finally:
            conn.close()
        log_event("license_unrevoke", "ok", license_key=key)
        self.refresh_all()
        self.set_status(f"Da bo revoke key: {key}")

    def ban_ip(self) -> None:
        ip = self.ip_var.get().strip()
        reason = self.ip_reason.get().strip()
        if not ip:
            return
        conn = db_connect()
        try:
            conn.execute("INSERT OR REPLACE INTO banned_ips(ip, reason, created_at) VALUES (?, ?, ?)", (ip, reason, now_ts()))
            conn.commit()
        finally:
            conn.close()
        log_event("ip_ban", "ok", detail=ip)
        self.refresh_all()
        self.set_status(f"Da ban IP: {ip}")

    def unban_ip(self) -> None:
        ip = self.ip_var.get().strip() or self._selected_ip()
        if not ip:
            return
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
            conn.commit()
        finally:
            conn.close()
        log_event("ip_unban", "ok", detail=ip)
        self.refresh_all()
        self.set_status(f"Da go ban IP: {ip}")

    def ban_hwid(self) -> None:
        hwid = self.hwid_var.get().strip()
        reason = self.hwid_reason.get().strip()
        if not hwid:
            return
        conn = db_connect()
        try:
            conn.execute("INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at) VALUES (?, ?, ?)", (hwid, reason, now_ts()))
            conn.commit()
        finally:
            conn.close()
        log_event("hwid_ban", "ok", detail=hwid[:20])
        self.refresh_all()
        self.set_status("Da ban HWID")

    def unban_hwid(self) -> None:
        hwid = self.hwid_var.get().strip() or self._selected_hwid()
        if not hwid:
            return
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_hwids WHERE hwid=?", (hwid,))
            conn.commit()
        finally:
            conn.close()
        log_event("hwid_unban", "ok", detail=hwid[:20])
        self.refresh_all()
        self.set_status("Da go ban HWID")

    def _selected_ip(self) -> str:
        sel = self.tree_ips.selection()
        if not sel:
            return ""
        row = self.tree_ips.item(sel[0], "values")
        return str(row[0]) if row else ""

    def _selected_hwid(self) -> str:
        sel = self.tree_hwids.selection()
        if not sel:
            return ""
        row = self.tree_hwids.item(sel[0], "values")
        return str(row[0]) if row else ""

    def _on_ip_selected(self, _event: tk.Event | None = None) -> None:
        sel = self.tree_ips.selection()
        if not sel:
            return
        row = self.tree_ips.item(sel[0], "values")
        if not row:
            return
        self.ip_var.set(str(row[0]))
        self.ip_reason.set(str(row[1]))

    def _on_hwid_selected(self, _event: tk.Event | None = None) -> None:
        sel = self.tree_hwids.selection()
        if not sel:
            return
        row = self.tree_hwids.item(sel[0], "values")
        if not row:
            return
        self.hwid_var.set(str(row[0]))
        self.hwid_reason.set(str(row[1]))

    def update_selected_ip(self) -> None:
        old_ip = self._selected_ip()
        new_ip = self.ip_var.get().strip()
        reason = self.ip_reason.get().strip()
        if not old_ip or not new_ip:
            return messagebox.showwarning("Canh bao", "Chon IP can sua va nhap IP moi")
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_ips WHERE ip=?", (old_ip,))
            conn.execute("INSERT OR REPLACE INTO banned_ips(ip, reason, created_at) VALUES (?, ?, ?)", (new_ip, reason, now_ts()))
            conn.commit()
        finally:
            conn.close()
        log_event("ip_ban_update", "ok", detail=f"{old_ip}->{new_ip}")
        self.refresh_all()
        self.set_status(f"Da cap nhat IP ban: {old_ip} -> {new_ip}")

    def update_selected_hwid(self) -> None:
        old_hwid = self._selected_hwid()
        new_hwid = self.hwid_var.get().strip()
        reason = self.hwid_reason.get().strip()
        if not old_hwid or not new_hwid:
            return messagebox.showwarning("Canh bao", "Chon HWID can sua va nhap HWID moi")
        conn = db_connect()
        try:
            conn.execute("DELETE FROM banned_hwids WHERE hwid=?", (old_hwid,))
            conn.execute("INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at) VALUES (?, ?, ?)", (new_hwid, reason, now_ts()))
            conn.commit()
        finally:
            conn.close()
        log_event("hwid_ban_update", "ok", detail=f"{old_hwid[:12]}->{new_hwid[:12]}")
        self.refresh_all()
        self.set_status("Da cap nhat HWID ban")

    def delete_selected_ip(self) -> None:
        ip = self._selected_ip()
        if not ip:
            return messagebox.showwarning("Canh bao", "Chon IP can xoa")
        self.ip_var.set(ip)
        self.unban_ip()

    def delete_selected_hwid(self) -> None:
        hwid = self._selected_hwid()
        if not hwid:
            return messagebox.showwarning("Canh bao", "Chon HWID can xoa")
        self.hwid_var.set(hwid)
        self.unban_hwid()

    def refresh_bans(self) -> None:
        for it in self.tree_ips.get_children():
            self.tree_ips.delete(it)
        for it in self.tree_hwids.get_children():
            self.tree_hwids.delete(it)
        conn = db_connect()
        try:
            ip_rows = conn.execute("SELECT ip, reason, created_at FROM banned_ips ORDER BY created_at DESC").fetchall()
            hwid_rows = conn.execute("SELECT hwid, reason, created_at FROM banned_hwids ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()
        for i, r in enumerate(ip_rows):
            stripe = "even" if i % 2 == 0 else "odd"
            self.tree_ips.insert("", "end", values=(r["ip"], r["reason"], to_text(int(r["created_at"]))), tags=(stripe,))
        for i, r in enumerate(hwid_rows):
            stripe = "even" if i % 2 == 0 else "odd"
            self.tree_hwids.insert("", "end", values=(r["hwid"], r["reason"], to_text(int(r["created_at"]))), tags=(stripe,))

    def refresh_events(self) -> None:
        for it in self.tree_events.get_children():
            self.tree_events.delete(it)
        conn = db_connect()
        try:
            rows = conn.execute(
                "SELECT ts, action, status, ip, license_key, machine_id, detail FROM events ORDER BY id DESC LIMIT 2000"
            ).fetchall()
        finally:
            conn.close()
        for i, r in enumerate(rows):
            stripe = "even" if i % 2 == 0 else "odd"
            self.tree_events.insert(
                "",
                "end",
                values=(
                    to_text(int(r["ts"])),
                    r["action"],
                    r["status"],
                    r["ip"],
                    r["license_key"],
                    r["machine_id"],
                    r["detail"],
                ),
                tags=(stripe,),
            )

    def refresh_devices(self) -> None:
        for it in self.tree_devices.get_children():
            self.tree_devices.delete(it)
        conn = db_connect()
        try:
            rows = conn.execute(
                """
                SELECT e.machine_id AS machine_id,
                       MAX(e.license_key) AS linked_key,
                       MAX(e.ip) AS ip,
                       MAX(e.ts) AS last_active_ts
                FROM events e
                WHERE e.machine_id <> ''
                GROUP BY e.machine_id
                ORDER BY last_active_ts DESC
                LIMIT 5000
                """
            ).fetchall()
        finally:
            conn.close()

        for i, r in enumerate(rows):
            stripe = "even" if i % 2 == 0 else "odd"
            self.tree_devices.insert(
                "",
                "end",
                values=(
                    r["machine_id"],
                    r["linked_key"],
                    r["ip"],
                    to_text(int(r["last_active_ts"])) if r["last_active_ts"] else "",
                ),
                tags=(stripe,),
            )

    def _selected_device_row(self) -> tuple[str, ...]:
        sel = self.tree_devices.selection()
        if not sel:
            return ()
        row = self.tree_devices.item(sel[0], "values")
        return tuple(row) if row else ()

    def unbind_selected_device(self) -> None:
        row = self._selected_device_row()
        if not row:
            return messagebox.showwarning("Canh bao", "Chon device can unbind")
        machine_id = str(row[0])
        conn = db_connect()
        try:
            conn.execute("UPDATE licenses SET machine_id='' WHERE machine_id=?", (machine_id,))
            conn.commit()
        finally:
            conn.close()
        log_event("device_unbind", "ok", machine_id=machine_id)
        self.refresh_all()
        self.set_status(f"Da unbind device: {machine_id[:18]}")

    def ban_selected_device(self) -> None:
        row = self._selected_device_row()
        if not row:
            return messagebox.showwarning("Canh bao", "Chon device can ban")
        machine_id = str(row[0]).strip()
        if not machine_id:
            return
        conn = db_connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO banned_hwids(hwid, reason, created_at) VALUES (?, ?, ?)",
                (machine_id, "ban from devices panel", now_ts()),
            )
            conn.commit()
        finally:
            conn.close()
        log_event("device_ban", "ok", machine_id=machine_id)
        self.refresh_all()
        self.set_status(f"Da ban device: {machine_id[:18]}")


def main() -> None:
    init_db()
    login = LoginWindow()
    login.mainloop()


if __name__ == "__main__":
    main()
