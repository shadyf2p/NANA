let token = "";
let refreshToken = "";
let tokenRefreshPromise = null;
let meRole = "";
let licenseCache = [];
const recentPlainKeysByRef = new Map();
let deviceCache = [];
let logsCache = [];
let banCache = { ips: [], hwids: [] };
let userCache = [];
let userSessionCache = [];
let pendingConfirmAction = null;

function forceRelogin(message = "Phiên đăng nhập đã hết hạn hoặc bị thu hồi. Vui lòng đăng nhập lại.") {
  token = "";
  refreshToken = "";
  tokenRefreshPromise = null;
  meRole = "";
  qs("appBox")?.classList.add("hidden");
  qs("loginBox")?.classList.remove("hidden");
  setStatus("loginStatus", message, true);
}

function qs(id) {
  return document.getElementById(id);
}

function qsa(sel) {
  return Array.from(document.querySelectorAll(sel));
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Hiển thị HWID/hash đã lưu (64 hex) dạng rút gọn */
function maskHwid(h) {
  const s = String(h || "");
  if (!s) return "";
  if (s.length <= 12) return s.length > 6 ? `${s.slice(0, 6)}...` : s;
  return `${s.slice(0, 8)}...${s.slice(-4)}`;
}

function toTsFromLocalInput(v) {
  if (!v) return 0;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return 0;
  return Math.floor(d.getTime() / 1000);
}

function toLocalInputFromTs(ts) {
  if (!ts || Number(ts) <= 0) return "";
  const d = new Date(Number(ts) * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function setStatus(id, msg, isError = false) {
  const el = qs(id);
  if (!el) return;
  el.textContent = msg || "";
  el.classList.toggle("err", !!isError);
  el.classList.toggle("ok", !isError && !!msg);
}

function toast(message, isError = false) {
  const stack = qs("toastStack");
  if (!stack) return;
  if (stack.childElementCount >= 2) {
    stack.firstElementChild?.remove();
  }
  const node = document.createElement("div");
  node.className = `toast ${isError ? "err" : "ok"}`;
  node.textContent = message;
  stack.appendChild(node);
  setTimeout(() => node.remove(), 1400);
}

function setLoading(on) {
  const overlay = qs("loadingOverlay");
  if (!overlay) return;
  overlay.classList.toggle("hidden", !on);
}

function setLastRefresh() {
  const now = new Date().toLocaleString();
  const tag = qs("lastRefreshTag");
  if (tag) tag.textContent = `Cập nhật lúc: ${now}`;
}

function rememberCreatedKeys(rows) {
  const items = Array.isArray(rows) ? rows : [];
  for (const r of items) {
    const ref = String(r?.license_ref || "").trim();
    const plain = String(r?.license_key || "").trim();
    if (!ref || !plain) continue;
    recentPlainKeysByRef.set(ref, plain);
  }
  // Giới hạn cache nhẹ để tránh tăng vô hạn.
  if (recentPlainKeysByRef.size > 500) {
    const extra = recentPlainKeysByRef.size - 500;
    const keys = Array.from(recentPlainKeysByRef.keys());
    for (let i = 0; i < extra; i++) recentPlainKeysByRef.delete(keys[i]);
  }
}

function openConfirm(message, action) {
  pendingConfirmAction = action || null;
  qs("confirmMessage").textContent = message;
  qs("confirmModal").classList.remove("hidden");
}

function closeConfirm() {
  pendingConfirmAction = null;
  qs("confirmModal").classList.add("hidden");
}

async function api(path, method = "GET", body = null, auth = true) {
  const headers = { "Content-Type": "application/json" };
  if (auth && token) headers.Authorization = `Bearer ${token}`;
  let res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null });
  let data = await res.json().catch(() => ({}));

  // Auto refresh access token một lần khi 401.
  if (auth && res.status === 401 && refreshToken && path !== "/api/token/refresh") {
    if (!tokenRefreshPromise) {
      tokenRefreshPromise = (async () => {
        const r = await fetch("/api/token/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) {
          const err = String(d.error || `HTTP ${r.status}`);
          const mustRelogin = [
            "refresh_token_revoked",
            "refresh_token_expired",
            "session_revoked_suspicious",
            "invalid_refresh_token",
            "user_disabled",
          ];
          if (mustRelogin.includes(err)) {
            forceRelogin();
            throw new Error("session_expired_relogin_required");
          }
          throw new Error(err);
        }
        token = d.access_token || d.token || "";
        refreshToken = d.refresh_token || refreshToken;
      })().finally(() => {
        tokenRefreshPromise = null;
      });
    }
    try {
      await tokenRefreshPromise;
    } catch (e) {
      if (String(e?.message || "") === "session_expired_relogin_required") {
        throw new Error("vui_long_dang_nhap_lai");
      }
      throw e;
    }
    const retryHeaders = { "Content-Type": "application/json" };
    if (token) retryHeaders.Authorization = `Bearer ${token}`;
    res = await fetch(path, { method, headers: retryHeaders, body: body ? JSON.stringify(body) : null });
    data = await res.json().catch(() => ({}));
  }

  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function initNavigation() {
  qsa(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      qsa(".nav-btn").forEach((x) => x.classList.remove("active"));
      qsa(".tab-panel").forEach((x) => x.classList.remove("active"));
      btn.classList.add("active");
      qs(tab)?.classList.add("active");
    });
  });

  qs("btnToggleSidebar")?.addEventListener("click", () => {
    qs("sidebar")?.classList.toggle("collapsed");
  });
}

function renderDashboard(payload) {
  const d = payload?.data || {};
  const cards = [
    ["Tong key", d.total_keys || 0, "🔑"],
    ["Key dang hoat dong", d.active_keys || 0, "✅"],
    ["Key het han", d.expired_keys || 0, "⏳"],
    ["IP/HWID da ban", (d.banned_ip || 0) + (d.banned_hwid || 0), "⛔"],
    ["Nguoi dung hoat dong", d.active_users || 0, "👤"],
    ["API requests (tong)", d.api_total_requests || 0, "📡"],
    ["API bi chan rate", d.api_rate_rejections || 0, "🚧"],
  ];
  qs("dash").innerHTML = cards
    .map(([k, v, i]) => `<article class="metric glass"><div class="icon">${i}</div><div class="title">${escapeHtml(k)}</div><div class="value">${escapeHtml(v)}</div></article>`)
    .join("");
  drawLineChart("usageChart", d.usage_7d || [], "#63a2ff", "rgba(99,162,255,0.22)");
  drawBarChart("usersChart", d.active_users_7d || [], "#b779ff");
}

function drawLineChart(canvasId, rows, stroke, fill) {
  const c = qs(canvasId);
  if (!c) return;
  const ctx = c.getContext("2d");
  const w = c.width;
  const h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (!rows.length) return;
  const max = Math.max(1, ...rows.map((r) => Number(r.count || 0)));
  const pad = 16;
  const step = (w - pad * 2) / Math.max(1, rows.length - 1);

  ctx.beginPath();
  rows.forEach((r, idx) => {
    const x = pad + idx * step;
    const y = h - pad - ((Number(r.count || 0) / max) * (h - pad * 2));
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 2;
  ctx.shadowColor = stroke;
  ctx.shadowBlur = 10;
  ctx.stroke();

  ctx.lineTo(w - pad, h - pad);
  ctx.lineTo(pad, h - pad);
  ctx.closePath();
  ctx.fillStyle = fill;
  ctx.shadowBlur = 0;
  ctx.fill();
}

function drawBarChart(canvasId, rows, color) {
  const c = qs(canvasId);
  if (!c) return;
  const ctx = c.getContext("2d");
  const w = c.width;
  const h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (!rows.length) return;
  const max = Math.max(1, ...rows.map((r) => Number(r.count || 0)));
  const pad = 16;
  const barW = (w - pad * 2) / rows.length - 10;
  rows.forEach((r, idx) => {
    const x = pad + idx * (barW + 10);
    const barH = ((Number(r.count || 0) / max) * (h - pad * 2));
    const y = h - pad - barH;
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 8;
    ctx.fillRect(x, y, barW, barH);
  });
}

function statusView(row) {
  const nowTs = Date.now() / 1000;
  if ((row.status || "").toLowerCase() === "revoked") return "revoked";
  if ((row.status || "").toLowerCase() === "banned") return "banned";
  return Number(row.expires_at || 0) <= nowTs ? "expired" : "active";
}

function renderLicenses() {
  const q = (qs("keySearch")?.value || "").trim().toLowerCase();
  const f = (qs("keyStatusFilter")?.value || "all").trim().toLowerCase();
  const tbody = qs("licensesTable")?.querySelector("tbody");
  if (!tbody) return;

  const rows = licenseCache.filter((r) => {
    const s = statusView(r);
    if (f !== "all" && s !== f) return false;
    if (!q) return true;
    const hay = `${r.license_key_masked || ""} ${r.machine_id || ""} ${r.note || ""}`.toLowerCase();
    return hay.includes(q);
  });

  tbody.innerHTML = rows
    .map((r) => {
      const key = r.license_ref || r.license_key || "";
      const plainKey = r.license_key_plain || "";
      const s = statusView(r);
      return `
        <tr>
          <td title="${escapeHtml(key)}">${escapeHtml(r.license_key_masked || key)}</td>
          <td><span class="pill ${s}">${escapeHtml(s)}</span></td>
          <td title="${escapeHtml(r.machine_id || "")}">${escapeHtml(r.machine_id_masked || "")}</td>
          <td>${escapeHtml(String(Number(r.hwid_bindings_count ?? 0)))}</td>
          <td>${escapeHtml(r.expires_at_text || "")}</td>
          <td>${escapeHtml(r.created_at_text || "")}</td>
          <td>${escapeHtml(r.last_used_at_text || "-")}</td>
          <td>
            <button class="btn xs" onclick="copyKey('${escapeHtml(plainKey)}')">Copy</button>
            <button class="btn xs" onclick="openEditKey('${escapeHtml(key)}')">Sửa</button>
            <button class="btn xs" onclick="extendKey('${escapeHtml(key)}', 7)">+7d</button>
            <button class="btn xs danger" onclick="banKey('${escapeHtml(key)}')">Ban</button>
            <button class="btn xs danger" onclick="deleteKey('${escapeHtml(key)}')">Xóa</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderDevices() {
  const tbody = qs("devicesTable")?.querySelector("tbody");
  if (!tbody) return;
  tbody.innerHTML = deviceCache
    .map((d) => {
      const suspicious = d.status === "suspicious";
      return `
        <tr class="${suspicious ? "row-alert" : ""}">
          <td title="${escapeHtml(d.hwid || "")}">${escapeHtml(maskHwid(d.hwid || ""))}</td>
          <td>${escapeHtml(d.ip_address || "")}</td>
          <td title="${escapeHtml(d.linked_key || "")}">${escapeHtml(d.linked_key || "")}</td>
          <td>${escapeHtml(d.last_active_text || "")}</td>
          <td><span class="pill ${suspicious ? "banned" : "active"}">${escapeHtml(d.status || "normal")}</span></td>
          <td>
            <button class="btn xs" onclick="unbindDevice('${escapeHtml(d.hwid || "")}')">Gỡ HWID</button>
            <button class="btn xs danger" onclick="banDevice('${escapeHtml(d.hwid || "")}')">Ban</button>
            <button class="btn xs" onclick="kickDevice('${escapeHtml(d.hwid || "")}')">Kick</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderBanTables() {
  const ipBody = qs("ipBanTable")?.querySelector("tbody");
  const hwidBody = qs("hwidBanTable")?.querySelector("tbody");
  if (!ipBody || !hwidBody) return;

  ipBody.innerHTML = (banCache.ips || [])
    .map((b) => `
      <tr>
        <td>${escapeHtml(b.ip || "")}</td>
        <td>${escapeHtml(b.reason || "")}</td>
        <td><span class="pill ${escapeHtml(b.status || "active")}">${escapeHtml(b.status || "active")}</span></td>
        <td>${escapeHtml(b.created_at_text || "")}</td>
        <td>${escapeHtml(b.expire_at_text || "-")}</td>
        <td>
          <button class="btn xs" onclick="editIpBan('${escapeHtml(b.ip || "")}', '${escapeHtml(b.reason || "")}', ${Number(b.expire_at || 0)})">Sửa</button>
          <button class="btn xs danger" onclick="unbanIp('${escapeHtml(b.ip || "")}')">Bỏ ban</button>
        </td>
      </tr>
    `)
    .join("");

  hwidBody.innerHTML = (banCache.hwids || [])
    .map((b) => `
      <tr>
        <td title="${escapeHtml(b.hwid || "")}">${escapeHtml(b.hwid_masked || maskHwid(b.hwid || ""))}</td>
        <td>${escapeHtml(b.reason || "")}</td>
        <td><span class="pill ${escapeHtml(b.status || "active")}">${escapeHtml(b.status || "active")}</span></td>
        <td>${escapeHtml(b.created_at_text || "")}</td>
        <td>${escapeHtml(b.expire_at_text || "-")}</td>
        <td>
          <button class="btn xs" onclick="editHwidBan('${escapeHtml(b.hwid || "")}', '${escapeHtml(b.reason || "")}', ${Number(b.expire_at || 0)})">Sửa</button>
          <button class="btn xs danger" onclick="unbanHwid('${escapeHtml(b.hwid || "")}')">Bỏ ban</button>
        </td>
      </tr>
    `)
    .join("");
}

function renderLogs() {
  const tbody = qs("logsTable")?.querySelector("tbody");
  if (!tbody) return;
  tbody.innerHTML = logsCache
    .map((e) => {
      const isErr = (e.status || "").toLowerCase().includes("fail") || (e.action || "").toLowerCase().includes("error");
      return `
        <tr class="${isErr ? "row-error" : ""}">
          <td>${escapeHtml(e.action || "")}</td>
          <td>${escapeHtml(e.ip || "")}</td>
          <td>${escapeHtml(e.machine_id || e.license_key || "")}</td>
          <td>${escapeHtml(e.status || "")}</td>
          <td>${escapeHtml(e.detail || "")}</td>
          <td>${escapeHtml(e.time || "")}</td>
        </tr>
      `;
    })
    .join("");

  const recent = qs("recentActivity");
  if (recent) {
    recent.innerHTML = logsCache
      .slice(0, 12)
      .map((x) => `<div class="activity-item"><strong>${escapeHtml(x.action)}</strong><span>${escapeHtml(x.time)}</span></div>`)
      .join("");
  }
}

function renderUsers() {
  const tbody = qs("usersTable")?.querySelector("tbody");
  if (!tbody) return;
  tbody.innerHTML = (userCache || [])
    .map((u) => {
      const uname = String(u.username || "");
      const role = String(u.role || "mod");
      const active = Number(u.is_active || 0) === 1;
      const totp = Number(u.totp_enabled || 0) === 1;
      return `
        <tr>
          <td>${escapeHtml(uname)}</td>
          <td>${escapeHtml(role)}</td>
          <td><span class="pill ${active ? "active" : "banned"}">${active ? "active" : "disabled"}</span></td>
          <td><span class="pill ${totp ? "active" : "expired"}">${totp ? "on" : "off"}</span></td>
          <td>${escapeHtml(u.created_at_text || "")}</td>
          <td>${escapeHtml(u.updated_at_text || "")}</td>
          <td>
            <button class="btn xs" onclick="pickUser('${escapeHtml(uname)}', '${escapeHtml(role)}', ${active ? 1 : 0})">Chọn</button>
            <button class="btn xs danger" onclick="revokeUserSessionsQuick('${escapeHtml(uname)}')">Revoke sessions</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderUserSessions() {
  const tbody = qs("userSessionsTable")?.querySelector("tbody");
  if (!tbody) return;
  tbody.innerHTML = (userSessionCache || [])
    .map((s) => {
      const sid = String(s.session_id || "");
      const st = String(s.status || "");
      const susp = Number(s.suspicious_count || 0);
      const suspWarn = susp >= 3;
      return `
        <tr class="${suspWarn ? "row-alert" : ""}">
          <td title="${escapeHtml(sid)}">${escapeHtml(sid.slice(0, 14) + (sid.length > 14 ? "..." : ""))}</td>
          <td><span class="pill ${st === "active" ? "active" : (st === "revoked" ? "banned" : "expired")}">${escapeHtml(st)}</span></td>
          <td>${escapeHtml(s.last_ip || "")}</td>
          <td><span class="pill ${suspWarn ? "banned" : "active"}">${escapeHtml(String(susp))}${suspWarn ? " ⚠" : ""}</span></td>
          <td>${escapeHtml(s.created_at_text || "")}</td>
          <td>${escapeHtml(s.last_seen_at_text || "")}</td>
          <td>${escapeHtml(s.expires_at_text || "")}</td>
          <td><button class="btn xs danger" onclick="revokeSingleSession('${escapeHtml(sid)}')">Revoke</button></td>
        </tr>
      `;
    })
    .join("");
}

async function loadDashboard() {
  const d = await api("/api/dashboard");
  renderDashboard(d);
}

async function loadLicenses() {
  const d = await api("/api/licenses");
  const rows = Array.isArray(d?.data) ? d.data : [];
  licenseCache = rows.map((r) => {
    const ref = String(r?.license_ref || r?.license_key || "");
    const plain = recentPlainKeysByRef.get(ref) || "";
    if (!plain) return r;
    return { ...r, license_key_plain: plain };
  });
  renderLicenses();
}

async function loadDevices() {
  const d = await api("/api/devices");
  deviceCache = d?.data || [];
  renderDevices();
}

async function loadBans() {
  const d = await api("/api/bans");
  banCache = d?.data || { ips: [], hwids: [] };
  renderBanTables();
}

async function loadLogs() {
  const q = encodeURIComponent(qs("logsSearch")?.value?.trim() || "");
  const type = encodeURIComponent(qs("logsType")?.value || "");
  const from_ts = toTsFromLocalInput(qs("logsFrom")?.value || "");
  const to_ts = toTsFromLocalInput(qs("logsTo")?.value || "");
  const d = await api(`/api/events?q=${q}&type=${type}&from_ts=${from_ts}&to_ts=${to_ts}`);
  logsCache = d?.data || [];
  renderLogs();
}

async function loadSettings() {
  const d = await api("/api/settings");
  const st = d?.data || {};
  qs("st_default_duration").value = st.default_key_duration_days || "30";
  qs("st_max_devices").value = st.max_devices_per_key || "1";
  qs("st_enable_hwid").value = st.enable_hwid_binding || "1";
  qs("st_auto_ban").value = st.auto_ban_rules || "0";
  qs("st_auto_fail_limit").value = st.auto_ban_failed_attempt_limit || "6";
  qs("st_auto_window_seconds").value = st.auto_ban_window_seconds || "600";
  qs("st_auto_ban_seconds").value = st.auto_ban_duration_seconds || "3600";
  qs("st_auto_mismatch_limit").value = st.auto_ban_mismatch_limit || "3";
  qs("st_rule_failed_attempts").value = st.auto_ban_rule_failed_attempts || "1";
  qs("st_rule_hwid_mismatch").value = st.auto_ban_rule_hwid_mismatch || "1";
  qs("st_rule_multi_hwid_ip").value = st.auto_ban_rule_multi_hwid_ip || "0";
  qs("st_multi_hwid_limit").value = st.multi_hwid_ip_limit || "15";
  qs("st_multi_hwid_window").value = st.multi_hwid_ip_window_seconds || "900";
  qs("st_rule_invalid_sig").value = st.auto_ban_rule_invalid_signature || "1";
  qs("st_invalid_sig_limit").value = st.invalid_sig_ban_limit || "18";
  qs("st_invalid_sig_window").value = st.invalid_sig_window_seconds || "600";
  qs("st_hwid_swap_ban").value = st.hwid_swap_auto_ban_enabled || "1";
  qs("st_hwid_swap_limit").value = st.hwid_swap_fail_limit || "5";
  qs("st_hwid_swap_window").value = st.hwid_swap_window_seconds || "3600";
  qs("st_api_rate_ip").value = st.api_rate_ip_per_minute || "120";
  qs("st_api_rate_key").value = st.api_rate_key_per_minute || "60";
  qs("st_api_rate_window").value = st.api_rate_window_seconds || "60";
  qs("st_api_allowed_origins").value = st.api_allowed_origins || "";
  qs("st_api_auto_ban_rate").value = st.api_auto_ban_on_rate_violations || "1";
  qs("st_api_rate_ban_threshold").value = st.api_rate_violation_ban_threshold || "25";
  qs("st_api_rate_ban_window").value = st.api_rate_violation_ban_window_sec || "600";
  qs("st_license_sig_required").value = st.license_signature_required || "1";
  qs("st_license_sig_legacy").value = st.license_signature_allow_legacy || "1";
  qs("st_license_clock_skew").value = st.license_clock_skew_seconds || "300";
  qs("st_license_nonce_retain").value = st.license_nonce_retain_seconds || "172800";
  qs("st_license_nonce_min").value = st.license_nonce_min_length || "16";
  qs("st_pwd_min_len").value = st.password_policy_min_length || "8";
  qs("st_pwd_upper").value = st.password_policy_require_upper || "1";
  qs("st_pwd_lower").value = st.password_policy_require_lower || "1";
  qs("st_pwd_digit").value = st.password_policy_require_digit || "1";
  qs("st_pwd_special").value = st.password_policy_require_special || "0";
  qs("st_api_base_url").value = st.api_base_url || "";
}

async function loadUsers() {
  try {
    const d = await api("/api/users");
    userCache = d?.data || [];
    renderUsers();
    setStatus("usersStatus", "");
  } catch (e) {
    userCache = [];
    renderUsers();
    setStatus("usersStatus", `Không tải được users: ${e.message}`, true);
  }
}

async function loadUserSessions() {
  const username = qs("usr_sessions_username")?.value?.trim() || "";
  if (!username) {
    userSessionCache = [];
    renderUserSessions();
    return;
  }
  const includeRevoked = qs("usr_sessions_include_revoked")?.checked ? "1" : "0";
  const status = encodeURIComponent(qs("usr_sessions_status")?.value || "");
  const ip = encodeURIComponent(qs("usr_sessions_ip")?.value?.trim() || "");
  const d = await api(`/api/users/sessions?username=${encodeURIComponent(username)}&include_revoked=${includeRevoked}&status=${status}&ip=${ip}`);
  userSessionCache = d?.data || [];
  renderUserSessions();
}

async function saveSettings() {
  const items = {
    default_key_duration_days: String(qs("st_default_duration").value || "30"),
    max_devices_per_key: String(qs("st_max_devices").value || "1"),
    enable_hwid_binding: String(qs("st_enable_hwid").value || "1"),
    auto_ban_rules: String(qs("st_auto_ban").value || "0"),
    auto_ban_failed_attempt_limit: String(qs("st_auto_fail_limit").value || "6"),
    auto_ban_window_seconds: String(qs("st_auto_window_seconds").value || "600"),
    auto_ban_duration_seconds: String(qs("st_auto_ban_seconds").value || "3600"),
    auto_ban_mismatch_limit: String(qs("st_auto_mismatch_limit").value || "3"),
    auto_ban_rule_failed_attempts: String(qs("st_rule_failed_attempts").value || "1"),
    auto_ban_rule_hwid_mismatch: String(qs("st_rule_hwid_mismatch").value || "1"),
    auto_ban_rule_multi_hwid_ip: String(qs("st_rule_multi_hwid_ip").value || "0"),
    multi_hwid_ip_limit: String(qs("st_multi_hwid_limit").value || "15"),
    multi_hwid_ip_window_seconds: String(qs("st_multi_hwid_window").value || "900"),
    auto_ban_rule_invalid_signature: String(qs("st_rule_invalid_sig").value || "1"),
    invalid_sig_ban_limit: String(qs("st_invalid_sig_limit").value || "18"),
    invalid_sig_window_seconds: String(qs("st_invalid_sig_window").value || "600"),
    hwid_swap_auto_ban_enabled: String(qs("st_hwid_swap_ban").value || "1"),
    hwid_swap_fail_limit: String(qs("st_hwid_swap_limit").value || "5"),
    hwid_swap_window_seconds: String(qs("st_hwid_swap_window").value || "3600"),
    api_rate_ip_per_minute: String(qs("st_api_rate_ip").value || "120"),
    api_rate_key_per_minute: String(qs("st_api_rate_key").value || "60"),
    api_rate_window_seconds: String(qs("st_api_rate_window").value || "60"),
    api_allowed_origins: String(qs("st_api_allowed_origins").value || ""),
    api_auto_ban_on_rate_violations: String(qs("st_api_auto_ban_rate").value || "1"),
    api_rate_violation_ban_threshold: String(qs("st_api_rate_ban_threshold").value || "25"),
    api_rate_violation_ban_window_sec: String(qs("st_api_rate_ban_window").value || "600"),
    license_signature_required: String(qs("st_license_sig_required").value || "1"),
    license_signature_allow_legacy: String(qs("st_license_sig_legacy").value || "1"),
    license_clock_skew_seconds: String(qs("st_license_clock_skew").value || "300"),
    license_nonce_retain_seconds: String(qs("st_license_nonce_retain").value || "172800"),
    license_nonce_min_length: String(qs("st_license_nonce_min").value || "16"),
    password_policy_min_length: String(qs("st_pwd_min_len").value || "8"),
    password_policy_require_upper: String(qs("st_pwd_upper").value || "1"),
    password_policy_require_lower: String(qs("st_pwd_lower").value || "1"),
    password_policy_require_digit: String(qs("st_pwd_digit").value || "1"),
    password_policy_require_special: String(qs("st_pwd_special").value || "0"),
    api_base_url: String(qs("st_api_base_url").value || ""),
  };
  await api("/api/settings/update", "POST", { items });
  setStatus("settingsStatus", "Đã lưu cài đặt.");
  toast("Lưu cài đặt thành công");
}

function openKeyModal(mode = "create", row = null) {
  qs("km_mode").value = mode;
  qs("keyModalTitle").textContent = mode === "edit" ? "Chỉnh sửa key" : "Tạo key";
  qs("km_qty").value = "1";
  qs("km_duration").value = String(row?.duration_days || 7);
  qs("km_status").value = row?.status || "";
  qs("km_key").value = row?.license_key || "";
  qs("km_hwid").value = row?.machine_id || "";
  qs("km_note").value = row?.note || "";
  qs("keyModal").classList.remove("hidden");
}

function closeKeyModal() {
  qs("keyModal").classList.add("hidden");
}

async function saveKeyModal() {
  const mode = qs("km_mode").value;
  const key = qs("km_key").value.trim();
  const duration_days = Number(qs("km_duration").value || "7");
  const note = qs("km_note").value.trim();
  const machine_id = qs("km_hwid").value.trim();
  const status = qs("km_status").value.trim();
  const quantity = Number(qs("km_qty").value || "1");

  if (mode === "create") {
    const createdResp = await api("/api/licenses/create", "POST", {
      duration_days,
      quantity,
      note,
      manual_key: key,
    });
    rememberCreatedKeys(createdResp?.data || []);
    toast("Tạo key thành công");
  } else {
    if (!key) throw new Error("missing_license_key");
    await api("/api/licenses/update", "POST", {
      license_key: key,
      duration_days,
      status,
      note,
      machine_id,
    });
    toast("Cập nhật key thành công");
  }
  closeKeyModal();
  await refreshAll();
}

async function refreshAll() {
  setLoading(true);
  try {
    await Promise.allSettled([loadDashboard(), loadLicenses(), loadDevices(), loadBans(), loadLogs(), loadSettings(), loadUsers()]);
    setLastRefresh();
  } finally {
    setLoading(false);
  }
}

async function doLogin() {
  setStatus("loginStatus", "Đang đăng nhập...");
  try {
    const username = qs("username").value.trim();
    const password = qs("password").value;
    const totp_code = qs("totpCode")?.value?.trim() || "";
    const d = await api("/api/login", "POST", { username, password, totp_code }, false);
    token = d.access_token || d.token || "";
    refreshToken = d.refresh_token || "";
    meRole = d.role || "";
    qs("loginBox").classList.add("hidden");
    qs("appBox").classList.remove("hidden");
    setStatus("loginStatus", "");
    await refreshAll();
    toast("Đăng nhập thành công");
  } catch (e) {
    const msg = String(e.message || "");
    if (msg.includes("totp_required")) {
      setStatus("loginStatus", "Tài khoản yêu cầu mã 2FA. Vui lòng nhập mã OTP 6 số.", true);
    } else {
      setStatus("loginStatus", `Đăng nhập thất bại: ${msg}`, true);
    }
    toast("Đăng nhập thất bại", true);
  }
}

window.pickUser = function pickUser(username, role, active) {
  qs("usr_target_username").value = username || "";
  qs("usr_target_role").value = role || "mod";
  qs("usr_target_active").value = String(Number(active ? 1 : 0));
  qs("usr_sessions_username").value = username || "";
  loadUserSessions().catch(() => {});
};

window.revokeUserSessionsQuick = async function revokeUserSessionsQuick(username) {
  openConfirm(`Revoke all sessions của ${username}?`, async () => {
    await api("/api/users/revoke_all_sessions", "POST", { username });
    await refreshAll();
    toast("Đã revoke sessions");
  });
};

window.revokeSingleSession = async function revokeSingleSession(sessionId) {
  openConfirm(`Revoke session ${sessionId}?`, async () => {
    await api("/api/users/revoke_session", "POST", { session_id: sessionId });
    await loadUserSessions();
    toast("Đã revoke session");
  });
};

async function createUser() {
  const username = qs("usr_new_username").value.trim();
  const password = qs("usr_new_password").value;
  const role = qs("usr_new_role").value;
  await api("/api/users/create", "POST", { username, password, role });
  setStatus("usersStatus", "Tạo user thành công");
  await loadUsers();
}

async function setUserRole() {
  const username = qs("usr_target_username").value.trim();
  const role = qs("usr_target_role").value;
  await api("/api/users/role", "POST", { username, role });
  setStatus("usersStatus", "Đã cập nhật role");
  await loadUsers();
}

async function setUserActive() {
  const username = qs("usr_target_username").value.trim();
  const is_active = qs("usr_target_active").value === "1";
  await api("/api/users/disable", "POST", { username, is_active });
  setStatus("usersStatus", "Đã cập nhật trạng thái user");
  await loadUsers();
}

async function resetUserPassword() {
  const username = qs("usr_target_username").value.trim();
  const new_password = qs("usr_target_new_password").value;
  await api("/api/users/reset_password", "POST", { username, new_password });
  setStatus("usersStatus", "Đã reset password và revoke session");
  qs("usr_target_new_password").value = "";
}

async function revokeUserSessions() {
  const username = qs("usr_target_username").value.trim();
  const d = await api("/api/users/revoke_all_sessions", "POST", { username });
  setStatus("usersStatus", `Đã revoke ${Number(d.revoked || 0)} session`);
}

async function revokeActiveUserSessions() {
  const username = qs("usr_sessions_username")?.value?.trim() || qs("usr_target_username")?.value?.trim() || "";
  if (!username) throw new Error("missing_username");
  const d = await api("/api/users/revoke_active_sessions", "POST", { username });
  setStatus("usersStatus", `Đã revoke ${Number(d.revoked || 0)} active session`);
  await loadUserSessions();
}

async function setup2fa() {
  const username = qs("usr_target_username").value.trim();
  const d = await api("/api/2fa/setup", "POST", { username });
  qs("usr_target_totp_secret").value = d.secret || "";
  qs("usr_target_totp_uri").value = d.otpauth_uri || "";
  setStatus("usersStatus", "Đã tạo secret 2FA, hãy scan QR bằng app Authenticator");
}

async function enable2fa() {
  const username = qs("usr_target_username").value.trim();
  const secret = qs("usr_target_totp_secret").value.trim();
  const code = qs("usr_target_totp_code").value.trim();
  await api("/api/2fa/enable", "POST", { username, secret, code });
  setStatus("usersStatus", "Đã bật 2FA");
  await loadUsers();
}

async function disable2fa() {
  const username = qs("usr_target_username").value.trim();
  const code = qs("usr_target_totp_code").value.trim();
  await api("/api/2fa/disable", "POST", { username, code });
  setStatus("usersStatus", "Đã tắt 2FA");
  await loadUsers();
}

window.copyKey = async function copyKey(key) {
  if (!key) {
    toast("Key chi hien day du luc vua tao. Danh sach chi luu ban ma hoa.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(key);
  } catch (_e) {
    const input = document.createElement("input");
    input.value = key;
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    input.remove();
  }
  toast("Đã copy key");
};

window.openEditKey = function openEditKey(key) {
  const row = licenseCache.find((x) => x.license_key === key);
  if (!row) return toast("Không tìm thấy key", true);
  openKeyModal("edit", row);
};

window.extendKey = async function extendKey(key, days) {
  try {
    await api("/api/licenses/extend", "POST", { license_key: key, days });
    await refreshAll();
    toast(`Đã gia hạn ${days} ngày`);
  } catch (e) {
    toast(e.message, true);
  }
};

window.banKey = async function banKey(key) {
  openConfirm(`Ban key ${key}?`, async () => {
    await api("/api/licenses/update", "POST", { license_key: key, status: "banned" });
    await refreshAll();
    toast("Đã ban key");
  });
};

window.deleteKey = async function deleteKey(key) {
  openConfirm(`Xóa key ${key}?`, async () => {
    await api("/api/licenses/delete", "POST", { license_key: key });
    await refreshAll();
    toast("Đã xóa key");
  });
};

window.unbindDevice = async function unbindDevice(hwid) {
  await api("/api/devices/unbind", "POST", { hwid });
  await refreshAll();
  toast("Đã gỡ HWID");
};

window.banDevice = async function banDevice(hwid) {
  await api("/api/devices/ban", "POST", { hwid, reason: "ban_from_device_panel" });
  await refreshAll();
  toast("Đã ban thiết bị");
};

window.kickDevice = async function kickDevice(hwid) {
  await api("/api/devices/kick", "POST", { hwid });
  await refreshAll();
  toast("Đã kick session");
};

window.editIpBan = function editIpBan(ip, reason, expireAt) {
  qs("banIp").value = ip || "";
  qs("banIpReason").value = reason || "";
  qs("banIpExpire").value = toLocalInputFromTs(expireAt || 0);
  toast("Đã nạp IP vào form");
};

window.editHwidBan = function editHwidBan(hwid, reason, expireAt) {
  qs("banHwid").value = hwid || "";
  qs("banHwidReason").value = reason || "";
  qs("banHwidExpire").value = toLocalInputFromTs(expireAt || 0);
  toast("Đã nạp HWID vào form");
};

window.unbanIp = async function unbanIp(ip) {
  openConfirm(`Bỏ ban IP ${ip}?`, async () => {
    await api("/api/bans/ip/remove", "POST", { ip });
    await refreshAll();
    toast("Đã bỏ ban IP");
  });
};

window.unbanHwid = async function unbanHwid(hwid) {
  openConfirm(`Bỏ ban HWID ${hwid}?`, async () => {
    await api("/api/bans/hwid/remove", "POST", { hwid });
    await refreshAll();
    toast("Đã bỏ ban HWID");
  });
};

async function submitIpBan() {
  const ip = qs("banIp").value.trim();
  const reason = qs("banIpReason").value.trim();
  const expire_at = toTsFromLocalInput(qs("banIpExpire").value);
  await api("/api/bans/ip", "POST", { ip, reason, expire_at });
  await refreshAll();
  toast("Đã cập nhật IP ban");
}

async function submitHwidBan() {
  const hwid = qs("banHwid").value.trim();
  const reason = qs("banHwidReason").value.trim();
  const expire_at = toTsFromLocalInput(qs("banHwidExpire").value);
  await api("/api/bans/hwid", "POST", { hwid, reason, expire_at });
  await refreshAll();
  toast("Đã cập nhật HWID ban");
}

function bindEvents() {
  qs("btnLogin")?.addEventListener("click", doLogin);
  qs("btnRefreshDash")?.addEventListener("click", refreshAll);
  qs("btnLoadLicenses")?.addEventListener("click", loadLicenses);
  qs("btnLoadDevices")?.addEventListener("click", loadDevices);
  qs("btnLoadEvents")?.addEventListener("click", loadLogs);
  qs("btnSaveSettings")?.addEventListener("click", async () => {
    try {
      await saveSettings();
    } catch (e) {
      setStatus("settingsStatus", `Lỗi lưu cài đặt: ${e.message}`, true);
      toast(e.message, true);
    }
  });
  qs("btnLoadSettings")?.addEventListener("click", loadSettings);
  qs("btnLoadUsers")?.addEventListener("click", loadUsers);
  qs("btnLoadUserSessions")?.addEventListener("click", async () => {
    try {
      await loadUserSessions();
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btnRevokeActiveSessions")?.addEventListener("click", async () => {
    try {
      await revokeActiveUserSessions();
      toast("Đã revoke active sessions");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("usr_sessions_status")?.addEventListener("change", () => { loadUserSessions().catch(() => {}); });
  qs("usr_sessions_include_revoked")?.addEventListener("change", () => { loadUserSessions().catch(() => {}); });
  qs("btnBanIp")?.addEventListener("click", async () => {
    try {
      await submitIpBan();
    } catch (e) {
      toast(e.message, true);
    }
  });
  qs("btnBanHwid")?.addEventListener("click", async () => {
    try {
      await submitHwidBan();
    } catch (e) {
      toast(e.message, true);
    }
  });

  qs("btnOpenCreateKey")?.addEventListener("click", () => openKeyModal("create"));
  qs("btnOpenBulk")?.addEventListener("click", () => {
    openKeyModal("create");
    qs("km_qty").value = "10";
  });
  qs("btnModalCancel")?.addEventListener("click", closeKeyModal);
  qs("btnModalSave")?.addEventListener("click", async () => {
    try {
      await saveKeyModal();
    } catch (e) {
      toast(e.message, true);
    }
  });

  qs("btnConfirmNo")?.addEventListener("click", closeConfirm);
  qs("btnConfirmYes")?.addEventListener("click", async () => {
    const action = pendingConfirmAction;
    closeConfirm();
    if (!action) return;
    try {
      await action();
    } catch (e) {
      toast(e.message, true);
    }
  });

  qs("keySearch")?.addEventListener("input", renderLicenses);
  qs("keyStatusFilter")?.addEventListener("change", renderLicenses);

  qs("btnCreateUser")?.addEventListener("click", async () => {
    try {
      await createUser();
      toast("Tạo user thành công");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btnSetUserRole")?.addEventListener("click", async () => {
    try {
      await setUserRole();
      toast("Đã set role");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btnSetUserActive")?.addEventListener("click", async () => {
    try {
      await setUserActive();
      toast("Đã cập nhật trạng thái user");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btnResetUserPassword")?.addEventListener("click", async () => {
    try {
      await resetUserPassword();
      toast("Đã reset password");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btnRevokeUserSessions")?.addEventListener("click", async () => {
    try {
      await revokeUserSessions();
      toast("Đã revoke sessions");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btn2faSetup")?.addEventListener("click", async () => {
    try {
      await setup2fa();
      toast("Đã tạo secret 2FA");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btn2faEnable")?.addEventListener("click", async () => {
    try {
      await enable2fa();
      toast("Bật 2FA thành công");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
  qs("btn2faDisable")?.addEventListener("click", async () => {
    try {
      await disable2fa();
      toast("Tắt 2FA thành công");
    } catch (e) {
      setStatus("usersStatus", e.message, true);
      toast(e.message, true);
    }
  });
}

initNavigation();
bindEvents();
