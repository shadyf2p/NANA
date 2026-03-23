import bcrypt from "bcrypt";
import { getAdminById, getAdminByUsername, touchAdminLogin } from "../models/adminModel.js";
import { createRefreshTokenRow, getRefreshTokenRow, revokeRefreshToken } from "../models/tokenModel.js";
import { getClientIp, getIpPrefix } from "../utils/network.js";
import { sha256Hex } from "../utils/hash.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt.js";
import { hitRateLimit } from "../services/rateService.js";
import { insertAdminSecurityLog, isIpBanned } from "../models/securityModel.js";

function refreshTokenExpiresAt(days = 7) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d;
}

export async function login(req, res) {
  const { username, password } = req.body;
  const ip = getClientIp(req);
  const banned = await isIpBanned(ip);
  if (banned) {
    return res.status(403).json({ message: "IP banned temporarily" });
  }

  const limit = await hitRateLimit({
    scope: "login:ip",
    key: ip,
    windowSeconds: 900,
    max: 20
  });
  if (limit.limited) {
    return res.status(429).json({ message: "Too many login attempts" });
  }

  const admin = await getAdminByUsername(username);
  if (!admin || Number(admin.is_active) !== 1) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const passOk = await bcrypt.compare(password, admin.password_hash);
  if (!passOk) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const prevIp = String(admin.last_login_ip || "");
  const prevPrefix = getIpPrefix(prevIp);
  const currentPrefix = getIpPrefix(ip);
  const ipAnomaly = !!prevPrefix && !!currentPrefix && prevPrefix !== currentPrefix;
  if (ipAnomaly) {
    await insertAdminSecurityLog({
      adminId: admin.id,
      username: admin.username,
      ip,
      eventType: "login_ip_anomaly",
      detail: `prev=${prevPrefix};current=${currentPrefix}`
    });
  }

  await touchAdminLogin({ adminId: admin.id, ip });

  const accessToken = signAccessToken(admin);
  const refreshToken = signRefreshToken(admin);
  await createRefreshTokenRow({
    adminId: admin.id,
    tokenHash: sha256Hex(refreshToken),
    issuedIp: ip,
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
    expiresAt: refreshTokenExpiresAt(7)
  });

  return res.json({
    accessToken,
    refreshToken,
    role: admin.role,
    security: {
      ip_anomaly: ipAnomaly
    }
  });
}

export async function refresh(req, res) {
  const { refreshToken } = req.body;
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (_err) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
  if (String(payload.typ || "") !== "refresh") {
    return res.status(401).json({ message: "Invalid refresh token type" });
  }

  const tokenHash = sha256Hex(refreshToken);
  const row = await getRefreshTokenRow(tokenHash);
  if (!row || row.revoked_at) {
    return res.status(401).json({ message: "Refresh token revoked" });
  }
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return res.status(401).json({ message: "Refresh token expired" });
  }

  const admin = await getAdminById(Number(payload.sub));
  if (!admin || Number(admin.is_active) !== 1) {
    return res.status(401).json({ message: "Account disabled" });
  }

  await revokeRefreshToken(tokenHash);
  const newAccess = signAccessToken(admin);
  const newRefresh = signRefreshToken(admin);
  await createRefreshTokenRow({
    adminId: admin.id,
    tokenHash: sha256Hex(newRefresh),
    issuedIp: getClientIp(req),
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
    expiresAt: refreshTokenExpiresAt(7)
  });

  return res.json({
    accessToken: newAccess,
    refreshToken: newRefresh,
    role: admin.role
  });
}

export async function logout(req, res) {
  const { refreshToken } = req.body;
  await revokeRefreshToken(sha256Hex(refreshToken));
  return res.json({ ok: true });
}

