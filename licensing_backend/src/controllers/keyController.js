import {
  banLicense,
  bindLicenseHwid,
  createLicense,
  deleteLicense,
  findLicenseByKey,
  listLicenses,
  markLicenseExpired
} from "../models/licenseModel.js";
import {
  countRecentFailedAttemptsByHwid,
  countRecentFailedAttemptsByIp,
  countRecentFailedAttemptsByKey,
  createVerifyLog,
  listVerifyLogs
} from "../models/logModel.js";
import { generateLicenseKey } from "../utils/licenseKey.js";
import { getClientIp } from "../utils/network.js";
import { env } from "../config/env.js";

function asIsoDate(value) {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

async function writeVerifyLog(req, { key, hwid, isValid, reason }) {
  await createVerifyLog({
    licenseKey: key,
    hwid: hwid || null,
    ip: getClientIp(req),
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
    isValid,
    reason
  });
}

export async function createKey(req, res) {
  const expireAtIso = asIsoDate(req.body.expireAt);
  if (!expireAtIso) {
    return res.status(400).json({ message: "expireAt must be a valid ISO datetime" });
  }

  const expireAt = new Date(expireAtIso);
  if (expireAt.getTime() <= Date.now()) {
    return res.status(400).json({ message: "expireAt must be in the future" });
  }

  const prefix = (req.body.prefix || "MMO").toUpperCase();
  const key = generateLicenseKey(prefix);
  await createLicense({
    licenseKey: key,
    expireAt: expireAtIso.slice(0, 19).replace("T", " "),
    createdBy: req.admin.id
  });

  return res.status(201).json({
    message: "License created",
    data: { key, expireAt: expireAtIso, status: "active" }
  });
}

export async function verifyKey(req, res) {
  const key = req.body.key.trim();
  const hwid = req.body.hwid.trim();
  const ip = getClientIp(req);

  const [failedByIp, failedByHwid, failedByKey] = await Promise.all([
    countRecentFailedAttemptsByIp(ip, env.verifyFailWindowSeconds),
    countRecentFailedAttemptsByHwid(hwid, env.verifyFailWindowSeconds),
    countRecentFailedAttemptsByKey(key, env.verifyFailWindowSeconds)
  ]);

  if (
    failedByIp >= env.verifyFailMaxPerIp ||
    failedByHwid >= env.verifyFailMaxPerHwid ||
    failedByKey >= env.verifyFailMaxPerKey
  ) {
    await writeVerifyLog(req, { key, hwid, isValid: false, reason: "suspicious_repeated_requests" });
    return res.status(429).json({ valid: false, message: "Too many suspicious requests. Try later." });
  }

  const license = await findLicenseByKey(key);
  if (!license) {
    await writeVerifyLog(req, { key, hwid, isValid: false, reason: "key_not_found" });
    return res.status(404).json({ valid: false, message: "License key not found" });
  }

  if (license.status === "banned") {
    await writeVerifyLog(req, { key, hwid, isValid: false, reason: "key_banned" });
    return res.status(403).json({ valid: false, message: "License is banned" });
  }

  const expireAt = new Date(license.expire_at);
  if (expireAt.getTime() <= Date.now()) {
    await markLicenseExpired(key);
    await writeVerifyLog(req, { key, hwid, isValid: false, reason: "key_expired" });
    return res.status(403).json({ valid: false, message: "License expired" });
  }

  if (!license.hwid) {
    await bindLicenseHwid(license.id, hwid);
    const afterBind = await findLicenseByKey(key);
    if (!afterBind || String(afterBind.hwid || "") !== hwid) {
      await writeVerifyLog(req, { key, hwid, isValid: false, reason: "hwid_race_conflict" });
      return res.status(403).json({ valid: false, message: "HWID mismatch" });
    }
    await writeVerifyLog(req, { key, hwid, isValid: true, reason: "hwid_bound_first_time" });
    return res.json({ valid: true, message: "License valid (HWID bound)" });
  }

  if (license.hwid !== hwid) {
    await writeVerifyLog(req, { key, hwid, isValid: false, reason: "hwid_mismatch" });
    return res.status(403).json({ valid: false, message: "HWID mismatch" });
  }

  await writeVerifyLog(req, { key, hwid, isValid: true, reason: "license_valid" });
  return res.json({ valid: true, message: "License valid" });
}

export async function banKey(req, res) {
  const key = req.body.key.trim();
  const affected = await banLicense(key);
  if (!affected) {
    return res.status(404).json({ message: "License key not found" });
  }
  return res.json({ message: "License banned" });
}

export async function removeKey(req, res) {
  const key = req.body.key.trim();
  const affected = await deleteLicense(key);
  if (!affected) {
    return res.status(404).json({ message: "License key not found" });
  }
  return res.json({ message: "License deleted" });
}

export async function listKeys(req, res) {
  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
  const page = Math.max(Number(req.query.page || 1), 1);
  const offset = (page - 1) * limit;

  const rows = await listLicenses({ limit, offset });
  return res.json({ page, limit, data: rows });
}

export async function listLogs(req, res) {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const page = Math.max(Number(req.query.page || 1), 1);
  const offset = (page - 1) * limit;

  const rows = await listVerifyLogs({ limit, offset });
  return res.json({ page, limit, data: rows });
}

