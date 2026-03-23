import { env } from "../config/env.js";
import { decryptEnvelope, encryptEnvelope, getActiveKid, safeEqualHex, signRequestShape } from "../utils/cryptoEnvelope.js";
import { sha256Hex } from "../utils/hash.js";
import { consumeNonceOnce } from "../services/nonceService.js";
import { getClientIp, getGeoCountryHint } from "../utils/network.js";
import {
  getFailureCounter,
  hitRateLimit,
  incrementFailureCounter,
  readRateWindowCount
} from "../services/rateService.js";
import {
  getLicenseByHash,
  markLicenseStatus,
  updateLicenseUsage
} from "../models/licenseModel.js";
import { insertVerifyLog } from "../models/logModel.js";
import { buildExecutionInstructions } from "../services/executionService.js";
import { computeRisk, shouldAutoSuspend } from "../services/riskService.js";
import { createOrExtendIpBan, isIpBanned } from "../models/securityModel.js";

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

async function fail(req, res, {
  keyHash = "",
  hwid = "",
  reason,
  statusCode = 403,
  riskScore = 0,
  extra = {}
}) {
  const ip = getClientIp(req);
  const responseKid = getActiveKid();
  const geoCountry = getGeoCountryHint(req);
  const requestFrequency = await readRateWindowCount({
    scope: "verify:ip",
    key: ip,
    windowSeconds: 60
  });
  if (ip) await incrementFailureCounter({ dim: "ip", key: ip, windowSeconds: env.verifyFailWindowSeconds });
  if (keyHash) await incrementFailureCounter({ dim: "key", key: keyHash, windowSeconds: env.verifyFailWindowSeconds });
  if (hwid) await incrementFailureCounter({ dim: "hwid", key: hwid, windowSeconds: env.verifyFailWindowSeconds });

  const failByIp = ip ? await getFailureCounter({ dim: "ip", key: ip }) : 0;
  if (ip && failByIp >= env.autoBanIpFailThreshold) {
    await createOrExtendIpBan({
      ip,
      reason: `auto_ban:${reason};fails=${failByIp}`,
      durationSeconds: env.autoBanIpDurationSeconds
    });
  }

  await insertVerifyLog({
    licenseKeyHash: keyHash || "-",
    hwid: hwid || null,
    ip,
    geoCountry,
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
    valid: false,
    reason,
    riskScore,
    requestFrequency,
    metadataJson: extra
  });

  const plain = {
    valid: false,
    message: reason,
    server_time: nowSeconds(),
    instructions: [{ op: "runtime.exit", reason }]
  };
  const encrypted_payload = encryptEnvelope(plain, responseKid);
  const timestamp = nowSeconds();
  const nonce = `srv-${Date.now().toString(36)}`;
  const signature = signRequestShape(encrypted_payload, timestamp, nonce, responseKid);
  return res.status(statusCode).json({ kid: responseKid, encrypted_payload, timestamp, nonce, signature });
}

export async function verify(req, res) {
  const ip = getClientIp(req);
  const requestKid = String(req.body.kid || "v1");
  const banned = await isIpBanned(ip);
  if (banned) {
    return fail(req, res, {
      reason: "ip_banned",
      statusCode: 403,
      extra: { ban_reason: banned.reason, ban_expires_at: banned.expires_at }
    });
  }

  const ipRate = await hitRateLimit({
    scope: "verify:ip",
    key: ip,
    windowSeconds: 60,
    max: env.verifyRateLimitPerMin
  });
  if (ipRate.limited) {
    return fail(req, res, { reason: "rate_limited", statusCode: 429 });
  }

  const { encrypted_payload, timestamp, nonce, signature } = req.body;
  let expectedSig = "";
  try {
    expectedSig = signRequestShape(encrypted_payload, timestamp, nonce, requestKid);
  } catch (_err) {
    return fail(req, res, { reason: "unknown_request_kid", statusCode: 401 });
  }
  if (!safeEqualHex(signature, expectedSig)) {
    return fail(req, res, { reason: "bad_signature", statusCode: 401 });
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(nowSeconds() - ts) > env.maxClockSkewSeconds) {
    return fail(req, res, { reason: "clock_skew_rejected", statusCode: 401 });
  }

  const nonceOk = await consumeNonceOnce(String(nonce || ""));
  if (!nonceOk) {
    return fail(req, res, { reason: "nonce_replay_detected", statusCode: 401 });
  }

  let payload;
  try {
    payload = decryptEnvelope(encrypted_payload, requestKid);
  } catch (_err) {
    return fail(req, res, { reason: "decrypt_failed", statusCode: 400 });
  }

  const licensePlain = String(payload.license_key || "").trim().toUpperCase();
  const hwid = String(payload.hwid || "").trim();
  if (!licensePlain || !hwid) {
    return fail(req, res, { reason: "invalid_payload_fields", statusCode: 400 });
  }
  const keyHash = sha256Hex(licensePlain);

  const [fIp, fKey, fHwid] = await Promise.all([
    getFailureCounter({ dim: "ip", key: ip }),
    getFailureCounter({ dim: "key", key: keyHash }),
    getFailureCounter({ dim: "hwid", key: hwid })
  ]);
  if (fIp >= env.verifyFailMaxPerIp || fKey >= env.verifyFailMaxPerKey || fHwid >= env.verifyFailMaxPerHwid) {
    return fail(req, res, {
      keyHash,
      hwid,
      reason: "suspicious_repeated_requests",
      statusCode: 429
    });
  }

  const lic = await getLicenseByHash(keyHash);
  if (!lic) {
    return fail(req, res, { keyHash, hwid, reason: "license_not_found", statusCode: 404 });
  }
  if (String(lic.status) === "banned") {
    return fail(req, res, { keyHash, hwid, reason: "license_banned", statusCode: 403, riskScore: Number(lic.risk_score || 0) });
  }
  if (new Date(lic.expire_at).getTime() <= Date.now()) {
    await markLicenseStatus({ id: lic.id, status: "expired" });
    return fail(req, res, { keyHash, hwid, reason: "license_expired", statusCode: 403, riskScore: Number(lic.risk_score || 0) });
  }

  const ipChanged = !!lic.last_ip && String(lic.last_ip) !== ip;
  const hwidMismatch = !!lic.hwid && String(lic.hwid) !== hwid;
  const geoCountry = getGeoCountryHint(req);
  const requestFrequency = await readRateWindowCount({
    scope: "verify:ip",
    key: ip,
    windowSeconds: 60
  });
  const riskScore = computeRisk({
    previousRiskScore: lic.risk_score,
    ipChanged,
    hwidMismatch,
    failByIp: fIp,
    failByKey: fKey,
    failByHwid: fHwid,
    requestFrequency,
    geoCountry
  });

  if (hwidMismatch) {
    return fail(req, res, { keyHash, hwid, reason: "hwid_mismatch", statusCode: 403, riskScore });
  }

  if (shouldAutoSuspend(riskScore)) {
    await markLicenseStatus({ id: lic.id, status: "suspended" });
    return fail(req, res, { keyHash, hwid, reason: "license_auto_suspended", statusCode: 403, riskScore });
  }

  await updateLicenseUsage({
    id: lic.id,
    hwid,
    ip,
    riskScore
  });

  const exec = await buildExecutionInstructions({
    planCode: String(lic.plan_code || "basic"),
    riskScore,
    context: {
      ipChanged,
      requestFrequency,
      geoCountry
    }
  });

  await insertVerifyLog({
    licenseKeyHash: keyHash,
    hwid,
    ip,
    geoCountry,
    userAgent: String(req.headers["user-agent"] || "").slice(0, 512),
    valid: true,
    reason: "ok",
    riskScore,
    requestFrequency,
    metadataJson: {
      plan: lic.plan_code,
      policyVersion: exec.policyVersion,
      ipChanged,
      failByIp: fIp,
      failByKey: fKey,
      failByHwid: fHwid
    }
  });

  const plain = {
    valid: true,
    message: "license_ok",
    server_time: nowSeconds(),
    risk_score: riskScore,
    plan_code: lic.plan_code,
    policy_version: exec.policyVersion,
    instructions: exec.instructions,
    signed_meta: {
      req_freq_1m: requestFrequency,
      geo_country: geoCountry || null
    }
  };
  const responseKid = getActiveKid();
  const outPayload = encryptEnvelope(plain, responseKid);
  const outTs = nowSeconds();
  const outNonce = `srv-${Date.now().toString(36)}`;
  const outSig = signRequestShape(outPayload, outTs, outNonce, responseKid);
  return res.json({
    kid: responseKid,
    encrypted_payload: outPayload,
    timestamp: outTs,
    nonce: outNonce,
    signature: outSig
  });
}

