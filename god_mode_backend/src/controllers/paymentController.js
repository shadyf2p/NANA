import crypto from "crypto";
import { env } from "../config/env.js";
import { insertLicense } from "../models/licenseModel.js";
import {
  getCustomerLicensesByDeliveryTokenHash,
  insertCustomerLicense,
  insertPaymentEvent,
  markDeliveryTokenUsed,
  markPaymentEventProcessed,
  upsertCustomerByEmail
} from "../models/paymentModel.js";
import { getActiveKid, decryptEnvelope, encryptEnvelope } from "../utils/cryptoEnvelope.js";
import { hmacHex, sha256Hex } from "../utils/hash.js";
import { generatePlainLicense } from "../utils/licenseGen.js";

function signWebhookShape(body) {
  const parts = [
    String(body.event_id || ""),
    String(body.event_type || ""),
    String(body.payment_ref || ""),
    String(body.customer_email || "").toLowerCase(),
    String(body.amount_cents || 0),
    String(body.currency || "").toUpperCase()
  ];
  return hmacHex(env.paymentWebhookSecret || "", parts.join("|"));
}

function portalTokenExpiresAt(hours) {
  const d = new Date();
  d.setHours(d.getHours() + hours);
  return d;
}

function normalizeStatusByExpire(expireAt) {
  return new Date(expireAt).getTime() > Date.now() ? "active" : "expired";
}

export async function paymentWebhook(req, res) {
  if (!env.paymentWebhookSecret) {
    return res.status(503).json({ message: "payment_webhook_not_configured" });
  }
  const signature = String(req.headers["x-webhook-signature"] || "").trim();
  const expectedSig = signWebhookShape(req.body);
  const sigA = Buffer.from(signature);
  const sigB = Buffer.from(expectedSig);
  if (!signature || sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
    return res.status(401).json({ message: "invalid_webhook_signature" });
  }

  const body = req.body;
  const eventType = String(body.event_type || "");

  try {
    await insertPaymentEvent({
      eventId: body.event_id,
      provider: body.provider,
      eventType,
      paymentRef: body.payment_ref,
      amountCents: body.amount_cents,
      currency: body.currency,
      customerEmail: String(body.customer_email || "").toLowerCase(),
      rawJson: body
    });
  } catch (err) {
    if (String(err?.code || "") === "ER_DUP_ENTRY") {
      return res.json({ ok: true, deduplicated: true });
    }
    throw err;
  }

  if (eventType !== "payment.succeeded" && eventType !== "checkout.completed") {
    await markPaymentEventProcessed(body.event_id);
    return res.json({ ok: true, ignored: true });
  }

  const customer = await upsertCustomerByEmail(
    String(body.customer_email || "").toLowerCase(),
    String(body.customer_name || "")
  );
  const durationDays = Number(body.duration_days || env.paymentDefaultDurationDays || 30);
  const planCode = String(body.plan_code || "basic").toLowerCase();
  const plainKey = generatePlainLicense(env.paymentLicensePrefix || "PAY");
  const keyHash = sha256Hex(plainKey.toUpperCase());
  const expireAt = new Date(Date.now() + durationDays * 86400 * 1000);
  const status = normalizeStatusByExpire(expireAt);

  await insertLicense({
    licenseKeyHash: keyHash,
    planCode,
    expireAt,
    createdBy: null
  });

  const deliveryToken = crypto.randomBytes(24).toString("base64url");
  const deliveryTokenHash = sha256Hex(deliveryToken);
  const keyKid = getActiveKid();
  const licenseCipher = encryptEnvelope(
    {
      license_key: plainKey,
      license_key_hash: keyHash,
      plan_code: planCode,
      expire_at: expireAt.toISOString()
    },
    keyKid
  );
  await insertCustomerLicense({
    customerId: customer.id,
    licenseKeyHash: keyHash,
    licenseKeyCiphertext: licenseCipher,
    keyKid,
    planCode,
    status,
    expireAt,
    deliveryTokenHash,
    deliveryExpiresAt: portalTokenExpiresAt(env.customerPortalTokenTtlHours)
  });

  await markPaymentEventProcessed(body.event_id);

  return res.json({
    ok: true,
    auto_issued: true,
    delivery_token: deliveryToken,
    dashboard_url: `/api/public/dashboard/licenses?token=${encodeURIComponent(deliveryToken)}`,
    license_key_hash: keyHash
  });
}

export async function dashboardLicenses(req, res) {
  const token = String(req.query.token || "").trim();
  const tokenHash = sha256Hex(token);
  const rows = await getCustomerLicensesByDeliveryTokenHash(tokenHash);
  if (!rows.length) {
    return res.status(404).json({ message: "dashboard_token_invalid_or_expired" });
  }

  const data = rows.map((r) => {
    let plain = "";
    try {
      const obj = decryptEnvelope(String(r.license_key_ciphertext || ""), String(r.key_kid || ""));
      plain = String(obj.license_key || "");
    } catch (_err) {
      plain = "";
    }
    return {
      email: r.email,
      customer_name: r.display_name || "",
      license_key: plain,
      license_key_hash: r.license_key_hash,
      plan_code: r.plan_code,
      status: r.status,
      expire_at: r.expire_at,
      issued_at: r.issued_at
    };
  });

  await markDeliveryTokenUsed(tokenHash);
  return res.json({ ok: true, data });
}

