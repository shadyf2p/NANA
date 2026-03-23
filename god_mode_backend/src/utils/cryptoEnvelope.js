import crypto from "crypto";
import { env } from "../config/env.js";
import { hmacHex } from "./hash.js";

const AES_KEYS = Object.fromEntries(
  Object.entries(env.commAesKeysJson).map(([kid, keyB64]) => {
    const buf = Buffer.from(String(keyB64 || ""), "base64");
    if (buf.length !== 32) {
      throw new Error(`AES key for kid=${kid} must decode to 32 bytes`);
    }
    return [kid, buf];
  })
);

const HMAC_KEYS = Object.fromEntries(
  Object.entries(env.commHmacKeysJson).map(([kid, secret]) => [kid, String(secret || "")])
);

if (!AES_KEYS[env.commActiveKid] || !HMAC_KEYS[env.commActiveKid]) {
  throw new Error(`COMM_ACTIVE_KID=${env.commActiveKid} not found in key maps`);
}

function resolveAesKey(kid) {
  const key = AES_KEYS[String(kid || "")];
  if (!key) throw new Error("unknown_key_id");
  return key;
}

function resolveHmacSecret(kid) {
  const secret = HMAC_KEYS[String(kid || "")];
  if (!secret) throw new Error("unknown_hmac_key_id");
  return secret;
}

export function getActiveKid() {
  return env.commActiveKid;
}

export function encryptEnvelope(plainObj, kid = getActiveKid()) {
  const AES_KEY = resolveAesKey(kid);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
  const plain = Buffer.from(JSON.stringify(plainObj), "utf8");
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

export function decryptEnvelope(payloadB64, kid) {
  const AES_KEY = resolveAesKey(kid);
  const blob = Buffer.from(String(payloadB64 || ""), "base64");
  if (blob.length < 12 + 16 + 1) {
    throw new Error("invalid_encrypted_payload");
  }
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const encrypted = blob.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  return JSON.parse(plain);
}

export function signRequestShape(encryptedPayload, timestamp, nonce, kid = getActiveKid()) {
  const secret = resolveHmacSecret(kid);
  const message = `${encryptedPayload}.${timestamp}.${nonce}`;
  return hmacHex(secret, message);
}

export function safeEqualHex(a, b) {
  try {
    const A = Buffer.from(String(a || ""), "hex");
    const B = Buffer.from(String(b || ""), "hex");
    if (A.length === 0 || B.length === 0 || A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch (_err) {
    return false;
  }
}

