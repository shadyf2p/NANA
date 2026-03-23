import crypto from "crypto";

export function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text), "utf8").digest("hex");
}

export function hmacHex(secret, text) {
  return crypto.createHmac("sha256", String(secret)).update(String(text), "utf8").digest("hex");
}

