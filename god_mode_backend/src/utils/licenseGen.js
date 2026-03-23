import crypto from "crypto";

export function generatePlainLicense(prefix = "PAY") {
  const bytes = crypto.randomBytes(16).toString("hex").toUpperCase();
  return `${prefix}-${bytes.slice(0, 8)}-${bytes.slice(8, 16)}-${bytes.slice(16, 24)}-${bytes.slice(24, 32)}`;
}

