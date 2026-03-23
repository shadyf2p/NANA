import crypto from "crypto";

export function generateLicenseKey(prefix = "MMO") {
  const random = crypto.randomBytes(16).toString("hex").toUpperCase();
  const groupA = random.slice(0, 8);
  const groupB = random.slice(8, 16);
  const groupC = random.slice(16, 24);
  const groupD = random.slice(24, 32);
  return `${prefix}-${groupA}-${groupB}-${groupC}-${groupD}`;
}

