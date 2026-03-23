export function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || "0.0.0.0";
}

export function getGeoCountryHint(req) {
  const headersToTry = [
    "cf-ipcountry",
    "x-country-code",
    "x-vercel-ip-country",
    "x-geo-country"
  ];
  for (const key of headersToTry) {
    const value = String(req.headers[key] || "").trim();
    if (value) return value.toUpperCase().slice(0, 16);
  }
  return "";
}

export function getIpPrefix(ip) {
  const raw = String(ip || "").trim();
  if (!raw) return "";
  if (raw.includes(".")) {
    const p = raw.split(".");
    return `${p[0] || ""}.${p[1] || ""}`;
  }
  if (raw.includes(":")) {
    const p = raw.split(":");
    return `${p[0] || ""}:${p[1] || ""}`;
  }
  return raw;
}

