export function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return (
    req.ip ||
    req.socket?.remoteAddress ||
    "0.0.0.0"
  );
}

