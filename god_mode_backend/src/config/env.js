import dotenv from "dotenv";

dotenv.config();

function read(name, fallback = "") {
  const value = process.env[name];
  return value === undefined ? fallback : String(value).trim();
}

function readNum(name, fallback) {
  const n = Number(read(name, String(fallback)));
  return Number.isFinite(n) ? n : fallback;
}

function required(name) {
  const value = read(name, "");
  if (!value) throw new Error(`Missing env: ${name}`);
  return value;
}

function parseKeyJsonMap(raw, label) {
  let parsed;
  try {
    parsed = JSON.parse(String(raw || "{}"));
  } catch (_err) {
    throw new Error(`${label} must be valid JSON object`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed;
}

export const env = {
  nodeEnv: read("NODE_ENV", "development"),
  port: readNum("PORT", 8081),

  mysqlHost: read("MYSQL_HOST", "127.0.0.1"),
  mysqlPort: readNum("MYSQL_PORT", 3306),
  mysqlUser: required("MYSQL_USER"),
  mysqlPassword: read("MYSQL_PASSWORD", ""),
  mysqlDatabase: required("MYSQL_DATABASE"),
  mysqlPoolSize: readNum("MYSQL_POOL_SIZE", 12),

  redisUrl: required("REDIS_URL"),

  jwtAccessSecret: required("JWT_ACCESS_SECRET"),
  jwtRefreshSecret: required("JWT_REFRESH_SECRET"),
  jwtAccessExpires: read("JWT_ACCESS_EXPIRES", "15m"),
  jwtRefreshExpires: read("JWT_REFRESH_EXPIRES", "7d"),

  commActiveKid: read("COMM_ACTIVE_KID", "v1"),
  commAesKeysJson: parseKeyJsonMap(
    read("COMM_AES_KEYS_JSON", JSON.stringify({ v1: required("COMM_AES_KEY_B64") })),
    "COMM_AES_KEYS_JSON"
  ),
  commHmacKeysJson: parseKeyJsonMap(
    read("COMM_HMAC_KEYS_JSON", JSON.stringify({ v1: required("COMM_HMAC_SECRET") })),
    "COMM_HMAC_KEYS_JSON"
  ),
  maxClockSkewSeconds: readNum("MAX_CLOCK_SKEW_SECONDS", 120),
  nonceTtlSeconds: readNum("NONCE_TTL_SECONDS", 300),

  verifyRateLimitPerMin: readNum("VERIFY_RATE_LIMIT_PER_MIN", 120),
  verifyFailWindowSeconds: readNum("VERIFY_FAIL_WINDOW_SECONDS", 600),
  verifyFailMaxPerIp: readNum("VERIFY_FAIL_MAX_PER_IP", 50),
  verifyFailMaxPerKey: readNum("VERIFY_FAIL_MAX_PER_KEY", 35),
  verifyFailMaxPerHwid: readNum("VERIFY_FAIL_MAX_PER_HWID", 30),
  autoBanIpFailThreshold: readNum("AUTO_BAN_IP_FAIL_THRESHOLD", 120),
  autoBanIpDurationSeconds: readNum("AUTO_BAN_IP_DURATION_SECONDS", 3600),
  adminIpAnomalyDistance: readNum("ADMIN_IP_ANOMALY_DISTANCE", 1),

  seedAdminUsername: read("SEED_ADMIN_USERNAME", "admin"),
  seedAdminPassword: read("SEED_ADMIN_PASSWORD", "ChangeMeStrong123!"),
  seedAdminRole: read("SEED_ADMIN_ROLE", "owner"),

  paymentWebhookSecret: read("PAYMENT_WEBHOOK_SECRET", ""),
  paymentDefaultDurationDays: readNum("PAYMENT_DEFAULT_DURATION_DAYS", 30),
  paymentLicensePrefix: read("PAYMENT_LICENSE_PREFIX", "PAY"),
  customerPortalTokenTtlHours: readNum("CUSTOMER_PORTAL_TOKEN_TTL_HOURS", 72),

  corsOrigins: read("CORS_ORIGINS", "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
};

