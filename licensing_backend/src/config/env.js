import dotenv from "dotenv";

dotenv.config();

function readEnv(name, fallback = "") {
  const value = process.env[name];
  return value === undefined ? fallback : String(value).trim();
}

function readNumber(name, fallback) {
  const raw = readEnv(name, String(fallback));
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function readRequired(name) {
  const value = readEnv(name, "");
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const env = {
  nodeEnv: readEnv("NODE_ENV", "development"),
  port: readNumber("PORT", 8080),

  dbHost: readEnv("DB_HOST", "127.0.0.1"),
  dbPort: readNumber("DB_PORT", 3306),
  dbUser: readRequired("DB_USER"),
  dbPassword: readEnv("DB_PASSWORD", ""),
  dbName: readRequired("DB_NAME"),
  dbConnLimit: readNumber("DB_CONN_LIMIT", 10),

  jwtSecret: readRequired("JWT_SECRET"),
  jwtExpiresIn: readEnv("JWT_EXPIRES_IN", "2h"),

  corsOrigins: readEnv("CORS_ORIGINS", "http://localhost:5173")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),

  seedAdminUsername: readEnv("SEED_ADMIN_USERNAME", "admin"),
  seedAdminPassword: readEnv("SEED_ADMIN_PASSWORD", "ChangeThisStrongPassword!"),

  verifyFailWindowSeconds: readNumber("VERIFY_FAIL_WINDOW_SECONDS", 600),
  verifyFailMaxPerIp: readNumber("VERIFY_FAIL_MAX_PER_IP", 40),
  verifyFailMaxPerHwid: readNumber("VERIFY_FAIL_MAX_PER_HWID", 25),
  verifyFailMaxPerKey: readNumber("VERIFY_FAIL_MAX_PER_KEY", 25),
  verifyRateLimitPerMinute: readNumber("VERIFY_RATE_LIMIT_PER_MINUTE", 120)
};

