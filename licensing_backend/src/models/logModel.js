import { query } from "../config/db.js";

export async function createVerifyLog({ licenseKey, hwid, ip, userAgent, isValid, reason }) {
  await query(
    `INSERT INTO verify_logs (license_key, hwid, ip, user_agent, is_valid, reason)
     VALUES (:licenseKey, :hwid, :ip, :userAgent, :isValid, :reason)`,
    { licenseKey, hwid, ip, userAgent, isValid: isValid ? 1 : 0, reason }
  );
}

export async function countRecentFailedAttemptsByIp(ip, windowSeconds) {
  const cutoff = new Date(Date.now() - windowSeconds * 1000);
  const rows = await query(
    `SELECT COUNT(*) AS total
     FROM verify_logs
     WHERE ip = :ip
       AND is_valid = 0
       AND created_at >= :cutoff`,
    { ip, cutoff }
  );
  return Number(rows[0]?.total || 0);
}

export async function countRecentFailedAttemptsByHwid(hwid, windowSeconds) {
  if (!hwid) return 0;
  const cutoff = new Date(Date.now() - windowSeconds * 1000);
  const rows = await query(
    `SELECT COUNT(*) AS total
     FROM verify_logs
     WHERE hwid = :hwid
       AND is_valid = 0
       AND created_at >= :cutoff`,
    { hwid, cutoff }
  );
  return Number(rows[0]?.total || 0);
}

export async function countRecentFailedAttemptsByKey(licenseKey, windowSeconds) {
  const cutoff = new Date(Date.now() - windowSeconds * 1000);
  const rows = await query(
    `SELECT COUNT(*) AS total
     FROM verify_logs
     WHERE license_key = :licenseKey
       AND is_valid = 0
       AND created_at >= :cutoff`,
    { licenseKey, cutoff }
  );
  return Number(rows[0]?.total || 0);
}

export async function listVerifyLogs({ limit, offset }) {
  const rows = await query(
    `SELECT id, license_key, hwid, ip, user_agent, is_valid, reason, created_at
     FROM verify_logs
     ORDER BY created_at DESC
     LIMIT :limit OFFSET :offset`,
    { limit, offset }
  );
  return rows;
}

