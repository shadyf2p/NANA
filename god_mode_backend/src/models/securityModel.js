import { dbQuery } from "../config/mysql.js";

export async function isIpBanned(ip) {
  const rows = await dbQuery(
    `SELECT id, ip, reason, expires_at
     FROM ip_bans
     WHERE ip = :ip AND expires_at > NOW()
     ORDER BY expires_at DESC
     LIMIT 1`,
    { ip }
  );
  return rows[0] || null;
}

export async function createOrExtendIpBan({ ip, reason, durationSeconds }) {
  await dbQuery(
    `INSERT INTO ip_bans (ip, reason, expires_at)
     VALUES (:ip, :reason, DATE_ADD(NOW(), INTERVAL :durationSeconds SECOND))`,
    { ip, reason, durationSeconds }
  );
}

export async function insertAdminSecurityLog({ adminId, username, ip, eventType, detail }) {
  await dbQuery(
    `INSERT INTO admin_security_logs (admin_id, username, ip, event_type, detail)
     VALUES (:adminId, :username, :ip, :eventType, :detail)`,
    {
      adminId: adminId || null,
      username,
      ip,
      eventType,
      detail: detail || null
    }
  );
}

