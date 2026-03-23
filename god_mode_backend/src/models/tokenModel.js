import { dbQuery } from "../config/mysql.js";

export async function createRefreshTokenRow({ adminId, tokenHash, issuedIp, userAgent, expiresAt }) {
  const result = await dbQuery(
    `INSERT INTO refresh_tokens (admin_id, token_hash, issued_ip, user_agent, expires_at)
     VALUES (:adminId, :tokenHash, :issuedIp, :userAgent, :expiresAt)`,
    { adminId, tokenHash, issuedIp, userAgent, expiresAt }
  );
  return result.insertId;
}

export async function getRefreshTokenRow(tokenHash) {
  const rows = await dbQuery(
    `SELECT id, admin_id, token_hash, issued_ip, user_agent, expires_at, revoked_at
     FROM refresh_tokens
     WHERE token_hash = :tokenHash
     LIMIT 1`,
    { tokenHash }
  );
  return rows[0] || null;
}

export async function revokeRefreshToken(tokenHash) {
  await dbQuery(
    `UPDATE refresh_tokens
     SET revoked_at = NOW()
     WHERE token_hash = :tokenHash AND revoked_at IS NULL`,
    { tokenHash }
  );
}

