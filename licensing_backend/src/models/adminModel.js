import { query } from "../config/db.js";

export async function findAdminByUsername(username) {
  const rows = await query(
    `SELECT id, username, password_hash, is_active
     FROM admins
     WHERE username = :username
     LIMIT 1`,
    { username }
  );
  return rows[0] || null;
}

export async function createAdmin(username, passwordHash) {
  const result = await query(
    `INSERT INTO admins (username, password_hash, is_active)
     VALUES (:username, :passwordHash, 1)`,
    { username, passwordHash }
  );
  return result.insertId;
}

