import { dbQuery } from "../config/mysql.js";

export async function getAdminByUsername(username) {
  const rows = await dbQuery(
    `SELECT id, username, password_hash, role, is_active, last_login_ip, last_login_at
     FROM admins
     WHERE username = :username
     LIMIT 1`,
    { username }
  );
  return rows[0] || null;
}

export async function getAdminById(id) {
  const rows = await dbQuery(
    `SELECT id, username, role, is_active
     FROM admins
     WHERE id = :id
     LIMIT 1`,
    { id }
  );
  return rows[0] || null;
}

export async function createAdmin({ username, passwordHash, role }) {
  const result = await dbQuery(
    `INSERT INTO admins (username, password_hash, role, is_active)
     VALUES (:username, :passwordHash, :role, 1)`,
    { username, passwordHash, role }
  );
  return result.insertId;
}

export async function touchAdminLogin({ adminId, ip }) {
  await dbQuery(
    `UPDATE admins
     SET last_login_ip = :ip, last_login_at = NOW()
     WHERE id = :adminId`,
    { adminId, ip }
  );
}

