import { query } from "../config/db.js";

export async function createLicense({ licenseKey, expireAt, createdBy }) {
  const result = await query(
    `INSERT INTO licenses (license_key, hwid, expire_at, status, created_by)
     VALUES (:licenseKey, NULL, :expireAt, 'active', :createdBy)`,
    { licenseKey, expireAt, createdBy }
  );
  return result.insertId;
}

export async function findLicenseByKey(licenseKey) {
  const rows = await query(
    `SELECT id, license_key, hwid, expire_at, status, created_at, updated_at
     FROM licenses
     WHERE license_key = :licenseKey
     LIMIT 1`,
    { licenseKey }
  );
  return rows[0] || null;
}

export async function bindLicenseHwid(licenseId, hwid) {
  await query(
    `UPDATE licenses
     SET hwid = :hwid, updated_at = CURRENT_TIMESTAMP
     WHERE id = :licenseId AND hwid IS NULL`,
    { licenseId, hwid }
  );
}

export async function banLicense(licenseKey) {
  const result = await query(
    `UPDATE licenses
     SET status = 'banned', updated_at = CURRENT_TIMESTAMP
     WHERE license_key = :licenseKey`,
    { licenseKey }
  );
  return result.affectedRows || 0;
}

export async function markLicenseExpired(licenseKey) {
  await query(
    `UPDATE licenses
     SET status = 'expired', updated_at = CURRENT_TIMESTAMP
     WHERE license_key = :licenseKey AND status <> 'expired'`,
    { licenseKey }
  );
}

export async function deleteLicense(licenseKey) {
  const result = await query(
    `DELETE FROM licenses WHERE license_key = :licenseKey`,
    { licenseKey }
  );
  return result.affectedRows || 0;
}

export async function listLicenses({ limit, offset }) {
  const rows = await query(
    `SELECT id, license_key, hwid, expire_at, status, created_at, updated_at
     FROM licenses
     ORDER BY created_at DESC
     LIMIT :limit OFFSET :offset`,
    { limit, offset }
  );
  return rows;
}

