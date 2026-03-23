import { dbQuery } from "../config/mysql.js";

export async function insertLicense({ licenseKeyHash, planCode, expireAt, createdBy }) {
  const result = await dbQuery(
    `INSERT INTO licenses (license_key_hash, plan_code, expire_at, status, created_by)
     VALUES (:licenseKeyHash, :planCode, :expireAt, 'active', :createdBy)`,
    { licenseKeyHash, planCode, expireAt, createdBy }
  );
  return result.insertId;
}

export async function getLicenseByHash(licenseKeyHash) {
  const rows = await dbQuery(
    `SELECT id, license_key_hash, hwid, plan_code, expire_at, status, risk_score, last_ip, last_used_at
     FROM licenses
     WHERE license_key_hash = :licenseKeyHash
     LIMIT 1`,
    { licenseKeyHash }
  );
  return rows[0] || null;
}

export async function updateLicenseUsage({ id, hwid, ip, riskScore }) {
  await dbQuery(
    `UPDATE licenses
     SET hwid = COALESCE(hwid, :hwid),
         last_ip = :ip,
         last_used_at = NOW(),
         risk_score = :riskScore
     WHERE id = :id`,
    { id, hwid, ip, riskScore }
  );
}

export async function markLicenseStatus({ id, status }) {
  await dbQuery(
    `UPDATE licenses
     SET status = :status, updated_at = NOW()
     WHERE id = :id`,
    { id, status }
  );
}

export async function banByHash(licenseKeyHash) {
  const result = await dbQuery(
    `UPDATE licenses
     SET status = 'banned', updated_at = NOW()
     WHERE license_key_hash = :licenseKeyHash`,
    { licenseKeyHash }
  );
  return result.affectedRows || 0;
}

export async function listLicenses({ limit, offset }) {
  return dbQuery(
    `SELECT id, license_key_hash, hwid, plan_code, expire_at, status, risk_score, last_ip, last_used_at, created_at
     FROM licenses
     ORDER BY created_at DESC
     LIMIT :limit OFFSET :offset`,
    { limit, offset }
  );
}

