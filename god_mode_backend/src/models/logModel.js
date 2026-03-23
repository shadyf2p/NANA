import { dbQuery } from "../config/mysql.js";

export async function insertVerifyLog({
  licenseKeyHash,
  hwid,
  ip,
  geoCountry,
  userAgent,
  valid,
  reason,
  riskScore,
  requestFrequency,
  metadataJson
}) {
  await dbQuery(
    `INSERT INTO verify_logs (
      license_key_hash, hwid, ip, geo_country, user_agent, valid, reason, risk_score, request_frequency, metadata_json
    ) VALUES (
      :licenseKeyHash, :hwid, :ip, :geoCountry, :userAgent, :valid, :reason, :riskScore, :requestFrequency, :metadataJson
    )`,
    {
      licenseKeyHash,
      hwid: hwid || null,
      ip,
      geoCountry: geoCountry || null,
      userAgent: userAgent || null,
      valid: valid ? 1 : 0,
      reason,
      riskScore,
      requestFrequency: Number(requestFrequency || 0),
      metadataJson: metadataJson ? JSON.stringify(metadataJson) : null
    }
  );
}

export async function listVerifyLogs({ limit, offset }) {
  return dbQuery(
    `SELECT id, license_key_hash, hwid, ip, user_agent, valid, reason, risk_score, metadata_json, created_at
     FROM verify_logs
     ORDER BY created_at DESC
     LIMIT :limit OFFSET :offset`,
    { limit, offset }
  );
}

