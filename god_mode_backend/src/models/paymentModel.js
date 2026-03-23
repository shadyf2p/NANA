import { dbQuery } from "../config/mysql.js";

export async function insertPaymentEvent({
  eventId,
  provider,
  eventType,
  paymentRef,
  amountCents,
  currency,
  customerEmail,
  rawJson
}) {
  const result = await dbQuery(
    `INSERT INTO payment_events (
      event_id, provider, event_type, payment_ref, amount_cents, currency, customer_email, raw_json
    ) VALUES (
      :eventId, :provider, :eventType, :paymentRef, :amountCents, :currency, :customerEmail, :rawJson
    )`,
    {
      eventId,
      provider,
      eventType,
      paymentRef: paymentRef || null,
      amountCents: Number(amountCents || 0),
      currency: String(currency || "USD").toUpperCase(),
      customerEmail,
      rawJson: rawJson ? JSON.stringify(rawJson) : null
    }
  );
  return result.insertId;
}

export async function markPaymentEventProcessed(eventId) {
  await dbQuery(
    `UPDATE payment_events
     SET processed_at = NOW()
     WHERE event_id = :eventId`,
    { eventId }
  );
}

export async function upsertCustomerByEmail(email, displayName = "") {
  await dbQuery(
    `INSERT INTO customers (email, display_name)
     VALUES (:email, :displayName)
     ON DUPLICATE KEY UPDATE
       display_name = COALESCE(NULLIF(:displayName, ''), display_name),
       updated_at = NOW()`,
    { email, displayName }
  );
  const rows = await dbQuery(
    `SELECT id, email, display_name
     FROM customers
     WHERE email = :email
     LIMIT 1`,
    { email }
  );
  return rows[0] || null;
}

export async function insertCustomerLicense({
  customerId,
  licenseKeyHash,
  licenseKeyCiphertext,
  keyKid,
  planCode,
  status,
  expireAt,
  deliveryTokenHash,
  deliveryExpiresAt
}) {
  const result = await dbQuery(
    `INSERT INTO customer_licenses (
      customer_id, license_key_hash, license_key_ciphertext, key_kid, plan_code, status, expire_at,
      delivery_token_hash, delivery_expires_at
    ) VALUES (
      :customerId, :licenseKeyHash, :licenseKeyCiphertext, :keyKid, :planCode, :status, :expireAt,
      :deliveryTokenHash, :deliveryExpiresAt
    )`,
    {
      customerId,
      licenseKeyHash,
      licenseKeyCiphertext,
      keyKid,
      planCode,
      status,
      expireAt,
      deliveryTokenHash: deliveryTokenHash || null,
      deliveryExpiresAt: deliveryExpiresAt || null
    }
  );
  return result.insertId;
}

export async function getCustomerLicensesByDeliveryTokenHash(tokenHash) {
  const rows = await dbQuery(
    `SELECT
      cl.id, cl.license_key_hash, cl.license_key_ciphertext, cl.key_kid, cl.plan_code, cl.status, cl.expire_at, cl.issued_at,
      c.email, c.display_name
     FROM customer_licenses cl
     JOIN customers c ON c.id = cl.customer_id
     WHERE cl.delivery_token_hash = :tokenHash
       AND cl.delivery_expires_at > NOW()
     ORDER BY cl.issued_at DESC`,
    { tokenHash }
  );
  return rows;
}

export async function markDeliveryTokenUsed(tokenHash) {
  await dbQuery(
    `UPDATE customer_licenses
     SET delivery_used_at = NOW()
     WHERE delivery_token_hash = :tokenHash AND delivery_used_at IS NULL`,
    { tokenHash }
  );
}

