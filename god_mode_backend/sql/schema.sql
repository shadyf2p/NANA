CREATE DATABASE IF NOT EXISTS god_mode_licensing
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE god_mode_licensing;

CREATE TABLE IF NOT EXISTS admins (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('owner', 'admin', 'support', 'viewer') NOT NULL DEFAULT 'admin',
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  last_login_ip VARCHAR(64) NULL,
  last_login_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_admin_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  admin_id BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,
  issued_ip VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512) NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_refresh_token_hash (token_hash),
  KEY idx_refresh_admin (admin_id),
  CONSTRAINT fk_refresh_admin FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS licenses (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  license_key_hash CHAR(64) NOT NULL,
  hwid VARCHAR(128) NULL,
  plan_code VARCHAR(32) NOT NULL DEFAULT 'basic',
  expire_at TIMESTAMP NOT NULL,
  status ENUM('active', 'banned', 'expired', 'suspended') NOT NULL DEFAULT 'active',
  risk_score INT NOT NULL DEFAULT 0,
  last_ip VARCHAR(64) NULL,
  last_used_at TIMESTAMP NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_license_hash (license_key_hash),
  KEY idx_license_status_expire (status, expire_at),
  CONSTRAINT fk_license_admin FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS execution_policies (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  plan_code VARCHAR(32) NOT NULL,
  version INT NOT NULL DEFAULT 1,
  policy_json JSON NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_policy_lookup (plan_code, is_active, version)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS verify_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  license_key_hash CHAR(64) NOT NULL,
  hwid VARCHAR(128) NULL,
  ip VARCHAR(64) NOT NULL,
  geo_country VARCHAR(16) NULL,
  user_agent VARCHAR(512) NULL,
  valid TINYINT(1) NOT NULL,
  reason VARCHAR(128) NOT NULL,
  risk_score INT NOT NULL DEFAULT 0,
  request_frequency INT NOT NULL DEFAULT 0,
  metadata_json JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_verify_time (created_at),
  KEY idx_verify_ip_time (ip, created_at),
  KEY idx_verify_hash_time (license_key_hash, created_at),
  KEY idx_verify_hwid_time (hwid, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ip_bans (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(64) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_ip_bans_lookup (ip, expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS admin_security_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  admin_id BIGINT UNSIGNED NULL,
  username VARCHAR(64) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_admin_sec_time (created_at),
  KEY idx_admin_sec_user (username, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS customers (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(191) NOT NULL,
  display_name VARCHAR(120) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_customers_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS payment_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  event_id VARCHAR(128) NOT NULL,
  provider VARCHAR(32) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  payment_ref VARCHAR(128) NULL,
  amount_cents BIGINT NOT NULL DEFAULT 0,
  currency VARCHAR(16) NOT NULL DEFAULT 'USD',
  customer_email VARCHAR(191) NOT NULL,
  raw_json JSON NULL,
  processed_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_payment_event_id (event_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS customer_licenses (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  customer_id BIGINT UNSIGNED NOT NULL,
  license_key_hash CHAR(64) NOT NULL,
  license_key_ciphertext TEXT NOT NULL,
  key_kid VARCHAR(32) NOT NULL DEFAULT 'v1',
  plan_code VARCHAR(32) NOT NULL DEFAULT 'basic',
  status ENUM('active', 'expired', 'banned', 'suspended') NOT NULL DEFAULT 'active',
  expire_at TIMESTAMP NOT NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delivery_token_hash CHAR(64) NULL,
  delivery_expires_at TIMESTAMP NULL,
  delivery_used_at TIMESTAMP NULL,
  PRIMARY KEY (id),
  KEY idx_customer_licenses_customer (customer_id, issued_at),
  KEY idx_customer_licenses_delivery (delivery_token_hash, delivery_expires_at),
  CONSTRAINT fk_customer_licenses_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
) ENGINE=InnoDB;

INSERT INTO execution_policies (plan_code, version, policy_json, is_active)
VALUES
(
  'basic',
  1,
  JSON_OBJECT(
    'instructions', JSON_ARRAY(
      JSON_OBJECT('op', 'feature.toggle', 'feature', 'market_scanner', 'enabled', true),
      JSON_OBJECT('op', 'feature.toggle', 'feature', 'bulk_automation', 'enabled', false),
      JSON_OBJECT('op', 'runtime.set', 'key', 'max_parallel_jobs', 'value', 1),
      JSON_OBJECT('op', 'runtime.set', 'key', 'heartbeat_seconds', 'value', 120)
    )
  ),
  1
),
(
  'pro',
  1,
  JSON_OBJECT(
    'instructions', JSON_ARRAY(
      JSON_OBJECT('op', 'feature.toggle', 'feature', 'market_scanner', 'enabled', true),
      JSON_OBJECT('op', 'feature.toggle', 'feature', 'bulk_automation', 'enabled', true),
      JSON_OBJECT('op', 'runtime.set', 'key', 'max_parallel_jobs', 'value', 4),
      JSON_OBJECT('op', 'runtime.set', 'key', 'heartbeat_seconds', 'value', 60)
    )
  ),
  1
);
