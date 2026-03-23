CREATE DATABASE IF NOT EXISTS licensing_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE licensing_db;

CREATE TABLE IF NOT EXISTS admins (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_admin_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS licenses (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  license_key VARCHAR(128) NOT NULL,
  hwid VARCHAR(128) NULL,
  expire_at TIMESTAMP NOT NULL,
  status ENUM('active', 'banned', 'expired') NOT NULL DEFAULT 'active',
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_license_key (license_key),
  KEY idx_licenses_status_expire (status, expire_at),
  CONSTRAINT fk_licenses_admin_created_by
    FOREIGN KEY (created_by) REFERENCES admins(id)
    ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS verify_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  license_key VARCHAR(128) NOT NULL,
  hwid VARCHAR(128) NULL,
  ip VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512) NULL,
  is_valid TINYINT(1) NOT NULL,
  reason VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_verify_logs_created_at (created_at),
  KEY idx_verify_logs_ip_created_at (ip, created_at),
  KEY idx_verify_logs_key_created_at (license_key, created_at),
  KEY idx_verify_logs_hwid_created_at (hwid, created_at)
) ENGINE=InnoDB;
