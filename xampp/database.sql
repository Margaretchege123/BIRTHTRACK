CREATE DATABASE IF NOT EXISTS birthtrack
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE birthtrack;

CREATE TABLE IF NOT EXISTS system_settings (
  singleton TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  admin_created TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB;

INSERT IGNORE INTO system_settings (singleton, admin_created) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(120) NOT NULL,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('applicant', 'clerk', 'admin') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS applications (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  application_code VARCHAR(20) NULL UNIQUE,
  child_name VARCHAR(180) NOT NULL,
  birth_date DATE NOT NULL,
  place_of_birth VARCHAR(180) NOT NULL,
  parent_name VARCHAR(180) NOT NULL,
  parent_national_id VARCHAR(80) NOT NULL,
  parent_phone VARCHAR(40) NOT NULL,
  applicant_id INT UNSIGNED NULL,
  duplicate_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  status ENUM('Submitted', 'Under Review', 'Approved', 'Issued') NOT NULL DEFAULT 'Submitted',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_applications_duplicate (duplicate_key),
  KEY idx_applications_status (status),
  KEY idx_applications_applicant (applicant_id),
  CONSTRAINT fk_applications_applicant
    FOREIGN KEY (applicant_id) REFERENCES users (id)
    ON DELETE SET NULL
) ENGINE=InnoDB;
