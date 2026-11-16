-- 002_extension_schema.sql
-- Browser-extension side of CIRS: users, website reports, scan history,
-- notifications and mitigation actions. Additive only.

CREATE TABLE IF NOT EXISTS `User` (
  user_id        INT AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(120) NOT NULL,
  email          VARCHAR(190) NOT NULL UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,
  is_active      TINYINT(1) NOT NULL DEFAULT 1,
  notifications_enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_login     DATETIME NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS WebsiteReport (
  report_id        INT AUTO_INCREMENT PRIMARY KEY,
  reference_id     VARCHAR(32) NOT NULL UNIQUE,
  user_id          INT NOT NULL,
  url              TEXT NOT NULL,
  url_hash         CHAR(64) NOT NULL,
  domain           VARCHAR(255) NOT NULL,
  detection_result ENUM('SAFE','SUSPICIOUS','DANGEROUS','UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
  risk_score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
  threat_category  VARCHAR(120) NULL,
  reasons          TEXT NULL,
  description      TEXT NULL,
  status           ENUM('Submitted','Under Review','Investigating','Confirmed Threat','False Positive','Resolved') NOT NULL DEFAULT 'Submitted',
  analyst_id       INT NULL,
  analyst_notes    TEXT NULL,
  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_report_user (user_id, created_at),
  INDEX idx_report_status (status),
  INDEX idx_report_domain (domain),
  INDEX idx_report_hash (url_hash),
  INDEX idx_report_created (created_at),
  CONSTRAINT fk_report_user FOREIGN KEY (user_id) REFERENCES `User`(user_id) ON DELETE CASCADE,
  CONSTRAINT fk_report_analyst FOREIGN KEY (analyst_id) REFERENCES Analyst(analyst_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ScanHistory (
  scan_id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT NULL,
  url            TEXT NOT NULL,
  url_hash       CHAR(64) NOT NULL,
  domain         VARCHAR(255) NOT NULL,
  verdict        ENUM('SAFE','SUSPICIOUS','DANGEROUS','UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
  risk_score     TINYINT UNSIGNED NOT NULL DEFAULT 0,
  heuristic_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
  category       VARCHAR(100) NULL,
  reasons        TEXT NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scan_user (user_id, created_at),
  INDEX idx_scan_domain (domain),
  INDEX idx_scan_verdict (verdict),
  CONSTRAINT fk_scan_user FOREIGN KEY (user_id) REFERENCES `User`(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS UserNotification (
  notification_id   INT AUTO_INCREMENT PRIMARY KEY,
  user_id           INT NOT NULL,
  type              VARCHAR(40) NOT NULL DEFAULT 'system',
  title             VARCHAR(160) NOT NULL,
  message           TEXT NOT NULL,
  severity          ENUM('info','warning','danger','success') NOT NULL DEFAULT 'info',
  related_report_id INT NULL,
  is_read           TINYINT(1) NOT NULL DEFAULT 0,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_notification_user (user_id, is_read, created_at),
  CONSTRAINT fk_notification_user FOREIGN KEY (user_id) REFERENCES `User`(user_id) ON DELETE CASCADE,
  CONSTRAINT fk_notification_report FOREIGN KEY (related_report_id) REFERENCES WebsiteReport(report_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS MitigationAction (
  action_id    INT AUTO_INCREMENT PRIMARY KEY,
  alert_id     INT NOT NULL,
  action_type  VARCHAR(160) NOT NULL,
  description  TEXT NULL,
  performed_by INT NULL,
  status       ENUM('Pending','In Progress','Completed','Failed') NOT NULL DEFAULT 'Completed',
  performed_at DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_mitigation_alert (alert_id),
  CONSTRAINT fk_mitigation_alert FOREIGN KEY (alert_id) REFERENCES Alert(alert_id) ON DELETE CASCADE,
  CONSTRAINT fk_mitigation_analyst FOREIGN KEY (performed_by) REFERENCES Analyst(analyst_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Columns added to existing tables are created by scripts/migrate.js because
-- MySQL does not support "ADD COLUMN IF NOT EXISTS":
--   Analyst.password_hash / is_active / last_login / created_at
--   SecurityEvent.report_id
--   Alert.report_id
