-- 001_core_schema.sql
-- Core CIRS schema (analyst side).
-- Everything is CREATE TABLE IF NOT EXISTS so an existing cybersecurity_irs
-- database is never dropped or overwritten by running the migrations.

CREATE DATABASE IF NOT EXISTS cybersecurity_irs
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS Analyst (
  analyst_id   INT AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(120) NOT NULL,
  email        VARCHAR(190) NOT NULL UNIQUE,
  role         VARCHAR(60)  NOT NULL DEFAULT 'SOC Analyst',
  department   VARCHAR(120) NULL,
  password_hash VARCHAR(255) NULL,
  is_active    TINYINT(1) NOT NULL DEFAULT 1,
  last_login   DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Threat (
  threat_id    INT AUTO_INCREMENT PRIMARY KEY,
  threat_name  VARCHAR(160) NOT NULL,
  category     VARCHAR(80)  NOT NULL,
  risk_level   ENUM('Critical','High','Medium','Low') NOT NULL DEFAULT 'Medium',
  description  TEXT NULL,
  first_seen   DATETIME NULL,
  last_seen    DATETIME NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_threat_risk (risk_level)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Vulnerability (
  vuln_id         INT AUTO_INCREMENT PRIMARY KEY,
  cve_id          VARCHAR(32) NULL,
  name            VARCHAR(200) NOT NULL,
  severity        ENUM('Critical','High','Medium','Low') NOT NULL DEFAULT 'Medium',
  cvss_score      DECIMAL(3,1) NULL,
  affected_system VARCHAR(200) NULL,
  patch_available TINYINT(1) NOT NULL DEFAULT 0,
  description     TEXT NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_vuln_cvss (cvss_score)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS SecurityEvent (
  event_id    INT AUTO_INCREMENT PRIMARY KEY,
  event_type  VARCHAR(160) NOT NULL,
  severity    ENUM('Critical','High','Medium','Low') NOT NULL DEFAULT 'Medium',
  timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip   VARCHAR(64) NULL,
  dest_ip     VARCHAR(64) NULL,
  protocol    VARCHAR(32) NULL,
  description TEXT NULL,
  threat_id   INT NULL,
  vuln_id     INT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_event_time (timestamp),
  INDEX idx_event_severity (severity),
  CONSTRAINT fk_event_threat FOREIGN KEY (threat_id) REFERENCES Threat(threat_id) ON DELETE SET NULL,
  CONSTRAINT fk_event_vuln FOREIGN KEY (vuln_id) REFERENCES Vulnerability(vuln_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Alert (
  alert_id    INT AUTO_INCREMENT PRIMARY KEY,
  alert_type  VARCHAR(160) NOT NULL,
  priority    ENUM('Critical','High','Medium','Low') NOT NULL DEFAULT 'Medium',
  status      ENUM('Open','In Progress','Resolved','Closed') NOT NULL DEFAULT 'Open',
  event_id    INT NULL,
  assigned_to INT NULL,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_alert_status (status),
  INDEX idx_alert_priority (priority),
  CONSTRAINT fk_alert_event FOREIGN KEY (event_id) REFERENCES SecurityEvent(event_id) ON DELETE SET NULL,
  CONSTRAINT fk_alert_analyst FOREIGN KEY (assigned_to) REFERENCES Analyst(analyst_id) ON DELETE SET NULL
) ENGINE=InnoDB;
