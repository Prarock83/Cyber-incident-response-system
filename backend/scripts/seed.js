'use strict';

/**
 * Seed script: creates a demo analyst and a demo extension user, plus a small
 * amount of reference data for the analyst dashboard when those tables are empty.
 *
 * Passwords come from the environment. If they are not supplied, a random
 * password is generated and printed once so nothing hardcoded ships.
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../src/db');

function passwordFrom(value, label) {
  if (value && String(value).trim()) return String(value).trim();
  const generated = `Cirs-${crypto.randomBytes(6).toString('base64url')}9`;
  console.log(`[seed] ${label} password (generated, shown once): ${generated}`);
  return generated;
}

async function main() {
  const analystEmail = (process.env.SEED_ANALYST_EMAIL || 'analyst@cirs.local').toLowerCase();
  const analystName = process.env.SEED_ANALYST_NAME || 'CIRS Duty Analyst';
  const analystPassword = passwordFrom(process.env.SEED_ANALYST_PASSWORD, 'analyst');

  const userEmail = (process.env.SEED_USER_EMAIL || 'user@cirs.local').toLowerCase();
  const userName = process.env.SEED_USER_NAME || 'CIRS Demo User';
  const userPassword = passwordFrom(process.env.SEED_USER_PASSWORD, 'extension user');

  const analystHash = await bcrypt.hash(analystPassword, 10);
  const existingAnalyst = await db.one('SELECT analyst_id FROM Analyst WHERE email = ?', [analystEmail]);
  if (existingAnalyst) {
    await db.execute('UPDATE Analyst SET password_hash = ?, is_active = 1 WHERE analyst_id = ?', [analystHash, existingAnalyst.analyst_id]);
    console.log(`[seed] analyst ${analystEmail} password refreshed`);
  } else {
    await db.execute(
      "INSERT INTO Analyst (name, email, role, department, password_hash) VALUES (?, ?, 'SOC Analyst', 'Security Operations', ?)",
      [analystName, analystEmail, analystHash],
    );
    console.log(`[seed] analyst ${analystEmail} created`);
  }

  const userHash = await bcrypt.hash(userPassword, 10);
  const existingUser = await db.one('SELECT user_id FROM `User` WHERE email = ?', [userEmail]);
  if (existingUser) {
    await db.execute('UPDATE `User` SET password_hash = ?, is_active = 1 WHERE user_id = ?', [userHash, existingUser.user_id]);
    console.log(`[seed] extension user ${userEmail} password refreshed`);
  } else {
    await db.execute('INSERT INTO `User` (name, email, password_hash) VALUES (?, ?, ?)', [userName, userEmail, userHash]);
    console.log(`[seed] extension user ${userEmail} created`);
  }

  const threatCount = await db.one('SELECT COUNT(*) AS count FROM Threat');
  if (!Number(threatCount.count)) {
    await db.query(
      `INSERT INTO Threat (threat_name, category, risk_level, description, first_seen, last_seen) VALUES
       ('Credential Harvesting Page', 'Phishing', 'High', 'Cloned login page used to capture user credentials.', NOW(), NOW()),
       ('Fake Banking Portal', 'Phishing', 'Critical', 'Lookalike banking domain requesting card and OTP data.', NOW(), NOW()),
       ('Malware Download Redirect', 'Malware', 'Critical', 'Compromised site redirecting visitors to an executable payload.', NOW(), NOW()),
       ('Crypto Wallet Drainer', 'Scam', 'High', 'Fake wallet-connect flow that drains funds.', NOW(), NOW())`,
    );
    console.log('[seed] sample threats inserted');
  }

  const vulnCount = await db.one('SELECT COUNT(*) AS count FROM Vulnerability');
  if (!Number(vulnCount.count)) {
    await db.query(
      `INSERT INTO Vulnerability (cve_id, name, severity, cvss_score, affected_system, patch_available, description) VALUES
       ('CVE-2024-3400', 'Palo Alto PAN-OS command injection', 'Critical', 10.0, 'Edge firewall', 1, 'Unauthenticated command injection in GlobalProtect.'),
       ('CVE-2023-4966', 'Citrix Bleed session token leak', 'Critical', 9.4, 'Citrix ADC', 1, 'Session token disclosure allowing hijack.'),
       ('CVE-2024-21413', 'Outlook remote code execution', 'High', 9.8, 'Microsoft Outlook', 1, 'Preview pane RCE via crafted link.'),
       ('CVE-2022-22965', 'Spring4Shell', 'High', 9.8, 'Spring Framework', 0, 'Data binding RCE on JDK9+ applications.')`,
    );
    console.log('[seed] sample vulnerabilities inserted');
  }

  console.log('[seed] complete');
}

main()
  .then(async () => {
    await db.close();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('[seed] failed:', err.message);
    await db.close().catch(() => {});
    process.exit(1);
  });
