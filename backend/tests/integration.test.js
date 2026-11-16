'use strict';

/**
 * End-to-end journey against a REAL MySQL database.
 *
 * Requires DB_HOST/DB_USER/DB_PASSWORD/DB_NAME and migrations already applied:
 *   npm run migrate
 * Run with:  npm run test:integration
 * Skips automatically (rather than faking anything) when MySQL is unreachable.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { once } = require('node:events');
const crypto = require('crypto');

process.env.NODE_ENV = process.env.NODE_ENV || 'test';
if (!process.env.JWT_SECRET) process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');

const db = require('../src/db');
const { createApp } = require('../src/app');

const suffix = crypto.randomBytes(4).toString('hex');
const userEmail = `journey-${suffix}@cirs.test`;
const analystEmail = `analyst-${suffix}@cirs.test`;
const password = 'JourneyPass123';

async function startServer() {
  const app = createApp();
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test('full report investigation journey', async (t) => {
  const connected = await db.health();
  if (!connected) {
    t.skip('MySQL is not reachable - start MySQL and run `npm run migrate` to execute this test');
    return;
  }

  const { server, base } = await startServer();
  let userId = null;
  let analystId = null;

  try {
    // 1. register extension user
    let res = await fetch(`${base}/api/users/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Journey User', email: userEmail, password }),
    });
    const registered = await res.json();
    assert.equal(res.status, 201, JSON.stringify(registered));
    assert.ok(registered.token);
    userId = registered.user.id;
    let userToken = registered.token;

    // 2. invalid login
    res = await fetch(`${base}/api/users/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password: 'WrongPass123' }),
    });
    assert.equal(res.status, 401);

    // 3. valid login
    res = await fetch(`${base}/api/users/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password }),
    });
    assert.equal(res.status, 200);
    userToken = (await res.json()).token;

    // 4. scan a suspicious website
    res = await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify' }),
    });
    const scan = await res.json();
    assert.equal(res.status, 200, JSON.stringify(scan));
    assert.equal(scan.verdict, 'SUSPICIOUS');
    assert.ok(scan.riskScore >= 40);

    // 5. report it
    res = await fetch(`${base}/api/reports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify', description: 'Asks for card details via email link' }),
    });
    const report = await res.json();
    assert.equal(res.status, 201, JSON.stringify(report));
    assert.match(report.referenceId, /^CIRS-\d{6}-[A-F0-9]{6}$/);
    assert.ok(report.alertId, 'a suspicious report must raise an alert');

    // 6. duplicate report is rejected
    res = await fetch(`${base}/api/reports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify', description: 'again' }),
    });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).code, 'DUPLICATE_REPORT');

    // 7. report is stored in MySQL
    const stored = await db.one('SELECT * FROM WebsiteReport WHERE reference_id = ?', [report.referenceId]);
    assert.ok(stored, 'report row should exist');
    assert.equal(stored.status, 'Submitted');
    const event = await db.one('SELECT * FROM SecurityEvent WHERE report_id = ?', [stored.report_id]);
    assert.ok(event, 'a security event should be linked');
    const alert = await db.one('SELECT * FROM Alert WHERE report_id = ?', [stored.report_id]);
    assert.ok(alert, 'an alert should be linked');
    assert.equal(alert.status, 'Open');

    // 8. analyst account + login
    const hash = await bcrypt.hash(password, 10);
    const inserted = await db.execute(
      "INSERT INTO Analyst (name, email, role, department, password_hash) VALUES ('Journey Analyst', ?, 'SOC Analyst', 'Testing', ?)",
      [analystEmail, hash],
    );
    analystId = inserted.insertId;

    res = await fetch(`${base}/api/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: analystEmail, password }),
    });
    const analystLogin = await res.json();
    assert.equal(res.status, 200, JSON.stringify(analystLogin));
    const analystToken = analystLogin.token;

    // 9. analyst sees the report
    res = await fetch(`${base}/api/analyst/reports?status=Submitted`, {
      headers: { authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 200);
    const list = await res.json();
    const found = list.find((item) => item.referenceId === report.referenceId);
    assert.ok(found, 'analyst should see the submitted report');
    assert.equal(found.userEmail, userEmail);

    // 10. investigate and update status
    res = await fetch(`${base}/api/analyst/reports/${report.referenceId}/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${analystToken}` },
      body: JSON.stringify({ status: 'Confirmed Threat', notes: 'Confirmed credential phishing kit' }),
    });
    const patched = await res.json();
    assert.equal(res.status, 200, JSON.stringify(patched));
    assert.equal(patched.status, 'Confirmed Threat');

    const updatedAlert = await db.one('SELECT * FROM Alert WHERE report_id = ?', [stored.report_id]);
    assert.equal(updatedAlert.status, 'In Progress');

    // 11. user sees the updated status and got a notification
    res = await fetch(`${base}/api/reports/${report.referenceId}`, {
      headers: { authorization: `Bearer ${userToken}` },
    });
    assert.equal(res.status, 200);
    const viewed = await res.json();
    assert.equal(viewed.status, 'Confirmed Threat');
    assert.match(viewed.analystNotes, /phishing kit/);

    res = await fetch(`${base}/api/user/notifications`, {
      headers: { authorization: `Bearer ${userToken}` },
    });
    const notifications = await res.json();
    assert.ok(notifications.some((note) => /Confirmed Threat/.test(note.title)));

    // 12. personal dashboard reflects the activity
    res = await fetch(`${base}/api/user/stats`, {
      headers: { authorization: `Bearer ${userToken}` },
    });
    const stats = await res.json();
    assert.ok(stats.totals.scans >= 1);
    assert.ok(stats.totals.reports >= 1);
    assert.equal(stats.totals.confirmedThreats, 1);

    // 13. another user cannot read this report
    const otherEmail = `other-${suffix}@cirs.test`;
    res = await fetch(`${base}/api/users/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Other User', email: otherEmail, password }),
    });
    const otherToken = (await res.json()).token;
    res = await fetch(`${base}/api/reports/${report.referenceId}`, {
      headers: { authorization: `Bearer ${otherToken}` },
    });
    assert.equal(res.status, 404);
    await db.execute('DELETE FROM `User` WHERE email = ?', [otherEmail]);

    // 14. unauthenticated access is rejected
    res = await fetch(`${base}/api/user/stats`);
    assert.equal(res.status, 401);
  } finally {
    server.close();
    if (userId) {
      await db.execute('DELETE FROM `User` WHERE user_id = ?', [userId]).catch(() => {});
    }
    if (analystId) {
      await db.execute('DELETE FROM Analyst WHERE analyst_id = ?', [analystId]).catch(() => {});
    }
    await db.close().catch(() => {});
  }
});
