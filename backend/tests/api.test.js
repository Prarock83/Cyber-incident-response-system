'use strict';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-for-cirs-api-tests';

const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const jwt = require('jsonwebtoken');

const db = require('../src/db');
const config = require('../src/config');
const { createApp } = require('../src/app');
const { userToken, analystToken } = require('../src/middleware/auth');

/** Minimal fake MySQL pool: returns rows from a per-test handler. */
class FakePool {
  constructor(handler) {
    this.handler = handler;
    this.statements = [];
    this.getConnection = async () => ({
      beginTransaction: async () => {},
      commit: async () => {},
      rollback: async () => {},
      release: () => {},
      query: async (sql, params) => {
        this.statements.push({ sql, params });
        return [this.handler(sql, params, this.statements)];
      },
    });
  }

  async query(sql, params) {
    this.statements.push({ sql, params });
    return [this.handler(sql, params, this.statements)];
  }

  async end() {}
}

async function withServer(handler, fn) {
  const pool = new FakePool(handler);
  db.__setPoolForTesting(pool);
  const app = createApp();
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn(base, pool);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    db.__setPoolForTesting(null);
  }
}

const user = { user_id: 3, email: 'user@example.com', name: 'Test User' };
const analyst = { analyst_id: 2, email: 'analyst@example.com', name: 'Test Analyst', role: 'SOC Analyst' };

test('rejects unauthenticated scans', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.code, 'NO_TOKEN');
  });
});

test('rejects an expired token with a distinct code', async () => {
  await withServer(() => [], async (base) => {
    const expired = jwt.sign({ sub: '3', role: 'user' }, config.jwtSecret, {
      expiresIn: -10,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });
    const res = await fetch(`${base}/api/user/stats`, {
      headers: { authorization: `Bearer ${expired}` },
    });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).code, 'TOKEN_EXPIRED');
  });
});

test('blocks extension users from analyst endpoints', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/dashboard/stats`, {
      headers: { authorization: `Bearer ${userToken(user)}` },
    });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).code, 'FORBIDDEN');
  });
});

test('blocks analysts from extension-user endpoints', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/user/stats`, {
      headers: { authorization: `Bearer ${analystToken(analyst)}` },
    });
    assert.equal(res.status, 403);
  });
});

test('scan returns an explainable heuristic assessment and records history', async () => {
  await withServer((sql) => {
    if (/INSERT INTO ScanHistory/i.test(sql)) return { insertId: 42, affectedRows: 1 };
    return [];
  }, async (base, pool) => {
    const res = await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken(user)}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.verdict, 'SUSPICIOUS');
    assert.ok(body.riskScore >= 40);
    assert.ok(body.reasons.length > 0);
    assert.equal(body.scanId, 42);
    assert.equal(body.threatIntel.configured, false);
    assert.ok(Array.isArray(body.indicators));

    const insert = pool.statements.find((entry) => /INSERT INTO ScanHistory/.test(entry.sql));
    assert.ok(insert, 'scan history should be stored');
    assert.equal(insert.params[0], 3);
    assert.equal(insert.params[3], 'paypal-secure-login.xyz');
  });
});

test('scan validates the URL', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken(user)}` },
      body: JSON.stringify({ url: 'javascript:alert(1)' }),
    });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).code, 'VALIDATION_ERROR');
  });
});

test('duplicate reports are rejected with the existing reference', async () => {
  await withServer((sql) => {
    if (/FROM WebsiteReport\s+WHERE user_id = \? AND url_hash/i.test(sql)) {
      return [{ reference_id: 'CIRS-260101-AAAAAA', status: 'Under Review', created_at: new Date() }];
    }
    return [];
  }, async (base) => {
    const res = await fetch(`${base}/api/reports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken(user)}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify', description: 'Looks fake' }),
    });
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.code, 'DUPLICATE_REPORT');
    assert.equal(body.referenceId, 'CIRS-260101-AAAAAA');
  });
});

test('reporting creates report, security event, alert and notification', async () => {
  await withServer((sql) => {
    if (/FROM WebsiteReport\s+WHERE user_id = \? AND url_hash/i.test(sql)) return [];
    if (/INSERT INTO WebsiteReport/i.test(sql)) return { insertId: 7, affectedRows: 1 };
    if (/INSERT INTO SecurityEvent/i.test(sql)) return { insertId: 11, affectedRows: 1 };
    if (/INSERT INTO Alert/i.test(sql)) return { insertId: 5, affectedRows: 1 };
    if (/INSERT INTO UserNotification/i.test(sql)) return { insertId: 1, affectedRows: 1 };
    return [];
  }, async (base, pool) => {
    const res = await fetch(`${base}/api/reports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${userToken(user)}` },
      body: JSON.stringify({ url: 'http://paypal-secure-login.xyz/verify', description: 'Asks for card details' }),
    });
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.match(body.referenceId, /^CIRS-\d{6}-[A-F0-9]{6}$/);
    assert.equal(body.status, 'Submitted');
    assert.equal(body.verdict, 'SUSPICIOUS');
    assert.equal(body.alertId, 5);
    assert.equal(body.eventId, 11);
    assert.ok(body.reviewFlow.includes('Confirmed Threat'));

    const alertInsert = pool.statements.find((entry) => /INSERT INTO Alert/i.test(entry.sql));
    assert.equal(alertInsert.params[1], 'High');
    const eventInsert = pool.statements.find((entry) => /INSERT INTO SecurityEvent/i.test(entry.sql));
    assert.equal(eventInsert.params[1], 'High');
    assert.match(eventInsert.params[3], /Asks for card details/);
  });
});

test('analyst can move a report through the investigation workflow', async () => {
  const reportRow = {
    report_id: 7,
    reference_id: 'CIRS-260101-BBBBBB',
    user_id: 3,
    url: 'http://paypal-secure-login.xyz/verify',
    domain: 'paypal-secure-login.xyz',
    detection_result: 'SUSPICIOUS',
    risk_score: 62,
    threat_category: 'lookalike-domain',
    reasons: '[]',
    description: 'Asks for card details',
    status: 'Submitted',
    created_at: new Date(),
    updated_at: new Date(),
  };

  await withServer((sql) => {
    if (/SELECT \* FROM WebsiteReport WHERE reference_id = \?/i.test(sql)) return [reportRow];
    if (/SELECT event_id FROM SecurityEvent WHERE report_id/i.test(sql)) return [{ event_id: 11 }];
    if (/SELECT alert_id FROM Alert WHERE report_id/i.test(sql)) return [{ alert_id: 5 }];
    if (/^UPDATE/i.test(sql.trim())) return { affectedRows: 1 };
    if (/INSERT INTO UserNotification/i.test(sql)) return { insertId: 1 };
    if (/FROM WebsiteReport r/i.test(sql)) {
      return [{ ...reportRow, status: 'Confirmed Threat', analyst_id: 2, analyst_notes: 'Verified phishing kit', analyst_name: 'Test Analyst', user_name: 'Test User' }];
    }
    return [];
  }, async (base, pool) => {
    const res = await fetch(`${base}/api/analyst/reports/CIRS-260101-BBBBBB/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${analystToken(analyst)}` },
      body: JSON.stringify({ status: 'Confirmed Threat', notes: 'Verified phishing kit' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'Confirmed Threat');
    assert.equal(body.analystName, 'Test Analyst');
    assert.match(body.message, /reporter has been notified/i);

    const alertUpdate = pool.statements.find((entry) => /UPDATE Alert SET status/i.test(entry.sql));
    assert.equal(alertUpdate.params[0], 'In Progress');
    assert.equal(alertUpdate.params[1], 2);
    const notification = pool.statements.find((entry) => /INSERT INTO UserNotification/i.test(entry.sql));
    assert.equal(notification.params[1], 'Report Confirmed Threat');
    assert.equal(notification.params[4], 7); // related_report_id
  });
});

test('analyst and user /api/reports routes are not shadowed by each other', async () => {
  const analystReport = {
    report_id: 7,
    reference_id: 'CIRS-260101-CCCCCC',
    user_id: 3,
    url: 'https://example.com/login',
    domain: 'example.com',
    detection_result: 'SUSPICIOUS',
    risk_score: 55,
    reasons: '[]',
    status: 'Submitted',
    created_at: new Date(),
  };

  await withServer((sql) => {
    if (/FROM WebsiteReport r/i.test(sql)) return [analystReport];
    return [];
  }, async (base) => {
    const asAnalyst = await fetch(`${base}/api/analyst/reports`, {
      headers: { authorization: `Bearer ${analystToken(analyst)}` },
    });
    assert.equal(asAnalyst.status, 200, 'analyst must reach the analyst reports handler');
    const analystRows = await asAnalyst.json();
    assert.equal(analystRows[0].referenceId, 'CIRS-260101-CCCCCC');

    const asUser = await fetch(`${base}/api/reports`, {
      headers: { authorization: `Bearer ${userToken(user)}` },
    });
    assert.equal(asUser.status, 200, 'user must reach the user reports handler');
    const userRows = await asUser.json();
    assert.equal(userRows[0].referenceId, 'CIRS-260101-CCCCCC');
  });
});

test('analyst status updates validate the status enum', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/analyst/reports/ANY/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${analystToken(analyst)}` },
      body: JSON.stringify({ status: 'Deleted Forever' }),
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /must be one of/);
  });
});

test('registration rejects a weak password before touching the database', async () => {
  await withServer(() => {
    throw new Error('database should not be queried for invalid input');
  }, async (base) => {
    const res = await fetch(`${base}/api/users/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Test User', email: 'new@example.com', password: 'weak' }),
    });
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /8 and 72/);
  });
});

test('login fails cleanly for an unknown account without leaking details', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/users/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.com', password: 'SomePass123' }),
    });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'Incorrect email or password');
  });
});

test('health endpoint reports database and threat-intel status', async () => {
  await withServer((sql) => {
    if (/SELECT 1 AS ok/i.test(sql)) return [{ ok: 1 }];
    if (/information_schema\.TABLES/i.test(sql)) {
      return ['Analyst', 'SecurityEvent', 'Alert', 'Threat', 'Vulnerability', 'User', 'WebsiteReport', 'ScanHistory', 'UserNotification', 'MitigationAction'].map((name) => ({ name }));
    }
    return [];
  }, async (base) => {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'ok');
    assert.equal(body.database.connected, true);
    assert.equal(body.database.schema.ready, true);
    assert.equal(body.threatIntel.configured, false);
  });
});

test('unknown API routes return JSON 404', async () => {
  await withServer(() => [], async (base) => {
    const res = await fetch(`${base}/api/nope`);
    assert.equal(res.status, 404);
    assert.equal((await res.json()).code, 'NOT_FOUND');
  });
});
