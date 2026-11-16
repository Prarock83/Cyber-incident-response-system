'use strict';

const express = require('express');
const db = require('../db');
const { authenticate } = require('../middleware/auth');
const {
  wrap, sanitizeText, oneOf, integer, ValidationError,
} = require('../middleware/validate');
const { reportRowToJson } = require('./user');

const router = express.Router();

const REPORT_STATUSES = ['Submitted', 'Under Review', 'Investigating', 'Confirmed Threat', 'False Positive', 'Resolved'];
const ALERT_STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed'];
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

const analyst = authenticate(['analyst']);

/** Allow a query to succeed on a database that has not been migrated yet. */
async function optionalQuery(sql, params, fallback) {
  try {
    return await db.query(sql, params);
  } catch (err) {
    if (err && (err.code === 'ER_NO_SUCH_TABLE' || /doesn't exist/i.test(err.message || ''))) {
      return fallback;
    }
    throw err;
  }
}

async function optionalOne(sql, params, fallback) {
  const rows = await optionalQuery(sql, params, fallback ? [fallback] : []);
  return rows && rows.length ? rows[0] : fallback;
}

function statusToSeverity(status) {
  if (status === 'Confirmed Threat') return 'Critical';
  if (status === 'Resolved') return 'Low';
  if (status === 'False Positive') return 'Low';
  return 'Medium';
}

function statusToAlertStatus(status) {
  if (status === 'False Positive') return 'Closed';
  if (status === 'Resolved') return 'Resolved';
  if (status === 'Confirmed Threat') return 'In Progress';
  return 'In Progress';
}

// ══════════════════════════════════════════════════════════════
//  DASHBOARD STATISTICS
// ══════════════════════════════════════════════════════════════

router.get('/dashboard/stats', analyst, wrap(async (req, res) => {
  const totalEvents = await db.one('SELECT COUNT(*) AS count FROM SecurityEvent');
  const openAlerts = await db.one("SELECT COUNT(*) AS count FROM Alert WHERE status IN ('Open','In Progress')");
  const criticalAlerts = await db.one("SELECT COUNT(*) AS count FROM Alert WHERE priority='Critical' AND status IN ('Open','In Progress')");
  const totalThreats = await db.one('SELECT COUNT(*) AS count FROM Threat');
  const unpatched = await db.one('SELECT COUNT(*) AS count FROM Vulnerability WHERE patch_available=0');

  const bySeverity = await db.query(
    "SELECT severity, COUNT(*) AS count FROM SecurityEvent GROUP BY severity ORDER BY FIELD(severity,'Critical','High','Medium','Low')",
  );

  const recentEvents = await db.query(`
    SELECT se.event_id, se.event_type, se.severity, se.timestamp, se.source_ip,
           t.threat_name, t.category
    FROM SecurityEvent se
    LEFT JOIN Threat t ON se.threat_id = t.threat_id
    ORDER BY se.timestamp DESC LIMIT 7
  `);

  const alertStatus = await db.query('SELECT status, COUNT(*) AS count FROM Alert GROUP BY status');

  const topThreats = await db.query(`
    SELECT t.threat_name, t.category, t.risk_level, COUNT(se.event_id) AS event_count
    FROM Threat t
    LEFT JOIN SecurityEvent se ON t.threat_id = se.threat_id
    GROUP BY t.threat_id ORDER BY event_count DESC LIMIT 5
  `);

  // Extension/user-report metrics (graceful if migrations have not run yet)
  const reportTotals = await optionalOne(
    `SELECT COUNT(*) AS totalReports,
            SUM(status IN ('Submitted','Under Review','Investigating')) AS openReports,
            SUM(detection_result = 'DANGEROUS') AS dangerousReports
     FROM WebsiteReport`,
    [],
    { totalReports: 0, openReports: 0, dangerousReports: 0 },
  );
  const reportsByStatus = await optionalQuery(
    'SELECT status, COUNT(*) AS count FROM WebsiteReport GROUP BY status',
    [],
    [],
  );
  const recentReports = await optionalQuery(
    `SELECT r.reference_id, r.domain, r.detection_result, r.risk_score, r.status, r.created_at, u.name AS user_name
     FROM WebsiteReport r LEFT JOIN \`User\` u ON r.user_id = u.user_id
     ORDER BY r.created_at DESC LIMIT 5`,
    [],
    [],
  );

  return res.json({
    totalEvents: totalEvents.count,
    openAlerts: openAlerts.count,
    criticalAlerts: criticalAlerts.count,
    totalThreats: totalThreats.count,
    unpatched: unpatched.count,
    bySeverity,
    recentEvents,
    alertStatus,
    topThreats,
    totalUserReports: Number(reportTotals.totalReports) || 0,
    openUserReports: Number(reportTotals.openReports) || 0,
    dangerousUserReports: Number(reportTotals.dangerousReports) || 0,
    reportsByStatus,
    recentReports,
  });
}));

// ══════════════════════════════════════════════════════════════
//  SECURITY EVENTS
// ══════════════════════════════════════════════════════════════

router.get('/events', analyst, wrap(async (req, res) => {
  const { severity, search } = req.query;
  const limit = integer(req.query.limit, { min: 1, max: 500, fallback: 50, field: 'limit' });
  let query = `
    SELECT se.*, t.threat_name, t.category AS threat_category,
           v.cve_id, v.name AS vuln_name, v.cvss_score
    FROM SecurityEvent se
    LEFT JOIN Threat t ON se.threat_id = t.threat_id
    LEFT JOIN Vulnerability v ON se.vuln_id = v.vuln_id
    WHERE 1=1
  `;
  const params = [];
  if (severity) {
    query += ' AND se.severity = ?';
    params.push(oneOf(severity, SEVERITIES, 'severity'));
  }
  if (search) {
    const term = `%${sanitizeText(search, 120, 'search')}%`;
    query += ' AND (se.event_type LIKE ? OR se.source_ip LIKE ? OR se.description LIKE ?)';
    params.push(term, term, term);
  }
  query += ' ORDER BY se.timestamp DESC LIMIT ?';
  params.push(limit);
  const rows = await db.query(query, params);
  return res.json(rows);
}));

router.post('/events', analyst, wrap(async (req, res) => {
  const body = req.body || {};
  const eventType = sanitizeText(body.event_type, 160, 'Event type');
  if (!eventType) throw new ValidationError('Event type is required');
  const severity = oneOf(body.severity, SEVERITIES, 'Severity');
  const sourceIp = body.source_ip ? sanitizeText(body.source_ip, 64, 'Source IP') : null;
  const destIp = body.dest_ip ? sanitizeText(body.dest_ip, 64, 'Destination IP') : null;
  const protocol = body.protocol ? sanitizeText(body.protocol, 32, 'Protocol') : null;
  const description = body.description ? sanitizeText(body.description, 4000, 'Description') : null;

  const result = await db.execute(
    'INSERT INTO SecurityEvent (event_type, severity, timestamp, source_ip, dest_ip, protocol, description, threat_id, vuln_id) VALUES (?,?,NOW(),?,?,?,?,?,?)',
    [eventType, severity, sourceIp, destIp, protocol, description, body.threat_id || null, body.vuln_id || null],
  );
  return res.status(201).json({ id: result.insertId, message: 'Event created' });
}));

router.delete('/events/:id', analyst, wrap(async (req, res) => {
  const id = integer(req.params.id, { min: 1, max: 2 ** 31 - 1, field: 'event id' });
  const result = await db.execute('DELETE FROM SecurityEvent WHERE event_id = ?', [id]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Event not found', code: 'NOT_FOUND' });
  return res.json({ message: 'Event deleted' });
}));

// ══════════════════════════════════════════════════════════════
//  ALERTS
// ══════════════════════════════════════════════════════════════

router.get('/alerts', analyst, wrap(async (req, res) => {
  const { status, priority } = req.query;
  let query = `
    SELECT a.*, an.name AS analyst_name, se.event_type, se.source_ip,
           t.threat_name, t.risk_level, r.reference_id, r.domain AS report_domain
    FROM Alert a
    LEFT JOIN Analyst an ON a.assigned_to = an.analyst_id
    LEFT JOIN SecurityEvent se ON a.event_id = se.event_id
    LEFT JOIN Threat t ON se.threat_id = t.threat_id
    LEFT JOIN WebsiteReport r ON a.report_id = r.report_id
    WHERE 1=1
  `;
  const params = [];
  if (status) { query += ' AND a.status = ?'; params.push(oneOf(status, ALERT_STATUSES, 'status')); }
  if (priority) { query += ' AND a.priority = ?'; params.push(oneOf(priority, SEVERITIES, 'priority')); }
  query += " ORDER BY FIELD(a.priority,'Critical','High','Medium','Low'), a.created_at DESC";
  const rows = await optionalQuery(query, params, []);
  return res.json(rows);
}));

router.post('/alerts', analyst, wrap(async (req, res) => {
  const body = req.body || {};
  const alertType = sanitizeText(body.alert_type, 160, 'Alert type');
  if (!alertType) throw new ValidationError('Alert type is required');
  const priority = oneOf(body.priority, SEVERITIES, 'Priority');
  const result = await db.execute(
    "INSERT INTO Alert (alert_type, priority, status, event_id, assigned_to) VALUES (?,?,'Open',?,?)",
    [alertType, priority, body.event_id || null, body.assigned_to || null],
  );
  return res.status(201).json({ id: result.insertId, message: 'Alert created' });
}));

router.patch('/alerts/:id/status', analyst, wrap(async (req, res) => {
  const id = integer(req.params.id, { min: 1, max: 2 ** 31 - 1, field: 'alert id' });
  const status = oneOf(req.body && req.body.status, ALERT_STATUSES, 'status');
  const result = await db.execute('UPDATE Alert SET status = ? WHERE alert_id = ?', [status, id]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Alert not found', code: 'NOT_FOUND' });
  return res.json({ message: 'Status updated' });
}));

// ══════════════════════════════════════════════════════════════
//  REFERENCE DATA
// ══════════════════════════════════════════════════════════════

router.get('/threats', analyst, wrap(async (req, res) => {
  return res.json(await db.query('SELECT * FROM Threat ORDER BY FIELD(risk_level,\'Critical\',\'High\',\'Medium\',\'Low\'), threat_name'));
}));

router.get('/vulnerabilities', analyst, wrap(async (req, res) => {
  return res.json(await db.query('SELECT * FROM Vulnerability ORDER BY cvss_score DESC'));
}));

router.get('/analysts', analyst, wrap(async (req, res) => {
  return res.json(await db.query('SELECT analyst_id, name, role, department FROM Analyst ORDER BY name'));
}));

// ══════════════════════════════════════════════════════════════
//  MITIGATION ACTIONS
// ══════════════════════════════════════════════════════════════

router.get('/mitigations', analyst, wrap(async (req, res) => {
  const rows = await optionalQuery(
    `SELECT m.*, a.name AS analyst_name, al.alert_type
     FROM MitigationAction m
     LEFT JOIN Analyst a ON m.performed_by = a.analyst_id
     LEFT JOIN Alert al ON m.alert_id = al.alert_id
     ORDER BY m.created_at DESC LIMIT 100`,
    [],
    [],
  );
  return res.json(rows);
}));

router.post('/mitigations', analyst, wrap(async (req, res) => {
  const body = req.body || {};
  const alertId = integer(body.alert_id, { min: 1, max: 2 ** 31 - 1, field: 'alert_id' });
  const actionType = sanitizeText(body.action_type, 160, 'Action type');
  if (!actionType) throw new ValidationError('Action type is required');
  const description = body.description ? sanitizeText(body.description, 2000, 'Description') : null;
  const performedBy = body.performed_by || req.auth.id;
  const status = body.status ? oneOf(body.status, ['Pending', 'In Progress', 'Completed', 'Failed'], 'status') : 'Completed';

  const result = await db.execute(
    `INSERT INTO MitigationAction (alert_id, action_type, description, performed_by, status, performed_at)
     VALUES (?, ?, ?, ?, ?, NOW())`,
    [alertId, actionType, description, performedBy, status],
  );
  return res.status(201).json({ id: result.insertId, message: 'Mitigation action recorded' });
}));

// ══════════════════════════════════════════════════════════════
//  USER WEBSITE REPORTS / INVESTIGATION WORKFLOW
// ══════════════════════════════════════════════════════════════

router.get('/analyst/reports', analyst, wrap(async (req, res) => {
  const limit = integer(req.query.limit, { min: 1, max: 200, fallback: 50, field: 'limit' });
  const params = [];
  let sql = `
    SELECT r.*, u.name AS user_name, u.email AS user_email, a.name AS analyst_name,
           (SELECT se.event_id FROM SecurityEvent se WHERE se.report_id = r.report_id LIMIT 1) AS event_id,
           (SELECT al.alert_id FROM Alert al WHERE al.report_id = r.report_id LIMIT 1) AS alert_id,
           (SELECT al.priority FROM Alert al WHERE al.report_id = r.report_id LIMIT 1) AS alert_priority
    FROM WebsiteReport r
    LEFT JOIN \`User\` u ON r.user_id = u.user_id
    LEFT JOIN Analyst a ON r.analyst_id = a.analyst_id
    WHERE 1=1
  `;
  if (req.query.status) {
    sql += ' AND r.status = ?';
    params.push(oneOf(req.query.status, REPORT_STATUSES, 'status'));
  }
  if (req.query.verdict) {
    sql += ' AND r.detection_result = ?';
    params.push(oneOf(req.query.verdict, ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN'], 'verdict'));
  }
  if (req.query.search) {
    const term = `%${sanitizeText(req.query.search, 120, 'search')}%`;
    sql += ' AND (r.domain LIKE ? OR r.url LIKE ? OR r.reference_id LIKE ?)';
    params.push(term, term, term);
  }
  sql += ' ORDER BY FIELD(r.status,\'Submitted\',\'Under Review\',\'Investigating\',\'Confirmed Threat\',\'False Positive\',\'Resolved\'), r.created_at DESC LIMIT ?';
  params.push(limit);

  const rows = await db.query(sql, params);
  return res.json(rows.map((row) => ({
    ...reportRowToJson(row),
    userId: row.user_id,
    userName: row.user_name || 'Unknown user',
    userEmail: row.user_email || null,
    alertPriority: row.alert_priority || null,
  })));
}));

router.get('/analyst/reports/:reference', analyst, wrap(async (req, res) => {
  const reference = String(req.params.reference || '').slice(0, 32);
  const row = await db.one(
    `SELECT r.*, u.name AS user_name, u.email AS user_email, a.name AS analyst_name,
            (SELECT se.event_id FROM SecurityEvent se WHERE se.report_id = r.report_id LIMIT 1) AS event_id,
            (SELECT al.alert_id FROM Alert al WHERE al.report_id = r.report_id LIMIT 1) AS alert_id
     FROM WebsiteReport r
     LEFT JOIN \`User\` u ON r.user_id = u.user_id
     LEFT JOIN Analyst a ON r.analyst_id = a.analyst_id
     WHERE r.reference_id = ?`,
    [reference],
  );
  if (!row) return res.status(404).json({ error: 'Report not found', code: 'NOT_FOUND' });

  let event = null;
  let alert = null;
  if (row.event_id) {
    event = await db.one(
      `SELECT event_id, event_type, severity, timestamp, protocol, description
       FROM SecurityEvent WHERE event_id = ?`,
      [row.event_id],
    );
  }
  if (row.alert_id) {
    alert = await db.one(
      'SELECT alert_id, alert_type, priority, status, created_at FROM Alert WHERE alert_id = ?',
      [row.alert_id],
    );
  }

  return res.json({
    ...reportRowToJson(row),
    userName: row.user_name || 'Unknown user',
    userEmail: row.user_email || null,
    event,
    alert,
  });
}));

router.patch('/analyst/reports/:reference/status', analyst, wrap(async (req, res) => {
  const reference = String(req.params.reference || '').slice(0, 32);
  const status = oneOf(req.body && req.body.status, REPORT_STATUSES, 'status');
  const notes = req.body && req.body.notes !== undefined
    ? sanitizeText(req.body.notes, 4000, 'Notes')
    : null;

  const report = await db.one('SELECT * FROM WebsiteReport WHERE reference_id = ?', [reference]);
  if (!report) return res.status(404).json({ error: 'Report not found', code: 'NOT_FOUND' });

  const result = await db.withTransaction(async (tx) => {
    const fields = ['status = ?', 'analyst_id = ?'];
    const params = [status, req.auth.id];
    if (notes !== null) { fields.push('analyst_notes = ?'); params.push(notes); }
    params.push(report.report_id);
    await tx.query(`UPDATE WebsiteReport SET ${fields.join(', ')} WHERE report_id = ?`, params);

    const event = await tx.one('SELECT event_id FROM SecurityEvent WHERE report_id = ? LIMIT 1', [report.report_id]);
    if (event) {
      await tx.query('UPDATE SecurityEvent SET severity = ? WHERE event_id = ?', [statusToSeverity(status), event.event_id]);
    }

    const alert = await tx.one('SELECT alert_id FROM Alert WHERE report_id = ? LIMIT 1', [report.report_id]);
    if (alert) {
      await tx.query('UPDATE Alert SET status = ?, assigned_to = ? WHERE alert_id = ?', [
        statusToAlertStatus(status), req.auth.id, alert.alert_id,
      ]);
    }

    const userMessage = status === 'Confirmed Threat'
      ? `Report ${reference} (${report.domain}) was confirmed as a threat by our security team. Avoid this website.`
      : status === 'False Positive'
        ? `Report ${reference} (${report.domain}) was reviewed and marked as a false positive.`
        : status === 'Resolved'
          ? `Report ${reference} (${report.domain}) has been resolved. Thank you for helping keep CIRS users safe.`
          : `Report ${reference} (${report.domain}) is now ${status}.`;

    await tx.query(
      `INSERT INTO UserNotification (user_id, type, title, message, severity, related_report_id)
       VALUES (?, 'report-status', ?, ?, ?, ?)`,
      [
        report.user_id,
        `Report ${status}`,
        userMessage,
        status === 'Confirmed Threat' ? 'danger' : status === 'False Positive' || status === 'Resolved' ? 'success' : 'info',
        report.report_id,
      ],
    );

    return { eventId: event ? event.event_id : null, alertId: alert ? alert.alert_id : null };
  });

  const updated = await db.one(
    `SELECT r.*, u.name AS user_name, a.name AS analyst_name
     FROM WebsiteReport r
     LEFT JOIN \`User\` u ON r.user_id = u.user_id
     LEFT JOIN Analyst a ON r.analyst_id = a.analyst_id
     WHERE r.report_id = ?`,
    [report.report_id],
  );

  return res.json({
    ...reportRowToJson(updated),
    userName: updated.user_name || 'Unknown user',
    eventId: result.eventId,
    alertId: result.alertId,
    message: 'Report status updated and the reporter has been notified',
  });
}));

module.exports = router;
