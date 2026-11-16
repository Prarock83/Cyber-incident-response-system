'use strict';

const express = require('express');
const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const { authenticate } = require('../middleware/auth');
const { createRateLimiter } = require('../middleware/rateLimit');
const {
  wrap, parseHttpUrl, sanitizeText, oneOf, integer, hashUrl, ValidationError,
} = require('../middleware/validate');
const { assessUrl } = require('../services/assessment');
const { providerStatus } = require('../services/threatIntel');

const router = express.Router();

const REPORT_STATUSES = ['Submitted', 'Under Review', 'Investigating', 'Confirmed Threat', 'False Positive', 'Resolved'];

const scanLimiter = createRateLimiter({
  windowMs: 60_000,
  max: config.limits.scansPerMinute,
  keyGenerator: (req) => `scan:${req.auth ? req.auth.id : req.ip}`,
  message: 'You are scanning too quickly. Please wait a moment before trying again.',
});

const reportLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: config.limits.reportsPerHour,
  keyGenerator: (req) => `report:${req.auth ? req.auth.id : req.ip}`,
  message: 'You have submitted many reports recently. Please try again later.',
});

function parseReasons(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function reportRowToJson(row) {
  return {
    referenceId: row.reference_id,
    url: row.url,
    domain: row.domain,
    verdict: row.detection_result,
    riskScore: row.risk_score,
    category: row.threat_category,
    reasons: parseReasons(row.reasons),
    description: row.description,
    status: row.status,
    analystNotes: row.analyst_notes || null,
    analystName: row.analyst_name || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    eventId: row.event_id || null,
    alertId: row.alert_id || null,
  };
}

function severityFor(verdict) {
  if (verdict === 'DANGEROUS') return 'Critical';
  if (verdict === 'SUSPICIOUS') return 'High';
  if (verdict === 'SAFE') return 'Low';
  return 'Medium';
}

function alertPriorityFor(verdict) {
  if (verdict === 'DANGEROUS') return 'Critical';
  if (verdict === 'SUSPICIOUS') return 'High';
  return 'Medium';
}

function referenceId() {
  const date = new Date();
  const stamp = `${String(date.getUTCFullYear()).slice(2)}${String(date.getUTCMonth() + 1).padStart(2, '0')}${String(date.getUTCDate()).padStart(2, '0')}`;
  return `CIRS-${stamp}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

// ── SCANNER ───────────────────────────────────────────────────

// GET /api/scan/providers - what threat intelligence is actually available
router.get('/scan/providers', wrap(async (req, res) => {
  const status = providerStatus();
  return res.json({
    ...status,
    disclaimer: 'Heuristic analysis is transparent pattern matching, not a commercial antivirus engine.',
  });
}));

// POST /api/scan  { url }
router.post('/scan', authenticate(['user']), scanLimiter, wrap(async (req, res) => {
  const target = parseHttpUrl(req.body && req.body.url);
  const assessment = await assessUrl(target.href);

  const scan = await db.execute(
    'INSERT INTO ScanHistory (user_id, url, url_hash, domain, verdict, risk_score, heuristic_score, category, reasons) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      req.auth.id,
      assessment.url,
      hashUrl(assessment.url),
      assessment.domain,
      assessment.verdict,
      assessment.riskScore,
      assessment.heuristicScore,
      assessment.category,
      JSON.stringify(assessment.reasons.map((reason) => ({ label: reason.label, detail: reason.detail, source: reason.source }))),
    ],
  );

  return res.json({ ...assessment, scanId: scan.insertId });
}));

// ── REPORTING ─────────────────────────────────────────────────

// POST /api/reports { url, description, category? }
router.post('/reports', authenticate(['user']), reportLimiter, wrap(async (req, res) => {
  const target = parseHttpUrl(req.body && req.body.url);
  const description = sanitizeText((req.body && req.body.description) || '', 1000, 'Description');
  const requestedCategory = req.body && req.body.category
    ? sanitizeText(req.body.category, 80, 'Category')
    : null;

  // The server runs its own assessment; client-supplied results are never trusted.
  const assessment = await assessUrl(target.href);
  const domain = assessment.domain;
  const urlHash = hashUrl(assessment.url);

  const duplicate = await db.one(
    `SELECT reference_id, status, created_at FROM WebsiteReport
     WHERE user_id = ? AND url_hash = ? AND status NOT IN ('Resolved','False Positive')
       AND created_at > (NOW() - INTERVAL 24 HOUR)
     ORDER BY created_at DESC LIMIT 1`,
    [req.auth.id, urlHash],
  );
  if (duplicate) {
    return res.status(409).json({
      error: `You already reported this website. Reference ${duplicate.reference_id} is ${duplicate.status}.`,
      code: 'DUPLICATE_REPORT',
      referenceId: duplicate.reference_id,
      status: duplicate.status,
    });
  }

  const reference = referenceId();
  const reasonsJson = JSON.stringify(assessment.reasons.map((reason) => ({
    label: reason.label,
    detail: reason.detail,
    severity: reason.severity,
    source: reason.source,
  })));
  const category = requestedCategory || assessment.categoryLabel || assessment.category;

  const result = await db.withTransaction(async (tx) => {
    const reportInsert = await tx.query(
      `INSERT INTO WebsiteReport
         (reference_id, user_id, url, url_hash, domain, detection_result, risk_score, threat_category, reasons, description, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Submitted')`,
      [reference, req.auth.id, assessment.url, urlHash, domain, assessment.verdict, assessment.riskScore, category, reasonsJson, description],
    );
    const reportId = reportInsert.insertId;

    const eventInsert = await tx.query(
      `INSERT INTO SecurityEvent (event_type, severity, timestamp, source_ip, dest_ip, protocol, description, threat_id, vuln_id, report_id)
       VALUES (?, ?, NOW(), NULL, NULL, ?, ?, NULL, NULL, ?)`,
      [
        assessment.verdict === 'DANGEROUS' ? 'Malicious Website Report' : 'Suspicious Website Report',
        severityFor(assessment.verdict),
        assessment.protocol.toUpperCase(),
        `User report ${reference} | ${assessment.verdict} (risk ${assessment.riskScore}/100) | ${assessment.url}${description ? ` | ${description}` : ''}`.slice(0, 4000),
        reportId,
      ],
    );
    const eventId = eventInsert.insertId;

    let alertId = null;
    if (assessment.verdict === 'DANGEROUS' || assessment.verdict === 'SUSPICIOUS' || assessment.riskScore >= 40) {
      const alertInsert = await tx.query(
        "INSERT INTO Alert (alert_type, priority, status, event_id, assigned_to, report_id) VALUES (?, ?, 'Open', ?, NULL, ?)",
        [`User report: ${domain}`, alertPriorityFor(assessment.verdict), eventId, reportId],
      );
      alertId = alertInsert.insertId;
    }

    await tx.query(
      `INSERT INTO UserNotification (user_id, type, title, message, severity, related_report_id)
       VALUES (?, 'report', 'Report submitted', ?, ?, ?)`,
      [
        req.auth.id,
        `Report ${reference} was received for ${domain}. A security analyst will review it.`,
        assessment.verdict === 'DANGEROUS' ? 'danger' : 'warning',
        reportId,
      ],
    );

    return { reportId, eventId, alertId };
  });

  return res.status(201).json({
    referenceId: reference,
    status: 'Submitted',
    verdict: assessment.verdict,
    riskScore: assessment.riskScore,
    domain,
    createdAt: new Date().toISOString(),
    eventId: result.eventId,
    alertId: result.alertId,
    reviewFlow: REPORT_STATUSES,
  });
}));

// GET /api/reports - the current user's reports
router.get('/reports', authenticate(['user']), wrap(async (req, res) => {
  const limit = integer(req.query.limit, { min: 1, max: 100, fallback: 25, field: 'limit' });
  const status = req.query.status ? oneOf(req.query.status, REPORT_STATUSES, 'status') : null;
  const params = [req.auth.id];
  let sql = `SELECT r.*, a.name AS analyst_name,
                    (SELECT se.event_id FROM SecurityEvent se WHERE se.report_id = r.report_id LIMIT 1) AS event_id,
                    (SELECT al.alert_id FROM Alert al WHERE al.report_id = r.report_id LIMIT 1) AS alert_id
             FROM WebsiteReport r
             LEFT JOIN Analyst a ON r.analyst_id = a.analyst_id
             WHERE r.user_id = ?`;
  if (status) { sql += ' AND r.status = ?'; params.push(status); }
  sql += ' ORDER BY r.created_at DESC LIMIT ?';
  params.push(limit);

  const rows = await db.query(sql, params);
  return res.json(rows.map(reportRowToJson));
}));

// GET /api/reports/:reference - owner only
router.get('/reports/:reference', authenticate(['user']), wrap(async (req, res) => {
  const row = await db.one(
    `SELECT r.*, a.name AS analyst_name,
            (SELECT se.event_id FROM SecurityEvent se WHERE se.report_id = r.report_id LIMIT 1) AS event_id,
            (SELECT al.alert_id FROM Alert al WHERE al.report_id = r.report_id LIMIT 1) AS alert_id
     FROM WebsiteReport r
     LEFT JOIN Analyst a ON r.analyst_id = a.analyst_id
     WHERE r.reference_id = ? AND r.user_id = ?`,
    [String(req.params.reference || '').slice(0, 32), req.auth.id],
  );
  if (!row) return res.status(404).json({ error: 'Report not found', code: 'NOT_FOUND' });
  return res.json(reportRowToJson(row));
}));

// ── PERSONAL DASHBOARD ────────────────────────────────────────

router.get('/user/stats', authenticate(['user']), wrap(async (req, res) => {
  const userId = req.auth.id;
  const counts = await db.one(
    `SELECT
       (SELECT COUNT(*) FROM ScanHistory WHERE user_id = ?) AS totalScans,
       (SELECT COUNT(*) FROM ScanHistory WHERE user_id = ? AND verdict IN ('SUSPICIOUS','DANGEROUS')) AS suspiciousScans,
       (SELECT COUNT(*) FROM ScanHistory WHERE user_id = ? AND verdict = 'DANGEROUS') AS dangerousScans,
       (SELECT COUNT(*) FROM WebsiteReport WHERE user_id = ?) AS totalReports,
       (SELECT COUNT(*) FROM WebsiteReport WHERE user_id = ? AND status IN ('Submitted','Under Review','Investigating')) AS openReports,
       (SELECT COUNT(*) FROM WebsiteReport WHERE user_id = ? AND status = 'Confirmed Threat') AS confirmedThreats,
       (SELECT COUNT(*) FROM WebsiteReport WHERE user_id = ? AND status = 'Resolved') AS resolvedReports,
       (SELECT COUNT(*) FROM UserNotification WHERE user_id = ? AND is_read = 0) AS unreadNotifications`,
    [userId, userId, userId, userId, userId, userId, userId, userId],
  );

  const [categoryRows, statusRows, recentScans, recentReports] = await Promise.all([
    db.query(
      `SELECT category, COUNT(*) AS count FROM ScanHistory
       WHERE user_id = ? AND category IS NOT NULL AND category <> 'general'
       GROUP BY category ORDER BY count DESC LIMIT 6`,
      [userId],
    ),
    db.query('SELECT status, COUNT(*) AS count FROM WebsiteReport WHERE user_id = ? GROUP BY status', [userId]),
    db.query(
      `SELECT scan_id, url, domain, verdict, risk_score, category, created_at
       FROM ScanHistory WHERE user_id = ? ORDER BY created_at DESC LIMIT 8`,
      [userId],
    ),
    db.query(
      `SELECT reference_id, url, domain, detection_result, risk_score, status, created_at
       FROM WebsiteReport WHERE user_id = ? ORDER BY created_at DESC LIMIT 8`,
      [userId],
    ),
  ]);

  const activity = [
    ...recentScans.map((scan) => ({
      type: 'scan',
      at: scan.created_at,
      domain: scan.domain,
      url: scan.url,
      verdict: scan.verdict,
      riskScore: scan.risk_score,
      label: `Scanned ${scan.domain}`,
    })),
    ...recentReports.map((report) => ({
      type: 'report',
      at: report.created_at,
      domain: report.domain,
      url: report.url,
      verdict: report.detection_result,
      riskScore: report.risk_score,
      status: report.status,
      referenceId: report.reference_id,
      label: `Reported ${report.domain}`,
    })),
  ].sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 10);

  return res.json({
    totals: {
      scans: counts.totalScans || 0,
      suspicious: counts.suspiciousScans || 0,
      dangerous: counts.dangerousScans || 0,
      reports: counts.totalReports || 0,
      openReports: counts.openReports || 0,
      confirmedThreats: counts.confirmedThreats || 0,
      resolvedReports: counts.resolvedReports || 0,
      unreadNotifications: counts.unreadNotifications || 0,
    },
    categories: categoryRows.map((row) => ({ category: row.category, count: row.count })),
    reportStatuses: statusRows.map((row) => ({ status: row.status, count: row.count })),
    recentActivity: activity,
    reportFlow: REPORT_STATUSES,
  });
}));

router.get('/user/scans', authenticate(['user']), wrap(async (req, res) => {
  const limit = integer(req.query.limit, { min: 1, max: 100, fallback: 25, field: 'limit' });
  const rows = await db.query(
    `SELECT scan_id, url, domain, verdict, risk_score, heuristic_score, category, created_at
     FROM ScanHistory WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
    [req.auth.id, limit],
  );
  return res.json(rows.map((row) => ({
    scanId: row.scan_id,
    url: row.url,
    domain: row.domain,
    verdict: row.verdict,
    riskScore: row.risk_score,
    heuristicScore: row.heuristic_score,
    category: row.category,
    createdAt: row.created_at,
  })));
}));

// ── NOTIFICATIONS ─────────────────────────────────────────────

router.get('/user/notifications', authenticate(['user']), wrap(async (req, res) => {
  const rows = await db.query(
    `SELECT n.notification_id, n.type, n.title, n.message, n.severity, n.is_read, n.created_at, r.reference_id
     FROM UserNotification n
     LEFT JOIN WebsiteReport r ON n.related_report_id = r.report_id
     WHERE n.user_id = ? ORDER BY n.created_at DESC LIMIT 50`,
    [req.auth.id],
  );
  return res.json(rows.map((row) => ({
    id: row.notification_id,
    type: row.type,
    title: row.title,
    message: row.message,
    severity: row.severity,
    isRead: Boolean(row.is_read),
    referenceId: row.reference_id,
    createdAt: row.created_at,
  })));
}));

router.patch('/user/notifications/:id/read', authenticate(['user']), wrap(async (req, res) => {
  await db.execute(
    'UPDATE UserNotification SET is_read = 1 WHERE notification_id = ? AND user_id = ?',
    [req.params.id, req.auth.id],
  );
  return res.json({ message: 'Notification marked as read' });
}));

router.post('/user/notifications/read-all', authenticate(['user']), wrap(async (req, res) => {
  await db.execute('UPDATE UserNotification SET is_read = 1 WHERE user_id = ?', [req.auth.id]);
  return res.json({ message: 'All notifications marked as read' });
}));

module.exports = router;
module.exports.REPORT_STATUSES = REPORT_STATUSES;
module.exports.reportRowToJson = reportRowToJson;
module.exports.severityFor = severityFor;
module.exports.ValidationError = ValidationError;
