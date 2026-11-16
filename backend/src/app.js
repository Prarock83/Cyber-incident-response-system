'use strict';

const path = require('path');
const express = require('express');
const cors = require('cors');
const config = require('./config');
const db = require('./db');
const { providerStatus } = require('./services/threatIntel');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const analystRoutes = require('./routes/analyst');

const EXTENSION_ORIGIN_RE = /^(chrome|moz|ms-browser)-extension:\/\/[a-z0-9]+$/i;
const LOOPBACK_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
  });

  app.use(cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true); // curl, server-to-server
      if (EXTENSION_ORIGIN_RE.test(origin)) return callback(null, true);
      if (config.corsOrigins.includes(origin)) return callback(null, true);
      if (!config.isProduction && LOOPBACK_RE.test(origin)) return callback(null, true);
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  }));

  app.use(express.json({ limit: '64kb' }));

  if (config.env !== 'test') {
    app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        if (req.path.startsWith('/api')) {
          console.log(`[cirs] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - start}ms)`);
        }
      });
      next();
    });
  }

  // ── HEALTH ─────────────────────────────────────────────────
  app.get('/api/health', async (req, res) => {
    const dbOk = await db.health();
    let schema = { ready: false, missing: [] };
    if (dbOk) {
      const required = ['Analyst', 'SecurityEvent', 'Alert', 'Threat', 'Vulnerability', 'User', 'WebsiteReport', 'ScanHistory', 'UserNotification', 'MitigationAction'];
      try {
        const rows = await db.query(
          'SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?',
          [config.db.database],
        );
        const existing = new Set(rows.map((row) => row.name));
        const missing = required.filter((table) => !existing.has(table));
        schema = { ready: missing.length === 0, missing };
      } catch (err) {
        schema = { ready: false, error: err.message, missing: [] };
      }
    }
    const intel = providerStatus();
    const healthy = dbOk;
    res.status(healthy ? 200 : 503).json({
      status: healthy ? (schema.ready ? 'ok' : 'degraded') : 'down',
      service: 'cirs-api',
      version: '2.0.0',
      time: new Date().toISOString(),
      database: { connected: dbOk, schema },
      threatIntel: {
        configured: intel.configured,
        enabled: intel.enabled,
        providers: intel.providers,
      },
    });
  });

  // ── ROUTES ─────────────────────────────────────────────────
  // Analyst routes are mounted first: /api/reports is shared by both roles and
  // Express uses the first matching handler, which then enforces its own role.
  app.use('/api', authRoutes);
  app.use('/api', analystRoutes);
  app.use('/api', userRoutes);

  // ── STATIC ANALYST DASHBOARD ───────────────────────────────
  if (config.serveFrontend) {
    const frontendDir = path.join(__dirname, '..', '..', 'frontend');
    app.use(express.static(frontendDir, { extensions: ['html'] }));
    app.get('/', (req, res) => res.sendFile(path.join(frontendDir, 'index.html')));
  }

  // ── 404 + ERRORS ───────────────────────────────────────────
  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found', code: 'NOT_FOUND' });
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Request body must be valid JSON', code: 'INVALID_JSON' });
    }
    if (err && err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request body is too large', code: 'PAYLOAD_TOO_LARGE' });
    }
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'That record already exists', code: 'DUPLICATE' });
    }
    if (err && err.code && String(err.code).startsWith('ER_')) {
      console.error('[cirs] database error:', err.code, err.message);
      return res.status(503).json({
        error: 'The security database is unavailable. Please try again shortly.',
        code: 'DATABASE_ERROR',
      });
    }
    if (err && err.code === 'ECONNREFUSED') {
      return res.status(503).json({ error: 'Upstream service unavailable', code: 'UPSTREAM_UNAVAILABLE' });
    }

    const status = err.status || 500;
    if (status >= 500) console.error('[cirs] unhandled error:', err);
    return res.status(status).json({
      error: status >= 500 ? 'Unexpected server error' : err.message,
      code: err.code || (status >= 500 ? 'INTERNAL_ERROR' : 'ERROR'),
    });
  });

  return app;
}

module.exports = { createApp };
