'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const config = require('../config');
const { authenticate, userToken, analystToken } = require('../middleware/auth');
const { createRateLimiter } = require('../middleware/rateLimit');
const {
  ValidationError, validateEmail, validateName, validatePassword, normalizeEmail, wrap,
} = require('../middleware/validate');

const router = express.Router();

const loginLimiter = createRateLimiter({
  windowMs: config.limits.loginWindowMs,
  max: config.limits.loginAttemptsPerWindow,
  keyGenerator: (req) => `${req.ip}:${normalizeEmail(req.body && req.body.email)}`,
  message: 'Too many sign-in attempts. Please wait a few minutes and try again.',
});

function publicUser(user) {
  return {
    id: user.user_id,
    name: user.name,
    email: user.email,
    notificationsEnabled: Boolean(user.notifications_enabled),
    createdAt: user.created_at,
  };
}

// ── EXTENSION USER AUTH ────────────────────────────────────────

// POST /api/users/register
router.post('/users/register', loginLimiter, wrap(async (req, res) => {
  const name = validateName(req.body && req.body.name);
  const email = validateEmail(req.body && req.body.email);
  const password = validatePassword(req.body && req.body.password);

  const existing = await db.one('SELECT user_id FROM `User` WHERE email = ?', [email]);
  if (existing) {
    return res.status(409).json({ error: 'An account with this email already exists', code: 'EMAIL_IN_USE' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const result = await db.execute(
    'INSERT INTO `User` (name, email, password_hash) VALUES (?, ?, ?)',
    [name, email, passwordHash],
  );
  const user = await db.one('SELECT * FROM `User` WHERE user_id = ?', [result.insertId]);

  await db.execute(
    "INSERT INTO UserNotification (user_id, type, title, message, severity) VALUES (?, 'system', ?, ?, 'success')",
    [user.user_id, 'Welcome to CIRS', 'Your CIRS account is ready. Open any website and run a security scan to get started.'],
  ).catch(() => {});

  return res.status(201).json({ token: userToken(user), user: publicUser(user) });
}));

// POST /api/users/login
router.post('/users/login', loginLimiter, wrap(async (req, res) => {
  const email = validateEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || '');
  if (!password) throw new ValidationError('Password is required');

  const user = await db.one('SELECT * FROM `User` WHERE email = ? AND is_active = 1', [email]);
  const valid = user ? await bcrypt.compare(password, user.password_hash) : false;
  if (!user || !valid) {
    return res.status(401).json({ error: 'Incorrect email or password', code: 'INVALID_CREDENTIALS' });
  }

  await db.execute('UPDATE `User` SET last_login = NOW() WHERE user_id = ?', [user.user_id]);
  return res.json({ token: userToken(user), user: publicUser(user) });
}));

// GET /api/users/me
router.get('/users/me', authenticate(['user']), wrap(async (req, res) => {
  const user = await db.one('SELECT * FROM `User` WHERE user_id = ? AND is_active = 1', [req.auth.id]);
  if (!user) return res.status(401).json({ error: 'Account no longer active', code: 'ACCOUNT_INACTIVE' });
  return res.json({ user: publicUser(user) });
}));

// PATCH /api/users/me
router.patch('/users/me', authenticate(['user']), wrap(async (req, res) => {
  const updates = [];
  const params = [];
  if (req.body && req.body.name !== undefined) {
    updates.push('name = ?');
    params.push(validateName(req.body.name));
  }
  if (req.body && req.body.notificationsEnabled !== undefined) {
    updates.push('notifications_enabled = ?');
    params.push(req.body.notificationsEnabled ? 1 : 0);
  }
  if (!updates.length) throw new ValidationError('Nothing to update');
  params.push(req.auth.id);
  await db.execute(`UPDATE \`User\` SET ${updates.join(', ')} WHERE user_id = ?`, params);
  const user = await db.one('SELECT * FROM `User` WHERE user_id = ?', [req.auth.id]);
  return res.json({ user: publicUser(user) });
}));

// POST /api/users/password
router.post('/users/password', authenticate(['user']), loginLimiter, wrap(async (req, res) => {
  const currentPassword = String((req.body && req.body.currentPassword) || '');
  const newPassword = validatePassword(req.body && req.body.newPassword);
  const user = await db.one('SELECT * FROM `User` WHERE user_id = ?', [req.auth.id]);
  if (!user) return res.status(404).json({ error: 'Account not found', code: 'NOT_FOUND' });
  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Current password is incorrect', code: 'INVALID_CREDENTIALS' });
  const hash = await bcrypt.hash(newPassword, 10);
  await db.execute('UPDATE `User` SET password_hash = ? WHERE user_id = ?', [hash, req.auth.id]);
  return res.json({ message: 'Password updated' });
}));

// ── ANALYST AUTH ───────────────────────────────────────────────

async function analystLogin(req, res) {
  const email = validateEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || '');
  if (!password) throw new ValidationError('Password is required');

  const analyst = await db.one('SELECT * FROM Analyst WHERE email = ? AND is_active = 1', [email]);
  if (!analyst || !analyst.password_hash) {
    return res.status(401).json({
      error: 'Incorrect email or password',
      code: 'INVALID_CREDENTIALS',
      hint: analyst ? 'This analyst account has no password set yet. Run `npm run seed` in the backend to set one.' : undefined,
    });
  }
  const valid = await bcrypt.compare(password, analyst.password_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect email or password', code: 'INVALID_CREDENTIALS' });

  await db.execute('UPDATE Analyst SET last_login = NOW() WHERE analyst_id = ?', [analyst.analyst_id]).catch(() => {});
  return res.json({
    token: analystToken(analyst),
    analyst: {
      id: analyst.analyst_id,
      name: analyst.name,
      role: analyst.role,
      email: analyst.email,
      department: analyst.department,
    },
  });
}

router.post('/analyst/login', loginLimiter, wrap(analystLogin));
// Backwards compatible with the original CIRS frontend.
router.post('/login', loginLimiter, wrap(analystLogin));

router.get('/analyst/me', authenticate(['analyst']), wrap(async (req, res) => {
  const analyst = await db.one(
    'SELECT analyst_id, name, email, role, department FROM Analyst WHERE analyst_id = ? AND is_active = 1',
    [req.auth.id],
  );
  if (!analyst) return res.status(401).json({ error: 'Analyst account no longer active', code: 'ACCOUNT_INACTIVE' });
  return res.json({
    analyst: {
      id: analyst.analyst_id,
      name: analyst.name,
      email: analyst.email,
      role: analyst.role,
      department: analyst.department,
    },
  });
}));

module.exports = router;
