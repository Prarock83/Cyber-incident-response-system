'use strict';

const crypto = require('crypto');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;

class ValidationError extends Error {
  constructor(message, code = 'VALIDATION_ERROR') {
    super(message);
    this.status = 400;
    this.code = code;
  }
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validateEmail(value) {
  const email = normalizeEmail(value);
  if (!email || email.length > 190 || !EMAIL_RE.test(email)) {
    throw new ValidationError('Enter a valid email address');
  }
  return email;
}

function validateName(value) {
  const name = String(value || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2 || name.length > 120) {
    throw new ValidationError('Name must be between 2 and 120 characters');
  }
  if (/[\u0000-\u001f<>]/.test(name)) {
    throw new ValidationError('Name contains invalid characters');
  }
  return name;
}

function validatePassword(value) {
  const password = String(value || '');
  if (password.length < 8 || password.length > 72) {
    throw new ValidationError('Password must be between 8 and 72 characters');
  }
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
    throw new ValidationError('Password must contain at least one letter and one number');
  }
  return password;
}

/**
 * Parse and normalise an http(s) URL. Rejects javascript:, data:, file: and
 * anything else that is not a plain web address.
 */
function parseHttpUrl(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.length > 2048) {
    throw new ValidationError('Enter a website address (http or https)');
  }
  let parsed;
  try {
    parsed = new URL(raw.includes('://') ? raw : `https://${raw}`);
  } catch {
    throw new ValidationError('That is not a valid website address');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new ValidationError('Only http and https website addresses are supported');
  }
  if (!parsed.hostname || !parsed.hostname.includes('.') && parsed.hostname !== 'localhost') {
    throw new ValidationError('That website address is missing a valid domain');
  }
  if (/[\s<>"]/.test(parsed.href)) {
    throw new ValidationError('That is not a valid website address');
  }
  return parsed;
}

function sanitizeText(value, max = 2000, field = 'text') {
  const text = String(value || '').trim();
  if (text.length > max) {
    throw new ValidationError(`${field} must be ${max} characters or fewer`);
  }
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
}

function oneOf(value, allowed, field = 'value') {
  const candidate = String(value || '').trim();
  if (!allowed.includes(candidate)) {
    throw new ValidationError(`${field} must be one of: ${allowed.join(', ')}`);
  }
  return candidate;
}

function integer(value, { min = 1, max = 100, fallback = null, field = 'value' } = {}) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    throw new ValidationError(`${field} must be a number between ${min} and ${max}`);
  }
  return parsed;
}

function hashUrl(url) {
  return crypto.createHash('sha256').update(String(url)).digest('hex');
}

/** Wrap async route handlers so rejected promises reach the error handler. */
function wrap(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

module.exports = {
  ValidationError,
  normalizeEmail,
  validateEmail,
  validateName,
  validatePassword,
  parseHttpUrl,
  sanitizeText,
  oneOf,
  integer,
  hashUrl,
  wrap,
};
