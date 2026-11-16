'use strict';

/**
 * CIRS configuration.
 * All secrets and connection details come from the environment.
 * A local backend/.env file is loaded when present (existing process env wins).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  const raw = fs.readFileSync(file, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (!key || Object.prototype.hasOwnProperty.call(process.env, key)) continue;
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadEnvFile(path.join(__dirname, '..', '.env'));

const env = process.env.NODE_ENV || 'development';
const isProduction = env === 'production';

function num(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function bool(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

// A stable secret is required in production. In development a random
// per-process secret is generated so nothing hardcoded ships in the repo.
let jwtSecret = process.env.JWT_SECRET || '';
if (!jwtSecret) {
  if (isProduction) {
    throw new Error('JWT_SECRET must be set when NODE_ENV=production');
  }
  jwtSecret = crypto.randomBytes(48).toString('hex');
  console.warn('[cirs] JWT_SECRET not set - using an ephemeral development secret. Tokens will not survive a restart.');
}

const corsOrigins = String(process.env.CORS_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

module.exports = {
  env,
  isProduction,
  port: num(process.env.PORT, 3000),
  jwtSecret,
  jwt: {
    issuer: 'cirs',
    audience: 'cirs-api',
    userExpiry: process.env.JWT_USER_EXPIRY || '7d',
    analystExpiry: process.env.JWT_ANALYST_EXPIRY || '8h',
  },
  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: num(process.env.DB_PORT, 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'cybersecurity_irs',
    connectionLimit: num(process.env.DB_CONNECTION_LIMIT, 10),
    ssl: bool(process.env.DB_SSL, false) ? { rejectUnauthorized: bool(process.env.DB_SSL_VERIFY, true) } : undefined,
  },
  corsOrigins,
  trustProxy: bool(process.env.TRUST_PROXY, isProduction),
  serveFrontend: bool(process.env.SERVE_FRONTEND, true),
  threatIntel: {
    safeBrowsingKey: process.env.SAFE_BROWSING_API_KEY || '',
    virusTotalKey: process.env.VIRUSTOTAL_API_KEY || '',
    timeoutMs: num(process.env.THREAT_INTEL_TIMEOUT_MS, 6000),
    cacheTtlSeconds: num(process.env.THREAT_INTEL_CACHE_TTL_SECONDS, 900),
    minIntervalMs: num(process.env.THREAT_INTEL_MIN_INTERVAL_MS, 1200),
    enabled: bool(process.env.THREAT_INTEL_ENABLED, true),
  },
  limits: {
    scansPerMinute: num(process.env.SCAN_RATE_LIMIT_PER_MINUTE, 30),
    reportsPerHour: num(process.env.REPORT_RATE_LIMIT_PER_HOUR, 10),
    loginAttemptsPerWindow: num(process.env.LOGIN_RATE_LIMIT, 10),
    loginWindowMs: num(process.env.LOGIN_RATE_WINDOW_MS, 15 * 60 * 1000),
  },
};
