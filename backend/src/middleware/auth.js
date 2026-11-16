'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

function sign(claims) {
  const expiresIn = claims.role === 'analyst' ? config.jwt.analystExpiry : config.jwt.userExpiry;
  return jwt.sign(claims, config.jwtSecret, {
    expiresIn,
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
  });
}

function userToken(user) {
  return sign({ sub: String(user.user_id), role: 'user', email: user.email, name: user.name });
}

function analystToken(analyst) {
  return sign({
    sub: String(analyst.analyst_id),
    id: analyst.analyst_id,
    role: 'analyst',
    email: analyst.email,
    name: analyst.name,
    analystRole: analyst.role,
  });
}

function readBearer(req) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (!token || scheme.toLowerCase() !== 'bearer') return null;
  return token.trim();
}

/**
 * Verify a JWT and attach `req.auth`.
 * @param {string[]} roles allowed roles; empty = any authenticated role.
 */
function authenticate(roles = []) {
  return (req, res, next) => {
    const token = readBearer(req);
    if (!token) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }
    let payload;
    try {
      payload = jwt.verify(token, config.jwtSecret, {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      });
    } catch (err) {
      const expired = err && err.name === 'TokenExpiredError';
      return res.status(401).json({
        error: expired ? 'Session expired, please sign in again' : 'Invalid authentication token',
        code: expired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
      });
    }
    if (roles.length && !roles.includes(payload.role)) {
      return res.status(403).json({ error: 'You do not have permission to access this resource', code: 'FORBIDDEN' });
    }
    req.auth = {
      id: Number(payload.sub),
      role: payload.role,
      email: payload.email,
      name: payload.name,
      analystRole: payload.analystRole || null,
    };
    return next();
  };
}

module.exports = { authenticate, userToken, analystToken, sign };
