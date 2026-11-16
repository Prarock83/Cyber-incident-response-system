'use strict';

/**
 * Small in-memory fixed-window rate limiter.
 * Node keeps a single process here; for multi-instance deployments put a shared
 * store (Redis) in front. Documented in docs/DEPLOYMENT.md.
 */
function createRateLimiter({ windowMs, max, keyGenerator, message }) {
  const buckets = new Map();

  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, Math.max(windowMs, 30_000));
  if (typeof cleanup.unref === 'function') cleanup.unref();

  return function rateLimiter(req, res, next) {
    const key = keyGenerator ? keyGenerator(req) : req.ip;
    if (!key) return next();

    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    const remaining = Math.max(0, max - bucket.count);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > max) {
      const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({
        error: message || 'Too many requests, please slow down and try again shortly',
        code: 'RATE_LIMITED',
        retryAfter,
      });
    }
    return next();
  };
}

module.exports = { createRateLimiter };
