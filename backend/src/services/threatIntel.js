'use strict';

/**
 * Threat-intelligence providers.
 *
 * Both providers are optional. With no API key configured the scanner is
 * heuristic-only and the API says so explicitly; it never invents results.
 */

const crypto = require('crypto');
const config = require('../config');

const cache = new Map();
const lastCall = new Map();

function cacheKey(source, url) {
  return `${source}:${url}`;
}

function readCache(source, url) {
  const entry = cache.get(cacheKey(source, url));
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    cache.delete(cacheKey(source, url));
    return null;
  }
  return { ...entry.value, cached: true };
}

function writeCache(source, url, value) {
  if (cache.size > 5000) {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (entry.expiresAt <= now) cache.delete(key);
    }
    if (cache.size > 5000) cache.delete(cache.keys().next().value);
  }
  cache.set(cacheKey(source, url), {
    value,
    expiresAt: Date.now() + config.threatIntel.cacheTtlSeconds * 1000,
  });
}

async function throttle(source) {
  const interval = config.threatIntel.minIntervalMs;
  const previous = lastCall.get(source) || 0;
  const wait = previous + interval - Date.now();
  if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
  lastCall.set(source, Date.now());
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(config.threatIntel.timeoutMs),
    headers: { accept: 'application/json', ...(options && options.headers) },
  });
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  return { status: response.status, ok: response.ok, body };
}

async function checkSafeBrowsing(url) {
  const source = 'google-safe-browsing';
  const cached = readCache(source, url);
  if (cached) return cached;

  await throttle(source);
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(config.threatIntel.safeBrowsingKey)}`;
  const { status, ok, body } = await fetchJson(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'cirs-extension', clientVersion: '2.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    }),
  });

  if (!ok) {
    const result = {
      source,
      verdict: 'error',
      error: body && body.error && body.error.message ? body.error.message : `Provider returned HTTP ${status}`,
    };
    if (status === 400 || status === 403) writeCache(source, url, result);
    return result;
  }

  const matches = (body && Array.isArray(body.matches)) ? body.matches : [];
  const result = matches.length
    ? {
      source,
      verdict: 'malicious',
      threats: [...new Set(matches.map((match) => match.threatType).filter(Boolean))],
      details: `Google Safe Browsing flagged this URL as ${[...new Set(matches.map((m) => m.threatType))].join(', ')}`,
    }
    : {
      source,
      verdict: 'clean',
      details: 'Google Safe Browsing reports no known threats for this URL',
    };
  writeCache(source, url, result);
  return result;
}

async function checkVirusTotal(url) {
  const source = 'virustotal';
  const cached = readCache(source, url);
  if (cached) return cached;

  await throttle(source);
  const id = Buffer.from(url).toString('base64url');
  const { status, ok, body } = await fetchJson(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { 'x-apikey': config.threatIntel.virusTotalKey },
  });

  if (status === 404) {
    const result = {
      source,
      verdict: 'unknown',
      details: 'VirusTotal does not have an analysis for this URL yet',
    };
    writeCache(source, url, result);
    return result;
  }
  if (!ok) {
    const result = {
      source,
      verdict: 'error',
      error: body && body.error && body.error.message ? body.error.message : `Provider returned HTTP ${status}`,
    };
    if (status === 401 || status === 403) writeCache(source, url, result);
    return result;
  }

  const stats = (body && body.data && body.data.attributes && body.data.attributes.last_analysis_stats) || null;
  const suspicious = (stats && stats.suspicious) || 0;
  const malicious = (stats && stats.malicious) || 0;
  const harmless = (stats && stats.harmless) || 0;
  const undetected = (stats && stats.undetected) || 0;

  let verdict = 'unknown';
  if (malicious > 0) verdict = 'malicious';
  else if (suspicious > 0) verdict = 'suspicious';
  else if (harmless + undetected > 0) verdict = 'clean';

  const result = {
    source,
    verdict,
    stats: { malicious, suspicious, harmless, undetected },
    details: verdict === 'malicious'
      ? `${malicious} of ${malicious + suspicious + harmless + undetected} VirusTotal engines flag this URL`
      : verdict === 'suspicious'
        ? `${suspicious} VirusTotal engines mark this URL as suspicious`
        : verdict === 'clean'
          ? `VirusTotal engines report no detections (${harmless + undetected} engines checked)`
          : 'VirusTotal returned no usable analysis for this URL',
  };
  writeCache(source, url, result);
  return result;
}

function providerStatus() {
  return {
    configured: Boolean(config.threatIntel.safeBrowsingKey || config.threatIntel.virusTotalKey),
    enabled: config.threatIntel.enabled,
    providers: [
      { id: 'google-safe-browsing', name: 'Google Safe Browsing', configured: Boolean(config.threatIntel.safeBrowsingKey) },
      { id: 'virustotal', name: 'VirusTotal', configured: Boolean(config.threatIntel.virusTotalKey) },
    ],
    cacheTtlSeconds: config.threatIntel.cacheTtlSeconds,
  };
}

/**
 * Ask every configured provider about one URL.
 * Only the specific URL being scanned leaves the server - never browsing history.
 */
async function checkUrl(url) {
  const status = providerStatus();
  if (!status.enabled) {
    return { configured: status.configured, results: [], verdict: 'unchecked', note: 'Threat intelligence lookups are disabled by configuration.' };
  }
  if (!status.configured) {
    return {
      configured: false,
      results: [],
      verdict: 'unchecked',
      note: 'No threat-intelligence API key is configured, so this assessment uses local heuristics only.',
    };
  }

  const tasks = [];
  if (config.threatIntel.safeBrowsingKey) tasks.push(checkSafeBrowsing(url).catch((err) => ({ source: 'google-safe-browsing', verdict: 'error', error: err.message })));
  if (config.threatIntel.virusTotalKey) tasks.push(checkVirusTotal(url).catch((err) => ({ source: 'virustotal', verdict: 'error', error: err.message })));

  const results = await Promise.all(tasks);
  let verdict = 'unchecked';
  if (results.some((result) => result.verdict === 'malicious')) verdict = 'malicious';
  else if (results.some((result) => result.verdict === 'suspicious')) verdict = 'suspicious';
  else if (results.some((result) => result.verdict === 'clean')) verdict = 'clean';
  else if (results.some((result) => result.verdict === 'unknown')) verdict = 'unknown';

  return { configured: true, results, verdict, note: null };
}

function clearCache() {
  cache.clear();
}

module.exports = { checkUrl, providerStatus, clearCache, __hash: (value) => crypto.createHash('sha256').update(value).digest('hex') };
