'use strict';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-for-cirs-unit-tests';

const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeUrl, registrableDomain } = require('../src/services/urlAnalyzer');
const { assessUrl } = require('../src/services/assessment');
const threatIntel = require('../src/services/threatIntel');
const config = require('../src/config');
const {
  parseHttpUrl, validatePassword, validateEmail, hashUrl,
} = require('../src/middleware/validate');

test('registrableDomain handles multi-part suffixes', () => {
  assert.equal(registrableDomain('login.secure.paypal.com.evil.co.uk'), 'evil.co.uk');
  assert.equal(registrableDomain('mail.google.com'), 'google.com');
  assert.equal(registrableDomain('192.168.0.4'), '192.168.0.4');
});

test('clean https URL produces no high-risk indicators', () => {
  const analysis = analyzeUrl('https://www.google.com/search?q=cirs');
  assert.equal(analysis.isHttps, true);
  assert.equal(analysis.score < 40, true);
  assert.equal(analysis.indicators.some((item) => item.severity === 'high'), false);
});

test('brand lookalike domain is flagged with an explanation', () => {
  const analysis = analyzeUrl('http://paypal-secure-login.xyz/verify');
  assert.equal(analysis.score >= 40, true);
  const brand = analysis.indicators.find((item) => item.id === 'brand-in-host');
  assert.ok(brand, 'expected brand-in-host indicator');
  assert.equal(brand.category, 'lookalike-domain');
  assert.match(brand.detail, /paypal\.com/);
});

test('typosquatting (paypa1) is detected', () => {
  const analysis = analyzeUrl('https://paypa1.com/login');
  assert.equal(analysis.indicators.some((item) => item.id === 'typosquat'), true);
});

test('credentials-in-URL trick is flagged', () => {
  const analysis = analyzeUrl('https://apple.com@evil.example.org/account');
  const userinfo = analysis.indicators.find((item) => item.id === 'userinfo');
  assert.ok(userinfo);
  assert.equal(userinfo.severity, 'high');
});

test('plain HTTP and IP hosts are reported honestly', () => {
  const analysis = analyzeUrl('http://203.0.113.9/login.php');
  assert.equal(analysis.isHttps, false);
  assert.equal(analysis.indicators.some((item) => item.id === 'ip-host'), true);
  assert.equal(analysis.indicators.some((item) => item.id === 'no-https'), true);
});

test('private IP notice is low severity', () => {
  const analysis = analyzeUrl('http://192.168.1.10:8080/admin');
  const ip = analysis.indicators.find((item) => item.id === 'ip-host');
  assert.equal(ip.severity, 'low');
  assert.ok(analysis.indicators.some((item) => item.id === 'odd-port'));
});

test('a single high-severity indicator is enough for SUSPICIOUS', async () => {
  const result = await assessUrl('https://paypa1.com/login', { skipIntel: true });
  assert.ok(result.heuristicScore < 40, 'fixture should stay under the generic score threshold');
  assert.equal(result.verdict, 'SUSPICIOUS');
  assert.ok(result.reasons.some((reason) => /paypal/i.test(reason.label + reason.detail)));
});

test('heuristics alone never return SAFE', async () => {
  const result = await assessUrl('https://example.com/', { skipIntel: true });
  assert.equal(result.verdict, 'UNKNOWN');
  assert.equal(result.threatIntel.configured, false);
  assert.match(result.summary, /cannot confirm|No threat-intelligence provider/i);
  assert.equal(result.confidence, 'heuristic-only');
  assert.match(result.disclaimer, /not an antivirus/i);
});

test('configured but clean reputation source produces SAFE with a caveat', async () => {
  const original = threatIntel.checkUrl;
  threatIntel.checkUrl = async () => ({
    configured: true,
    verdict: 'clean',
    results: [{ source: 'google-safe-browsing', verdict: 'clean', details: 'no matches' }],
    note: null,
  });
  try {
    const result = await assessUrl('https://example.com/');
    assert.equal(result.verdict, 'SAFE');
    assert.equal(result.confidence, 'reputation-assisted');
    assert.match(result.summary, /not a guarantee/i);
  } finally {
    threatIntel.checkUrl = original;
  }
});

test('a malicious threat-intelligence hit always wins', async () => {
  const original = threatIntel.checkUrl;
  threatIntel.checkUrl = async () => ({
    configured: true,
    verdict: 'malicious',
    results: [{ source: 'virustotal', verdict: 'malicious', details: '5 engines flag this URL' }],
    note: null,
  });
  try {
    const result = await assessUrl('https://example.com/');
    assert.equal(result.verdict, 'DANGEROUS');
    assert.equal(result.riskScore, 100);
    assert.equal(result.reasons[0].source, 'virustotal');
  } finally {
    threatIntel.checkUrl = original;
  }
});

test('Safe Browsing lookup maps matches to a malicious verdict', async () => {
  const previousKey = config.threatIntel.safeBrowsingKey;
  config.threatIntel.safeBrowsingKey = 'test-key';
  threatIntel.clearCache();
  const originalFetch = global.fetch;
  let calledUrl = '';
  global.fetch = async (url) => {
    calledUrl = String(url);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }),
    };
  };
  try {
    const result = await threatIntel.checkUrl('https://evil.example/login');
    assert.match(calledUrl, /safebrowsing\.googleapis\.com/);
    assert.equal(result.verdict, 'malicious');
    assert.equal(result.results[0].threats[0], 'SOCIAL_ENGINEERING');
  } finally {
    global.fetch = originalFetch;
    config.threatIntel.safeBrowsingKey = previousKey;
    threatIntel.clearCache();
  }
});

test('provider errors degrade to an unknown verdict instead of inventing a result', async () => {
  const previousKey = config.threatIntel.virusTotalKey;
  config.threatIntel.virusTotalKey = 'test-key';
  threatIntel.clearCache();
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: false, status: 429, text: async () => JSON.stringify({ error: { message: 'quota exceeded' } }) });
  try {
    const result = await threatIntel.checkUrl('https://example.com/');
    assert.equal(result.verdict, 'unchecked');
    assert.equal(result.results[0].verdict, 'error');
    assert.match(result.results[0].error, /quota exceeded/);
  } finally {
    global.fetch = originalFetch;
    config.threatIntel.virusTotalKey = previousKey;
    threatIntel.clearCache();
  }
});

test('URL validation rejects dangerous schemes and accepts bare domains', () => {
  assert.equal(parseHttpUrl('example.com').protocol, 'https:');
  assert.equal(parseHttpUrl('http://example.com/a').hostname, 'example.com');
  for (const bad of ['javascript:alert(1)', 'data:text/html,<script>', 'file:///etc/passwd', 'not a url', '']) {
    assert.throws(() => parseHttpUrl(bad), /website address|valid/i);
  }
});

test('password and email validation', () => {
  assert.throws(() => validatePassword('short1'), /8 and 72/);
  assert.throws(() => validatePassword('onlyletters'), /letter and one number/);
  assert.equal(validatePassword('Str0ngPass'), 'Str0ngPass');
  assert.throws(() => validateEmail('not-an-email'), /valid email/);
  assert.equal(validateEmail('  Test@Example.COM '), 'test@example.com');
  assert.equal(hashUrl('https://a.test').length, 64);
});
