'use strict';

const { analyzeUrl, primaryCategory } = require('./urlAnalyzer');
const threatIntel = require('./threatIntel');

const VERDICTS = ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'UNKNOWN'];

const CATEGORY_LABELS = {
  'lookalike-domain': 'Lookalike / impersonation domain',
  'credential-phishing': 'Credential phishing',
  'ip-host': 'IP-address host',
  obfuscation: 'URL obfuscation',
  'malware-distribution': 'Malware distribution',
  'suspicious-redirect': 'Suspicious redirect',
  'insecure-transport': 'Insecure transport',
  'suspicious-structure': 'Suspicious URL structure',
  general: 'General risk signal',
};

/**
 * Combine local heuristics with optional threat-intelligence results.
 *
 * Rules:
 *  - A malicious reputation hit always wins -> DANGEROUS.
 *  - Heuristic risk alone can only produce SUSPICIOUS or UNKNOWN, never SAFE.
 *  - SAFE requires an explicit "clean" answer from a configured provider.
 *  - No indicators and no provider = UNKNOWN (never "safe just because nothing matched").
 */
async function assessUrl(rawUrl, options = {}) {
  const analysis = analyzeUrl(rawUrl);

  let intel = { configured: false, results: [], verdict: 'unchecked', note: null };
  if (options.skipIntel !== true) {
    try {
      intel = await threatIntel.checkUrl(analysis.url);
    } catch (err) {
      intel = { configured: true, results: [], verdict: 'error', note: `Threat intelligence lookup failed: ${err.message}` };
    }
  }

  let verdict = 'UNKNOWN';
  let riskScore = analysis.score;
  const reasons = analysis.indicators.map((item) => ({
    id: item.id,
    label: item.label,
    detail: item.detail,
    severity: item.severity,
    weight: item.weight,
    category: item.category,
    categoryLabel: CATEGORY_LABELS[item.category] || CATEGORY_LABELS.general,
    source: 'heuristic',
  }));

  const maliciousResults = (intel.results || []).filter((result) => result.verdict === 'malicious');
  const suspiciousResults = (intel.results || []).filter((result) => result.verdict === 'suspicious');
  const cleanResults = (intel.results || []).filter((result) => result.verdict === 'clean');
  // A single high-severity indicator (typosquat, IP host, credentials trick,
  // brand impersonation) always warrants at least a SUSPICIOUS verdict, even
  // when the summed score sits below the generic threshold.
  const hasHighSeverity = analysis.indicators.some((item) => item.severity === 'high');

  for (const result of [...maliciousResults, ...suspiciousResults]) {
    reasons.unshift({
      id: `${result.source}-${result.verdict}`,
      label: result.source === 'virustotal' ? 'VirusTotal reputation hit' : 'Google Safe Browsing threat match',
      detail: result.details || 'A threat-intelligence provider flagged this URL.',
      severity: result.verdict === 'malicious' ? 'high' : 'medium',
      weight: result.verdict === 'malicious' ? 100 : 40,
      category: 'threat-intelligence',
      categoryLabel: 'Threat intelligence',
      source: result.source,
    });
  }

  if (maliciousResults.length) {
    verdict = 'DANGEROUS';
    riskScore = 100;
  } else if (suspiciousResults.length) {
    verdict = 'SUSPICIOUS';
    riskScore = Math.max(riskScore, 65);
  } else if (analysis.score >= 40 || hasHighSeverity) {
    verdict = 'SUSPICIOUS';
  } else if (cleanResults.length) {
    verdict = 'SAFE';
  } else {
    verdict = 'UNKNOWN';
  }

  const reasonsOut = reasons.slice(0, 25);

  let summary;
  if (verdict === 'DANGEROUS') {
    summary = 'A trusted threat-intelligence source has flagged this address as malicious. Do not enter passwords, card details or personal information.';
  } else if (verdict === 'SUSPICIOUS') {
    summary = analysis.indicators.length
      ? `The address shows ${analysis.indicators.length} risk indicator${analysis.indicators.length === 1 ? '' : 's'} that are commonly seen in phishing and scam campaigns.`
      : 'A threat-intelligence provider raised a concern about this address.';
  } else if (verdict === 'SAFE') {
    summary = 'A threat-intelligence provider reports no known threat for this address, and the URL structure looks ordinary. This is not a guarantee that the site is trustworthy.';
  } else if (!intel.configured) {
    summary = 'No threat-intelligence provider is configured, so CIRS cannot confirm this site is safe. Only local URL signals were checked.';
  } else {
    summary = 'No suspicious URL patterns were found, but no reputation source has confirmed this site either. Treat it as unverified.';
  }

  const disclaimer = 'CIRS combines transparent URL heuristics with optional reputation lookups. It is not an antivirus or a commercial phishing-detection engine and cannot guarantee that a website is safe.';

  return {
    url: analysis.url,
    domain: analysis.domain,
    hostname: analysis.hostname,
    protocol: analysis.protocol,
    isHttps: analysis.isHttps,
    verdict,
    riskScore: Math.min(100, Math.round(riskScore)),
    riskLevel: riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : riskScore >= 15 ? 'LOW' : 'MINIMAL',
    category: analysis.indicators.length ? primaryCategory(analysis.indicators) : 'general',
    categoryLabel: CATEGORY_LABELS[primaryCategory(analysis.indicators)] || CATEGORY_LABELS.general,
    heuristicScore: analysis.score,
    heuristicLevel: analysis.level,
    indicators: analysis.indicators,
    signals: analysis.signals,
    reasons: reasonsOut,
    summary,
    disclaimer,
    confidence: intel.configured ? (cleanResults.length || maliciousResults.length || suspiciousResults.length ? 'reputation-assisted' : 'heuristic-only') : 'heuristic-only',
    threatIntel: {
      configured: Boolean(intel.configured),
      verdict: intel.verdict,
      note: intel.note || null,
      results: (intel.results || []).map((result) => ({
        source: result.source,
        verdict: result.verdict,
        details: result.details || null,
        error: result.error || null,
        cached: Boolean(result.cached),
      })),
    },
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { assessUrl, VERDICTS, CATEGORY_LABELS };
