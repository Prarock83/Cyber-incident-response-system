'use strict';

/**
 * Explainable, transparent URL heuristic analyser.
 *
 * These are heuristics, NOT a commercial phishing/anti-malware engine. Every
 * indicator carries a plain-language reason and a weight so the extension can
 * show the user exactly why a score was produced.
 */

const SUSPICIOUS_TLDS = {
  tk: 14, ml: 14, ga: 14, cf: 14, gq: 14,
  zip: 14, mov: 12, cam: 10, rest: 8, cyou: 10, sbs: 10, icu: 10,
  top: 8, work: 8, click: 8, link: 8, quest: 8, buzz: 8, monster: 8,
  country: 8, lol: 10, support: 6, live: 4,
};

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 'rebrand.ly', 'bl.ink', 'tiny.cc',
]);

const BRANDS = {
  paypal: ['paypal.com'],
  google: ['google.com', 'google.co.in', 'googleusercontent.com'],
  gmail: ['gmail.com', 'google.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  netflix: ['netflix.com'],
  linkedin: ['linkedin.com'],
  twitter: ['twitter.com', 'x.com'],
  telegram: ['telegram.org', 't.me'],
  dropbox: ['dropbox.com'],
  github: ['github.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
  metamask: ['metamask.io'],
  dhl: ['dhl.com'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  irctc: ['irctc.co.in'],
  sbi: ['onlinesbi.sbi', 'sbi.co.in', 'onlinesbi.com'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  kotak: ['kotak.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  gpay: ['pay.google.com'],
  flipkart: ['flipkart.com'],
  myntra: ['myntra.com'],
  swiggy: ['swiggy.com'],
  zomato: ['zomato.com'],
  aadhaar: ['uidai.gov.in'],
  income_tax: ['incometax.gov.in'],
};

const LOOKALIKE_NORMALISATION = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '$': 's', '@': 'a' };

const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
  'account', 'update', 'confirm', 'password', 'passwd', 'wallet', 'banking',
  'unlock', 'recovery', 'billing', 'invoice', 'payment', 'authenticate',
  'webscr', 'session', 'support',
];

const RISKY_FILE_EXTENSIONS = ['.exe', '.apk', '.scr', '.msi', '.bat', '.cmd', '.jar', '.vbs', '.ps1', '.zip', '.rar', '.7z'];

const MULTI_PART_SUFFIXES = [
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'co.uk', 'org.uk',
  'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br',
  'com.mx', 'com.sg', 'com.tr', 'co.za', 'com.pk', 'com.bd', 'co.id',
];

function registrableDomain(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.includes(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

function isIpHost(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[');
}

function isPrivateIp(hostname) {
  const match = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const [a, b] = [Number(match[1]), Number(match[2])];
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

function normaliseLookalike(label) {
  return label.replace(/[0134578$@]/g, (char) => LOOKALIKE_NORMALISATION[char] || char);
}

function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j += 1) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return matrix[a.length][b.length];
}

function indicator(id, label, severity, weight, detail, category) {
  return { id, label, severity, weight, detail, category: category || 'general' };
}

/**
 * Analyse a URL.
 * @param {string} rawUrl
 * @returns {object} analysis with indicators, score (0-100) and level.
 */
function analyzeUrl(rawUrl) {
  const url = new URL(rawUrl);
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  const registrable = registrableDomain(hostname);
  const indicators = [];
  const path = `${url.pathname}${url.search}`;
  const full = url.href;
  const labels = hostname.split('.').filter(Boolean);
  const subdomainCount = Math.max(0, labels.length - registrable.split('.').length);
  const domainLabels = registrable.split('.');
  const secondLevel = domainLabels.length > 1 ? domainLabels[domainLabels.length - 2] : domainLabels[0];

  // 1. Transport security
  if (url.protocol !== 'https:') {
    indicators.push(indicator(
      'no-https',
      'Connection is not encrypted',
      'medium',
      18,
      'This address uses plain HTTP, so anything typed on the page can be read or changed in transit.',
      'insecure-transport',
    ));
  }

  // 2. Raw IP address instead of a domain name
  if (isIpHost(hostname)) {
    const privateIp = isPrivateIp(hostname);
    indicators.push(indicator(
      'ip-host',
      privateIp ? 'Local network address' : 'IP address instead of a domain name',
      privateIp ? 'low' : 'high',
      privateIp ? 6 : 26,
      privateIp
        ? 'This points at a private/local address. Only trust it if you set it up yourself.'
        : 'Legitimate public websites almost always use a domain name, not a bare IP address.',
      'ip-host',
    ));
  }

  // 3. Internationalised / punycode hostnames
  if (hostname.split('.').some((part) => part.startsWith('xn--'))) {
    indicators.push(indicator(
      'punycode',
      'Internationalised domain name',
      'medium',
      16,
      'The domain uses non-Latin characters that can look identical to a familiar brand name.',
      'lookalike-domain',
    ));
  }

  // 4. Brand / lookalike domain checks
  let brandMatched = false;
  for (const [brand, canonicalDomains] of Object.entries(BRANDS)) {
    const brandKey = brand.replace(/_/g, '');
    const canonical = canonicalDomains.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    );
    if (canonical) { brandMatched = true; break; }

    const escaped = brandKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`(^|[^a-z])${escaped}([^a-z]|$)`, 'i').test(hostname)) {
      indicators.push(indicator(
        'brand-in-host',
        `Mentions "${brandKey}" but is not the official domain`,
        'high',
        32,
        `The address references ${brandKey} while the real domain is ${canonicalDomains[0]}. This is a common phishing pattern.`,
        'lookalike-domain',
      ));
      brandMatched = true;
      break;
    }
  }

  if (!brandMatched) {
    for (const [brand, canonicalDomains] of Object.entries(BRANDS)) {
      const brandKey = brand.replace(/_/g, '');
      if (brandKey.length < 5) continue;
      const candidate = normaliseLookalike(secondLevel);
      const distance = editDistance(candidate, brandKey);
      const homoglyph = candidate === brandKey && secondLevel !== brandKey;
      if (homoglyph || (distance === 1 && candidate !== brandKey)) {
        indicators.push(indicator(
          'typosquat',
          homoglyph
            ? `Domain imitates "${brandKey}" using lookalike characters`
            : `Domain looks like "${brandKey}" with one character changed`,
          'high',
          28,
          `"${secondLevel}" impersonates ${brandKey} (official: ${canonicalDomains[0]}). This is a classic typosquatting pattern.`,
          'lookalike-domain',
        ));
        break;
      }
    }
  }

  // 5. Excessively deep subdomains
  if (subdomainCount >= 4) {
    indicators.push(indicator(
      'deep-subdomains',
      'Unusually deep subdomain chain',
      'medium',
      12,
      `The hostname has ${subdomainCount} subdomain levels before "${registrable}", which is often used to make a URL look official.`,
      'suspicious-structure',
    ));
  } else if (subdomainCount === 3) {
    indicators.push(indicator(
      'many-subdomains',
      'Several subdomain levels',
      'low',
      5,
      `The hostname has ${subdomainCount} subdomain levels. Often harmless, but worth a second look.`,
      'suspicious-structure',
    ));
  }

  // 6. Credential-harvesting keywords in the hostname
  const hostKeywords = CREDENTIAL_KEYWORDS.filter((word) => hostname.includes(word));
  if (hostKeywords.length) {
    indicators.push(indicator(
      'credential-keyword-host',
      `Login/security keywords in the domain (${hostKeywords.slice(0, 3).join(', ')})`,
      'medium',
      Math.min(24, 8 + hostKeywords.length * 6),
      'Attackers add words like "login", "verify" or "secure" to a domain to look trustworthy.',
      'credential-phishing',
    ));
  }

  // 7. Hyphen-heavy domains
  const hyphenCount = (secondLevel.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    indicators.push(indicator(
      'hyphen-heavy',
      'Many hyphens in the domain name',
      'medium',
      10,
      `The domain "${registrable}" contains ${hyphenCount} hyphens, a very common phishing style.`,
      'suspicious-structure',
    ));
  }

  // 8. Digits in the domain
  const digitCount = (secondLevel.match(/\d/g) || []).length;
  if (digitCount >= 4) {
    indicators.push(indicator(
      'digit-heavy',
      'Many digits in the domain name',
      'low',
      8,
      'Random-looking digit sequences are typical of throwaway phishing domains.',
      'suspicious-structure',
    ));
  }

  // 9. Userinfo trick (https://real-bank.com@evil.example)
  if (url.username || url.password) {
    indicators.push(indicator(
      'userinfo',
      'Address contains an "@" credentials trick',
      'high',
      30,
      'Everything before "@" is ignored by the browser; the real site is the part after it.',
      'obfuscation',
    ));
  }

  // 10. Excessive URL length
  if (full.length > 200) {
    indicators.push(indicator(
      'very-long-url',
      'Very long address',
      'medium',
      14,
      `This URL is ${full.length} characters long. Long URLs are used to hide the real destination.`,
      'obfuscation',
    ));
  } else if (full.length > 120) {
    indicators.push(indicator(
      'long-url',
      'Long address',
      'low',
      7,
      `This URL is ${full.length} characters long.`,
      'obfuscation',
    ));
  }

  // 11. Percent-encoding / obfuscation
  const encodedCount = (full.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encodedCount >= 4) {
    indicators.push(indicator(
      'encoded-url',
      'Heavily encoded address',
      'medium',
      12,
      `The URL contains ${encodedCount} encoded characters, which can hide the real destination.`,
      'obfuscation',
    ));
  }

  // 12. Redirect parameters
  if (/[?&](url|redirect|redirect_uri|next|continue|target|dest)={1,2}https?/i.test(url.search)) {
    indicators.push(indicator(
      'redirect-param',
      'Address contains an embedded redirect URL',
      'low',
      8,
      'Redirect parameters can send you to a different site after the first page loads.',
      'suspicious-redirect',
    ));
  }

  // 13. URL shortener
  if (URL_SHORTENERS.has(registrable)) {
    indicators.push(indicator(
      'shortener',
      'URL shortener hides the real destination',
      'low',
      8,
      `${registrable} redirects to an unknown destination. Expand it before sharing credentials.`,
      'suspicious-redirect',
    ));
  }

  // 14. Risky downloadable file
  const riskyExtension = RISKY_FILE_EXTENSIONS.find((ext) => path.toLowerCase().includes(ext));
  if (riskyExtension) {
    indicators.push(indicator(
      'risky-file',
      `Links to a downloadable ${riskyExtension} file`,
      'medium',
      15,
      'Executable or compressed downloads from an unfamiliar site are a common malware delivery route.',
      'malware-distribution',
    ));
  }

  // 15. Suspicious TLD
  const tld = registrable.split('.').pop();
  if (SUSPICIOUS_TLDS[tld]) {
    indicators.push(indicator(
      'suspicious-tld',
      `.${tld} domains are widely abused for scams`,
      'low',
      SUSPICIOUS_TLDS[tld],
      `The .${tld} top-level domain has a high abuse rate. This alone is not proof of a problem.`,
      'suspicious-structure',
    ));
  }

  // 16. Odd port
  if (url.port && !['80', '443', ''].includes(url.port)) {
    indicators.push(indicator(
      'odd-port',
      `Unusual network port :${url.port}`,
      'low',
      5,
      'Websites normally use the standard ports; unusual ports can point to a temporary server.',
      'suspicious-structure',
    ));
  }

  // 17. Path keywords (lower weight, only if host was clean)
  const pathKeywords = CREDENTIAL_KEYWORDS.filter((word) => path.toLowerCase().includes(word));
  if (pathKeywords.length && !hostKeywords.length) {
    indicators.push(indicator(
      'credential-keyword-path',
      `Page path mentions ${pathKeywords.slice(0, 3).join(', ')}`,
      'low',
      Math.min(10, 3 + pathKeywords.length * 2),
      'Login-style words in the path are common on real sites too, so this is a weak signal.',
      'credential-phishing',
    ));
  }

  const score = Math.min(100, indicators.reduce((total, item) => total + item.weight, 0));
  const level = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 15 ? 'LOW' : 'MINIMAL';

  return {
    url: full,
    hostname,
    domain: registrable,
    protocol: url.protocol.replace(':', ''),
    isHttps: url.protocol === 'https:',
    score,
    level,
    indicators,
    signals: {
      subdomainCount,
      hostLength: hostname.length,
      urlLength: full.length,
      isIpHost: isIpHost(hostname),
      hasPunycode: hostname.includes('xn--'),
      usesShortener: URL_SHORTENERS.has(registrable),
      hyphenCount,
      encodedCount,
      brandImpersonation: indicators.some((item) => item.category === 'lookalike-domain'),
    },
  };
}

/** Pick the most useful threat category from the indicators. */
function primaryCategory(indicators) {
  const order = ['lookalike-domain', 'credential-phishing', 'ip-host', 'obfuscation', 'malware-distribution', 'suspicious-redirect', 'insecure-transport', 'suspicious-structure'];
  for (const category of order) {
    if (indicators.some((item) => item.category === category)) return category;
  }
  return 'general';
}

module.exports = { analyzeUrl, registrableDomain, primaryCategory, isIpHost, isPrivateIp };
