// Shared extension configuration and storage helpers.

export const DEFAULT_SETTINGS = {
  apiBase: '',
  notificationsEnabled: true,
  notifySuspicious: true,
  protectionEnabled: true,
  warnOnDangerous: true,
};

const SETTINGS_KEY = 'settings';
const AUTH_KEY = 'auth';
const LAST_SCAN_KEY = 'lastScan';

export async function getSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(stored[SETTINGS_KEY] || {}) };
}

export async function saveSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

export async function getAuth() {
  const stored = await chrome.storage.local.get(AUTH_KEY);
  return stored[AUTH_KEY] || null;
}

export async function setAuth(token, user) {
  const auth = { token, user, savedAt: Date.now() };
  await chrome.storage.local.set({ [AUTH_KEY]: auth });
  return auth;
}

export async function clearAuth() {
  await chrome.storage.local.remove([AUTH_KEY]);
}

export async function getLastScan() {
  const stored = await chrome.storage.local.get(LAST_SCAN_KEY);
  return stored[LAST_SCAN_KEY] || null;
}

export async function setLastScan(scan) {
  await chrome.storage.local.set({ [LAST_SCAN_KEY]: scan });
}

// ── session-scoped state (cleared when the browser closes) ───────

async function getSession(key) {
  const stored = await chrome.storage.session.get(key);
  return stored[key] || {};
}

async function setSession(key, value) {
  await chrome.storage.session.set({ [key]: value });
}

export async function rememberDangerousSite(entry) {
  const cache = await getSession('dangerousSites');
  const now = Date.now();
  for (const [domain, value] of Object.entries(cache)) {
    if (!value || value.expiresAt < now) delete cache[domain];
  }
  cache[entry.domain] = { ...entry, expiresAt: now + 60 * 60 * 1000 };
  await setSession('dangerousSites', cache);
}

export async function getDangerousSite(domain) {
  const cache = await getSession('dangerousSites');
  const entry = cache[domain];
  if (!entry || entry.expiresAt < Date.now()) return null;
  return entry;
}

export async function allowSiteForSession(domain) {
  const bypass = await getSession('bypass');
  const now = Date.now();
  for (const [key, value] of Object.entries(bypass)) {
    if (!value || value < now) delete bypass[key];
  }
  bypass[domain] = now + 30 * 60 * 1000;
  await setSession('bypass', bypass);
  return bypass;
}

export async function isSiteBypassed(domain) {
  const bypass = await getSession('bypass');
  const until = bypass[domain];
  return Boolean(until && until > Date.now());
}
