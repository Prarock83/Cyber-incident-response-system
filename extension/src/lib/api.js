// Backend API client for CIRS extension pages.

import { getAuth, getSettings, clearAuth } from './storage.js';

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'ERROR', payload = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.payload = payload;
  }
}

/** Turn a user-entered server address into an API base such as https://host/api */
export function normaliseApiBase(raw) {
  const value = String(raw || '').trim();
  if (!value) return '';
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ApiError('Enter a full server URL, for example https://cirs-api.onrender.com/api', { code: 'INVALID_API_BASE' });
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new ApiError('The server URL must start with http:// or https://', { code: 'INVALID_API_BASE' });
  }
  let path = url.pathname.replace(/\/+$/, '');
  if (!/\/api$/i.test(path)) path = `${path}/api`;
  return `${url.origin}${path}`;
}

export function originPattern(apiBase) {
  const url = new URL(apiBase);
  return `${url.protocol}//${url.host}/*`;
}

export async function hasHostPermission(apiBase) {
  if (!apiBase) return false;
  try {
    const pattern = originPattern(apiBase);
    return await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    return false;
  }
}

export async function requestServerPermission(apiBase) {
  const pattern = originPattern(apiBase);
  return chrome.permissions.request({ origins: [pattern] });
}

async function resolveBase(explicit) {
  const base = explicit || (await getSettings()).apiBase;
  return normaliseApiBase(base);
}

export async function apiRequest(path, { method = 'GET', body, token, apiBase, timeoutMs = 20000 } = {}) {
  let base;
  try {
    base = await resolveBase(apiBase);
  } catch (err) {
    throw err;
  }
  if (!base) {
    throw new ApiError('Connect the extension to your CIRS server in Settings first.', { code: 'NOT_CONFIGURED' });
  }

  const auth = token === undefined ? await getAuth() : null;
  const bearer = token === undefined ? (auth && auth.token) : token;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      credentials: 'omit',
      cache: 'no-store',
    });

    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = null; }

    if (!response.ok) {
      if (response.status === 401 && token === undefined) await clearAuth();
      throw new ApiError(
        (payload && payload.error) || `The CIRS server returned ${response.status}`,
        { status: response.status, code: (payload && payload.code) || `HTTP_${response.status}`, payload },
      );
    }
    return payload;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err.name === 'AbortError') {
      throw new ApiError('The CIRS server took too long to respond. Please try again.', { code: 'TIMEOUT' });
    }
    throw new ApiError('Cannot reach the CIRS server. Check the server address in Settings and your connection.', { code: 'NETWORK_ERROR' });
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  health: () => apiRequest('/health', { token: null }),
  providers: () => apiRequest('/scan/providers', { token: null }),
  login: (email, password) => apiRequest('/users/login', { method: 'POST', body: { email, password }, token: null }),
  register: (name, email, password) => apiRequest('/users/register', { method: 'POST', body: { name, email, password }, token: null }),
  me: () => apiRequest('/users/me'),
  scan: (url) => apiRequest('/scan', { method: 'POST', body: { url } }),
  report: (payload) => apiRequest('/reports', { method: 'POST', body: payload }),
  reports: (query = '') => apiRequest(`/reports${query}`),
  reportDetail: (reference) => apiRequest(`/reports/${encodeURIComponent(reference)}`),
  stats: () => apiRequest('/user/stats'),
  scans: (limit = 25) => apiRequest(`/user/scans?limit=${limit}`),
  notifications: () => apiRequest('/user/notifications'),
  markNotificationRead: (id) => apiRequest(`/user/notifications/${id}/read`, { method: 'PATCH', body: {} }),
  markAllNotificationsRead: () => apiRequest('/user/notifications/read-all', { method: 'POST', body: {} }),
};
