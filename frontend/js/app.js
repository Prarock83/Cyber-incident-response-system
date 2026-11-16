// ── CONFIG ───────────────────────────────────────────────────
const API = (window.CIRS_CONFIG && window.CIRS_CONFIG.apiBase) || '/api';

// ── AUTH ──────────────────────────────────────────────────────
function getToken() { return localStorage.getItem('cirs_token'); }
function getAnalyst() {
  try { return JSON.parse(localStorage.getItem('cirs_analyst')); }
  catch { return null; }
}
function requireAuth() {
  if (!getToken()) { window.location.replace('../index.html'); return false; }
  return true;
}
function logout() {
  localStorage.removeItem('cirs_token');
  localStorage.removeItem('cirs_analyst');
  window.location.replace('../index.html');
}

// ── API HELPER ────────────────────────────────────────────────
async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(API + path, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + getToken(),
        ...(opts.headers || {})
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
  } catch (networkError) {
    throw new Error('Cannot reach the CIRS API at ' + API + '. Check the backend is running and CORS_ORIGINS is configured.');
  }

  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    const message = data.error || 'Your session expired. Please sign in again.';
    logout();
    throw new Error(message);
  }
  if (!res.ok) {
    const error = new Error(data.error || `Request failed (${res.status})`);
    error.code = data.code;
    error.status = res.status;
    error.payload = data;
    throw error;
  }
  return data;
}

// ── SIDEBAR INIT ──────────────────────────────────────────────
function initSidebar(activePage) {
  const analyst = getAnalyst();
  if (!analyst) return;

  const nameEl = document.getElementById('analystName');
  const roleEl = document.getElementById('analystRole');
  const initialsEl = document.getElementById('analystInitials');
  if (nameEl) nameEl.textContent = analyst.name;
  if (roleEl) roleEl.textContent = analyst.role;
  if (initialsEl) {
    initialsEl.textContent = analyst.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
  }

  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === activePage);
  });

  api('/dashboard/stats').then(stats => {
    const badge = document.getElementById('alertBadge');
    if (badge && stats?.criticalAlerts > 0) {
      badge.textContent = stats.criticalAlerts;
      badge.style.display = 'inline-block';
    }
    const reportBadge = document.getElementById('reportBadge');
    if (reportBadge && stats?.openUserReports > 0) {
      reportBadge.textContent = stats.openUserReports;
      reportBadge.style.display = 'inline-block';
    }
  }).catch(() => {});
}

// ── CLOCK ─────────────────────────────────────────────────────
function initClock(id) {
  function tick() {
    const el = document.getElementById(id);
    if (el) el.textContent = new Date().toISOString().replace('T', ' ').split('.')[0] + ' UTC';
  }
  tick(); setInterval(tick, 1000);
}

// ── TOAST ─────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.className = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = (type === 'success' ? '✓ ' : '⚠ ') + msg;
  t.className = 'toast ' + type;
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 4000);
}

// ── MODAL ─────────────────────────────────────────────────────
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── BADGE HELPERS ─────────────────────────────────────────────
function severityBadge(s) {
  const map = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' };
  return `<span class="badge badge-${(map[s] || 'low')}">${s || '—'}</span>`;
}
function statusBadge(s) {
  const map = { 'Open': 'open', 'In Progress': 'progress', 'Resolved': 'resolved', 'Closed': 'closed' };
  return `<span class="badge badge-${(map[s] || 'closed')}">${s || '—'}</span>`;
}
function verdictBadge(v) {
  const map = { SAFE: 'status-safe', SUSPICIOUS: 'status-suspicious', DANGEROUS: 'status-dangerous', UNKNOWN: 'status-unknown' };
  const label = v || 'UNKNOWN';
  return `<span class="badge verdict ${map[label] || 'status-unknown'}">${label}</span>`;
}
function reportStatusBadge(s) {
  const map = {
    'Submitted': 'progress',
    'Under Review': 'medium',
    'Investigating': 'high',
    'Confirmed Threat': 'critical',
    'False Positive': 'resolved',
    'Resolved': 'resolved'
  };
  return `<span class="badge badge-${map[s] || 'closed'}">${s || '—'}</span>`;
}
function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}
function fmtIp(ip) {
  return ip ? `<span class="mono text-accent">${ip}</span>` : '<span class="text-muted">—</span>';
}
function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function parseReasons(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed : []; }
  catch { return []; }
}
