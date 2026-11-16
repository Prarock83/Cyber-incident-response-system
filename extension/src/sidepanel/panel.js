import { getSettings, saveSettings, getAuth, setAuth, clearAuth } from '../lib/storage.js';
import { api, ApiError } from '../lib/api.js';
import { escapeHtml, timeAgo, verdictMeta, statusTone, formatDateTime } from '../lib/format.js';

const $ = (id) => document.getElementById(id);

const REPORT_FLOW = ['Submitted', 'Under Review', 'Investigating', 'Confirmed Threat', 'False Positive', 'Resolved'];

const state = {
  settings: null,
  auth: null,
  tab: 'overview',
  stats: null,
  scans: [],
  reports: [],
  notifications: [],
  expandedReport: null,
  currentTab: null,
  filterStatus: '',
};

function show(el, visible) {
  if (el) el.classList.toggle('hidden', !visible);
}

function setAlert(el, message) {
  if (!el) return;
  if (!message) { el.classList.add('hidden'); el.textContent = ''; return; }
  el.textContent = message;
  el.classList.remove('hidden');
}

function initials(name) {
  return String(name || '?')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join('') || '?';
}

function humanise(value) {
  return String(value || '')
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderProtection() {
  const pill = $('protectionPill');
  const on = Boolean(state.settings && state.settings.protectionEnabled && state.settings.warnOnDangerous);
  pill.textContent = on ? 'Protected' : 'Limited';
  pill.className = `pill ${on ? 'on' : 'off'}`;
  if (state.settings) {
    $('toggleProtection').checked = Boolean(state.settings.protectionEnabled && state.settings.warnOnDangerous);
    $('toggleNotifications').checked = Boolean(state.settings.notificationsEnabled);
    $('toggleSuspicious').checked = Boolean(state.settings.notifySuspicious);
  }
}

function renderUser() {
  const user = state.auth && state.auth.user;
  if (!user) return;
  $('userName').textContent = user.name || 'CIRS user';
  $('userEmail').textContent = user.email || '';
  $('userInitials').textContent = initials(user.name);
}

async function ping() {
  const el = $('connStatus');
  el.className = 'connection';
  el.textContent = 'Checking…';
  try {
    const providers = await api.providers();
    el.className = 'connection on';
    el.textContent = providers.configured ? 'Connected · intel on' : 'Connected';
    el.title = providers.configured
      ? 'Server reachable, threat intelligence configured'
      : 'Server reachable. No threat-intelligence key configured.';
  } catch (err) {
    el.className = 'connection off';
    el.textContent = err.code === 'NOT_CONFIGURED' ? 'Not configured' : 'Offline';
    el.title = err.message;
  }
}

async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.currentTab = tab || null;
  let parsed = null;
  try { parsed = new URL((tab && tab.url) || ''); } catch { parsed = null; }
  const scannable = Boolean(parsed && ['http:', 'https:'].includes(parsed.protocol));
  $('currentDomain').textContent = scannable ? parsed.hostname.replace(/^www\./, '') : 'This page cannot be scanned';
  $('currentPath').textContent = scannable ? `${parsed.protocol}//${parsed.host}${parsed.pathname}` : 'Open a normal website to use CIRS';
  $('scanCurrentBtn').disabled = !scannable;
}

function renderStats() {
  const totals = (state.stats && state.stats.totals) || {};
  const stats = [
    { label: 'Scans', value: totals.scans || 0, tone: 'accent' },
    { label: 'Suspicious', value: totals.suspicious || 0, tone: 'warn' },
    { label: 'Reports', value: totals.reports || 0, tone: 'accent' },
    { label: 'Open reports', value: totals.openReports || 0, tone: totals.openReports ? 'danger' : 'safe' },
  ];
  $('statGrid').innerHTML = stats.map((item) => `
    <div class="stat">
      <div class="label">${item.label}</div>
      <div class="value ${item.tone}">${item.value}</div>
    </div>`).join('');

  const categories = (state.stats && state.stats.categories) || [];
  const max = categories.reduce((acc, row) => Math.max(acc, row.count), 1);
  $('categoryList').innerHTML = categories.length
    ? categories.map((row) => `
      <div class="category-row">
        <span class="category-name truncate" title="${escapeHtml(row.category)}">${escapeHtml(humanise(row.category))}</span>
        <span class="category-track"><span class="category-fill" style="width:${Math.round((row.count / max) * 100)}%"></span></span>
        <span class="category-count">${row.count}</span>
      </div>`).join('')
    : '<div class="empty-state"><div class="icon">◌</div>No threat categories recorded yet. Run a scan to start building your history.</div>';

  const activity = (state.stats && state.stats.recentActivity) || [];
  $('activityList').innerHTML = activity.length
    ? activity.map((item) => {
      const meta = verdictMeta(item.verdict);
      const detail = item.type === 'report' ? `Report ${item.referenceId} · ${item.status}` : `Scan · ${meta.label}`;
      return `<div class="list-item">
        <div class="row between">
          <span class="domain truncate">${escapeHtml(item.domain)}</span>
          <span class="chip ${meta.tone}">${meta.label}</span>
        </div>
        <div class="row between">
          <span class="tiny muted truncate">${escapeHtml(detail)}</span>
          <span class="tiny muted">${timeAgo(item.at)}</span>
        </div>
      </div>`;
    }).join('')
    : '<div class="empty-state"><div class="icon">◌</div>No activity yet.</div>';

  const unread = totals.unreadNotifications || 0;
  const badge = $('notifBadge');
  badge.textContent = String(unread);
  show(badge, unread > 0);
}

function renderScans() {
  const container = $('scanList');
  if (!state.scans.length) {
    container.innerHTML = '<div class="empty-state"><div class="icon">◎</div>No scans yet. Open the extension popup and scan a website.</div>';
    return;
  }
  container.innerHTML = state.scans.map((scan) => {
    const meta = verdictMeta(scan.verdict);
    return `<div class="list-item">
      <div class="row between">
        <span class="domain truncate">${escapeHtml(scan.domain)}</span>
        <span class="chip ${meta.tone}">${meta.label}</span>
      </div>
      <div class="row between">
        <span class="tiny muted truncate" title="${escapeHtml(scan.url)}">${escapeHtml(scan.url)}</span>
        <span class="mono muted tiny">${scan.riskScore}/100</span>
      </div>
      <div class="row between">
        <span class="tiny muted truncate">${escapeHtml(humanise(scan.category || 'general'))}</span>
        <span class="tiny muted">${timeAgo(scan.createdAt)}</span>
      </div>
    </div>`;
  }).join('');
}

function reportDetailHtml(report) {
  const reasons = (report.reasons || []).slice(0, 6);
  const flow = REPORT_FLOW.map((status) => {
    const tone = statusTone(status);
    const active = status === report.status;
    return `<span class="chip ${active ? tone : ''}" style="${active ? '' : 'opacity:.45'}">${escapeHtml(status)}</span>`;
  }).join(' ');
  return `<div class="report-detail">
    <div class="row wrap" style="gap:4px">${flow}</div>
    <div><strong>Submitted:</strong> ${formatDateTime(report.createdAt)}${report.updatedAt ? ` · <strong>Updated:</strong> ${formatDateTime(report.updatedAt)}` : ''}</div>
    ${report.description ? `<div><strong>Your description:</strong> ${escapeHtml(report.description)}</div>` : ''}
    ${reasons.length ? `<div><strong>Detected indicators:</strong><ul>${reasons.map((reason) => `<li>${escapeHtml(reason.label || reason)}</li>`).join('')}</ul></div>` : ''}
    ${report.analystNotes ? `<div class="notes"><strong>Analyst notes:</strong> ${escapeHtml(report.analystNotes)}</div>` : '<div class="muted">No analyst notes yet. A security analyst will review your report.</div>'}
    ${report.analystName ? `<div class="tiny muted">Reviewed by ${escapeHtml(report.analystName)}</div>` : ''}
  </div>`;
}

function renderReports() {
  const container = $('reportList');
  const reports = state.filterStatus
    ? state.reports.filter((report) => report.status === state.filterStatus)
    : state.reports;

  if (!reports.length) {
    container.innerHTML = `<div class="empty-state"><div class="icon">◎</div>${state.filterStatus ? 'No reports with this status.' : 'You have not reported any websites yet.'}</div>`;
    return;
  }

  container.innerHTML = reports.map((report) => {
    const meta = verdictMeta(report.verdict);
    const expanded = state.expandedReport === report.referenceId;
    return `<div class="list-item report-item" data-ref="${escapeHtml(report.referenceId)}">
      <div class="row between">
        <span class="domain truncate">${escapeHtml(report.domain)}</span>
        <span class="chip ${statusTone(report.status)}">${escapeHtml(report.status)}</span>
      </div>
      <div class="report-meta">
        <span class="ref">${escapeHtml(report.referenceId)}</span>
        <span class="chip ${meta.tone}">${meta.label} ${report.riskScore}/100</span>
        <span class="tiny muted">${timeAgo(report.createdAt)}</span>
      </div>
      ${expanded ? reportDetailHtml(report) : ''}
    </div>`;
  }).join('');

  container.querySelectorAll('.report-item').forEach((item) => {
    item.addEventListener('click', () => {
      const ref = item.getAttribute('data-ref');
      state.expandedReport = state.expandedReport === ref ? null : ref;
      renderReports();
    });
  });
}

function renderNotifications() {
  const container = $('notificationList');
  if (!state.notifications.length) {
    container.innerHTML = '<div class="empty-state"><div class="icon">🔔</div>No alerts yet. Report updates and security notices will appear here.</div>';
    return;
  }
  container.innerHTML = state.notifications.map((note) => `
    <div class="list-item notification ${note.isRead ? 'read' : ''} ${escapeHtml(note.severity || 'info')}" data-id="${note.id}">
      <span class="unread-dot"></span>
      <div class="grow">
        <div class="row between">
          <strong style="font-size:12px">${escapeHtml(note.title)}</strong>
          <span class="tiny muted">${timeAgo(note.createdAt)}</span>
        </div>
        <div class="tiny dim" style="margin-top:3px;line-height:1.5">${escapeHtml(note.message)}</div>
        ${note.referenceId ? `<div class="ref" style="margin-top:4px">${escapeHtml(note.referenceId)}</div>` : ''}
      </div>
    </div>`).join('');

  container.querySelectorAll('.notification').forEach((item) => {
    item.addEventListener('click', async () => {
      const id = item.getAttribute('data-id');
      const note = state.notifications.find((entry) => String(entry.id) === String(id));
      if (!note || note.isRead) return;
      try {
        await api.markNotificationRead(id);
        note.isRead = true;
        renderNotifications();
        if (state.stats && state.stats.totals) {
          state.stats.totals.unreadNotifications = Math.max(0, (state.stats.totals.unreadNotifications || 1) - 1);
          renderStats();
        }
      } catch {}
    });
  });
}

async function refreshData() {
  const results = await Promise.allSettled([
    api.stats(), api.scans(25), api.reports('?limit=100'), api.notifications(),
  ]);

  const [stats, scans, reports, notifications] = results;
  if (stats.status === 'fulfilled') state.stats = stats.value;
  if (scans.status === 'fulfilled') state.scans = scans.value || [];
  if (reports.status === 'fulfilled') state.reports = reports.value || [];
  if (notifications.status === 'fulfilled') state.notifications = notifications.value || [];

  const rejected = results.find((result) => result.status === 'rejected');
  if (rejected && rejected.reason instanceof ApiError && rejected.reason.status === 401) {
    await clearAuth();
    showBlocked('Your session expired. Sign in again.');
    return;
  }

  renderStats();
  renderScans();
  renderReports();
  renderNotifications();
}

function showBlocked(message) {
  show($('panelBody'), false);
  show($('authBlocked'), true);
  if (message) setAlert($('panelLoginError'), message);
}

async function scanCurrent() {
  const tab = state.currentTab;
  if (!tab || !/^https?:/i.test(tab.url || '')) return;
  const button = $('scanCurrentBtn');
  button.disabled = true;
  button.textContent = 'Scanning…';
  setAlert($('scanPanelError'), '');
  try {
    const result = await api.scan(tab.url);
    const meta = verdictMeta(result.verdict);
    $('currentResult').innerHTML = `
      <div class="mini-result">
        <div class="row between">
          <span class="verdict ${meta.tone}">${meta.label}</span>
          <span class="mono muted tiny">${result.riskScore}/100</span>
        </div>
        <div class="tiny dim">${escapeHtml(result.summary || '')}</div>
        ${result.reasons && result.reasons.length ? `<div class="tiny muted">${escapeHtml(result.reasons.slice(0, 2).map((reason) => reason.label).join(' · '))}</div>` : ''}
      </div>`;
    show($('currentResult'), true);
    chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result }).catch(() => {});
    await refreshData();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { await clearAuth(); showBlocked('Your session expired. Sign in again.'); }
    else setAlert($('scanPanelError'), err.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Scan';
  }
}

function switchTab(name) {
  state.tab = name;
  document.querySelectorAll('.tab[data-tab]').forEach((tab) => {
    tab.classList.toggle('active', tab.getAttribute('data-tab') === name);
  });
  ['overview', 'scans', 'reports', 'notifications'].forEach((pane) => {
    show($(`pane-${pane}`), pane === name);
  });
}

async function handleAuthAndLoad() {
  state.auth = await getAuth();
  if (!state.auth) { showBlocked(); return; }
  show($('authBlocked'), false);
  show($('panelBody'), true);
  renderUser();
  await loadCurrentTab();
  await ping();
  await refreshData();
}

async function init() {
  bindEvents();
  state.settings = await getSettings();
  renderProtection();
  $('footerApi').textContent = state.settings.apiBase
    ? new URL(state.settings.apiBase).host
    : 'no server configured';

  const requested = new URLSearchParams(location.search).get('tab');
  if (requested) switchTab(requested);

  if (!state.settings.apiBase) {
    showBlocked();
    show($('panelLoginForm'), false);
    setAlert($('panelLoginError'), 'Connect the extension to your CIRS server first. Open the extension popup and choose “Connect to server”.');
    return;
  }
  await handleAuthAndLoad();
}

function bindEvents() {
  $('settingsBtn').addEventListener('click', () => chrome.runtime.openOptionsPage());
  $('refreshBtn').addEventListener('click', async () => {
    await ping();
    await refreshData();
  });
  $('refreshScans').addEventListener('click', () => refreshData());
  $('scanCurrentBtn').addEventListener('click', scanCurrent);

  document.querySelectorAll('.tab[data-tab]').forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.getAttribute('data-tab')));
  });

  $('reportFilter').addEventListener('change', (event) => {
    state.filterStatus = event.target.value;
    renderReports();
  });

  $('markAllRead').addEventListener('click', async () => {
    try {
      await api.markAllNotificationsRead();
      state.notifications = state.notifications.map((note) => ({ ...note, isRead: true }));
      if (state.stats) state.stats.totals.unreadNotifications = 0;
      renderNotifications();
      renderStats();
    } catch (err) {
      setAlert($('scanPanelError'), err.message);
    }
  });

  ['toggleProtection', 'toggleNotifications', 'toggleSuspicious'].forEach((id) => {
    $(id).addEventListener('change', async () => {
      const protection = $('toggleProtection').checked;
      state.settings = await saveSettings({
        protectionEnabled: protection,
        warnOnDangerous: protection,
        notificationsEnabled: $('toggleNotifications').checked,
        notifySuspicious: $('toggleSuspicious').checked,
      });
      renderProtection();
    });
  });

  $('panelLoginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAlert($('panelLoginError'), '');
    const button = $('panelLoginBtn');
    button.disabled = true;
    button.textContent = 'Signing in…';
    try {
      const result = await api.login($('panelEmail').value.trim(), $('panelPassword').value);
      await setAuth(result.token, result.user);
      state.auth = { token: result.token, user: result.user };
      $('panelPassword').value = '';
      await handleAuthAndLoad();
    } catch (err) {
      setAlert($('panelLoginError'), err.message);
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  });

  $('signOutBtn').addEventListener('click', async () => {
    await clearAuth();
    state.auth = null;
    showBlocked();
  });
}

init();
