import { getSettings, saveSettings, getAuth, clearAuth } from '../lib/storage.js';
import { api, normaliseApiBase, requestServerPermission, hasHostPermission } from '../lib/api.js';
import { escapeHtml } from '../lib/format.js';

const $ = (id) => document.getElementById(id);

function show(el, visible) {
  if (el) el.classList.toggle('hidden', !visible);
}

function setMessage(text, tone = 'info') {
  const el = $('serverMessage');
  if (!text) { el.classList.add('hidden'); return; }
  el.textContent = text;
  el.className = `alert ${tone}`;
}

function initials(name) {
  return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2)
    .map((part) => part[0].toUpperCase()).join('') || '?';
}

function renderPill(settings) {
  const on = settings.protectionEnabled && settings.warnOnDangerous;
  const pill = $('protectionPill');
  pill.textContent = on ? 'Protected' : 'Limited';
  pill.className = `pill ${on ? 'on' : 'off'}`;
}

function renderAccount(auth) {
  if (!auth || !auth.user) {
    $('accountName').textContent = 'Not signed in';
    $('accountEmail').textContent = 'Sign in from the extension popup.';
    $('accountInitials').textContent = '--';
    return;
  }
  $('accountName').textContent = auth.user.name || 'CIRS user';
  $('accountEmail').textContent = auth.user.email || '';
  $('accountInitials').textContent = initials(auth.user.name);
}

async function refreshPermissionHint(settings) {
  const hint = $('permissionHint');
  if (!settings.apiBase) {
    hint.textContent = 'No server configured yet.';
    hint.style.color = '';
    return;
  }
  const granted = await hasHostPermission(settings.apiBase);
  hint.textContent = granted
    ? 'Permission granted for this server.'
    : 'Access to this server is not granted yet — press “Save & allow access”.';
  hint.style.color = granted ? 'var(--safe)' : 'var(--warn)';
}

async function testConnection(base) {
  const details = $('serverDetails');
  details.innerHTML = '<span class="skeleton" style="width:70%"></span>';
  show(details, true);
  try {
    const providers = await api.providers();
    let health = null;
    try { health = await api.health(); } catch (err) { health = err.payload || null; }
    details.innerHTML = `
      <div><span class="ok">✓ Server reachable</span> — ${escapeHtml(base)}</div>
      <div>Database: ${health && health.database && health.database.connected ? '<span class="ok">connected</span>' : '<span class="bad">not connected (scan history and reports need the database)</span>'}</div>
      <div>Threat intelligence: ${providers.configured
        ? providers.providers.filter((p) => p.configured).map((p) => escapeHtml(p.name)).join(', ')
        : '<span class="bad">not configured — heuristic-only scans</span>'}</div>
      ${health && health.database && health.database.schema && health.database.schema.ready === false
        ? `<div class="bad">Schema not ready${health.database.schema.missing && health.database.schema.missing.length ? `: missing ${escapeHtml(health.database.schema.missing.join(', '))}` : ''}</div>`
        : ''}
    `;
    setMessage('Connection successful.', 'success');
  } catch (err) {
    details.innerHTML = `<div class="bad">${escapeHtml(err.message)}</div>`;
    setMessage('Could not reach that server. Check the URL and that the backend is running.', 'error');
  }
}

async function init() {
  const settings = await getSettings();
  const auth = await getAuth();

  $('apiBase').value = settings.apiBase || '';
  $('protectionEnabled').checked = settings.protectionEnabled && settings.warnOnDangerous;
  $('notificationsEnabled').checked = settings.notificationsEnabled;
  $('notifySuspicious').checked = settings.notifySuspicious;
  renderPill(settings);
  renderAccount(auth);
  await refreshPermissionHint(settings);
  if (settings.apiBase) testConnection(settings.apiBase);
}

$('saveServer').addEventListener('click', async () => {
  setMessage('');
  let base;
  try {
    base = normaliseApiBase($('apiBase').value);
  } catch (err) {
    setMessage(err.message, 'error');
    return;
  }
  if (!base) { setMessage('Enter your CIRS server URL.', 'error'); return; }

  const button = $('saveServer');
  button.disabled = true;
  try {
    const granted = await requestServerPermission(base);
    if (!granted) {
      setMessage('Chrome did not grant access to that server, so the extension cannot use it.', 'error');
      return;
    }
    const settings = await saveSettings({ apiBase: base });
    $('apiBase').value = settings.apiBase;
    await refreshPermissionHint(settings);
    renderPill(settings);
    await testConnection(settings.apiBase);
  } catch (err) {
    setMessage(err.message, 'error');
  } finally {
    button.disabled = false;
  }
});

$('testServer').addEventListener('click', async () => {
  let base;
  try { base = normaliseApiBase($('apiBase').value); } catch (err) { setMessage(err.message, 'error'); return; }
  if (!base) { setMessage('Enter your CIRS server URL first.', 'error'); return; }
  await testConnection(base);
});

['protectionEnabled', 'notificationsEnabled', 'notifySuspicious'].forEach((id) => {
  $(id).addEventListener('change', async () => {
    const settings = await saveSettings({
      protectionEnabled: $('protectionEnabled').checked,
      warnOnDangerous: $('protectionEnabled').checked,
      notificationsEnabled: $('notificationsEnabled').checked,
      notifySuspicious: $('notifySuspicious').checked,
    });
    renderPill(settings);
  });
});

$('signOut').addEventListener('click', async () => {
  await clearAuth();
  renderAccount(null);
  setMessage('Signed out. Sign in again from the extension popup.', 'success');
});

$('openDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('src/sidepanel/panel.html') });
});

init();
