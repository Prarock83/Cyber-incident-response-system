import {
  getSettings, saveSettings, getAuth, setAuth, clearAuth, getLastScan, setLastScan,
} from '../lib/storage.js';
import {
  api, ApiError, normaliseApiBase, hasHostPermission, requestServerPermission,
} from '../lib/api.js';
import { escapeHtml, timeAgo, verdictMeta, severityTone } from '../lib/format.js';

const $ = (id) => document.getElementById(id);

const state = {
  settings: null,
  auth: null,
  tab: null,
  scan: null,
  lastScan: null,
  busy: false,
  expanded: false,
  reported: null,
  authMode: 'login',
};

const VIEWS = { loading: 'viewLoading', setup: 'viewSetup', auth: 'viewAuth', main: 'viewMain' };

function showView(name) {
  for (const [key, id] of Object.entries(VIEWS)) {
    $(id).classList.toggle('hidden', key !== name);
  }
}

function show(el, visible) {
  if (!el) return;
  el.classList.toggle('hidden', !visible);
}

function setAlert(el, message) {
  if (!el) return;
  if (!message) { el.classList.add('hidden'); el.textContent = ''; return; }
  el.textContent = message;
  el.classList.remove('hidden');
}

function currentUrlInfo() {
  const url = (state.tab && state.tab.url) || '';
  let parsed = null;
  try { parsed = new URL(url); } catch { parsed = null; }
  const scannable = Boolean(parsed && ['http:', 'https:'].includes(parsed.protocol));
  return { url, parsed, scannable };
}

function renderProtectionPill() {
  const pill = $('protectionPill');
  if (!state.settings) return;
  const on = state.settings.protectionEnabled && state.settings.warnOnDangerous;
  pill.textContent = on ? 'Protected' : 'Limited';
  pill.className = `pill ${on ? 'on' : 'off'}`;
  pill.title = on
    ? 'CIRS warns you before high-risk websites load'
    : 'Automatic high-risk warnings are turned off in Settings';
}

function renderSite() {
  const { parsed, scannable } = currentUrlInfo();
  const domainEl = $('siteDomain');

  if (!scannable) {
    domainEl.textContent = (state.tab && state.tab.title) || 'This page';
    $('sitePath').textContent = parsed && parsed.protocol === 'chrome:' ? 'Browser page' : 'Local page';
    $('siteProtocol').textContent = 'N/A';
    $('siteProtocol').className = 'chip neutral';
    $('siteIcon').textContent = '🌐';
    setAlert($('scanNotice'), 'CIRS cannot scan browser settings pages, extension pages or local files. Open a normal website to run a scan.');
    $('rescanBtn').disabled = true;
    $('reportBtn').disabled = true;
    $('scanBtn').disabled = true;
    return;
  }

  setAlert($('scanNotice'), '');
  const host = parsed.hostname.replace(/^www\./, '');
  domainEl.textContent = host;
  domainEl.title = parsed.href;
  $('sitePath').textContent = `${parsed.pathname === '/' ? '' : parsed.pathname}${parsed.search}`.slice(0, 46) || '/';
  const https = parsed.protocol === 'https:';
  $('siteProtocol').textContent = https ? 'HTTPS' : 'HTTP';
  $('siteProtocol').className = `chip ${https ? 'safe' : 'warn'}`;
  $('siteIcon').textContent = https ? '🔒' : '🌐';
  $('rescanBtn').disabled = false;
  $('reportBtn').disabled = false;
  $('scanBtn').disabled = false;
}

function reasonTone(severity) {
  return severityTone(severity);
}

function renderResult() {
  const card = $('resultCard');
  if (!state.scan) { show(card, false); return; }
  show(card, true);

  const scan = state.scan;
  const meta = verdictMeta(scan.verdict);
  const verdictLabel = $('verdictLabel');
  verdictLabel.textContent = meta.label;
  verdictLabel.className = `verdict-label ${meta.tone}`;
  $('verdictHeadline').textContent = meta.headline;

  $('scoreValue').textContent = scan.riskScore;
  const ring = $('scoreRing');
  ring.className = `score-ring ${meta.tone}`;

  const fill = $('scoreFill');
  fill.className = `score-fill ${meta.tone}`;
  requestAnimationFrame(() => { fill.style.width = `${Math.max(3, Math.min(100, scan.riskScore))}%`; });

  $('confidenceChip').textContent = scan.confidence === 'reputation-assisted' ? 'Reputation assisted' : 'Heuristic only';
  $('confidenceChip').className = `chip ${scan.confidence === 'reputation-assisted' ? 'safe' : 'neutral'}`;

  $('resultSummary').textContent = scan.summary || '';
  $('disclaimer').textContent = scan.disclaimer || '';

  const reasons = scan.reasons || [];
  $('reasonCount').textContent = reasons.length ? `(${reasons.length})` : '(no indicators)';
  const visible = state.expanded ? reasons : reasons.slice(0, 4);
  const list = $('reasonList');
  list.innerHTML = visible.length
    ? visible.map((reason) => `
      <li class="reason-item">
        <span class="dot ${reasonTone(reason.severity)}"></span>
        <span class="reason-text">
          <span class="reason-label">${escapeHtml(reason.label || 'Risk indicator')}</span>
          <span class="reason-detail">${escapeHtml(reason.detail || '')}</span>
        </span>
      </li>`).join('')
    : '<li class="reason-item"><span class="dot safe"></span><span class="reason-text"><span class="reason-label">No URL risk indicators found</span><span class="reason-detail">This does not prove the site is safe — only that the address matches no known risky patterns.</span></span></li>';

  const toggle = $('toggleReasons');
  if (reasons.length > 4) {
    show(toggle, true);
    toggle.textContent = state.expanded ? 'Show fewer reasons' : `Show all ${reasons.length} reasons`;
  } else {
    show(toggle, false);
  }

  const intel = scan.threatIntel || {};
  if (!intel.configured) {
    $('intelLine').textContent = 'Threat intelligence: not configured on this server — result is based on URL heuristics only.';
  } else {
    const parts = (intel.results || []).map((result) => {
      const source = result.source === 'virustotal' ? 'VirusTotal' : 'Google Safe Browsing';
      if (result.error) return `${source}: unavailable`;
      return `${source}: ${result.verdict}`;
    });
    $('intelLine').textContent = parts.length
      ? `Threat intelligence: ${parts.join(' · ')}${intel.note ? ` — ${intel.note}` : ''}`
      : (intel.note || 'Threat intelligence: no result returned.');
  }

  renderExistingReport();
}

function renderExistingReport() {
  const el = $('existingReport');
  if (!state.reported) { show(el, false); return; }
  el.innerHTML = `You already reported this website. Reference <span class="mono">${escapeHtml(state.reported.referenceId)}</span> is <strong>${escapeHtml(state.reported.status)}</strong>.`;
  show(el, true);
}

function renderFooter() {
  const last = state.lastScan;
  $('footerLastScan').textContent = last
    ? `Last scan ${timeAgo(last.scannedAt)} · ${last.verdict}`
    : 'No scans yet';
}

function renderIdleState() {
  const { scannable } = currentUrlInfo();
  const idle = $('scanIdle');
  show(idle, scannable && !state.scan && !state.busy);
  show($('scanBusy'), state.busy);
}

function renderMain() {
  renderSite();
  renderIdleState();
  renderResult();
  renderFooter();
  renderProtectionPill();
  $('rescanBtn').textContent = state.scan ? 'Scan again' : 'Scan website';
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
      ? 'Server reachable and at least one threat-intelligence provider is configured'
      : 'Server reachable. No threat-intelligence key configured, so scans are heuristic-only.';
  } catch (err) {
    el.className = 'connection off';
    el.textContent = err.code === 'NOT_CONFIGURED' ? 'Not configured' : 'Offline';
    el.title = err.message;
  }
}

async function loadExistingReport() {
  if (!state.auth || !state.scan) return;
  try {
    const reports = await api.reports('?limit=100');
    const match = (reports || []).find((item) => item.domain === state.scan.domain);
    state.reported = match || null;
  } catch {
    state.reported = null;
  }
  renderExistingReport();
}

function handleError(err, alertId) {
  if (err instanceof ApiError && (err.status === 401 || err.code === 'TOKEN_EXPIRED' || err.code === 'INVALID_TOKEN')) {
    clearAuth().finally(() => {
      state.auth = null;
      state.scan = null;
      showView('auth');
      setAuthMode('login');
      setAlert($('loginError'), 'Your session expired. Please sign in again.');
    });
    return;
  }
  setAlert($(alertId), err.message || 'Something went wrong. Please try again.');
}

// ── SCAN ───────────────────────────────────────────────────────

async function scanWebsite() {
  if (state.busy) return;
  const { url, scannable } = currentUrlInfo();
  if (!scannable) return;

  state.busy = true;
  state.scan = null;
  state.reported = null;
  setAlert($('scanError'), '');
  setAlert($('existingReport'), '');
  show($('reportForm'), false);
  show($('reportSuccess'), false);
  renderMain();

  try {
    const result = await api.scan(url);
    state.scan = result;
    state.expanded = false;
    await setLastScan(result);
    state.lastScan = result;
    chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result }).catch(() => {});
    loadExistingReport();
  } catch (err) {
    handleError(err, 'scanError');
  } finally {
    state.busy = false;
    renderMain();
  }
}

// ── REPORT ─────────────────────────────────────────────────────

function openReportForm() {
  const { parsed, scannable } = currentUrlInfo();
  if (!scannable) return;
  show($('reportSuccess'), false);
  show($('reportForm'), true);
  setAlert($('reportError'), '');
  const context = state.scan
    ? `Reporting ${parsed.hostname} · CIRS result: ${state.scan.verdict} (risk ${state.scan.riskScore}/100)`
    : `Reporting ${parsed.hostname} — no scan was run, so CIRS will assess the address when you submit.`;
  $('reportContext').textContent = context;
  $('reportDescription').focus();
}

async function submitReport(event) {
  event.preventDefault();
  const { url, scannable } = currentUrlInfo();
  if (!scannable) return;

  const submit = $('submitReport');
  submit.disabled = true;
  submit.textContent = 'Submitting…';
  setAlert($('reportError'), '');

  try {
    const result = await api.report({
      url,
      category: $('reportCategory').value,
      description: $('reportDescription').value.trim(),
    });

    show($('reportForm'), false);
    show($('reportSuccess'), true);
    $('reportReference').textContent = result.referenceId;
    $('reportSuccessText').textContent = `CIRS assessed this website as ${result.verdict} (risk ${result.riskScore}/100). A security analyst will review your report and you can follow its status in the dashboard.`;
    $('reportDescription').value = '';
    state.reported = { referenceId: result.referenceId, status: result.status, domain: result.domain };
    renderExistingReport();
    chrome.runtime.sendMessage({
      type: 'REMEMBER_REPORT',
      report: { referenceId: result.referenceId, domain: result.domain, status: result.status },
    }).catch(() => {});
  } catch (err) {
    if (err instanceof ApiError && err.code === 'DUPLICATE_REPORT') {
      const existing = err.payload && err.payload.referenceId;
      setAlert($('reportError'), `${err.message}${existing ? '' : ''} You can follow it in your security history.`);
      if (existing) {
        state.reported = { referenceId: existing, status: (err.payload && err.payload.status) || 'Submitted' };
        renderExistingReport();
      }
    } else {
      handleError(err, 'reportError');
    }
  } finally {
    submit.disabled = false;
    submit.textContent = 'Submit report';
  }
}

// ── NAVIGATION ─────────────────────────────────────────────────

async function openDashboard(tabName = 'overview') {
  const response = await chrome.runtime
    .sendMessage({ type: 'OPEN_PANEL', windowId: state.tab && state.tab.windowId })
    .catch(() => null);
  if (!response || !response.ok) {
    chrome.tabs.create({ url: chrome.runtime.getURL(`src/sidepanel/panel.html?tab=${tabName}`) });
  }
}

function setAuthMode(mode) {
  state.authMode = mode;
  $('tabLogin').classList.toggle('active', mode === 'login');
  $('tabRegister').classList.toggle('active', mode === 'register');
  show($('loginForm'), mode === 'login');
  show($('registerForm'), mode === 'register');
}

function setButtonBusy(button, busy, label) {
  if (!button) return;
  button.disabled = busy;
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = label || 'Please wait…';
  } else if (button.dataset.label) {
    button.textContent = button.dataset.label;
  }
}

// ── STARTUP ────────────────────────────────────────────────────

async function enterMain() {
  state.auth = await getAuth();
  if (!state.auth) { showView('auth'); setAuthMode('login'); return; }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.tab = tab || null;
  state.lastScan = await getLastScan();
  const { parsed } = currentUrlInfo();
  const currentHost = parsed ? parsed.hostname.replace(/^www\./, '') : '';
  state.scan = state.lastScan && state.lastScan.domain === currentHost ? state.lastScan : null;
  state.expanded = false;
  showView('main');
  renderMain();
  ping();
  if (state.scan) loadExistingReport();
}

async function init() {
  bindEvents();
  state.settings = await getSettings();
  renderProtectionPill();

  if (!state.settings.apiBase) {
    showView('setup');
    return;
  }
  const permitted = await hasHostPermission(state.settings.apiBase);
  if (!permitted) {
    $('apiBaseInput').value = state.settings.apiBase;
    setAlert($('setupError'), 'CIRS needs permission to contact your server. Click Connect to allow it.');
    showView('setup');
    return;
  }
  state.auth = await getAuth();
  if (!state.auth) {
    showView('auth');
    setAuthMode('login');
    return;
  }
  await enterMain();
}

function bindEvents() {
  $('settingsBtn').addEventListener('click', () => chrome.runtime.openOptionsPage());
  $('panelBtn').addEventListener('click', () => openDashboard('overview'));

  $('saveApiBtn').addEventListener('click', async () => {
    setAlert($('setupError'), '');
    let base;
    try {
      base = normaliseApiBase($('apiBaseInput').value);
    } catch (err) {
      setAlert($('setupError'), err.message);
      return;
    }
    if (!base) { setAlert($('setupError'), 'Enter your CIRS server URL.'); return; }

    const button = $('saveApiBtn');
    setButtonBusy(button, true, 'Connecting…');
    try {
      const granted = await requestServerPermission(base);
      if (!granted) {
        setAlert($('setupError'), 'Permission to contact that server was not granted. CIRS cannot work without it.');
        return;
      }
      await saveSettings({ apiBase: base });
      state.settings = await getSettings();
      state.auth = await getAuth();
      if (state.auth) await enterMain();
      else { showView('auth'); setAuthMode('login'); }
    } catch (err) {
      setAlert($('setupError'), err.message);
    } finally {
      setButtonBusy(button, false);
    }
  });

  $('apiBaseInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') $('saveApiBtn').click();
  });

  $('tabLogin').addEventListener('click', () => setAuthMode('login'));
  $('tabRegister').addEventListener('click', () => setAuthMode('register'));

  $('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAlert($('loginError'), '');
    const button = $('loginBtn');
    setButtonBusy(button, true, 'Signing in…');
    try {
      const result = await api.login($('loginEmail').value.trim(), $('loginPassword').value);
      await setAuth(result.token, result.user);
      state.auth = { token: result.token, user: result.user };
      $('loginPassword').value = '';
      await enterMain();
    } catch (err) {
      setAlert($('loginError'), err.message);
    } finally {
      setButtonBusy(button, false);
    }
  });

  $('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAlert($('registerError'), '');
    const button = $('registerBtn');
    setButtonBusy(button, true, 'Creating account…');
    try {
      const result = await api.register(
        $('registerName').value.trim(),
        $('registerEmail').value.trim(),
        $('registerPassword').value,
      );
      await setAuth(result.token, result.user);
      state.auth = { token: result.token, user: result.user };
      $('registerPassword').value = '';
      await enterMain();
    } catch (err) {
      setAlert($('registerError'), err.message);
    } finally {
      setButtonBusy(button, false);
    }
  });

  $('scanBtn').addEventListener('click', scanWebsite);
  $('rescanBtn').addEventListener('click', scanWebsite);
  $('reportBtn').addEventListener('click', openReportForm);
  $('cancelReport').addEventListener('click', () => show($('reportForm'), false));
  $('reportForm').addEventListener('submit', submitReport);
  $('detailsBtn').addEventListener('click', () => openDashboard('overview'));
  $('historyBtn').addEventListener('click', () => openDashboard('history'));
  $('viewReportsBtn').addEventListener('click', () => openDashboard('reports'));
  $('anotherReportBtn').addEventListener('click', openReportForm);

  $('toggleReasons').addEventListener('click', () => {
    state.expanded = !state.expanded;
    renderResult();
  });

  $('signOutBtn').addEventListener('click', async () => {
    await clearAuth();
    state.auth = null;
    state.scan = null;
    state.reported = null;
    $('loginEmail').value = '';
    $('loginPassword').value = '';
    showView('auth');
    setAuthMode('login');
  });
}

init();
