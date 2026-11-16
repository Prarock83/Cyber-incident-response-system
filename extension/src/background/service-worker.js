// CIRS background service worker (Manifest V3).
// Responsibilities: remember high-risk sites, show the interstitial before a
// high-risk site loads, fire deduplicated notifications, and serve popup
// actions that need an extension-level API.

import { getSettings, rememberDangerousSite, getDangerousSite, isSiteBypassed } from '../lib/storage.js';
import { api } from '../lib/api.js';

const NOTIFY_COOLDOWN_MS = 12 * 60 * 60 * 1000;
const TAB_BYPASS_MS = 4000;

async function getTabBypass() {
  const stored = await chrome.storage.session.get('tabBypass');
  const map = stored.tabBypass || {};
  const now = Date.now();
  for (const [key, value] of Object.entries(map)) {
    if (!value || value.expiresAt < now) delete map[key];
  }
  return map;
}

async function bypassTab(tabId, url, ms = TAB_BYPASS_MS) {
  const map = await getTabBypass();
  map[String(tabId)] = { url, expiresAt: Date.now() + ms };
  await chrome.storage.session.set({ tabBypass: map });
}

async function isTabBypassed(tabId, url) {
  const map = await getTabBypass();
  const entry = map[String(tabId)];
  return Boolean(entry && entry.url === url && entry.expiresAt > Date.now());
}

async function shouldNotify(key) {
  const stored = await chrome.storage.local.get('notificationLog');
  const log = stored.notificationLog || {};
  const now = Date.now();
  for (const [entry, at] of Object.entries(log)) {
    if (now - at > NOTIFY_COOLDOWN_MS) delete log[entry];
  }
  await chrome.storage.local.set({ notificationLog: log });
  if (log[key] && now - log[key] < NOTIFY_COOLDOWN_MS) return false;
  return { log };
}

async function markNotified(key) {
  const stored = await chrome.storage.local.get('notificationLog');
  const log = stored.notificationLog || {};
  log[key] = Date.now();
  await chrome.storage.local.set({ notificationLog: log });
}

async function notify({ title, message, key, priority = 2 }) {
  const settings = await getSettings();
  if (!settings.notificationsEnabled) return;
  const gate = await shouldNotify(key);
  if (!gate) return;
  try {
    await chrome.notifications.create(`cirs-${key}-${Date.now()}`, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon128.png'),
      title,
      message,
      priority,
    });
    await markNotified(key);
  } catch (err) {
    console.warn('[cirs] notification failed:', err.message);
  }
}

async function findExistingReport(domain) {
  try {
    const reports = await api.reports('?limit=100');
    return (reports || []).find((report) => report.domain === domain) || null;
  } catch {
    return null;
  }
}

async function handleScanResult(result) {
  if (!result || !result.domain || !result.verdict) return;

  if (result.verdict === 'SUSPICIOUS' || result.verdict === 'DANGEROUS') {
    await rememberDangerousSite({
      domain: result.domain,
      url: result.url,
      verdict: result.verdict,
      score: result.riskScore,
      reasons: (result.reasons || []).slice(0, 6).map((reason) => ({ label: reason.label, detail: reason.detail, severity: reason.severity })),
      savedAt: Date.now(),
    });
  }

  const existingReport = await findExistingReport(result.domain);
  const reportedNote = existingReport
    ? ` You reported this site (${existingReport.referenceId}, currently ${existingReport.status}).`
    : '';

  if (result.verdict === 'DANGEROUS') {
    await notify({
      title: existingReport ? 'CIRS: website you reported is dangerous' : 'CIRS: high-risk website detected',
      message: `${result.domain} is flagged as dangerous (risk ${result.riskScore}/100). Avoid entering personal details.${reportedNote}`,
      key: `danger:${result.domain}:${existingReport ? 'reported' : 'new'}`,
      priority: 2,
    });
    return;
  }

  if (result.verdict === 'SUSPICIOUS') {
    const settings = await getSettings();
    if (!settings.notifySuspicious) return;
    await notify({
      title: existingReport ? 'CIRS: website you reported is still suspicious' : 'CIRS: suspicious website detected',
      message: `${result.domain} shows risk indicators (risk ${result.riskScore}/100). Review the reasons before signing in.${reportedNote}`,
      key: `suspicious:${result.domain}:${existingReport ? 'reported' : 'new'}`,
    });
  }
}

async function handleRememberReported(report) {
  if (!report || !report.domain) return;
  await notify({
    title: 'CIRS: report update',
    message: `Your report ${report.referenceId} for ${report.domain} is now "${report.status}".`,
    key: `report:${report.referenceId}:${report.status}`,
  });
}

async function openWarning(tabId, url) {
  const domain = new URL(url).hostname.toLowerCase();
  const entry = await getDangerousSite(domain);
  if (!entry) return;
  if (await isSiteBypassed(domain)) return;
  if (await isTabBypassed(tabId, url)) return;

  const params = new URLSearchParams({
    url,
    domain,
    verdict: entry.verdict,
    score: String(entry.score || 0),
    reasons: JSON.stringify(entry.reasons || []),
  });
  const warningUrl = chrome.runtime.getURL(`src/warning/warning.html?${params.toString()}`);
  await bypassTab(tabId, url, 1500);
  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
    await notify({
      title: 'CIRS blocked a high-risk website',
      message: `${domain} was flagged as dangerous. Review the warning before continuing.`,
      key: `block:${domain}:${Math.floor(Date.now() / NOTIFY_COOLDOWN_MS)}`,
    });
  } catch (err) {
    console.warn('[cirs] could not open warning:', err.message);
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  try {
    await chrome.sidePanel.setOptions({ path: 'src/sidepanel/panel.html', enabled: true });
  } catch {}
  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
  } catch {}
  chrome.alarms.create('cirs-housekeeping', { periodInMinutes: 60 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'cirs-housekeeping') return;
  const stored = await chrome.storage.local.get('notificationLog');
  const log = stored.notificationLog || {};
  const now = Date.now();
  let changed = false;
  for (const [key, at] of Object.entries(log)) {
    if (now - at > NOTIFY_COOLDOWN_MS) { delete log[key]; changed = true; }
  }
  if (changed) await chrome.storage.local.set({ notificationLog: log });
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // React as early as possible: on the new URL while loading, or on completion.
  const url = changeInfo.url || (changeInfo.status === 'complete' && tab ? tab.url : null);
  if (!url || !/^https?:/i.test(url)) return;
  const settings = await getSettings();
  if (!settings.protectionEnabled || !settings.warnOnDangerous) return;
  try {
    await openWarning(tabId, url);
  } catch (err) {
    console.warn('[cirs] warning check failed:', err.message);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string') return false;

  if (message.type === 'SCAN_RESULT') {
    handleScanResult(message.result)
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'REMEMBER_REPORT') {
    handleRememberReported(message.report)
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'OPEN_PANEL') {
    (async () => {
      try {
        const options = message.tabId ? { tabId: message.tabId } : { windowId: message.windowId };
        await chrome.sidePanel.open(options);
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ ok: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'GO_SAFE') {
    (async () => {
      const tabId = (sender.tab && sender.tab.id) || message.tabId;
      if (!tabId) { sendResponse({ ok: false }); return; }
      try {
        await bypassTab(tabId, message.url || '', TAB_BYPASS_MS);
        await chrome.tabs.goBack(tabId);
        // Step back once more so the warning page itself is skipped as well.
        setTimeout(async () => {
          try {
            await bypassTab(tabId, message.url || '', 500);
            await chrome.tabs.goBack(tabId);
          } catch {}
        }, 350);
        sendResponse({ ok: true });
      } catch {
        try {
          await chrome.tabs.update(tabId, { url: 'about:blank' });
          sendResponse({ ok: true });
        } catch (err) {
          sendResponse({ ok: false, error: err.message });
        }
      }
    })();
    return true;
  }

  if (message.type === 'CONTINUE_TO_SITE') {
    (async () => {
      const tabId = (sender.tab && sender.tab.id) || message.tabId;
      if (!tabId || !message.url || !/^https?:/i.test(message.url)) {
        sendResponse({ ok: false, error: 'Invalid destination' });
        return;
      }
      try {
        const host = new URL(message.url).hostname;
        const map = await getTabBypass();
        map[String(tabId)] = { url: message.url, expiresAt: Date.now() + 10_000 };
        await chrome.storage.session.set({ tabBypass: map });
        const { allowSiteForSession } = await import('../lib/storage.js');
        await allowSiteForSession(host);
        await chrome.tabs.update(tabId, { url: message.url });
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ ok: false, error: err.message });
      }
    })();
    return true;
  }

  return false;
});
