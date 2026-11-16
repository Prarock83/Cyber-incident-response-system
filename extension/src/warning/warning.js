import { escapeHtml, verdictMeta, severityTone } from '../lib/format.js';

const params = new URLSearchParams(location.search);
const rawUrl = params.get('url') || '';

let reasons = [];
try {
  const parsed = JSON.parse(params.get('reasons') || '[]');
  reasons = Array.isArray(parsed) ? parsed : [];
} catch {
  reasons = [];
}

const domain = params.get('domain') || (() => {
  try { return new URL(rawUrl).hostname; } catch { return 'unknown domain'; }
})();
const verdict = params.get('verdict') || 'DANGEROUS';
const score = Number.parseInt(params.get('score') || '0', 10) || 0;

const meta = verdictMeta(verdict);

document.getElementById('warningTitle').textContent = verdict === 'DANGEROUS'
  ? 'This website is flagged as dangerous'
  : 'This website shows strong risk indicators';

document.getElementById('warningLead').textContent = verdict === 'DANGEROUS'
  ? 'A trusted threat-intelligence source reports this address as malicious. Do not sign in, pay, or share personal information.'
  : 'CIRS found URL patterns that are commonly used for phishing and scams. Continue only if you are certain this site is genuine.';

document.getElementById('warningUrl').textContent = rawUrl || domain;
document.getElementById('verdictChip').textContent = meta.label;
document.getElementById('verdictChip').className = `chip ${meta.tone}`;
document.getElementById('riskScore').textContent = `${score}/100`;

const fill = document.getElementById('scoreFill');
requestAnimationFrame(() => { fill.style.width = `${Math.max(4, Math.min(100, score))}%`; });

const list = document.getElementById('reasonList');
if (reasons.length) {
  list.innerHTML = reasons.map((reason) => {
    const tone = severityTone(reason.severity);
    return `<li class="reason ${tone}">
      <strong>${escapeHtml(reason.label || 'Risk indicator')}</strong>
      ${escapeHtml(reason.detail || '')}
    </li>`;
  }).join('');
} else {
  list.innerHTML = '<li class="reason muted">The site was flagged without additional detail. Treat it as unsafe.</li>';
}
list.classList.add('collapsed');

document.getElementById('toggleDetails').addEventListener('click', () => {
  const collapsed = list.classList.toggle('collapsed');
  document.getElementById('toggleDetails').textContent = collapsed ? 'View details' : 'Hide details';
});
document.getElementById('detailsBtn').addEventListener('click', () => {
  list.classList.remove('collapsed');
  document.getElementById('toggleDetails').textContent = 'Hide details';
  list.scrollIntoView({ behavior: 'smooth', block: 'center' });
});

const ack = document.getElementById('ackCheck');
const continueBtn = document.getElementById('continueBtn');
ack.addEventListener('change', () => { continueBtn.disabled = !ack.checked; });

async function activeTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.id;
}

document.getElementById('goBackBtn').addEventListener('click', async () => {
  const tabId = await activeTabId();
  const response = await chrome.runtime.sendMessage({ type: 'GO_SAFE', tabId, url: rawUrl }).catch(() => null);
  if (!response || !response.ok) {
    if (tabId) await chrome.tabs.update(tabId, { url: 'about:blank' }).catch(() => {});
  }
});

continueBtn.addEventListener('click', async () => {
  if (!ack.checked) return;
  continueBtn.disabled = true;
  continueBtn.textContent = 'Opening website…';
  const tabId = await activeTabId();
  const response = await chrome.runtime.sendMessage({ type: 'CONTINUE_TO_SITE', tabId, url: rawUrl }).catch(() => null);
  if (!response || !response.ok) {
    continueBtn.disabled = false;
    continueBtn.textContent = 'Continue to this website';
    alert('CIRS could not open that website. It may have been closed.');
  }
});
