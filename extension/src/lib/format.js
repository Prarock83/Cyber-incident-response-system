// Small formatting helpers shared by the popup, side panel and warning page.

export function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export const VERDICTS = {
  SAFE: { label: 'SAFE', tone: 'safe', headline: 'No threat reported', hint: 'A reputation source reports no known threat. This is not a guarantee.' },
  SUSPICIOUS: { label: 'SUSPICIOUS', tone: 'warn', headline: 'Risk indicators found', hint: 'Treat this site with caution and avoid entering personal details.' },
  DANGEROUS: { label: 'DANGEROUS', tone: 'danger', headline: 'Known malicious site', hint: 'Do not sign in, pay or share personal information on this site.' },
  UNKNOWN: { label: 'UNKNOWN', tone: 'neutral', headline: 'Not enough information', hint: 'No threat intelligence has confirmed this site either way.' },
};

export function verdictMeta(verdict) {
  return VERDICTS[verdict] || VERDICTS.UNKNOWN;
}

export function timeAgo(value) {
  if (!value) return 'never';
  const date = new Date(value);
  const seconds = Math.max(1, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return date.toLocaleDateString();
}

export function formatDateTime(value) {
  if (!value) return '—';
  try {
    return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  } catch {
    return String(value);
  }
}

export function statusTone(status) {
  switch (status) {
    case 'Confirmed Threat': return 'danger';
    case 'False Positive': return 'safe';
    case 'Resolved': return 'safe';
    case 'Investigating': return 'warn';
    case 'Under Review': return 'warn';
    default: return 'neutral';
  }
}

export function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

export function shorten(text, max = 64) {
  const value = String(text || '');
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function severityTone(severity) {
  if (severity === 'high') return 'danger';
  if (severity === 'medium') return 'warn';
  return 'neutral';
}
