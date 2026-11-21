export function formatDateTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat('en-GB', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(d);
}

export function formatShortTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat('en-GB', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(d);
}

/** HH:MM:SS wall-clock time, for live mono feeds. */
export function formatClock(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

export function formatRelativeTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr} h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay} d ago`;
}

export function formatDurationSeconds(seconds?: number | null): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '—';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const remS = s % 60;
  if (m < 60) return `${m}m ${remS}s`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return `${h}h ${remM}m`;
}

export function formatNumber(n?: number | null): string {
  if (n == null || !Number.isFinite(n)) return '0';
  return new Intl.NumberFormat('en-GB').format(n);
}

/**
 * Semantic tones. Quiet, theme-aware tints — accents reserved for real risk/status.
 * Use with <Pill className={TONE.x}> from components/common.
 */
export const TONE = {
  neutral: 'bg-muted text-muted-foreground border-border',
  info: 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/25',
  primary: 'bg-primary/10 text-primary dark:text-red-300 border-primary/25',
  success: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/25',
  warning: 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25',
  orange: 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/25',
  danger: 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/25',
  violet: 'bg-violet-500/10 text-violet-700 dark:text-violet-300 border-violet-500/25',
} as const;

export type Tone = keyof typeof TONE;

export function lifecycleMeta(state?: string): {
  label: string;
  badge: string;
  dot: string;
  stroke: string;
} {
  switch (state) {
    case 'NEW':
      return { label: 'NEW', badge: TONE.info, dot: 'bg-sky-500', stroke: '#38bdf8' };
    case 'ACTIVE':
      return { label: 'ACTIVE', badge: TONE.success, dot: 'bg-emerald-500', stroke: '#10b981' };
    case 'INTERMITTENT':
      return { label: 'UNSTABLE', badge: TONE.warning, dot: 'bg-amber-500', stroke: '#f59e0b' };
    case 'MISSING':
      return { label: 'MISSING', badge: TONE.orange, dot: 'bg-orange-500', stroke: '#f97316' };
    case 'INACTIVE':
      return { label: 'INACTIVE', badge: TONE.neutral, dot: 'bg-stone-400', stroke: '#78716c' };
    case 'REACTIVATED':
      return { label: 'REACTIVATED', badge: TONE.violet, dot: 'bg-violet-500', stroke: '#a78bfa' };
    default:
      return { label: state || 'UNKNOWN', badge: TONE.neutral, dot: 'bg-stone-400', stroke: '#a8a29e' };
  }
}

export function scanStatusMeta(status?: string): {
  label: string;
  badge: string;
  pulse?: boolean;
} {
  switch (status) {
    case 'RUNNING':
      return { label: 'RUNNING', badge: TONE.primary, pulse: true };
    case 'CALIBRATING':
      return { label: 'CALIBRATING', badge: TONE.info, pulse: true };
    case 'QUEUED':
      return { label: 'QUEUED', badge: TONE.neutral };
    case 'PAUSED_WINDOW':
      return { label: 'PAUSED (WINDOW)', badge: TONE.warning };
    case 'PAUSED_USER':
      return { label: 'PAUSED', badge: TONE.warning };
    case 'COMPLETED':
      return { label: 'COMPLETED', badge: TONE.success };
    case 'STOPPED':
      return { label: 'STOPPED', badge: TONE.neutral };
    case 'FAILED':
      return { label: 'FAILED', badge: TONE.danger };
    default:
      return { label: status || '—', badge: TONE.neutral };
  }
}

export function severityMeta(severity?: string): {
  label: string;
  badge: string;
} {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return { label: 'HIGH', badge: TONE.danger };
    case 'medium':
      return { label: 'MEDIUM', badge: TONE.warning };
    case 'low':
      return { label: 'LOW', badge: TONE.info };
    default:
      return { label: 'INFO', badge: TONE.neutral };
  }
}

export function scoreColor(score: number): string {
  if (score >= 75) return TONE.danger;
  if (score >= 50) return TONE.warning;
  if (score >= 25) return TONE.info;
  return TONE.neutral;
}

export function scoreBarColor(score: number): string {
  if (score >= 75) return 'bg-rose-500';
  if (score >= 50) return 'bg-amber-500';
  if (score >= 25) return 'bg-sky-500';
  return 'bg-stone-400';
}

/** "1 host", "3 hosts" (English plural; pass an explicit plural for irregular words). */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`;
}

const ENV_LABELS: Record<string, string> = {
  prod: 'Production',
  production: 'Production',
  staging: 'Staging',
  dev: 'Development',
  development: 'Development',
  test: 'Test',
  unknown: 'Unknown',
};

export function envLabel(env?: string | null): string {
  if (!env) return '—';
  return ENV_LABELS[env.toLowerCase()] || env;
}

/** Translate EOL labels produced by the backend in Polish ("nginx 1.14 – gałąź EOL od 2019-04"). */
export function eolLabel(label: string): string {
  return label.replace(/\s*[–-]\s*gałąź EOL od\s*/i, ' · EOL since ');
}

/**
 * Score factor as shown to the analyst. Most backend reasons are English already; EOL / CVE
 * factors carry a Polish prefix.
 */
export function translateFactor(reason: string): string {
  return eolLabel(
    reason
      .replace(/^Wersja EOL:\s*/i, 'End-of-life version: ')
      .replace(/^Pasywna wskazówka CVE:\s*/i, 'Known CVE (passive, by version): ')
      .replace(/ < próg /g, ' < threshold ')
  );
}

/** Asset-query term with the value quoted when it contains spaces or commas. */
export function queryTerm(key: string, value: string): string {
  const v = value.trim().replace(/"/g, '');
  return /[\s,]/.test(v) ? `${key}:"${v}"` : `${key}:${v}`;
}

/** /assets URL for an asset query. */
export function assetsLink(q: string): string {
  return `/assets?q=${encodeURIComponent(q)}`;
}
