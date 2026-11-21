export function formatDateTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat('pl-PL', {
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
  return new Intl.DateTimeFormat('pl-PL', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(d);
}

export function formatRelativeTime(value?: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 5) return 'przed chwilą';
  if (diffSec < 60) return `${diffSec}s temu`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min temu`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr} godz. temu`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay} dn. temu`;
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
  return new Intl.NumberFormat('pl-PL').format(n);
}

export function lifecycleMeta(state?: string): {
  label: string;
  badge: string;
  dot: string;
  stroke: string;
} {
  switch (state) {
    case 'NEW':
      return {
        label: 'NOWY',
        badge: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
        dot: 'bg-sky-400',
        stroke: '#38bdf8',
      };
    case 'ACTIVE':
      return {
        label: 'AKTYWNY',
        badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        dot: 'bg-emerald-400',
        stroke: '#10b981',
      };
    case 'INTERMITTENT':
      return {
        label: 'NIESTABILNY',
        badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
        dot: 'bg-amber-400',
        stroke: '#f59e0b',
      };
    case 'MISSING':
      return {
        label: 'ZAGINIONY',
        badge: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
        dot: 'bg-orange-400',
        stroke: '#f97316',
      };
    case 'INACTIVE':
      return {
        label: 'NIEAKTYWNY',
        badge: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
        dot: 'bg-slate-400',
        stroke: '#64748b',
      };
    case 'REACTIVATED':
      return {
        label: 'REAKTYWOWANY',
        badge: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
        dot: 'bg-violet-400',
        stroke: '#a78bfa',
      };
    default:
      return {
        label: state || 'NIEZNANY',
        badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
        dot: 'bg-slate-400',
        stroke: '#94a3b8',
      };
  }
}

export function scanStatusMeta(status?: string): {
  label: string;
  badge: string;
  pulse?: boolean;
} {
  switch (status) {
    case 'RUNNING':
      return {
        label: 'W TRAKCIE',
        badge: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
        pulse: true,
      };
    case 'CALIBRATING':
      return {
        label: 'KALIBRACJA',
        badge: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
        pulse: true,
      };
    case 'QUEUED':
      return {
        label: 'W KOLEJCE',
        badge: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/35',
      };
    case 'PAUSED_WINDOW':
      return {
        label: 'PAUSED_WINDOW',
        badge: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
      };
    case 'PAUSED_USER':
      return {
        label: 'WSTRZYMANY',
        badge: 'bg-amber-500/15 text-amber-300 border-amber-500/35',
      };
    case 'COMPLETED':
      return {
        label: 'ZAKOŃCZONY',
        badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      };
    case 'STOPPED':
      return {
        label: 'ZATRZYMANY',
        badge: 'bg-slate-500/15 text-slate-300 border-slate-500/35',
      };
    case 'FAILED':
      return {
        label: 'BŁĄD',
        badge: 'bg-rose-500/15 text-rose-400 border-rose-500/35',
      };
    default:
      return {
        label: status || '—',
        badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
      };
  }
}

export function severityMeta(severity?: string): {
  label: string;
  badge: string;
} {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return {
        label: 'WYSOKI',
        badge: 'bg-rose-500/15 text-rose-400 border-rose-500/35',
      };
    case 'medium':
      return {
        label: 'ŚREDNI',
        badge: 'bg-amber-500/15 text-amber-400 border-amber-500/35',
      };
    case 'low':
      return {
        label: 'NISKI',
        badge: 'bg-sky-500/15 text-sky-400 border-sky-500/35',
      };
    default:
      return {
        label: 'INFO',
        badge: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
      };
  }
}

export function scoreColor(score: number): string {
  if (score >= 75) return 'text-rose-400 bg-rose-500/15 border-rose-500/35';
  if (score >= 50) return 'text-amber-400 bg-amber-500/15 border-amber-500/35';
  if (score >= 25) return 'text-cyan-400 bg-cyan-500/15 border-cyan-500/30';
  return 'text-slate-400 bg-slate-500/15 border-slate-500/30';
}

export function scoreBarColor(score: number): string {
  if (score >= 75) return 'bg-rose-500';
  if (score >= 50) return 'bg-amber-500';
  if (score >= 25) return 'bg-cyan-500';
  return 'bg-slate-500';
}
