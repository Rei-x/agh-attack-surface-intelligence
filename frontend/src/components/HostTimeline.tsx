import { useEffect, useState } from 'react';
import { RiAlertLine } from '@remixicon/react';
import { api } from '@/lib/api';
import type { HostTimelineEntry } from '@/types/api';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import { Empty, Pill } from '@/components/common';
import { Input } from '@/components/ui/input';

const SEVERITY_TONE: Record<string, 'danger' | 'warning' | 'info' | 'neutral'> = {
  high: 'danger',
  critical: 'danger',
  medium: 'warning',
  low: 'info',
  info: 'neutral',
};

/**
 * Incident-response timeline of one host: change events plus observation spans, newest
 * first, optionally narrowed to one port ("when did 3389 first appear?").
 */
export function HostTimeline({ hostId }: { hostId: string }) {
  const [port, setPort] = useState('');
  const [entries, setEntries] = useState<HostTimelineEntry[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const p = Number(port);
    const t = window.setTimeout(async () => {
      try {
        const list = await api.getHostTimeline(hostId, p > 0 ? p : undefined);
        if (!cancelled) {
          setEntries(list);
          setError('');
        }
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      }
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [hostId, port]);

  const firstSeen =
    entries && Number(port) > 0
      ? [...entries].reverse().find((e) => e.kind === 'observation' || e.event_type === 'NEW_SERVICE')
      : undefined;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Input
          value={port}
          onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ''))}
          placeholder="Port, np. 3389"
          className="w-36 font-mono"
        />
        {firstSeen && (
          <span className="text-xs text-muted-foreground">
            Port {port} pierwszy raz widziany:{' '}
            <span className="font-mono text-foreground">{formatDateTime(firstSeen.at)}</span>
          </span>
        )}
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {entries === null ? (
        <Empty>Ładowanie…</Empty>
      ) : entries.length === 0 ? (
        <Empty>Brak zdarzeń</Empty>
      ) : (
        <ol className="relative border-l border-border pl-4">
          {entries.map((e, idx) => (
            <li key={`${e.kind}-${e.at}-${idx}`} className="relative pb-4 last:pb-0">
              <span
                className={cn(
                  'absolute top-1.5 -left-[21px] size-2.5 border border-background',
                  e.kind === 'change'
                    ? e.severity === 'high'
                      ? 'bg-rose-500'
                      : e.severity === 'medium'
                        ? 'bg-amber-500'
                        : 'bg-sky-500'
                    : e.kind === 'first_seen'
                      ? 'bg-emerald-500'
                      : 'bg-muted-foreground/40'
                )}
                aria-hidden
              />
              <div className="flex flex-wrap items-center gap-1.5 text-xs text-foreground">
                {e.details?.time_anomaly === true && (
                  <RiAlertLine className="size-3.5 text-rose-600 dark:text-rose-400" />
                )}
                <span className={cn(e.kind === 'observation' && 'font-mono text-muted-foreground')}>
                  {e.summary}
                </span>
                {e.kind === 'change' && e.severity && (
                  <Pill tone={SEVERITY_TONE[e.severity] || 'neutral'}>{e.severity}</Pill>
                )}
              </div>
              <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                {e.kind === 'change' && `${e.event_type} · `}
                {formatDateTime(e.at)}
                {e.kind === 'observation' &&
                  e.until &&
                  ` → ${formatDateTime(e.until)} · ${e.count}× w skanach`}
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
