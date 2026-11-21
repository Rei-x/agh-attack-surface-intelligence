import { memo, useMemo, useState } from 'react';
import { formatDurationSeconds, formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { ScanChunk } from '@/types/api';

const FILL: Record<string, string> = {
  DONE: 'bg-emerald-500',
  RUNNING: 'bg-primary animate-pulse',
  PAUSED: 'bg-amber-500',
  FAILED: 'bg-rose-500',
  PENDING: 'bg-muted-foreground/25',
};

const LEGEND: { status: string; label: string }[] = [
  { status: 'DONE', label: 'Done' },
  { status: 'RUNNING', label: 'Running' },
  { status: 'PAUSED', label: 'Paused' },
  { status: 'PENDING', label: 'Pending' },
  { status: 'FAILED', label: 'Failed' },
];

/**
 * Dense chunk tile matrix for the Coverage Ledger. Scales from 4 to 1000+ chunks
 * (a /16 = 256 chunks) without overflowing: tiles shrink with count, wrap, and a
 * single shared hover card shows per-chunk details.
 */
export const ChunkMatrix = memo(function ChunkMatrix({ chunks }: { chunks: ScanChunk[] }) {
  const [hover, setHover] = useState<ScanChunk | null>(null);

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    let ips = 0;
    let hosts = 0;
    let services = 0;
    for (const c of chunks) {
      const s = String(c.status || 'PENDING').toUpperCase();
      out[s] = (out[s] || 0) + 1;
      if (s === 'DONE') ips += c.ip_count || 0;
      hosts += c.active_hosts || 0;
      services += c.services_found || 0;
    }
    return { by: out, ips, hosts, services };
  }, [chunks]);

  const total = chunks.length;
  const tile = total <= 32 ? 'size-7' : total <= 128 ? 'size-4' : total <= 512 ? 'size-3' : 'size-2';
  const showIndex = total <= 32;
  const totalIps = chunks.reduce((a, c) => a + (c.ip_count || 0), 0);

  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] tracking-wider text-muted-foreground uppercase">
        {LEGEND.map((l) => (
          <span key={l.status} className="flex items-center gap-1.5">
            <span className={cn('size-2', FILL[l.status].replace(' animate-pulse', ''))} />
            {l.label}
            <span className="font-mono text-foreground tabular-nums">{formatNumber(counts.by[l.status] || 0)}</span>
          </span>
        ))}
        <span className="ml-auto font-mono normal-case tabular-nums">
          {formatNumber(counts.ips)} / {formatNumber(totalIps)} IP · {formatNumber(counts.hosts)} H ·{' '}
          {formatNumber(counts.services)} S
        </span>
      </div>

      <div className="flex flex-wrap gap-[3px]" onMouseLeave={() => setHover(null)}>
        {chunks.map((c) => {
          const s = String(c.status || 'PENDING').toUpperCase();
          return (
            <div
              key={c.id || c.chunk_index}
              onMouseEnter={() => setHover(c)}
              title={`#${c.chunk_index + 1} · ${s} · ${c.ip_count} IP · ${c.active_hosts}H/${c.services_found}S${c.error ? ` · ${c.error}` : ''}`}
              className={cn(
                'flex shrink-0 cursor-default items-center justify-center font-mono text-[9px] font-semibold text-white/90 transition-transform hover:z-10 hover:scale-150 hover:ring-1 hover:ring-foreground',
                tile,
                FILL[s] || FILL.PENDING,
                hover?.chunk_index === c.chunk_index && 'ring-1 ring-foreground'
              )}
            >
              {showIndex ? c.chunk_index + 1 : null}
            </div>
          );
        })}
      </div>

      <div className="flex h-5 items-center gap-3 font-mono text-[11px] text-muted-foreground tabular-nums">
        {hover ? (
          <>
            <span className="font-semibold text-foreground">Chunk #{hover.chunk_index + 1}</span>
            <span>{String(hover.status).toUpperCase()}</span>
            <span>{formatNumber(hover.ip_count)} IP</span>
            <span>
              {formatNumber(hover.active_hosts)} hostów · {formatNumber(hover.services_found)} usług
            </span>
            {hover.duration_ms > 0 && <span>{formatDurationSeconds(hover.duration_ms / 1000)}</span>}
            {hover.targets && hover.targets.length > 0 && (
              <span className="truncate">
                {hover.targets.slice(0, 2).join(', ')}
                {hover.targets.length > 2 ? ` +${hover.targets.length - 2}` : ''}
              </span>
            )}
            {hover.worker ? (
              <span>
                worker {hover.worker}
                {hover.max_rate_pps ? ` · ${hover.max_rate_pps} PPS` : ''}
              </span>
            ) : null}
            {hover.error && <span className="truncate text-rose-500">{hover.error}</span>}
          </>
        ) : (
          <span>Najedź na kafelek, aby zobaczyć szczegóły chunka</span>
        )}
      </div>
      {hover?.nmap_commands && hover.nmap_commands.length > 0 && (
        <div className="space-y-1 rounded-md bg-muted/50 p-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
          {hover.nmap_commands.map((cmd, i) => (
            <div key={i} className="break-all">
              <span className="select-none text-foreground/60">$ </span>
              {cmd}
            </div>
          ))}
        </div>
      )}
    </div>
  );
});
