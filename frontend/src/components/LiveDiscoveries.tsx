import { Link } from 'react-router-dom';
import { RiArrowRightUpLine, RiCheckLine } from '@remixicon/react';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { formatClock, formatNumber, plural } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { ScanRun } from '@/types/api';
import { Notice, SectionTitle } from '@/components/common';
import { PeckSpinner } from '@/components/Woodpecker';

const ACTIVE = new Set(['QUEUED', 'CALIBRATING', 'RUNNING', 'PAUSED_USER', 'PAUSED_WINDOW']);
const SHOWN = 200;

/**
 * Hosts and services of one run as the scanner reports them (scan.host_discovered over SSE),
 * newest first. A scan reports a block of addresses (a chunk) when the block is done, so with
 * small chunks the list fills up block by block while the scan runs.
 */
export function LiveDiscoveries({ scan }: { scan: ScanRun }) {
  const { runHosts, recentIPs } = useLiveEvents();
  const hosts = runHosts[scan.id] ?? [];
  const active = ACTIVE.has(scan.status);
  if (!active && hosts.length === 0) return null;

  const services = hosts.reduce((n, h) => n + (h.services ?? h.ports.length), 0);
  const earlier = Math.max(0, scan.active_hosts - hosts.length);

  return (
    <div className="space-y-2">
      <SectionTitle
        actions={
          <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
            {scan.completed_chunks}/{scan.total_chunks || '?'} blocks · {formatNumber(scan.scanned_ips)}/
            {formatNumber(scan.total_ips)} IP
          </span>
        }
      >
        Live discoveries · {plural(hosts.length, 'host')} · {plural(services, 'service')}
      </SectionTitle>

      {hosts.length === 0 ? (
        <div className="flex items-center gap-2.5 border border-dashed px-3 py-3 text-xs text-muted-foreground">
          <PeckSpinner className="h-3.5" />
          {scan.status === 'QUEUED'
            ? 'Waiting for the scanner to pick up this scan.'
            : scan.status === 'PAUSED_WINDOW' || scan.status === 'PAUSED_USER'
              ? 'The scan is paused.'
              : 'Scanning. Hosts appear here as soon as each block of addresses is done.'}
        </div>
      ) : (
        <div className="max-h-96 divide-y divide-border overflow-y-auto border border-border bg-background">
          {hosts.slice(0, SHOWN).map((h) => (
            <div
              key={h.ip}
              className={cn(
                'grid grid-cols-[8.5rem_minmax(0,1fr)_auto] items-center gap-3 px-3 py-1.5 text-xs',
                'animate-in fade-in slide-in-from-top-1 duration-300',
                recentIPs[h.ip] && 'bg-emerald-500/5'
              )}
            >
              <Link
                to={`/assets?q=${encodeURIComponent(h.ip)}`}
                className="truncate font-mono font-semibold hover:underline"
                title={h.hostname || h.ip}
              >
                {h.ip}
              </Link>
              <div className="flex min-w-0 flex-wrap items-center gap-1">
                {h.ports.slice(0, 8).map((p) => (
                  <span key={p} className="border border-border bg-muted/50 px-1 font-mono text-[10px] tabular-nums">
                    {p}
                  </span>
                ))}
                {h.ports.length > 8 && (
                  <span className="font-mono text-[10px] text-muted-foreground">+{h.ports.length - 8}</span>
                )}
                {(h.titles?.[0] || h.hostname) && (
                  <span className="min-w-0 truncate text-muted-foreground">{h.titles?.[0] || h.hostname}</span>
                )}
              </div>
              <span className="font-mono text-[10px] text-muted-foreground tabular-nums">{formatClock(h.at)}</span>
            </div>
          ))}
        </div>
      )}

      {hosts.length > SHOWN && (
        <p className="text-[11px] text-muted-foreground">Showing the newest {SHOWN} hosts.</p>
      )}
      {earlier > 0 && (
        <p className="text-[11px] text-muted-foreground">
          {formatNumber(earlier)} more {earlier === 1 ? 'host was' : 'hosts were'} found before this page opened.{' '}
          <Link to="/assets" className="underline underline-offset-2">
            See all hosts
          </Link>
        </p>
      )}
      {scan.status === 'COMPLETED' && (
        <Notice tone="success" icon={RiCheckLine}>
          <span>
            Scan finished: {plural(scan.active_hosts, 'host')}, {plural(scan.services_found, 'service')}.{' '}
            <Link to="/assets" className="inline-flex items-center gap-0.5 font-semibold underline underline-offset-2">
              Open the inventory <RiArrowRightUpLine className="size-3" />
            </Link>
          </span>
        </Notice>
      )}
    </div>
  );
}
