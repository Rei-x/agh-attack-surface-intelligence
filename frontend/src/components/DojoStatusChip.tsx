import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { RiExternalLinkLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { CopyButton } from '@/components/common';
import type { DefectDojoStatus } from '@/types/api';

/** Dispatched on window after an admin changes DefectDojo settings, so the chip reloads now. */
export const DOJO_STATUS_CHANGED = 'dzieciol:dojo-status-changed';

function ago(iso?: string): string {
  if (!iso) return '';
  const sec = Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 1000));
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
  return `${Math.floor(sec / 86400)} d ago`;
}

function LoginRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-16 shrink-0 text-muted-foreground">{label}</span>
      <span className={cn('min-w-0 flex-1 truncate select-all', mono ? 'font-mono' : 'font-medium')} title={value}>
        {value}
      </span>
      <CopyButton text={value} label={`Copy ${label.toLowerCase()}`} className="size-6" />
    </div>
  );
}

/**
 * Header chip: is DefectDojo connected, when did the last automatic push run, how many
 * findings it holds. Its popover links to the DefectDojo test/product and shows the
 * DefectDojo login an admin set, ready to copy.
 */
export function DojoStatusChip() {
  const [st, setSt] = useState<DefectDojoStatus | null>(null);
  const { dataVersion } = useLiveEvents();

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .defectDojoStatus()
        .then((r) => alive && setSt(r))
        .catch(() => alive && setSt(null));
    load();
    const t = window.setInterval(load, 60000);
    window.addEventListener(DOJO_STATUS_CHANGED, load);
    return () => {
      alive = false;
      window.clearInterval(t);
      window.removeEventListener(DOJO_STATUS_CHANGED, load);
    };
  }, [dataVersion]);

  if (!st) return null;

  const base = 'flex h-7 items-center gap-1.5 border px-2 text-[11px] whitespace-nowrap transition-colors hover:bg-muted';
  if (!st.configured) {
    return (
      <Link to="/admin?tab=defectdojo" className={cn(base, 'text-muted-foreground')} title="Set up the DefectDojo integration">
        <span className="size-1.5 bg-muted-foreground/50" />
        DefectDojo not configured
      </Link>
    );
  }

  const sync = st.sync || { findings: 0, triage_synced: 0 };
  const failed = sync.last_status === 'failed';
  const href = sync.test_url || sync.product_url || st.url;
  const auto = st.auto_push_findings || st.auto_push_nmap;
  return (
    <Popover>
      <PopoverTrigger
        openOnHover
        delay={150}
        closeDelay={200}
        className={cn(base, 'data-popup-open:bg-muted', failed && 'border-rose-500/50')}
      >
        <span className={cn('size-1.5', failed ? 'bg-rose-500' : sync.last_sync_at ? 'bg-emerald-500' : 'bg-amber-500')} />
        <span className="font-semibold">DefectDojo</span>
        <span className="text-muted-foreground">
          {sync.last_sync_at ? `${sync.findings} findings · ${ago(sync.last_sync_at)}` : auto ? 'waiting for first run' : 'auto push off'}
        </span>
        <RiExternalLinkLine className="size-3 text-muted-foreground" />
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 gap-3 p-3 text-xs">
        <div className="space-y-0.5">
          <div className="break-all">{st.url}</div>
          <div>
            Automatic push after each completed run: {auto ? 'on' : 'off'}
            {st.auto_push_findings && st.auto_push_nmap ? ' (findings + nmap)' : st.auto_push_findings ? ' (findings)' : st.auto_push_nmap ? ' (nmap)' : ''}
          </div>
          {sync.last_sync_at && (
            <div>
              Last sync {ago(sync.last_sync_at)}: {failed ? `failed (${sync.last_error})` : `${sync.findings} change findings, ${sync.triage_synced} triage updates`}
            </div>
          )}
          {sync.nmap_pushed_at && <div>Last nmap import {ago(sync.nmap_pushed_at)}</div>}
        </div>
        <Button variant="outline" size="xs" nativeButton={false} render={<a href={href} target="_blank" rel="noreferrer" />}>
          <RiExternalLinkLine /> {sync.test_url ? 'Open the Dzięcioł changes test' : 'Open DefectDojo'}
        </Button>
        {st.login && (
          <div className="space-y-1 border-t pt-3">
            <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Log in</div>
            <LoginRow label="Username" value={st.login.username} />
            <LoginRow label="Password" value={st.login.password} mono />
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
