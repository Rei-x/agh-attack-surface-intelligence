import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { RiExternalLinkLine } from '@remixicon/react';
import { api } from '@/lib/api';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { DefectDojoStatus } from '@/types/api';

function ago(iso?: string): string {
  if (!iso) return '';
  const sec = Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 1000));
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
  return `${Math.floor(sec / 86400)} d ago`;
}

/**
 * Header chip: is DefectDojo connected, when did the last automatic push run, how many
 * findings it holds, and a link to the DefectDojo test/product.
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
    return () => {
      alive = false;
      window.clearInterval(t);
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
    <Tooltip>
      <TooltipTrigger
        render={<a href={href} target="_blank" rel="noreferrer" className={cn(base, failed && 'border-rose-500/50')} />}
      >
        <span className={cn('size-1.5', failed ? 'bg-rose-500' : sync.last_sync_at ? 'bg-emerald-500' : 'bg-amber-500')} />
        <span className="font-semibold">DefectDojo</span>
        <span className="text-muted-foreground">
          {sync.last_sync_at ? `${sync.findings} findings · ${ago(sync.last_sync_at)}` : auto ? 'waiting for first run' : 'auto push off'}
        </span>
        <RiExternalLinkLine className="size-3 text-muted-foreground" />
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <div className="space-y-0.5 text-xs">
          <div>{st.url}</div>
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
          <div className="text-muted-foreground">Click to open {sync.test_url ? 'the test' : 'DefectDojo'}</div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}
