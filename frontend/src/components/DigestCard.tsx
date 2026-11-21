import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { RiArrowRightUpLine } from '@remixicon/react';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { formatRelativeTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import { kindCategory, remediationApi, type Digest } from '@/lib/remediation';
import { Empty, Pill } from '@/components/common';
import { CategoryBadge } from '@/components/CategoryBadge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

function Num({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className={cn('font-heading text-xl font-semibold tabular-nums', value > 0 && tone)}>{value}</span>
      <span className="truncate text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">{label}</span>
    </div>
  );
}

/** Dashboard "Today" card: the latest morning digest in a few lines. */
export function DigestCard({ className, onOpenHost }: { className?: string; onOpenHost?: (hostId: string) => void }) {
  const { lastEvent } = useLiveEvents();
  const [d, setD] = useState<Digest | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    remediationApi
      .latestDigest()
      .then(setD)
      .catch(() => setFailed(true));
  }, []);
  useEffect(() => {
    if (lastEvent?.type === 'digest.created' || lastEvent?.type === 'remediation.updated') {
      remediationApi.latestDigest().then(setD).catch(() => undefined);
    }
  }, [lastEvent]);

  return (
    <Card size="sm" className={className}>
      <CardHeader>
        <CardTitle className="text-xs font-semibold tracking-widest text-muted-foreground uppercase">Today</CardTitle>
        <CardAction>
          <Button variant="link" size="xs" className="px-0" nativeButton={false} render={<Link to="/digest" />}>
            Full digest <RiArrowRightUpLine />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {failed ? (
          <Empty>Digest is not available</Empty>
        ) : !d ? (
          <div className="h-24" />
        ) : (
          <>
            <div className="flex items-start justify-between gap-3">
              <p className="text-sm font-medium text-foreground">{d.headline}</p>
              <span className="shrink-0 text-[11px] text-muted-foreground">
                {d.preview ? 'last 24h' : formatRelativeTime(d.created_at)}
              </span>
            </div>
            <div className="grid grid-cols-4 gap-3">
              <Num label="Risky" value={d.counts.risky} tone="text-amber-700 dark:text-amber-400" />
              <Num label="New services" value={d.counts.new_services} />
              <Num label="Fixed" value={d.counts.fixed} tone="text-emerald-700 dark:text-emerald-400" />
              <Num label="Overdue" value={d.counts.overdue} tone="text-amber-700 dark:text-amber-400" />
            </div>
            {d.top_risks.length > 0 && (
              <ul className="divide-y divide-border border-t border-border">
                {d.top_risks.slice(0, 3).map((r) => {
                  const cat = kindCategory(r.kind);
                  return (
                    <li key={`${r.service_id}-${r.kind}`}>
                      <button
                        type="button"
                        onClick={() => onOpenHost?.(r.host_id)}
                        className="flex w-full items-center gap-2 py-2 text-left text-xs hover:bg-muted/40"
                      >
                        {cat ? <CategoryBadge kind={cat} size="xs" /> : <span className="size-[18px]" />}
                        <span className="min-w-0 flex-1 truncate">{r.title}</span>
                        {r.ticket_status && <Pill tone="info">{r.ticket_status.replace('_', ' ')}</Pill>}
                        <span className="w-28 shrink-0 truncate text-right text-muted-foreground">{r.owner || 'Unassigned'}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
