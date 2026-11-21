import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  RiArrowDownSLine,
  RiArrowRightSLine,
  RiExternalLinkLine,
  RiRefreshLine,
  RiShieldCheckLine,
} from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveEvents } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { formatDateTime, formatRelativeTime } from '@/lib/format';
import {
  ACTION_LABEL,
  KIND_LABEL,
  STATUS_META,
  formatDay,
  invalidateTickets,
  isActive,
  kindCategory,
  remediationApi,
  type Ticket,
  type TicketStats,
  type TicketStatus,
} from '@/lib/remediation';
import { Empty, PageHeader, Pill, SimpleSelect, Stat, StatStrip } from '@/components/common';
import { CategoryBadge } from '@/components/CategoryBadge';
import { NotifyOwnerButton } from '@/components/NotifyOwnerDialog';
import { DeliveryChannelsPanel } from '@/components/DeliveryChannelsPanel';
import { PeckLoader } from '@/components/Woodpecker';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

type Filter = 'active' | 'overdue' | TicketStatus | 'all';

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'active', label: 'Active' },
  { value: 'overdue', label: 'Overdue' },
  { value: 'open', label: 'Open' },
  { value: 'notified', label: 'Notified' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'reopened', label: 'Reopened' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'accepted_risk', label: 'Accepted risk' },
  { value: 'all', label: 'All' },
];

const ANY_OWNER = '__any__';

function overdue(t: Ticket): boolean {
  return isActive(t.status) && (t.overdue || !!t.past_due);
}

export function StatusPill({ t }: { t: Ticket }) {
  if (overdue(t)) return <Pill tone="warning">Overdue</Pill>;
  const meta = STATUS_META[t.status];
  return (
    <Pill tone={meta.tone}>
      {t.status === 'fixed' && t.verified ? 'Fix verified' : meta.label}
    </Pill>
  );
}

const HISTORY_LABEL: Record<string, string> = {
  created: 'Opened',
  notified: 'Notified',
  status: 'Status',
  verified_fixed: 'Verified fixed',
  reopened: 'Reopened',
  overdue: 'Overdue',
  delivery_failed: 'Delivery failed',
  due_changed: 'Due date',
  note: 'Note',
};

function TicketDetail({ t, canWrite, onChanged }: { t: Ticket; canWrite: boolean; onChanged: () => void }) {
  const toast = useToast();
  const [note, setNote] = useState('');
  const [due, setDue] = useState(t.due_at?.slice(0, 10) || '');
  const [busy, setBusy] = useState<string | null>(null);

  const apply = async (status?: TicketStatus, extra?: { due_at?: string }) => {
    if (status === 'accepted_risk' && !note.trim()) {
      toast.warning('Add a reason first', 'Accepting a risk needs a short reason in the note field.');
      return;
    }
    setBusy(status || 'due');
    try {
      await remediationApi.setStatus(t.id, { status, note: note.trim() || undefined, ...extra });
      setNote('');
      invalidateTickets();
      onChanged();
    } catch (err) {
      toast.error('Update failed', (err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const active = isActive(t.status);
  return (
    <div className="grid grid-cols-1 gap-6 bg-muted/20 px-5 py-4 lg:grid-cols-[1fr_20rem]">
      <div className="min-w-0 space-y-3 text-xs">
        {t.evidence && (
          <div>
            <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Evidence</div>
            <p className="mt-1 text-foreground">{t.evidence}</p>
          </div>
        )}
        {t.last_check_note && (
          <div>
            <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Last check</div>
            <p className="mt-1">
              {t.last_check_note}
              {t.last_checked_at && <span className="text-muted-foreground"> · {formatRelativeTime(t.last_checked_at)}</span>}
              {t.fixed_scan_id && <span className="font-mono text-muted-foreground"> · scan {t.fixed_scan_id.slice(0, 8)}</span>}
            </p>
          </div>
        )}
        {t.body && (
          <details className="group">
            <summary className="cursor-pointer text-[10px] font-semibold tracking-widest text-muted-foreground uppercase hover:text-foreground">
              Message sent{t.channel ? ` by ${t.channel}` : ''}
            </summary>
            <pre className="mt-2 max-h-64 overflow-auto border border-border bg-card p-3 font-mono text-[11px] whitespace-pre-wrap">
              {t.subject ? `Subject: ${t.subject}\n\n` : ''}
              {t.body}
            </pre>
          </details>
        )}
        <div>
          <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">History</div>
          <ol className="mt-1.5 space-y-1">
            {[...t.history].reverse().map((h, i) => (
              <li key={i} className="flex gap-3">
                <span className="w-32 shrink-0 font-mono text-[11px] text-muted-foreground">{formatDateTime(h.at)}</span>
                <span className="min-w-0">
                  <span className="font-semibold">{HISTORY_LABEL[h.action] || h.action}</span>
                  {h.to && h.action === 'status' && <> to {STATUS_META[h.to as TicketStatus]?.label || h.to}</>}
                  <span className="text-muted-foreground"> · {h.by}</span>
                  {h.note && <span className="text-muted-foreground"> · {h.note}</span>}
                </span>
              </li>
            ))}
          </ol>
        </div>
      </div>

      {canWrite && (
        <div className="space-y-3">
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (owner reply, reason)" className="h-8 text-xs" />
          <div className="flex flex-wrap gap-1.5">
            {active && t.status !== 'acknowledged' && (
              <Button variant="outline" size="xs" disabled={!!busy} onClick={() => apply('acknowledged')}>
                Acknowledged
              </Button>
            )}
            {active && (
              <Button variant="outline" size="xs" disabled={!!busy} onClick={() => apply('fixed')}>
                Mark fixed
              </Button>
            )}
            {active && (
              <Button variant="outline" size="xs" disabled={!!busy} onClick={() => apply('accepted_risk')}>
                Accept risk
              </Button>
            )}
            {!active && (
              <Button variant="outline" size="xs" disabled={!!busy} onClick={() => apply('reopened')}>
                Reopen
              </Button>
            )}
            {active && note.trim() && (
              <Button variant="ghost" size="xs" disabled={!!busy} onClick={() => apply()}>
                Add note
              </Button>
            )}
          </div>
          {active && (
            <div className="flex items-center gap-1.5">
              <Input type="date" value={due} onChange={(e) => setDue(e.target.value)} className="h-8 w-40 text-xs" aria-label="Due date" />
              <Button
                variant="ghost"
                size="xs"
                disabled={!!busy || !due || due === t.due_at?.slice(0, 10)}
                onClick={() => apply(undefined, { due_at: new Date(`${due}T23:59:00Z`).toISOString() })}
              >
                Set due
              </Button>
            </div>
          )}
          {active && (
            <NotifyOwnerButton hostId={t.host_id} serviceId={t.service_id} issueKey={t.issue_key} onSent={onChanged} />
          )}
          <p className="text-[11px] text-muted-foreground">
            Every completed scan checks this ticket again. A fix the scan confirms closes it and is mitigated in DefectDojo.
          </p>
        </div>
      )}
    </div>
  );
}

export function RemediationPage() {
  const { can } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const { lastEvent } = useLiveEvents();
  const [params, setParams] = useSearchParams();
  const canWrite = can(PERMISSIONS.ASSETS_WRITE);

  const [tickets, setTickets] = useState<Ticket[] | null>(null);
  const [stats, setStats] = useState<TicketStats | null>(null);
  const [owners, setOwners] = useState<string[]>([]);
  const [filter, setFilter] = useState<Filter>((params.get('status') as Filter) || 'active');
  const [owner, setOwner] = useState(params.get('owner') || ANY_OWNER);
  const [expanded, setExpanded] = useState<string | null>(params.get('ticket'));
  const [checking, setChecking] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await remediationApi.listTickets();
      setTickets(res.tickets);
      setStats(res.stats);
      setOwners(res.owners);
    } catch (err) {
      toast.error('Could not load tickets', (err as Error).message);
      setTickets([]);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  // Refresh when the verifier or another analyst changes tickets.
  useEffect(() => {
    if (lastEvent?.type === 'remediation.updated') load();
  }, [lastEvent, load]);

  useEffect(() => {
    const next = new URLSearchParams(params);
    filter === 'active' ? next.delete('status') : next.set('status', filter);
    owner === ANY_OWNER ? next.delete('owner') : next.set('owner', owner);
    if (next.toString() !== params.toString()) setParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, owner]);

  const shown = useMemo(() => {
    return (tickets || []).filter((t) => {
      if (owner !== ANY_OWNER && t.owner !== owner) return false;
      switch (filter) {
        case 'all':
          return true;
        case 'active':
          return isActive(t.status);
        case 'overdue':
          return overdue(t);
        default:
          return t.status === filter;
      }
    });
  }, [tickets, filter, owner]);

  const checkNow = async () => {
    setChecking(true);
    try {
      const res = await remediationApi.verify();
      const fixed = res.outcomes.filter((o) => o.action === 'verified_fixed').length;
      toast.success(
        'Tickets checked',
        res.outcomes.length === 0
          ? 'No change against the latest scan'
          : `${fixed} verified fixed, ${res.outcomes.length - fixed} other change(s)`
      );
      invalidateTickets();
      await load();
    } catch (err) {
      toast.error('Check failed', (err as Error).message);
    } finally {
      setChecking(false);
    }
  };

  const by = stats?.by_status || {};
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        className="pb-0"
        title="Remediation"
        meta={stats && stats.median_days_to_fix > 0 ? `median ${stats.median_days_to_fix} days to fix` : undefined}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={load}>
              <RiRefreshLine />
              Refresh
            </Button>
            {canWrite && (
              <Button size="sm" disabled={checking} onClick={checkNow} title="Check every ticket against the latest scan">
                <RiShieldCheckLine className={cn(checking && 'animate-pulse')} />
                Check now
              </Button>
            )}
          </>
        }
      />

      <StatStrip>
        <Stat label="Active" value={stats?.open ?? 0} />
        <Stat label="Open" value={by.open ?? 0} />
        <Stat label="Notified" value={by.notified ?? 0} />
        <Stat label="Acknowledged" value={by.acknowledged ?? 0} />
        <Stat label="Overdue" value={stats?.overdue ?? 0} tone={(stats?.overdue || 0) > 0 ? 'warning' : undefined} />
        <Stat
          label="Fixed"
          value={stats?.fixed ?? 0}
          hint={stats?.fixed_last_24h ? `${stats.fixed_last_24h} in the last 24h` : undefined}
          tone={(stats?.fixed_last_24h || 0) > 0 ? 'success' : undefined}
        />
      </StatStrip>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => setFilter(f.value)}
              className={cn(
                'h-7 border px-2.5 text-[11px] font-semibold transition-colors',
                filter === f.value
                  ? 'border-foreground/40 bg-muted text-foreground'
                  : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
        <SimpleSelect
          className="w-64"
          size="sm"
          value={owner}
          onValueChange={setOwner}
          options={[{ value: ANY_OWNER, label: 'All owners' }, ...owners.map((o) => ({ value: o, label: o }))]}
        />
      </div>

      <Card size="sm" className="py-0">
        {tickets === null ? (
          <PeckLoader />
        ) : shown.length === 0 ? (
          <Empty bird>
            {tickets.length === 0
              ? 'No tickets yet. Open a host and use Notify owner on a risky service.'
              : 'Nothing matches this filter'}
          </Empty>
        ) : (
          <Table className="table-fixed">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8 pl-4" />
                <TableHead className="w-32">Status</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead className="w-40">Where</TableHead>
                <TableHead className="w-48">Owner</TableHead>
                <TableHead className="w-16 text-right">Age</TableHead>
                <TableHead className="w-20">Due</TableHead>
                <TableHead className="w-10 pr-4" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((t) => {
                const open = expanded === t.id;
                const cat = kindCategory(t.kind);
                return (
                  <React.Fragment key={t.id}>
                    <TableRow className={cn('cursor-pointer', open && 'border-b-0 bg-muted/30')} onClick={() => setExpanded(open ? null : t.id)}>
                      <TableCell className="pl-4 text-muted-foreground">
                        {open ? <RiArrowDownSLine className="size-4" /> : <RiArrowRightSLine className="size-4" />}
                      </TableCell>
                      <TableCell>
                        <StatusPill t={t} />
                      </TableCell>
                      <TableCell>
                        <div className="flex min-w-0 items-center gap-2">
                          {cat ? (
                            <CategoryBadge kind={cat} size="xs" />
                          ) : (
                            <Pill tone="neutral">{KIND_LABEL[t.kind] || t.kind}</Pill>
                          )}
                          <span className="truncate text-xs" title={t.title}>
                            {t.title}
                          </span>
                          <span className="shrink-0 text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
                            {ACTION_LABEL[t.action]}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="truncate font-mono text-xs">
                        <button
                          type="button"
                          className="hover:underline"
                          title="Open host"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/assets?host=${t.host_id}`);
                          }}
                        >
                          {t.host_ip}
                          {t.port ? `:${t.port}` : ''}
                        </button>
                      </TableCell>
                      <TableCell className="truncate text-xs" title={t.owner_email || t.owner}>
                        {t.owner || <span className="text-muted-foreground">Unassigned</span>}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{t.age_days ?? 0}d</TableCell>
                      <TableCell className={cn('font-mono text-xs', overdue(t) && 'text-amber-700 dark:text-amber-400')}>
                        {isActive(t.status) ? formatDay(t.due_at) : formatDay(t.fixed_at || t.updated_at)}
                      </TableCell>
                      <TableCell className="pr-4 text-right">
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          className="text-muted-foreground"
                          aria-label="Open host"
                          title="Open host"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/assets?host=${t.host_id}`);
                          }}
                        >
                          <RiExternalLinkLine />
                        </Button>
                      </TableCell>
                    </TableRow>
                    {open && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={8} className="p-0 whitespace-normal">
                          <TicketDetail t={t} canWrite={canWrite} onChanged={load} />
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <DeliveryChannelsPanel />
    </div>
  );
}
