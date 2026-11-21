import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  RiAlertLine,
  RiArrowDownSLine,
  RiArrowLeftRightLine,
  RiArrowRightSLine,
  RiCheckboxCircleLine,
  RiFileCopyLine,
  RiRefreshLine,
  RiSendPlaneLine,
  RiTimeLine,
} from '@remixicon/react';
import { useSearchParams } from 'react-router-dom';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveRefresh } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import { TONE, formatDateTime, formatShortTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Empty, Field, PageHeader, Pill, SimpleSelect, Stat, StatStrip } from '@/components/common';
import type { ChangeEvent, ChangedServiceDiff, ScanDiffResponse, ScanRun } from '@/types/api';
import { PeckLoader } from '@/components/Woodpecker';

type DiffTab = 'added' | 'removed' | 'changed' | 'log';
type ChangeLike = ChangeEvent | ChangedServiceDiff;

const ALL = '__all__';
const NO_OWNER = '__none__';

const SEVERITY: Record<string, { label: string; badge: string }> = {
  critical: { label: 'HIGH', badge: TONE.danger },
  high: { label: 'HIGH', badge: TONE.danger },
  medium: { label: 'MEDIUM', badge: TONE.warning },
  low: { label: 'LOW', badge: TONE.info },
  info: { label: 'INFO', badge: TONE.neutral },
};
const sevMeta = (s?: string) => SEVERITY[(s || '').toLowerCase()] || SEVERITY.info;

const EVENT_LABEL: Record<string, string> = {
  NEW_HOST: 'New host',
  NEW_SERVICE: 'New service',
  ADMIN_PANEL_EXPOSED: 'Admin panel',
  SERVICE_CHANGED: 'Service changed',
  SERVICE_CLOSED: 'Service closed',
  OUTDATED_VERSION: 'End of life',
  HOST_STATE_CHANGED: 'Host state',
  HOST_REACTIVATED: 'Host back',
  HOST_MISSING: 'Host missing',
  HOST_INACTIVE: 'Host gone',
  TIME_ANOMALY: 'Time anomaly',
  EXPECTED_OFF_HOURS: 'Expected off-hours',
};

const s = (v: unknown): string => (v == null ? '' : typeof v === 'string' ? v : String(v));
const ownerOf = (ch: ChangeLike) => s(ch.after?.owner);
const where = (ch: ChangeLike) => `${ch.host_ip}${ch.port ? `:${ch.port}` : ''}`;

interface Described {
  /** One line, human readable. */
  line: string;
  /** Expandable details (label: value), no raw JSON or hashes. */
  details: { label: string; value: string }[];
  /** What the owner should do (used for "copy note for owner"). */
  action: string;
}

function arrow(a: unknown, b: unknown) {
  return `${s(a) || '(none)'} → ${s(b) || '(none)'}`;
}

/** Turns a change event into a one-line description, details and an owner action. */
function describeChange(ch: ChangeLike): Described {
  const type = (ch as ChangeEvent).event_type || '';
  const before = ch.before || {};
  const after = ch.after || {};
  const details: { label: string; value: string }[] = [];
  const add = (label: string, value: unknown) => {
    const v = s(value).trim();
    if (v) details.push({ label, value: v });
  };
  const at = where(ch);

  if (type === 'OUTDATED_VERSION' && Array.isArray(after.outdated)) {
    const items = after.outdated as Record<string, unknown>[];
    const first = items[0] || {};
    const product = s(first.product) || s(after.product);
    const version = s(first.version) || s(after.version);
    for (const it of items) {
      add(`${s(it.product)} ${s(it.version)}`, `branch ${s(it.branch)} end of life since ${s(it.eol_date)}${it.days_since_eol ? ` (${s(it.days_since_eol)} days ago)` : ''}`);
      add('Evidence', it.evidence);
      add('Source', it.source);
    }
    if (s(before.version) && s(before.version) !== version) add('Version before', before.version);
    return {
      line: `${product} ${version} on ${at} is end of life (branch ${s(first.branch)} since ${s(first.eol_date)})`,
      details,
      action: `${product} ${version} on ${at} is end of life. Please upgrade to a supported version or remove it.`,
    };
  }

  if (type === 'SERVICE_CHANGED' || (!type && (Object.keys(before).length || Object.keys(after).length))) {
    const parts: string[] = [];
    if ('product' in after) {
      parts.push(`product ${arrow(before.product, after.product)}`);
      add('Product', arrow(before.product, after.product));
    }
    if ('version' in after) {
      parts.push(`version ${arrow(before.version, after.version)}`);
      add('Version', arrow(before.version, after.version));
    }
    if ('http_title' in after) {
      parts.push('page title changed');
      add('Page title', arrow(before.http_title, after.http_title));
    }
    if ('status_code' in after) {
      parts.push(`HTTP ${s(before.status_code)} → ${s(after.status_code)}`);
      add('HTTP status', arrow(before.status_code, after.status_code));
    }
    if ('is_admin_panel' in after) {
      parts.push('admin panel now exposed');
      add('Admin panel', 'newly detected');
    }
    if ('favicon_mmh3' in after) {
      parts.push('favicon changed');
      add('Favicon', 'different icon served');
    }
    if ('tls_sha256' in after) {
      parts.push('TLS certificate replaced');
      add('TLS certificate', 'a different certificate is served');
    }
    if ('banner' in after) {
      parts.push('banner changed');
      add('Banner before', s(before.banner).slice(0, 160));
      add('Banner now', s(after.banner).slice(0, 160));
    }
    if (!parts.length) {
      for (const k of Object.keys(after)) if (k !== 'owner') add(k.replace(/_/g, ' '), arrow(before[k], after[k]));
    }
    const line = parts.length ? `${at}: ${parts.join(', ')}` : ch.summary;
    return {
      line,
      details,
      action: `${at} changed (${parts.join(', ') || 'service details'}). Please confirm the change is expected.`,
    };
  }

  if (type === 'NEW_SERVICE' || type === 'ADMIN_PANEL_EXPOSED') {
    add('Service', after.service);
    add('Product', [s(after.product), s(after.version)].filter(Boolean).join(' '));
    add('Page title', after.title);
    const risky = /exposure/i.test(ch.summary);
    return {
      line: ch.summary,
      details,
      action:
        type === 'ADMIN_PANEL_EXPOSED'
          ? `An admin panel is reachable on ${at}. Please restrict access (VPN or allowlist) and enforce strong authentication.`
          : risky
            ? `${ch.summary}. Is this service needed? If not, turn it off or restrict access with a firewall or VPN.`
            : `A new service appeared on ${at}. Please confirm it is expected and needed.`,
    };
  }

  if (type.startsWith('HOST_') || type === 'TIME_ANOMALY' || type === 'EXPECTED_OFF_HOURS' || type === 'NEW_HOST') {
    if ('lifecycle_state' in after) add('State', arrow(before.lifecycle_state, after.lifecycle_state));
    if (typeof after.p_alive === 'number') add('Probability the host still exists', `${Math.round((after.p_alive as number) * 100)}%`);
    add('Why', after.liveness_reason);
    if (after.consecutive_misses) add('Missed scans in a row', after.consecutive_misses);
    return {
      line: ch.summary,
      details,
      action:
        type === 'HOST_INACTIVE' || type === 'HOST_MISSING'
          ? `Host ${ch.host_ip} stopped answering scans. Was it decommissioned on purpose? Please update the inventory.`
          : type === 'NEW_HOST'
            ? `A new host ${ch.host_ip} appeared on the network. Please confirm who runs it.`
            : `${ch.summary}. Please confirm this is expected.`,
    };
  }

  if (type === 'SERVICE_CLOSED') {
    add('Service', before.service);
    return { line: ch.summary, details, action: `${ch.summary}. No action needed if this was intended.` };
  }

  return { line: ch.summary, details, action: `${ch.summary}. Please confirm this is expected.` };
}

function ownerNote(ch: ChangeLike): string {
  const owner = ownerOf(ch);
  const d = describeChange(ch);
  return `${owner ? `To ${owner}: ` : ''}${d.action}\n\n(Dzięcioł, ${formatDateTime((ch as ChangeEvent).created_at || new Date().toISOString())})`;
}

/** Latest completed scan vs the previous completed scan of the same profile (or any). */
function defaultPair(scans: ScanRun[]): [string, string] | null {
  const done = scans.filter((x) => x.status === 'COMPLETED');
  // Same profile (imports group by type): the newest run that has an older sibling wins, so
  // a one-off scan of another scope never becomes the baseline.
  const key = (x: ScanRun) => x.profile_id || `type:${x.run_type}`;
  for (let i = 0; i < done.length; i++) {
    const prev = done.slice(i + 1).find((x) => key(x) === key(done[i]));
    if (prev) return [prev.id, done[i].id];
  }
  if (done.length >= 2) return [done[1].id, done[0].id];
  if (scans.length >= 2) return [scans[1].id, scans[0].id];
  if (scans.length === 1) return [scans[0].id, scans[0].id];
  return null;
}

export function DiffPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [searchParams] = useSearchParams();
  const [scans, setScans] = useState<ScanRun[]>([]);
  // Deep link from the dashboard: /diff?from=<scan>&to=<scan>
  const [fromId, setFromId] = useState(searchParams.get('from') || '');
  const [toId, setToId] = useState(searchParams.get('to') || '');
  const [diff, setDiff] = useState<ScanDiffResponse | null>(null);
  const [allChanges, setAllChanges] = useState<ChangeEvent[]>([]);
  const [anomalyOnly, setAnomalyOnly] = useState(false);
  const [ownerFilter, setOwnerFilter] = useState(ALL);
  const [loading, setLoading] = useState(true);
  const [diffLoading, setDiffLoading] = useState(false);
  const [ackingId, setAckingId] = useState<string | null>(null);
  const [pushingId, setPushingId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);
  const [tab, setTab] = useState<DiffTab>('added');
  const [tabTouched, setTabTouched] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const canWrite = can(PERMISSIONS.ASSETS_WRITE);
  const canPush = can(PERMISSIONS.DEFECTDOJO_PUSH);

  const loadInitial = useCallback(
    async (silent?: boolean) => {
      if (!silent) setLoading(true);
      try {
        const [scanList, changeList] = await Promise.all([
          api.listScans(),
          api.listChanges({ anomaly_only: anomalyOnly || undefined }),
        ]);
        setScans(scanList);
        setAllChanges(changeList);
        if (!fromId || !toId) {
          // Fill whatever the URL did not pin: B defaults to the latest completed run, A to the
          // previous completed run of the same profile.
          const ordered = toId ? [...scanList.filter((x) => x.id === toId), ...scanList.filter((x) => x.id !== toId)] : scanList;
          const pair = defaultPair(ordered);
          if (pair) {
            if (!fromId) setFromId(pair[0]);
            if (!toId) setToId(pair[1]);
          }
        }
      } catch (err) {
        if (!silent) toast.error('Could not load changes', (err as Error).message);
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [anomalyOnly, fromId, toId, toast]
  );

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  const runDiff = useCallback(
    async (silent?: boolean) => {
      if (!fromId || !toId) return;
      if (!silent) setDiffLoading(true);
      try {
        setDiff(await api.diffScans(fromId, toId));
      } catch (err) {
        if (!silent) toast.error('Comparison failed', (err as Error).message);
      } finally {
        if (!silent) setDiffLoading(false);
      }
    },
    [fromId, toId, toast]
  );

  useLiveRefresh(() => {
    loadInitial(true);
    runDiff(true);
  });

  useEffect(() => {
    if (fromId && toId) runDiff();
  }, [fromId, toId, runDiff]);

  const newHosts = diff?.new_hosts || [];
  const missingHosts = diff?.missing_hosts || [];
  const newServices = diff?.new_services || [];
  const closedServices = diff?.closed_services || [];
  const changedServices = diff?.changed_services || [];
  const timeAnomalies = diff?.time_anomalies || [];

  const addedCount = newHosts.length + newServices.length;
  const removedCount = missingHosts.length + closedServices.length;
  const changedCount = changedServices.length + timeAnomalies.length;
  const counts: Record<DiffTab, number> = {
    added: addedCount,
    removed: removedCount,
    changed: changedCount,
    log: allChanges.length,
  };

  // Open on the first tab that has something, unless the user picked one.
  useEffect(() => {
    if (!diff || tabTouched) return;
    const first = (['added', 'removed', 'changed'] as DiffTab[]).find((t) => counts[t] > 0) || 'log';
    setTab(first);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [diff, tabTouched, addedCount, removedCount, changedCount]);

  const selectTab = (t: DiffTab) => {
    setTab(t);
    setTabTouched(true);
  };

  const handleAck = async (ch: ChangeLike) => {
    if (!ch.id) return;
    setAckingId(ch.id);
    try {
      await api.acknowledgeChange(ch.id);
      toast.success('Acknowledged', ch.summary);
      await Promise.all([runDiff(), loadInitial()]);
    } catch (err) {
      toast.error('Could not acknowledge', (err as Error).message);
    } finally {
      setAckingId(null);
    }
  };

  const pushToDojo = async (ch: ChangeLike) => {
    if (!ch.id) return;
    setPushingId(ch.id);
    try {
      await api.pushDefectDojoFindings({ change_ids: [ch.id] });
      toast.success('Sent to DefectDojo', describeChange(ch).line);
    } catch (err) {
      toast.error('DefectDojo push failed', (err as Error).message);
    } finally {
      setPushingId(null);
    }
  };

  const copyNote = async (ch: ChangeLike) => {
    try {
      await navigator.clipboard.writeText(ownerNote(ch));
      toast.success('Note copied', ownerOf(ch) ? `for ${ownerOf(ch)}` : 'no owner rule matches this host');
    } catch {
      toast.error('Could not copy', 'Clipboard is not available in this browser');
    }
  };

  const owners = useMemo(() => {
    const set = new Set<string>();
    for (const c of allChanges) if (ownerOf(c)) set.add(ownerOf(c));
    return [...set].sort();
  }, [allChanges]);

  const logRows = useMemo(
    () =>
      allChanges.filter((c) =>
        ownerFilter === ALL ? true : ownerFilter === NO_OWNER ? !ownerOf(c) : ownerOf(c) === ownerFilter
      ),
    [allChanges, ownerFilter]
  );

  const scanOptions = scans.map((x) => ({
    value: x.id,
    label: `${x.name} · ${formatShortTime(x.started_at)} · ${x.active_hosts} hosts`,
  }));

  const hostLink = (hostId: string, ip: string, port?: number) => (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        setInspectHostId(hostId);
      }}
      className="font-mono text-xs font-semibold text-foreground underline-offset-2 hover:underline"
    >
      {ip}
      {port ? `:${port}` : ''}
    </button>
  );

  const rowActions = (ch: ChangeLike) => (
    <div className="flex items-center justify-end gap-0.5 whitespace-nowrap">
      <Button variant="ghost" size="icon-xs" title="Copy a note for the owner" aria-label="Copy note for owner" onClick={() => copyNote(ch)}>
        <RiFileCopyLine />
      </Button>
      {canPush && ch.id && (
        <Button
          variant="ghost"
          size="icon-xs"
          title="Send to DefectDojo now (changes are also pushed automatically after each run)"
          aria-label="Send to DefectDojo"
          disabled={pushingId === ch.id}
          onClick={() => pushToDojo(ch)}
        >
          <RiSendPlaneLine />
        </Button>
      )}
      {ch.acknowledged_at ? (
        <Pill tone="success" title={ch.acknowledged_by ? `by ${ch.acknowledged_by}` : undefined}>
          <RiCheckboxCircleLine className="size-3" /> Ack
        </Pill>
      ) : canWrite && ch.id ? (
        <Button variant="outline" size="xs" title="Acknowledge: mark as reviewed" disabled={ackingId === ch.id} onClick={() => handleAck(ch)}>
          {ackingId === ch.id ? '…' : 'Ack'}
        </Button>
      ) : null}
    </div>
  );

  const details = (key: string, d: Described) =>
    expanded[key] && d.details.length > 0 ? (
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-0.5 text-[11px]">
        {d.details.map((x, i) => (
          <React.Fragment key={i}>
            <dt className="text-muted-foreground">{x.label}</dt>
            <dd className="min-w-0 break-words">{x.value}</dd>
          </React.Fragment>
        ))}
      </dl>
    ) : null;

  const expander = (key: string, d: Described) =>
    d.details.length > 0 ? (
      <button
        type="button"
        onClick={() => setExpanded((e) => ({ ...e, [key]: !e[key] }))}
        className="inline-flex shrink-0 items-center text-muted-foreground hover:text-foreground"
        aria-label={expanded[key] ? 'Hide details' : 'Show details'}
      >
        {expanded[key] ? <RiArrowDownSLine className="size-4" /> : <RiArrowRightSLine className="size-4" />}
      </button>
    ) : (
      <span className="inline-block w-4 shrink-0" />
    );

  const kpi = (label: string, value: number, tone: 'success' | 'danger' | 'warning', target: DiffTab) => (
    <button type="button" onClick={() => selectTab(target)} className="text-left transition-colors hover:bg-muted/40">
      <Stat label={label} value={value} tone={value > 0 ? tone : undefined} />
    </button>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan diff"
        meta="What appeared, disappeared or changed between two scans, and who owns it"
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Scan A (before)" className="w-64">
              <SimpleSelect value={fromId} onValueChange={setFromId} options={scanOptions} placeholder="Baseline scan" size="sm" />
            </Field>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Swap A and B"
              title="Swap A and B"
              onClick={() => {
                setFromId(toId);
                setToId(fromId);
              }}
            >
              <RiArrowLeftRightLine />
            </Button>
            <Field label="Scan B (after)" className="w-64">
              <SimpleSelect value={toId} onValueChange={setToId} options={scanOptions} placeholder="Target scan" size="sm" />
            </Field>
            <Button size="sm" variant="outline" disabled={!fromId || !toId || diffLoading} onClick={() => runDiff()}>
              <RiRefreshLine className={cn(diffLoading && 'animate-spin')} />
              Compare
            </Button>
          </div>
        }
      />

      {diff && (
        <StatStrip>
          {kpi('New hosts', diff.summary?.new_hosts ?? newHosts.length, 'success', 'added')}
          {kpi('Gone hosts', diff.summary?.missing_hosts ?? missingHosts.length, 'danger', 'removed')}
          {kpi('New services', diff.summary?.new_services ?? newServices.length, 'success', 'added')}
          {kpi('Closed services', diff.summary?.closed_services ?? closedServices.length, 'danger', 'removed')}
          {kpi('Changed services', diff.summary?.changed_services ?? changedServices.length, 'warning', 'changed')}
          {kpi('Time-of-day anomalies', diff.summary?.time_anomalies ?? timeAnomalies.length, 'warning', 'changed')}
        </StatStrip>
      )}

      <Tabs value={tab} onValueChange={(v) => selectTab(v as DiffTab)}>
        <TabsList variant="line">
          <TabsTrigger value="added">Added ({addedCount})</TabsTrigger>
          <TabsTrigger value="removed">Removed ({removedCount})</TabsTrigger>
          <TabsTrigger value="changed">Changed ({changedCount})</TabsTrigger>
          <TabsTrigger value="log">Change log ({allChanges.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="added" className="pt-4">
          <Card size="sm" className="py-0">
            {addedCount === 0 ? (
              <Empty>Nothing new between these scans</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-28">Type</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {newHosts.map((h) => (
                    <TableRow key={h.id} onClick={() => setInspectHostId(h.id)} className="cursor-pointer">
                      <TableCell>
                        <Pill tone="success">+ host</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-semibold">
                        {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {h.owner ? `owner ${h.owner}` : 'no owner rule'} · {h.service_count ?? h.services?.length ?? 0} services
                      </TableCell>
                    </TableRow>
                  ))}
                  {newServices.map((x) => (
                    <TableRow key={x.id} onClick={() => setInspectHostId(x.host_id)} className="cursor-pointer">
                      <TableCell>
                        <Pill tone="success">+ service</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {x.host_ip || ''}:{x.port}/{x.protocol} ({x.service_name})
                      </TableCell>
                      <TableCell className="max-w-[320px] truncate text-xs text-muted-foreground">
                        {[x.product, x.version].filter(Boolean).join(' ')}
                        {x.http?.title ? ` · ${x.http.title}` : ''}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="removed" className="pt-4">
          <Card size="sm" className="py-0">
            {removedCount === 0 ? (
              <Empty>Nothing disappeared between these scans</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-28">Type</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {missingHosts.map((h) => (
                    <TableRow key={h.id} onClick={() => setInspectHostId(h.id)} className="cursor-pointer">
                      <TableCell>
                        <Pill tone="danger">− host</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-semibold">
                        {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {h.lifecycle_state.toLowerCase()}
                        {h.owner ? ` · owner ${h.owner}` : ''}
                      </TableCell>
                    </TableRow>
                  ))}
                  {closedServices.map((x) => (
                    <TableRow key={x.id} onClick={() => setInspectHostId(x.host_id)} className="cursor-pointer">
                      <TableCell>
                        <Pill tone="danger">− service</Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {x.host_ip || ''}:{x.port}/{x.protocol} ({x.service_name})
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">closed</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="changed" className="pt-4">
          <Card size="sm" className="py-0">
            {changedCount === 0 ? (
              <Empty bird>Knock, knock… nothing changed</Empty>
            ) : (
              <div className="divide-y divide-border">
                {[...timeAnomalies, ...changedServices].map((ch: ChangeLike, idx) => {
                  const sev = sevMeta(ch.severity || (ch.is_time_anomaly ? 'medium' : 'low'));
                  const key = ch.id || `${ch.host_id}-${ch.port}-${idx}`;
                  const d = describeChange(ch);
                  return (
                    <div key={key} className="px-5 py-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex min-w-0 flex-1 items-center gap-2">
                          {expander(key, d)}
                          <Pill className={sev.badge}>{sev.label}</Pill>
                          {hostLink(ch.host_id, ch.host_ip, ch.port)}
                          <span className="min-w-0 truncate text-xs" title={d.line}>
                            {d.line}
                          </span>
                          {ch.is_time_anomaly && (
                            <Pill tone="warning">
                              <RiAlertLine className="size-3" /> anomaly {ch.time_slot}
                            </Pill>
                          )}
                          {ch.is_expected_schedule && (
                            <Pill tone="neutral">
                              <RiTimeLine className="size-3" /> expected schedule
                            </Pill>
                          )}
                          {ownerOf(ch) && <span className="shrink-0 text-xs text-muted-foreground">owner {ownerOf(ch)}</span>}
                        </div>
                        {rowActions(ch)}
                      </div>
                      <div className="pl-6">{details(key, d)}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="log" className="space-y-3 pt-4">
          <div className="flex flex-wrap items-center justify-end gap-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Owner</span>
              <SimpleSelect
                size="sm"
                value={ownerFilter}
                onValueChange={(v) => setOwnerFilter(v || ALL)}
                options={[
                  { value: ALL, label: 'All owners' },
                  { value: NO_OWNER, label: 'No owner (no CIDR rule)' },
                  ...owners.map((o) => ({ value: o, label: o })),
                ]}
                className="w-56"
              />
            </div>
            <div className="flex items-center gap-2">
              <Switch id="anomaly-only" size="sm" checked={anomalyOnly} onCheckedChange={(c) => setAnomalyOnly(c)} />
              <Label htmlFor="anomaly-only" className="text-xs text-muted-foreground">
                Time anomalies only
              </Label>
            </div>
          </div>
          <Card size="sm" className="py-0">
            {loading && allChanges.length === 0 ? (
              <PeckLoader />
            ) : logRows.length === 0 ? (
              <Empty>No change events</Empty>
            ) : (
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-20">Severity</TableHead>
                    <TableHead className="w-28">Type</TableHead>
                    <TableHead className="w-36">Host</TableHead>
                    <TableHead>Change</TableHead>
                    <TableHead className="w-36">Owner</TableHead>
                    <TableHead className="w-28">Time</TableHead>
                    <TableHead className="w-36 text-right" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logRows.slice(0, 60).map((ch) => {
                    const sev = sevMeta(ch.severity);
                    const d = describeChange(ch);
                    return (
                      <TableRow key={ch.id} className="align-top">
                        <TableCell>
                          <Pill className={sev.badge}>{sev.label}</Pill>
                        </TableCell>
                        <TableCell className="text-[11px] text-muted-foreground">
                          {EVENT_LABEL[ch.event_type] || ch.event_type.toLowerCase().replace(/_/g, ' ')}
                        </TableCell>
                        <TableCell>{hostLink(ch.host_id, ch.host_ip, ch.port)}</TableCell>
                        <TableCell className="whitespace-normal text-xs">
                          <div className="flex items-start gap-1">
                            {expander(ch.id, d)}
                            <span className="min-w-0 break-words">{d.line}</span>
                          </div>
                          <div className="pl-5">{details(ch.id, d)}</div>
                        </TableCell>
                        <TableCell className="truncate text-xs text-muted-foreground" title={ownerOf(ch)}>
                          {ownerOf(ch) || <span className="opacity-60">none</span>}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          <span title={formatDateTime(ch.created_at)}>{formatShortTime(ch.created_at)}</span>
                        </TableCell>
                        <TableCell>{rowActions(ch)}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>
      </Tabs>

      <AssetInspectorDrawer hostId={inspectHostId} onClose={() => setInspectHostId(null)} onUpdated={loadInitial} />
    </div>
  );
}
