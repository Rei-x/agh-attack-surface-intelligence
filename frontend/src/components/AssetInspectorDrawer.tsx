import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  RiAlertLine,
  RiArrowDownSLine,
  RiArrowRightSLine,
  RiExternalLinkLine,
  RiHistoryLine,
  RiLockLine,
  RiLockUnlockLine,
  RiMailLine,
  RiSaveLine,
  RiSendPlaneLine,
} from '@remixicon/react';
import { api, type TriagePatch } from '@/lib/api';
import { HostTimeline } from '@/components/HostTimeline';
import { TriageEditor } from '@/components/TriageEditor';
import { PolicyViolationNotice } from '@/components/PolicyViolationNotice';
import { TriageBadge } from '@/components/AssetQueryHelp';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { useDefectDojoStatus } from '@/lib/defectdojo';
import { hostIdentity, identityLabel } from '@/lib/identity';
import {
  assetsLink,
  eolLabel,
  envLabel,
  formatDateTime,
  formatRelativeTime,
  lifecycleMeta,
  queryTerm,
  scoreBarColor,
  scoreColor,
  translateFactor,
} from '@/lib/format';
import { cn } from '@/lib/utils';
import { Empty, Notice, Pill, SectionTitle, SimpleSelect } from '@/components/common';
import { ServiceLogo, ServiceLogoFor } from '@/components/ServiceLogo';
import { CategoryBadges, serviceFlags } from '@/components/CategoryBadge';
import { EolEvidence } from '@/components/EolBadges';
import { ServiceScreenshot } from '@/components/ServiceScreenshot';
import { NotifyOwnerButton, TicketBadge } from '@/components/NotifyOwnerDialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Host, Service, ServiceObservation, TagRule, TimeSlotStat } from '@/types/api';
import { PeckLoader } from '@/components/Woodpecker';

interface Props {
  hostId: string | null;
  onClose: () => void;
  onUpdated?: () => void;
}

const DEFAULT_SLOTS = ['00-06', '06-12', '12-18', '18-24'];

const ENV_NONE = '__none__';
const ENV_OPTIONS = [
  { value: ENV_NONE, label: 'Not set' },
  { value: 'prod', label: 'Production' },
  { value: 'staging', label: 'Staging' },
  { value: 'dev', label: 'Development' },
  { value: 'test', label: 'Test' },
];

const LIFECYCLE_OPTIONS = ['NEW', 'ACTIVE', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'].map(
  (s) => ({ value: s, label: lifecycleMeta(s).label })
);

/** IPv4 CIDR membership (owner rules are IPv4 ranges). */
function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsStr] = cidr.split('/');
  const toNum = (s: string) => s.split('.').reduce((a, o) => (a << 8) + (Number(o) & 255), 0) >>> 0;
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(net || '')) return false;
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  if (!(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (toNum(ip) & mask) === (toNum(net) & mask);
}

const EMAIL_RE = /[^\s@<>()]+@[^\s@<>()]+\.[a-z]{2,}/i;

/** Clickable tag / technology chip that lists every host with it. */
function QueryChip({ q, children, title }: { q: string; children: React.ReactNode; title?: string }) {
  return (
    <Link
      to={assetsLink(q)}
      title={title || `Show all hosts: ${q}`}
      className="inline-flex h-5 items-center border border-border px-1.5 font-mono text-[11px] text-foreground transition-colors hover:border-foreground/40 hover:underline"
    >
      {children}
    </Link>
  );
}

type TabId = 'services' | 'overview' | 'heatmap' | 'summary' | 'timeline';

/* ---------- small presentational helpers ---------- */

function KV({ label, children, className }: { label: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('min-w-0', className)}>
      <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
        {label}
      </div>
      <div className="mt-1 font-mono text-xs break-all text-foreground">{children}</div>
    </div>
  );
}

/** Lock state indicator; when locked + allowed, clicking unlocks the field. */
function LockToggle({
  locked,
  canUnlock,
  disabled,
  onUnlock,
}: {
  locked: boolean;
  canUnlock: boolean;
  disabled?: boolean;
  onUnlock: () => void;
}) {
  if (!locked) {
    return (
      <span
        className="inline-flex size-7 items-center justify-center text-muted-foreground/50"
        title="Value from the scanner"
      >
        <RiLockUnlockLine className="size-3.5" />
      </span>
    );
  }
  if (!canUnlock) {
    return (
      <span
        className="inline-flex size-7 items-center justify-center text-violet-600 dark:text-violet-400"
        title="Locked by an analyst"
      >
        <RiLockLine className="size-3.5" />
      </span>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            disabled={disabled}
            onClick={onUnlock}
            aria-label="Unlock"
            className="text-violet-600 hover:text-foreground dark:text-violet-400"
          />
        }
      >
        <RiLockLine />
      </TooltipTrigger>
      <TooltipContent>Unlock (scanner value wins again)</TooltipContent>
    </Tooltip>
  );
}

function OverrideRow({
  label,
  lock,
  scanner,
  children,
}: {
  label: React.ReactNode;
  lock?: React.ReactNode;
  scanner?: string | null;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr_1.75rem] items-start gap-4 border-b border-border py-3 last:border-b-0">
      <Label className="pt-3 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
        {label}
      </Label>
      <div className="min-w-0">
        {children}
        {scanner && (
          <div className="mt-1 font-mono text-[11px] text-amber-700 dark:text-amber-400">
            Scanner saw: {scanner}
          </div>
        )}
      </div>
      <div className="pt-1.5">{lock}</div>
    </div>
  );
}

/** "What is it and whom do I tell": device identity, OS, owner (+ contact), environment. */
function HostIdentityLine({ host, rules }: { host: Host; rules: TagRule[] | null }) {
  const id = hostIdentity(host);
  const label = identityLabel(id);
  const rule = (rules || []).find((r) => r.enabled && r.owner && inCidr(host.ip, r.cidr));
  const owner = host.owner || rule?.owner || '';
  const email = EMAIL_RE.exec(`${owner} ${rule?.description || ''}`)?.[0];
  const subject = `[CBI AGH] ${host.ip}${label ? ` (${label})` : ''} needs attention`;
  return (
    <div className="grid grid-cols-1 gap-3 border border-border bg-muted/30 p-3 sm:grid-cols-2">
      <div className="flex min-w-0 items-center gap-2.5">
        <ServiceLogo names={id.logoNames.length ? id.logoNames : ['host']} kind="host" size="lg" />
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-foreground" title={id.evidence ? `From ${id.evidence}` : undefined}>
            {label || id.os || 'Unidentified device'}
          </div>
          <div className="truncate text-[11px] text-muted-foreground">
            {[id.kind, id.os && id.os !== label ? `OS: ${id.os}` : null].filter(Boolean).join(' · ') ||
              'No product banner or page title identified it yet'}
          </div>
        </div>
      </div>
      <div className="min-w-0 text-xs">
        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Owner</div>
        {owner ? (
          <div className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
            <Link
              to={assetsLink(queryTerm('owner', owner))}
              className="truncate font-medium text-foreground hover:underline"
              title={`All hosts owned by ${owner}`}
            >
              {owner}
            </Link>
            {email && (
              <a
                href={`mailto:${email}?subject=${encodeURIComponent(subject)}`}
                className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
                title={`Email ${email}`}
              >
                <RiMailLine className="size-3.5" />
                {email === owner ? 'Email' : email}
              </a>
            )}
          </div>
        ) : (
          <div className="mt-0.5 text-muted-foreground">Not assigned (add a CIDR owner rule or set it in Overrides)</div>
        )}
        <div className="mt-0.5 truncate text-[11px] text-muted-foreground">
          {[host.environment ? envLabel(host.environment) : null, rule?.description, rule ? `rule ${rule.cidr}` : null]
            .filter(Boolean)
            .join(' · ')}
        </div>
      </div>
    </div>
  );
}

/* ---------- main component ---------- */

export function AssetInspectorDrawer({ hostId, onClose, onUpdated }: Props) {
  const { can } = useAuth();
  const toast = useToast();

  const [host, setHost] = useState<Host | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>('services');

  // Host override form state
  const [hostname, setHostname] = useState('');
  const [environment, setEnvironment] = useState('');
  const [owner, setOwner] = useState('');
  const [lifecycleState, setLifecycleState] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [notes, setNotes] = useState('');
  const [savingHost, setSavingHost] = useState(false);

  // Expanded service cards & evidence & history
  const [expandedServiceId, setExpandedServiceId] = useState<string | null>(null);
  const [expandedTechKey, setExpandedTechKey] = useState<string | null>(null);
  const [obsByService, setObsByService] = useState<Record<string, ServiceObservation[]>>({});
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [svcForm, setSvcForm] = useState({
    service_name: '',
    product: '',
    version: '',
    http_title: '',
    triage_status: 'new',
    tags: '',
    notes: '',
  });
  const [savingSvc, setSavingSvc] = useState(false);
  const [pushingDD, setPushingDD] = useState<string | null>(null);

  const canWrite = can(PERMISSIONS.ASSETS_WRITE);
  const canPushDD = can(PERMISSIONS.DEFECTDOJO_PUSH);
  const dd = useDefectDojoStatus(canPushDD && !!hostId);
  const [ownerRules, setOwnerRules] = useState<TagRule[] | null>(null);

  useEffect(() => {
    if (!hostId || ownerRules) return;
    api
      .listTagRules()
      .then(setOwnerRules)
      .catch(() => setOwnerRules([]));
  }, [hostId, ownerRules]);

  /** silent: refresh in place (after a save) without swapping the drawer for the loader. */
  const loadHost = async (id: string, silent = false) => {
    if (!silent) setLoading(true);
    try {
      const h = await api.getHost(id);
      setHost(h);
      setHostname(h.hostname || '');
      setEnvironment(h.environment || '');
      setOwner(h.owner || '');
      setLifecycleState(h.lifecycle_state || 'ACTIVE');
      setTagsInput((h.tags || []).join(', '));
      setNotes(h.notes || '');
      if (h.services && h.services.length > 0 && !expandedServiceId) {
        setExpandedServiceId([...h.services].sort((a, b) => b.interestingness - a.interestingness)[0].id);
      }
    } catch (err) {
      toast.error('Could not load host', (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (hostId) {
      setExpandedServiceId(null);
      setEditingServiceId(null);
      loadHost(hostId);
    }
    // host is intentionally kept on close so the Sheet exit animation doesn't flash a loader
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostId]);

  const isHostFieldLocked = (field: string) => (host?.locked_fields || []).includes(field);
  const scannerSawHost = (field: string): string | null => {
    const val = host?.scanner_observed?.[field];
    if (val === undefined || val === null || val === '') return null;
    if (Array.isArray(val)) return val.join(', ');
    return String(val);
  };

  const handleSaveHostOverrides = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!host) return;
    setSavingHost(true);
    try {
      const payload: Record<string, unknown> = {};
      if (hostname !== (host.hostname || '')) payload.hostname = hostname;
      if (environment !== (host.environment || '')) payload.environment = environment;
      if (owner !== (host.owner || '')) payload.owner = owner;
      if (lifecycleState !== (host.lifecycle_state || '')) payload.lifecycle_state = lifecycleState;
      const parsedTags = tagsInput
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      if (parsedTags.join(',') !== (host.tags || []).join(',')) payload.tags = parsedTags;
      if (notes !== (host.notes || '')) payload.notes = notes;

      if (Object.keys(payload).length === 0) {
        toast.info('No changes');
        return;
      }

      const updated = await api.patchHostOverrides(host.id, payload);
      setHost(updated);
      toast.success('Overrides saved');
      onUpdated?.();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    } finally {
      setSavingHost(false);
    }
  };

  const handleUnlockHostField = async (field: string) => {
    if (!host) return;
    setSavingHost(true);
    try {
      const updated = await api.patchHostOverrides(host.id, { unlock_fields: [field] });
      setHost(updated);
      setHostname(updated.hostname || '');
      setEnvironment(updated.environment || '');
      setOwner(updated.owner || '');
      setLifecycleState(updated.lifecycle_state || 'ACTIVE');
      setTagsInput((updated.tags || []).join(', '));
      setNotes(updated.notes || '');
      toast.success('Unlocked', field);
      onUpdated?.();
    } catch (err) {
      toast.error('Unlock failed', (err as Error).message);
    } finally {
      setSavingHost(false);
    }
  };

  const startEditService = (svc: Service) => {
    setEditingServiceId(svc.id);
    setSvcForm({
      service_name: svc.service_name || '',
      product: svc.product || '',
      version: svc.version || '',
      http_title: svc.http?.title || '',
      triage_status: svc.triage_status || 'new',
      tags: (svc.tags || []).join(', '),
      notes: svc.notes || '',
    });
  };

  const handleSaveServiceOverrides = async (svc: Service) => {
    setSavingSvc(true);
    try {
      const payload: Record<string, unknown> = {};
      if (svcForm.service_name !== (svc.service_name || ''))
        payload.service_name = svcForm.service_name;
      if (svcForm.product !== (svc.product || '')) payload.product = svcForm.product;
      if (svcForm.version !== (svc.version || '')) payload.version = svcForm.version;
      if (svcForm.http_title !== (svc.http?.title || '')) payload.http_title = svcForm.http_title;
      const tags = svcForm.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      if (tags.join(',') !== (svc.tags || []).join(',')) payload.tags = tags;
      if (svcForm.notes !== (svc.notes || '')) payload.notes = svcForm.notes;

      await api.patchServiceOverrides(svc.id, payload);
      toast.success('Service overrides saved');
      setEditingServiceId(null);
      if (host) await loadHost(host.id, true);
      onUpdated?.();
    } catch (err) {
      toast.error('Save failed', (err as Error).message);
    } finally {
      setSavingSvc(false);
    }
  };

  // Triage decisions (accepted risk / false positive with reason + expiry). Errors propagate
  // to the TriageEditor so it can show the server's validation message inline.
  const handleSaveServiceTriage = async (svcId: string, patch: TriagePatch | null) => {
    await api.patchServiceOverrides(svcId, { triage: patch });
    if (host) await loadHost(host.id, true);
    onUpdated?.();
  };

  const handleSaveHostTriage = async (patch: TriagePatch | null) => {
    if (!host) return;
    const updated = await api.patchHostOverrides(host.id, { triage: patch });
    setHost((prev) => (prev ? { ...prev, ...updated, recent_changes: prev.recent_changes } : updated));
    onUpdated?.();
  };

  const handleUnlockServiceField = async (svcId: string, field: string) => {
    try {
      await api.patchServiceOverrides(svcId, { unlock_fields: [field] });
      toast.success('Unlocked', field);
      if (host) await loadHost(host.id, true);
      onUpdated?.();
    } catch (err) {
      toast.error('Unlock failed', (err as Error).message);
    }
  };

  const handleLoadObservations = async (svcId: string) => {
    if (obsByService[svcId]) return;
    try {
      const list = await api.getServiceObservations(svcId);
      setObsByService((prev) => ({ ...prev, [svcId]: list }));
    } catch (err) {
      toast.error('Could not load history', (err as Error).message);
    }
  };

  const handlePushServiceToDD = async (svc: Service) => {
    setPushingDD(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success('Sent to DefectDojo', `${host?.ip}:${svc.port}`);
    } catch (err) {
      toast.error('DefectDojo push failed', (err as Error).message);
    } finally {
      setPushingDD(null);
    }
  };

  const lc = lifecycleMeta(host?.lifecycle_state);

  // Build 4-slot time-of-day map
  const statsMap = new Map<string, TimeSlotStat>();
  for (const s of host?.time_of_day_stats || []) {
    statsMap.set(s.slot, s);
  }
  const heatmapSlots: TimeSlotStat[] = DEFAULT_SLOTS.map(
    (slot) => statsMap.get(slot) || { slot, seen: 0, total: 0, ratio: 0 }
  );

  const ready = !loading && !!host;

  return (
    <Sheet
      open={!!hostId}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent
        side="right"
        className="w-full gap-0 p-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl"
      >
        {/* Header */}
        <SheetHeader className="gap-3 border-b border-border p-6 pr-16">
          {!ready || !host ? (
            <SheetTitle className="text-sm text-muted-foreground">Loading…</SheetTitle>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <SheetTitle className="font-mono text-lg tracking-normal normal-case">
                  {host.ip}
                </SheetTitle>
                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-wider uppercase">
                  <span className={cn('size-2', lc.dot)} aria-hidden />
                  {lc.label}
                </span>
                <Tooltip>
                  <TooltipTrigger render={<span className="inline-flex" />}>
                    <Pill className={cn('cursor-help font-mono tabular-nums', scoreColor(host.interestingness))}>
                      Score {host.interestingness}
                    </Pill>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-sm flex-col items-start gap-0.5 text-left">
                    <span className="font-semibold">Why {host.interestingness}</span>
                    {(host.interesting_factors || []).length === 0 ? (
                      <span className="opacity-80">No risk factors</span>
                    ) : (
                      [...host.interesting_factors!]
                        .sort((a, b) => b.points - a.points)
                        .slice(0, 6)
                        .map((f, i) => (
                          <span key={i} className="opacity-80">
                            +{f.points} {translateFactor(f.reason)}
                          </span>
                        ))
                    )}
                  </TooltipContent>
                </Tooltip>
                {(host.locked_fields?.length || 0) > 0 && (
                  <Pill tone="violet" title={`Analyst overrides: ${host.locked_fields!.join(', ')}`}>
                    <RiLockLine className="size-3" />
                    {host.locked_fields!.length}
                  </Pill>
                )}
                <TriageBadge triage={host.triage} />
              </div>
              <HostIdentityLine host={host} rules={ownerRules} />
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {host.hostname && <span className="font-mono text-foreground">{host.hostname}</span>}
                <span>
                  Seen in{' '}
                  <span className="font-mono text-foreground">
                    {host.total_scans_seen}/{host.total_scans_checked}
                  </span>{' '}
                  scans
                </span>
                <span>Last seen {formatRelativeTime(host.last_seen)}</span>
              </div>
            </>
          )}
        </SheetHeader>

        {!ready || !host ? (
          <PeckLoader className="flex-1" />
        ) : (
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as TabId)}
            className="min-h-0 flex-1 gap-0"
          >
            <div className="border-b border-border px-6">
              <TabsList variant="line" className="-mb-px">
                <TabsTrigger value="services">
                  Services{' '}
                  <span className="font-mono text-muted-foreground tabular-nums">
                    {host.services?.length || 0}
                  </span>
                </TabsTrigger>
                <TabsTrigger value="summary">Overview</TabsTrigger>
                <TabsTrigger value="timeline">Timeline</TabsTrigger>
                <TabsTrigger value="heatmap">Availability</TabsTrigger>
                <TabsTrigger value="overview">Overrides</TabsTrigger>
              </TabsList>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto">
              {/* ===== SERVICES: Evidence + Confidence ===== */}
              <TabsContent value="services" className="p-6">
                {(host.services || []).length === 0 ? (
                  <Empty>No open services</Empty>
                ) : (
                  <div className="divide-y divide-border border border-border">
                    {(host.services || []).map((svc) => {
                      const isOpen = expandedServiceId === svc.id;
                      const isEditing = editingServiceId === svc.id;
                      const http = svc.http;
                      const tls = http?.tls;
                      const obsList = obsByService[svc.id];

                      return (
                        <div key={svc.id}>
                          {/* Service row */}
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => setExpandedServiceId(isOpen ? null : svc.id)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                setExpandedServiceId(isOpen ? null : svc.id);
                              }
                            }}
                            className="flex cursor-pointer items-center gap-3 px-4 py-3 transition-colors outline-none hover:bg-muted/50 focus-visible:bg-muted/50"
                          >
                            {isOpen ? (
                              <RiArrowDownSLine className="size-4 shrink-0 text-muted-foreground" />
                            ) : (
                              <RiArrowRightSLine className="size-4 shrink-0 text-muted-foreground" />
                            )}
                            <ServiceLogoFor service={svc} size="md" />
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-sm font-semibold text-foreground">
                                  {svc.port}/{svc.protocol}
                                </span>
                                <span className="text-sm text-foreground">
                                  {svc.service_name || 'unknown'}
                                </span>
                                {(svc.product || svc.version) && (
                                  <span className="font-mono text-xs text-muted-foreground">
                                    {[svc.product, svc.version].filter(Boolean).join(' ')}
                                  </span>
                                )}
                                <CategoryBadges flags={serviceFlags(svc)} size="xs" link />
                                {(svc.locked_fields?.length || 0) > 0 && (
                                  <RiLockLine className="size-3.5 text-violet-600 dark:text-violet-400" />
                                )}
                                <TriageBadge triage={svc.triage} />
                                <TicketBadge serviceId={svc.id} />
                              </div>
                              {http?.title && (
                                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                                  <span className="font-mono">{http.status_code}</span> · {http.title}
                                </p>
                              )}
                            </div>
                            <Pill className={cn('font-mono tabular-nums', scoreColor(svc.interestingness))}>
                              {svc.interestingness}
                            </Pill>
                          </div>

                          {/* Service details */}
                          {isOpen && (
                            <div className="space-y-6 border-t border-border bg-muted/20 px-4 py-5">
                              <PolicyViolationNotice hits={(svc as { policy_violations?: Parameters<typeof PolicyViolationNotice>[0]['hits'] }).policy_violations} />
                              {/* Action bar */}
                              <div className="space-y-2">
                                <div className="flex flex-wrap items-start justify-between gap-2">
                                  <div className="min-w-0 flex-1">
                                    <TriageEditor
                                      status={svc.triage_status}
                                      triage={svc.triage}
                                      workflow
                                      canWrite={canWrite}
                                      onSave={(patch) => handleSaveServiceTriage(svc.id, patch)}
                                    />
                                  </div>
                                  <div className="flex items-center gap-1">
                                    {canWrite && (
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="xs"
                                        onClick={() =>
                                          isEditing ? setEditingServiceId(null) : startEditService(svc)
                                        }
                                        title="Correct product, version or title; locked fields survive re-scans"
                                      >
                                        <RiLockLine data-icon="inline-start" />
                                        {isEditing ? 'Cancel' : 'Edit'}
                                      </Button>
                                    )}
                                    <NotifyOwnerButton hostId={host.id} serviceId={svc.id} />
                                    {canPushDD && (
                                      <Tooltip>
                                        <TooltipTrigger render={<span className="inline-flex" />}>
                                          <Button
                                            type="button"
                                            variant="ghost"
                                            size="xs"
                                            disabled={!dd.ready || pushingDD === svc.id}
                                            onClick={() => handlePushServiceToDD(svc)}
                                          >
                                            <RiSendPlaneLine data-icon="inline-start" />
                                            {pushingDD === svc.id ? 'Sending…' : 'DefectDojo'}
                                          </Button>
                                        </TooltipTrigger>
                                        <TooltipContent>
                                          {dd.ready
                                            ? 'Push now. Findings are also synced to DefectDojo automatically.'
                                            : dd.reason}
                                        </TooltipContent>
                                      </Tooltip>
                                    )}
                                  </div>
                                </div>
                                {(svc.tags || []).length > 0 && (
                                  <div className="flex flex-wrap items-center gap-1">
                                    {svc.tags!.map((t) => (
                                      <QueryChip key={t} q={queryTerm('tag', t)}>
                                        #{t}
                                      </QueryChip>
                                    ))}
                                  </div>
                                )}
                              </div>

                              <EolEvidence service={svc} />

                              {/* Service override editor */}
                              {isEditing && canWrite && (
                                <div className="border border-border bg-card px-4 py-2">
                                  {[
                                    { key: 'service_name', label: 'Service' },
                                    { key: 'product', label: 'Product' },
                                    { key: 'version', label: 'Version' },
                                    { key: 'http_title', label: 'HTTP title' },
                                  ].map((f) => {
                                    const locked = (svc.locked_fields || []).includes(f.key);
                                    const saw = svc.scanner_observed?.[f.key];
                                    const sawStr =
                                      saw !== undefined && saw !== null && saw !== ''
                                        ? String(saw)
                                        : null;
                                    return (
                                      <OverrideRow
                                        key={f.key}
                                        label={f.label}
                                        scanner={sawStr}
                                        lock={
                                          <LockToggle
                                            locked={locked}
                                            canUnlock
                                            onUnlock={() => handleUnlockServiceField(svc.id, f.key)}
                                          />
                                        }
                                      >
                                        <Input
                                          value={svcForm[f.key as keyof typeof svcForm]}
                                          onChange={(e) =>
                                            setSvcForm((prev) => ({
                                              ...prev,
                                              [f.key]: e.target.value,
                                            }))
                                          }
                                        />
                                      </OverrideRow>
                                    );
                                  })}
                                  <OverrideRow label="Tags">
                                    <Input
                                      value={svcForm.tags}
                                      onChange={(e) =>
                                        setSvcForm((p) => ({ ...p, tags: e.target.value }))
                                      }
                                      placeholder="tag1, tag2"
                                    />
                                  </OverrideRow>
                                  <OverrideRow label="Notes">
                                    <Textarea
                                      rows={2}
                                      value={svcForm.notes}
                                      onChange={(e) =>
                                        setSvcForm((p) => ({ ...p, notes: e.target.value }))
                                      }
                                    />
                                  </OverrideRow>
                                  <div className="flex justify-end gap-2 py-3">
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => setEditingServiceId(null)}
                                    >
                                      Cancel
                                    </Button>
                                    <Button
                                      type="button"
                                      size="sm"
                                      disabled={savingSvc}
                                      onClick={() => handleSaveServiceOverrides(svc)}
                                    >
                                      <RiSaveLine data-icon="inline-start" />
                                      {savingSvc ? 'Saving…' : 'Save'}
                                    </Button>
                                  </div>
                                </div>
                              )}

                              {/* Confidence (Noisy-OR) */}
                              {(svc.technologies?.length || 0) > 0 && (
                                <div className="space-y-2">
                                  <SectionTitle>Confidence</SectionTitle>
                                  <div className="divide-y divide-border border border-border bg-card">
                                    {svc.technologies!.map((tech, idx) => {
                                      const techKey = `${svc.id}-${idx}`;
                                      const techOpen = expandedTechKey === techKey;
                                      const hasEvidence = (tech.evidence?.length || 0) > 0;
                                      return (
                                        <div key={techKey} className="px-3 py-2.5">
                                          <div
                                            onClick={() =>
                                              setExpandedTechKey(techOpen ? null : techKey)
                                            }
                                            className={cn(
                                              'flex items-center justify-between gap-3',
                                              hasEvidence && 'cursor-pointer'
                                            )}
                                          >
                                            <div className="flex min-w-0 items-center gap-2">
                                              {hasEvidence &&
                                                (techOpen ? (
                                                  <RiArrowDownSLine className="size-3.5 shrink-0 text-muted-foreground" />
                                                ) : (
                                                  <RiArrowRightSLine className="size-3.5 shrink-0 text-muted-foreground" />
                                                ))}
                                              <Link
                                                to={assetsLink(queryTerm('tech', tech.name))}
                                                onClick={(e) => e.stopPropagation()}
                                                className="truncate text-xs font-medium text-foreground hover:underline"
                                                title={`All hosts running ${tech.name}`}
                                              >
                                                {tech.name}
                                              </Link>
                                              {tech.version && (
                                                <span className="font-mono text-[11px] text-muted-foreground">
                                                  v{tech.version}
                                                </span>
                                              )}
                                              <Pill>{tech.category}</Pill>
                                            </div>
                                            <div className="flex shrink-0 items-center gap-3">
                                              <Progress value={tech.confidence} className="w-24" />
                                              <span className="w-10 text-right font-mono text-xs text-foreground tabular-nums">
                                                {tech.confidence}%
                                              </span>
                                            </div>
                                          </div>
                                          {techOpen && hasEvidence && (
                                            <div className="mt-2.5 space-y-1 border-t border-border pt-2">
                                              {tech.evidence!.map((ev, eIdx) => (
                                                <div
                                                  key={eIdx}
                                                  className="flex items-center justify-between gap-2 font-mono text-[11px]"
                                                >
                                                  <span className="text-muted-foreground">
                                                    <span className="text-primary">
                                                      [{ev.signal_type}]
                                                    </span>{' '}
                                                    <span className="text-foreground">{ev.detail}</span>
                                                  </span>
                                                  <span className="shrink-0 text-muted-foreground tabular-nums">
                                                    w={ev.weight.toFixed(2)}
                                                  </span>
                                                </div>
                                              ))}
                                              {tech.explanation && (
                                                <div className="pt-1 font-mono text-[11px] text-muted-foreground">
                                                  noisy-OR: {tech.explanation}
                                                </div>
                                              )}
                                            </div>
                                          )}
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}

                              {/* HTTP Evidence */}
                              {http && (
                                <div className="space-y-2">
                                  <SectionTitle>Evidence · HTTP</SectionTitle>
                                  <div className="space-y-4 border border-border bg-card p-4">
                                    <ServiceScreenshot host={host} service={svc} />
                                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                                      <KV label="URL">
                                        {(() => {
                                          const url = http.url || `${http.scheme || 'http'}://${host.ip}:${svc.port}`;
                                          return /^https?:\/\//i.test(url) ? (
                                            <a
                                              href={url}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="inline-flex items-center gap-1 underline decoration-border underline-offset-2 hover:decoration-foreground"
                                            >
                                              {url}
                                              <RiExternalLinkLine className="size-3 shrink-0" />
                                            </a>
                                          ) : (
                                            url
                                          );
                                        })()}
                                      </KV>
                                      <KV label="Status">
                                        {http.status_code}
                                        {http.response_time_ms ? (
                                          <span className="text-muted-foreground">
                                            {' '}
                                            · {http.response_time_ms} ms
                                          </span>
                                        ) : null}
                                      </KV>
                                      {http.server_header && <KV label="Server">{http.server_header}</KV>}
                                      {http.meta_generator && (
                                        <KV label="Generator">{http.meta_generator}</KV>
                                      )}
                                      {http.favicon_mmh3 && (
                                        <KV label="Favicon MMH3">{http.favicon_mmh3}</KV>
                                      )}
                                      {http.favicon_sha256 && (
                                        <KV label="Favicon SHA256">
                                          <span className="block truncate" title={http.favicon_sha256}>
                                            {http.favicon_sha256.slice(0, 24)}…
                                          </span>
                                        </KV>
                                      )}
                                    </div>

                                    {(http.redirect_chain?.length || 0) > 0 && (
                                      <div className="space-y-1.5 border-t border-border pt-3">
                                        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          Przekierowania
                                        </div>
                                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                                          {http.redirect_chain!.map((hop, i) => (
                                            <span
                                              key={i}
                                              className="border border-border px-1.5 py-0.5 text-foreground"
                                            >
                                              {hop.status_code} → {hop.url}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {(http.missing_sec_headers?.length || 0) > 0 && (
                                      <div className="space-y-1.5 border-t border-border pt-3">
                                        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          Missing security headers
                                        </div>
                                        <div className="flex flex-wrap gap-1">
                                          {http.missing_sec_headers!.map((h) => (
                                            <Pill
                                              key={h}
                                              tone="danger"
                                              className="font-mono normal-case tracking-normal"
                                            >
                                              {h}
                                            </Pill>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {http.headers && Object.keys(http.headers).length > 0 && (
                                      <div className="space-y-1.5 border-t border-border pt-3">
                                        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          Headers
                                        </div>
                                        <div className="max-h-40 divide-y divide-border overflow-y-auto border border-border font-mono text-[11px]">
                                          {Object.entries(http.headers).map(([k, v]) => (
                                            <div key={k} className="flex gap-2 px-2.5 py-1">
                                              <span className="shrink-0 text-muted-foreground">{k}:</span>
                                              <span className="break-all text-foreground">{v}</span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {(http.cookies?.length || 0) > 0 && (
                                      <div className="space-y-1.5 border-t border-border pt-3">
                                        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          Cookies · {http.cookies!.length}
                                        </div>
                                        <div className="overflow-x-auto border border-border">
                                          <table className="w-full font-mono text-[11px]">
                                            <thead className="border-b border-border text-[10px] tracking-widest text-muted-foreground uppercase">
                                              <tr>
                                                <th className="px-2.5 py-1.5 text-left font-semibold">Name</th>
                                                <th className="px-2.5 py-1.5 text-left font-semibold">HttpOnly</th>
                                                <th className="px-2.5 py-1.5 text-left font-semibold">Secure</th>
                                                <th className="px-2.5 py-1.5 text-left font-semibold">SameSite</th>
                                              </tr>
                                            </thead>
                                            <tbody className="divide-y divide-border">
                                              {http.cookies!.map((c, ci) => (
                                                <tr key={ci}>
                                                  <td className="px-2.5 py-1.5 text-foreground">{c.name}</td>
                                                  <td className="px-2.5 py-1.5">
                                                    <span
                                                      className={
                                                        c.http_only
                                                          ? 'text-muted-foreground'
                                                          : 'font-semibold text-rose-600 dark:text-rose-400'
                                                      }
                                                    >
                                                      {c.http_only ? 'yes' : 'missing'}
                                                    </span>
                                                  </td>
                                                  <td className="px-2.5 py-1.5">
                                                    <span
                                                      className={
                                                        c.secure
                                                          ? 'text-muted-foreground'
                                                          : 'font-semibold text-rose-600 dark:text-rose-400'
                                                      }
                                                    >
                                                      {c.secure ? 'yes' : 'missing'}
                                                    </span>
                                                  </td>
                                                  <td className="px-2.5 py-1.5 text-muted-foreground">
                                                    {c.same_site || 'n/a'}
                                                  </td>
                                                </tr>
                                              ))}
                                            </tbody>
                                          </table>
                                        </div>
                                      </div>
                                    )}

                                    {(http.safe_path_hits?.length || 0) > 0 && (
                                      <div className="space-y-1.5 border-t border-border pt-3">
                                        <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          Paths probed (GET/HEAD)
                                        </div>
                                        <div className="divide-y divide-border border border-border">
                                          {http.safe_path_hits!.map((hit, hi) => (
                                            <div
                                              key={hi}
                                              className="flex items-center justify-between gap-3 px-2.5 py-1.5 font-mono text-[11px]"
                                            >
                                              <span className="text-foreground">{hit.path}</span>
                                              <span className="flex-1 truncate text-muted-foreground">
                                                {hit.title || hit.snippet || ''}
                                              </span>
                                              <span className="shrink-0 text-muted-foreground tabular-nums">
                                                {hit.status_code}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>

                                  {/* TLS */}
                                  {tls && (
                                    <div className="space-y-4 border border-border bg-card p-4">
                                      <div className="flex flex-wrap items-center justify-between gap-2">
                                        <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                                          TLS · <span className="font-mono">{tls.version}</span>
                                        </span>
                                        <div className="flex items-center gap-1.5">
                                          {tls.is_self_signed && <Pill tone="warning">Self-signed</Pill>}
                                          {tls.is_expired ? (
                                            <Pill tone="orange">Expired</Pill>
                                          ) : (
                                            <Pill
                                              tone={tls.days_to_expiry <= 30 ? 'danger' : 'neutral'}
                                              className="font-mono"
                                            >
                                              {tls.days_to_expiry} days
                                            </Pill>
                                          )}
                                        </div>
                                      </div>
                                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                                        <KV label="Subject CN">{tls.subject_cn}</KV>
                                        <KV label="Issuer">{tls.issuer}</KV>
                                        <KV label="Valid until">{formatDateTime(tls.not_after)}</KV>
                                        <KV label="SHA256">
                                          <span className="block truncate" title={tls.sha256}>
                                            {tls.sha256}
                                          </span>
                                        </KV>
                                        {tls.jarm && (
                                          <KV label="JARM (TLS stack)">
                                            <span
                                              className="block truncate font-mono"
                                              title={`${tls.jarm}: same JARM means the same TLS library and configuration`}
                                            >
                                              {tls.jarm}
                                            </span>
                                          </KV>
                                        )}
                                      </div>
                                      {(tls.sans?.length || 0) > 0 && (
                                        <div className="flex flex-wrap gap-1">
                                          {tls.sans!.map((san) => (
                                            <Pill
                                              key={san}
                                              className="font-mono font-normal normal-case tracking-normal"
                                            >
                                              {san}
                                            </Pill>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* Banner */}
                              {svc.banner && (
                                <div className="space-y-2">
                                  <SectionTitle>Banner</SectionTitle>
                                  <pre className="border border-border bg-card p-3 font-mono text-[11px] break-all whitespace-pre-wrap text-foreground">
                                    {svc.banner}
                                  </pre>
                                </div>
                              )}

                              {/* Observation history */}
                              <div className="space-y-2">
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="xs"
                                  className="-ml-3"
                                  onClick={() => handleLoadObservations(svc.id)}
                                >
                                  <RiHistoryLine data-icon="inline-start" />
                                  Observation history
                                </Button>
                                {obsList &&
                                  (obsList.length === 0 ? (
                                    <p className="text-xs text-muted-foreground">No history yet</p>
                                  ) : (
                                    <div className="divide-y divide-border border border-border bg-card">
                                      {obsList.map((o, idx) => (
                                        <div
                                          key={o.id || idx}
                                          className="flex items-center justify-between gap-2 px-3 py-2 font-mono text-[11px]"
                                        >
                                          <span className="text-foreground">
                                            {o.service_name || svc.service_name} {o.product || ''}{' '}
                                            {o.version || ''}
                                            {o.http?.title ? ` · "${o.http.title}"` : ''}
                                          </span>
                                          <span className="shrink-0 text-muted-foreground">
                                            {formatDateTime(o.observed_at || o.created_at)}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  ))}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </TabsContent>

              {/* ===== SUMMARY ===== */}
              <TabsContent value="summary" className="space-y-6 p-6">
                <div className="grid grid-cols-2 gap-5 border border-border bg-card p-4">
                  <KV label="First seen">{formatDateTime(host.first_seen)}</KV>
                  <KV label="Last seen">{formatDateTime(host.last_seen)}</KV>
                  <KV label="OS">
                    {(() => {
                      const id = hostIdentity(host);
                      return id.os ? (
                        <span title={id.evidence ? `From ${id.evidence}` : undefined}>
                          {id.os}
                          {!host.os_guess && <span className="text-muted-foreground"> (from banners)</span>}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">unknown</span>
                      );
                    })()}
                  </KV>
                  <KV label="State changes">
                    {host.state_transitions} transitions, {host.consecutive_misses} consecutive misses
                  </KV>
                  {host.liveness && (
                    <div className="col-span-2">
                      <KV label="Still alive? (Bayesian estimate)">
                        <span title={host.liveness.model}>
                          <span className="font-mono tabular-nums">
                            {Math.round(host.liveness.p_alive * 100)}%
                          </span>{' '}
                          <span className="text-muted-foreground">
                            (marked INACTIVE below {Math.round(host.liveness.threshold * 100)}%
                            {host.liveness.streak_misses > 0
                              ? `, ${host.liveness.streak_misses} missed scans in the ${host.liveness.slot} window`
                              : `, answering in the ${host.liveness.slot} window`}
                            )
                          </span>
                        </span>
                      </KV>
                    </div>
                  )}
                </div>

                {(host.interesting_factors?.length || 0) > 0 && (
                  <div className="space-y-2">
                    <SectionTitle>Why this score</SectionTitle>
                    <div className="divide-y divide-border border border-border bg-card">
                      {host.interesting_factors!.map((f, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                          <span className="text-foreground">{translateFactor(f.reason)}</span>
                          <span className="font-mono text-muted-foreground tabular-nums">+{f.points}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(host.recent_changes?.length || 0) > 0 && (
                  <div className="space-y-2">
                    <SectionTitle>Recent changes</SectionTitle>
                    <div className="divide-y divide-border border border-border bg-card">
                      {host.recent_changes!.map((ch) => (
                        <div key={ch.id} className="flex items-start justify-between gap-3 px-3 py-2.5 text-xs">
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5 text-foreground">
                              {ch.is_time_anomaly && (
                                <RiAlertLine className="size-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
                              )}
                              {eolLabel(ch.summary)}
                            </div>
                            <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                              {ch.event_type}{ch.time_slot ? ` · slot ${ch.time_slot}` : ''} · {formatDateTime(ch.created_at)}
                            </div>
                          </div>
                          <div className="flex shrink-0 gap-1">
                            {ch.is_expected_schedule && <Pill title="Matches the host's usual schedule">Scheduled</Pill>}
                            {ch.is_time_anomaly && <Pill tone="warning" title="Outside the host's usual time window">Off-hours</Pill>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>

              {/* ===== TIMELINE ===== */}
              <TabsContent value="timeline" className="p-6">
                <HostTimeline hostId={host.id} />
              </TabsContent>

              {/* ===== HEATMAP ===== */}
              <TabsContent value="heatmap" className="space-y-6 p-6">
                <div className="space-y-3">
                  <SectionTitle>Availability by time of day</SectionTitle>
                  <div className="grid grid-cols-2 border-t border-l border-border sm:grid-cols-4">
                    {heatmapSlots.map((slot) => {
                      const pct = Math.round((slot.ratio || 0) * 100);
                      const mix = slot.total === 0 ? 0 : Math.round(6 + pct * 0.5);
                      return (
                        <div
                          key={slot.slot}
                          className={cn(
                            'border-r border-b border-border p-4 text-center',
                            slot.total === 0 && 'bg-muted/40'
                          )}
                          style={
                            slot.total > 0
                              ? { background: `color-mix(in oklch, var(--primary) ${mix}%, transparent)` }
                              : undefined
                          }
                        >
                          <div className="font-mono text-[11px] text-muted-foreground">{slot.slot}</div>
                          <div className="mt-1 font-heading text-2xl font-semibold text-foreground tabular-nums">
                            {slot.total > 0 ? `${pct}%` : 'n/a'}
                          </div>
                          <div className="mt-1 font-mono text-[11px] text-muted-foreground tabular-nums">
                            {slot.seen}/{slot.total}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="flex items-center justify-between gap-4 border border-border bg-card px-4 py-3 text-xs">
                  <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                    Stability
                  </span>
                  <div className="flex items-center gap-3">
                    <div className="h-1 w-40 bg-muted">
                      <div
                        className={cn('h-full', scoreBarColor(100 - host.stability_score))}
                        style={{ width: `${host.stability_score}%` }}
                      />
                    </div>
                    <span className="w-10 text-right font-mono text-foreground tabular-nums">
                      {host.stability_score}%
                    </span>
                  </div>
                </div>
              </TabsContent>

              {/* ===== OVERRIDES ===== */}
              <TabsContent value="overview" className="space-y-5 p-6">
                <TriageEditor
                  status={host.triage_status}
                  triage={host.triage}
                  workflow={false}
                  canWrite={canWrite}
                  onSave={handleSaveHostTriage}
                />
                <form onSubmit={handleSaveHostOverrides} className="space-y-5">
                  {!canWrite && (
                    <Notice icon={RiLockLine}>
                      Read only · <span className="font-mono">assets:write</span>
                    </Notice>
                  )}

                  <div className="border border-border bg-card px-4 py-1">
                    {(
                      [
                        {
                          field: 'hostname',
                          label: 'Hostname',
                          value: hostname,
                          setValue: setHostname,
                          placeholder: 'usos-test.agh.edu.pl',
                        },
                        {
                          field: 'owner',
                          label: 'Owner',
                          value: owner,
                          setValue: setOwner,
                          placeholder: 'WIET / CBI AGH',
                        },
                      ] as const
                    ).map((f) => (
                      <OverrideRow
                        key={f.field}
                        label={f.label}
                        scanner={scannerSawHost(f.field)}
                        lock={
                          <LockToggle
                            locked={isHostFieldLocked(f.field)}
                            canUnlock={canWrite}
                            disabled={savingHost}
                            onUnlock={() => handleUnlockHostField(f.field)}
                          />
                        }
                      >
                        <Input
                          disabled={!canWrite}
                          value={f.value}
                          onChange={(e) => f.setValue(e.target.value)}
                          placeholder={f.placeholder}
                        />
                      </OverrideRow>
                    ))}

                    <OverrideRow
                      label="Environment"
                      scanner={scannerSawHost('environment')}
                      lock={
                        <LockToggle
                          locked={isHostFieldLocked('environment')}
                          canUnlock={canWrite}
                          disabled={savingHost}
                          onUnlock={() => handleUnlockHostField('environment')}
                        />
                      }
                    >
                      <SimpleSelect
                        disabled={!canWrite}
                        value={environment === '' ? ENV_NONE : environment}
                        onValueChange={(v) => setEnvironment(v === ENV_NONE ? '' : v)}
                        options={
                          environment && !ENV_OPTIONS.some((o) => o.value === environment)
                            ? [...ENV_OPTIONS, { value: environment, label: environment }]
                            : ENV_OPTIONS
                        }
                      />
                    </OverrideRow>

                    <OverrideRow
                      label="Lifecycle"
                      scanner={scannerSawHost('lifecycle_state')}
                      lock={
                        <LockToggle
                          locked={isHostFieldLocked('lifecycle_state')}
                          canUnlock={canWrite}
                          disabled={savingHost}
                          onUnlock={() => handleUnlockHostField('lifecycle_state')}
                        />
                      }
                    >
                      <SimpleSelect
                        disabled={!canWrite}
                        value={lifecycleState}
                        onValueChange={setLifecycleState}
                        options={LIFECYCLE_OPTIONS}
                      />
                    </OverrideRow>

                    <OverrideRow
                      label="Tags"
                      lock={
                        <LockToggle
                          locked={isHostFieldLocked('tags')}
                          canUnlock={canWrite}
                          disabled={savingHost}
                          onUnlock={() => handleUnlockHostField('tags')}
                        />
                      }
                    >
                      <Input
                        disabled={!canWrite}
                        value={tagsInput}
                        onChange={(e) => setTagsInput(e.target.value)}
                        placeholder="critical, agh-usos"
                      />
                    </OverrideRow>

                    <OverrideRow
                      label="Notes"
                      lock={
                        <LockToggle
                          locked={isHostFieldLocked('notes')}
                          canUnlock={canWrite}
                          disabled={savingHost}
                          onUnlock={() => handleUnlockHostField('notes')}
                        />
                      }
                    >
                      <Textarea
                        rows={4}
                        disabled={!canWrite}
                        value={notes}
                        onChange={(e) => setNotes(e.target.value)}
                        placeholder="Context for other analysts (stored encrypted)"
                      />
                    </OverrideRow>
                  </div>

                  {canWrite && (
                    <div className="flex justify-end">
                      <Button type="submit" disabled={savingHost}>
                        <RiSaveLine data-icon="inline-start" />
                        {savingHost ? 'Saving…' : 'Save and lock'}
                      </Button>
                    </div>
                  )}
                </form>
              </TabsContent>
            </div>
          </Tabs>
        )}
      </SheetContent>
    </Sheet>
  );
}
