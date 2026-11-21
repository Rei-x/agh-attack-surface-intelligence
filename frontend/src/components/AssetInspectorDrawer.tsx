import React, { useEffect, useState } from 'react';
import {
  RiAlertLine,
  RiArrowDownSLine,
  RiArrowRightSLine,
  RiHistoryLine,
  RiLockLine,
  RiLockUnlockLine,
  RiSaveLine,
  RiSendPlaneLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import {
  formatDateTime,
  formatRelativeTime,
  lifecycleMeta,
  scoreBarColor,
  scoreColor,
} from '@/lib/format';
import { cn } from '@/lib/utils';
import { Empty, Notice, Pill, SectionTitle, SimpleSelect } from '@/components/common';
import { ServiceLogoFor } from '@/components/ServiceLogo';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { Host, Service, ServiceObservation, TimeSlotStat } from '@/types/api';

interface Props {
  hostId: string | null;
  onClose: () => void;
  onUpdated?: () => void;
}

const DEFAULT_SLOTS = ['00-06', '06-12', '12-18', '18-24'];

const ENV_NONE = '__none__';
const ENV_OPTIONS = [
  { value: ENV_NONE, label: 'Nieokreślone' },
  { value: 'prod', label: 'prod' },
  { value: 'staging', label: 'staging' },
  { value: 'dev', label: 'dev' },
  { value: 'test', label: 'test' },
];

const LIFECYCLE_OPTIONS = ['NEW', 'ACTIVE', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'].map(
  (s) => ({ value: s, label: s })
);

const TRIAGE_OPTIONS = [
  { value: 'new', label: 'new' },
  { value: 'triaged', label: 'triaged' },
  { value: 'accepted_risk', label: 'accepted_risk' },
  { value: 'false_positive', label: 'false_positive' },
];

type TabId = 'services' | 'overview' | 'heatmap' | 'summary';

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
        title="Wartość ze skanera"
      >
        <RiLockUnlockLine className="size-3.5" />
      </span>
    );
  }
  if (!canUnlock) {
    return (
      <span
        className="inline-flex size-7 items-center justify-center text-violet-600 dark:text-violet-400"
        title="Zablokowane"
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
            aria-label="Odblokuj"
            className="text-violet-600 hover:text-foreground dark:text-violet-400"
          />
        }
      >
        <RiLockLine />
      </TooltipTrigger>
      <TooltipContent>Odblokuj</TooltipContent>
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
            Skaner: {scanner}
          </div>
        )}
      </div>
      <div className="pt-1.5">{lock}</div>
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

  const loadHost = async (id: string) => {
    setLoading(true);
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
        setExpandedServiceId(h.services[0].id);
      }
    } catch (err) {
      toast.error('Błąd ładowania hosta', (err as Error).message);
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
        toast.info('Brak zmian');
        return;
      }

      const updated = await api.patchHostOverrides(host.id, payload);
      setHost(updated);
      toast.success('Zapisano overrides');
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd zapisu', (err as Error).message);
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
      toast.success('Odblokowano', field);
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd odblokowania', (err as Error).message);
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
      if (svcForm.triage_status !== (svc.triage_status || 'new'))
        payload.triage_status = svcForm.triage_status;
      const tags = svcForm.tags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      if (tags.join(',') !== (svc.tags || []).join(',')) payload.tags = tags;
      if (svcForm.notes !== (svc.notes || '')) payload.notes = svcForm.notes;

      await api.patchServiceOverrides(svc.id, payload);
      toast.success('Zapisano overrides usługi');
      setEditingServiceId(null);
      if (host) await loadHost(host.id);
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd zapisu', (err as Error).message);
    } finally {
      setSavingSvc(false);
    }
  };

  const handleUnlockServiceField = async (svcId: string, field: string) => {
    try {
      await api.patchServiceOverrides(svcId, { unlock_fields: [field] });
      toast.success('Odblokowano', field);
      if (host) await loadHost(host.id);
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd odblokowania', (err as Error).message);
    }
  };

  const handleLoadObservations = async (svcId: string) => {
    if (obsByService[svcId]) return;
    try {
      const list = await api.getServiceObservations(svcId);
      setObsByService((prev) => ({ ...prev, [svcId]: list }));
    } catch (err) {
      toast.error('Błąd pobierania historii', (err as Error).message);
    }
  };

  const handlePushServiceToDD = async (svc: Service) => {
    setPushingDD(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success('Wysłano do DefectDojo', `${host?.ip}:${svc.port}`);
    } catch (err) {
      toast.error('Błąd DefectDojo', (err as Error).message);
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
            <SheetTitle className="text-sm text-muted-foreground">Ładowanie…</SheetTitle>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <SheetTitle className="font-mono text-lg tracking-normal normal-case">
                  {host.ip}
                </SheetTitle>
                <Pill className={lc.badge} dot>
                  {lc.label}
                </Pill>
                <Pill className={cn('font-mono tabular-nums', scoreColor(host.interestingness))}>
                  Score {host.interestingness}
                </Pill>
                {(host.locked_fields?.length || 0) > 0 && (
                  <Pill tone="violet">
                    <RiLockLine className="size-3" />
                    {host.locked_fields!.length}
                  </Pill>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {host.hostname && <span className="font-mono text-foreground">{host.hostname}</span>}
                <span>
                  Stabilność <span className="font-mono text-foreground">{host.stability_score}%</span>
                </span>
                <span>
                  Skany{' '}
                  <span className="font-mono text-foreground">
                    {host.total_scans_seen}/{host.total_scans_checked}
                  </span>
                </span>
                <span>{formatRelativeTime(host.last_seen)}</span>
              </div>
            </>
          )}
        </SheetHeader>

        {!ready || !host ? (
          <Empty className="flex-1">Ładowanie…</Empty>
        ) : (
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as TabId)}
            className="min-h-0 flex-1 gap-0"
          >
            <div className="border-b border-border px-6">
              <TabsList variant="line" className="-mb-px">
                <TabsTrigger value="services">
                  Usługi{' '}
                  <span className="font-mono text-muted-foreground tabular-nums">
                    {host.services?.length || 0}
                  </span>
                </TabsTrigger>
                <TabsTrigger value="summary">Przegląd</TabsTrigger>
                <TabsTrigger value="heatmap">Heatmapa</TabsTrigger>
                <TabsTrigger value="overview">Overrides</TabsTrigger>
              </TabsList>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto">
              {/* ===== SERVICES: Evidence + Confidence ===== */}
              <TabsContent value="services" className="p-6">
                {(host.services || []).length === 0 ? (
                  <Empty>Brak usług</Empty>
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
                                {svc.is_admin_panel && <Pill tone="danger">Admin</Pill>}
                                {svc.is_staging_env && <Pill tone="warning">Staging/Dev</Pill>}
                                {svc.is_iot && <Pill tone="violet">IoT</Pill>}
                                {(svc.locked_fields?.length || 0) > 0 && (
                                  <RiLockLine className="size-3.5 text-violet-600 dark:text-violet-400" />
                                )}
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
                              {/* Action bar */}
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <Pill className="font-mono normal-case tracking-normal">
                                    triage: {svc.triage_status || 'new'}
                                  </Pill>
                                  {(svc.tags || []).map((t) => (
                                    <Pill key={t} className="font-normal normal-case tracking-normal">
                                      #{t}
                                    </Pill>
                                  ))}
                                </div>
                                <div className="flex items-center gap-2">
                                  {canWrite && (
                                    <Button
                                      type="button"
                                      variant="outline"
                                      size="xs"
                                      onClick={() =>
                                        isEditing ? setEditingServiceId(null) : startEditService(svc)
                                      }
                                    >
                                      <RiLockLine data-icon="inline-start" />
                                      {isEditing ? 'Anuluj' : 'Overrides'}
                                    </Button>
                                  )}
                                  {canPushDD && (
                                    <Button
                                      type="button"
                                      variant="outline"
                                      size="xs"
                                      disabled={pushingDD === svc.id}
                                      onClick={() => handlePushServiceToDD(svc)}
                                    >
                                      <RiSendPlaneLine data-icon="inline-start" />
                                      {pushingDD === svc.id ? 'Wysyłanie…' : 'DefectDojo'}
                                    </Button>
                                  )}
                                </div>
                              </div>

                              {/* Service override editor */}
                              {isEditing && canWrite && (
                                <div className="border border-border bg-card px-4 py-2">
                                  {[
                                    { key: 'service_name', label: 'Usługa' },
                                    { key: 'product', label: 'Produkt' },
                                    { key: 'version', label: 'Wersja' },
                                    { key: 'http_title', label: 'Tytuł HTTP' },
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
                                  <OverrideRow label="Triage">
                                    <SimpleSelect
                                      value={svcForm.triage_status}
                                      onValueChange={(v) =>
                                        setSvcForm((p) => ({ ...p, triage_status: v }))
                                      }
                                      options={TRIAGE_OPTIONS}
                                    />
                                  </OverrideRow>
                                  <OverrideRow label="Tagi">
                                    <Input
                                      value={svcForm.tags}
                                      onChange={(e) =>
                                        setSvcForm((p) => ({ ...p, tags: e.target.value }))
                                      }
                                      placeholder="tag1, tag2"
                                    />
                                  </OverrideRow>
                                  <OverrideRow label="Notatki">
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
                                      Anuluj
                                    </Button>
                                    <Button
                                      type="button"
                                      size="sm"
                                      disabled={savingSvc}
                                      onClick={() => handleSaveServiceOverrides(svc)}
                                    >
                                      <RiSaveLine data-icon="inline-start" />
                                      {savingSvc ? 'Zapisywanie…' : 'Zapisz'}
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
                                              <span className="text-xs font-medium text-foreground">
                                                {tech.name}
                                              </span>
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
                                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                                      <KV label="URL">
                                        {http.url || `${http.scheme || 'http'}://${host.ip}:${svc.port}`}
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
                                          Brakujące nagłówki
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
                                          Nagłówki
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
                                                <th className="px-2.5 py-1.5 text-left font-semibold">Nazwa</th>
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
                                                      {c.http_only ? 'TAK' : 'BRAK'}
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
                                                      {c.secure ? 'TAK' : 'BRAK'}
                                                    </span>
                                                  </td>
                                                  <td className="px-2.5 py-1.5 text-muted-foreground">
                                                    {c.same_site || '—'}
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
                                          Ścieżki (GET/HEAD)
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
                                            <Pill tone="danger">Wygasły</Pill>
                                          ) : (
                                            <Pill
                                              tone={tls.days_to_expiry <= 30 ? 'danger' : 'neutral'}
                                              className="font-mono"
                                            >
                                              {tls.days_to_expiry} dn.
                                            </Pill>
                                          )}
                                        </div>
                                      </div>
                                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                                        <KV label="Subject CN">{tls.subject_cn}</KV>
                                        <KV label="Issuer">{tls.issuer}</KV>
                                        <KV label="Ważny do">{formatDateTime(tls.not_after)}</KV>
                                        <KV label="SHA256">
                                          <span className="block truncate" title={tls.sha256}>
                                            {tls.sha256}
                                          </span>
                                        </KV>
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
                                  Historia obserwacji
                                </Button>
                                {obsList &&
                                  (obsList.length === 0 ? (
                                    <p className="text-xs text-muted-foreground">Brak historii</p>
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
                  <KV label="Pierwsze wykrycie">{formatDateTime(host.first_seen)}</KV>
                  <KV label="Ostatnia aktywność">{formatDateTime(host.last_seen)}</KV>
                  <KV label="OS">{host.os_guess || '—'}</KV>
                  <KV label="Histereza">
                    {host.state_transitions} przejść · {host.consecutive_misses} braków
                  </KV>
                </div>

                {(host.interesting_factors?.length || 0) > 0 && (
                  <div className="space-y-2">
                    <SectionTitle>Czynniki score</SectionTitle>
                    <div className="divide-y divide-border border border-border bg-card">
                      {host.interesting_factors!.map((f, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                          <span className="text-foreground">{f.reason}</span>
                          <span className="font-mono text-muted-foreground tabular-nums">+{f.points}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(host.recent_changes?.length || 0) > 0 && (
                  <div className="space-y-2">
                    <SectionTitle>Ostatnie zmiany</SectionTitle>
                    <div className="divide-y divide-border border border-border bg-card">
                      {host.recent_changes!.map((ch) => (
                        <div key={ch.id} className="flex items-start justify-between gap-3 px-3 py-2.5 text-xs">
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5 text-foreground">
                              {ch.is_time_anomaly && (
                                <RiAlertLine className="size-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
                              )}
                              {ch.summary}
                            </div>
                            <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                              {ch.event_type} · slot {ch.time_slot || '—'} · {formatDateTime(ch.created_at)}
                            </div>
                          </div>
                          <div className="flex shrink-0 gap-1">
                            {ch.is_expected_schedule && <Pill>Harmonogram</Pill>}
                            {ch.is_time_anomaly && <Pill tone="danger">Anomalia</Pill>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>

              {/* ===== HEATMAP ===== */}
              <TabsContent value="heatmap" className="space-y-6 p-6">
                <div className="space-y-3">
                  <SectionTitle>Dostępność wg pory dnia</SectionTitle>
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
                            {slot.total > 0 ? `${pct}%` : '—'}
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
                    Stabilność
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
              <TabsContent value="overview" className="p-6">
                <form onSubmit={handleSaveHostOverrides} className="space-y-5">
                  {!canWrite && (
                    <Notice icon={RiLockLine}>
                      Tylko odczyt · <span className="font-mono">assets:write</span>
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
                          label: 'Właściciel',
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
                      label="Środowisko"
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
                      label="Cykl życia"
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
                      label="Tagi"
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
                        placeholder="krytyczny, agh-usos"
                      />
                    </OverrideRow>

                    <OverrideRow
                      label="Notatki"
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
                        placeholder="AES-256-GCM at rest"
                      />
                    </OverrideRow>
                  </div>

                  {canWrite && (
                    <div className="flex justify-end">
                      <Button type="submit" disabled={savingHost}>
                        <RiSaveLine data-icon="inline-start" />
                        {savingHost ? 'Zapisywanie…' : 'Zapisz i zablokuj'}
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
