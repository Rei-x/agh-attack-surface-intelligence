import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Cookie,
  Cpu,
  ExternalLink,
  FileCode2,
  Globe,
  History,
  Lock,
  Save,
  Send,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  X,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import {
  formatDateTime,
  formatRelativeTime,
  lifecycleMeta,
  scoreBarColor,
  scoreColor,
} from '../lib/format';
import type { Host, Service, ServiceObservation, TimeSlotStat } from '../types/api';

interface Props {
  hostId: string | null;
  onClose: () => void;
  onUpdated?: () => void;
}

const DEFAULT_SLOTS = ['00-06', '06-12', '12-18', '18-24'];

export function AssetInspectorDrawer({ hostId, onClose, onUpdated }: Props) {
  const { can } = useAuth();
  const toast = useToast();

  const [host, setHost] = useState<Host | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'services' | 'heatmap'>('services');

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
      toast.error('Nie udało się załadować hosta', (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (hostId) {
      setExpandedServiceId(null);
      setEditingServiceId(null);
      loadHost(hostId);
    } else {
      setHost(null);
    }
  }, [hostId]);

  if (!hostId) return null;

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
        toast.info('Brak zmian do zapisania');
        return;
      }

      const updated = await api.patchHostOverrides(host.id, payload);
      setHost(updated);
      toast.success(
        'Zapisano nadpisania analityka',
        'Pola zostały zablokowane i będą zachowane przy kolejnych skanach.'
      );
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd zapisu nadpisań', (err as Error).message);
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
      toast.success('Odblokowano pole', `Pole "${field}" wróciło do wartości ze skanera.`);
      onUpdated?.();
    } catch (err) {
      toast.error('Nie udało się odblokować pola', (err as Error).message);
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
      toast.success('Zapisano nadpisania usługi', 'Nadpisania chronione przed kolejnymi skanami.');
      setEditingServiceId(null);
      if (host) await loadHost(host.id);
      onUpdated?.();
    } catch (err) {
      toast.error('Błąd zapisu usługi', (err as Error).message);
    } finally {
      setSavingSvc(false);
    }
  };

  const handleUnlockServiceField = async (svcId: string, field: string) => {
    try {
      await api.patchServiceOverrides(svcId, { unlock_fields: [field] });
      toast.success('Odblokowano pole usługi', field);
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
      toast.error('Nie udało się pobrać historii obserwacji', (err as Error).message);
    }
  };

  const handlePushServiceToDD = async (svc: Service) => {
    setPushingDD(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success(
        'Wysłano do DefectDojo v2',
        `Usługa ${host?.ip}:${svc.port} została wyeksportowana z dowodami.`
      );
    } catch (err) {
      toast.error('Błąd eksportu do DefectDojo', (err as Error).message);
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

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs" onClick={onClose} />
      <div className="relative z-10 w-full max-w-3xl bg-bg-secondary border-l border-border-strong h-full flex flex-col shadow-2xl">
        {/* Drawer Header */}
        <div className="p-5 border-b border-border-subtle flex items-start justify-between gap-4 bg-bg-card">
          {loading || !host ? (
            <div className="text-sm text-text-muted">Ładowanie szczegółów zasobu...</div>
          ) : (
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-bold font-mono text-text-primary">{host.ip}</h2>
                <span className={`text-xs font-mono px-2 py-0.5 rounded border ${lc.badge}`}>
                  {lc.label}
                </span>
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded border ${scoreColor(
                    host.interestingness
                  )}`}
                >
                  Score: {host.interestingness}/100
                </span>
                {(host.locked_fields?.length || 0) > 0 && (
                  <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/35">
                    <Lock className="h-3 w-3" />
                    {host.locked_fields!.length} pól nadpisanych
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted mt-1.5">
                {host.hostname && <span className="font-mono text-text-secondary">{host.hostname}</span>}
                <span>Stabilność: <strong className="text-text-primary">{host.stability_score}%</strong></span>
                <span>Widziany: {host.total_scans_seen}/{host.total_scans_checked} skanów</span>
                <span>Ostatnio: {formatRelativeTime(host.last_seen)}</span>
              </div>
              {(host.interesting_factors?.length || 0) > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {host.interesting_factors!.map((f, idx) => (
                    <span
                      key={idx}
                      className="text-[11px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/25"
                    >
                      +{f.points} {f.reason}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-hover"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Drawer Tabs */}
        <div className="px-5 border-b border-border-subtle flex items-center gap-1 bg-bg-card/60">
          {[
            { id: 'services', label: `Usługi i Evidence Receipts (${host?.services?.length || 0})` },
            { id: 'overview', label: 'Nadpisania (Overrides) i Metadane' },
            { id: 'heatmap', label: 'Mapa Dostępności (Time-of-Day)' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-text-muted hover:text-text-primary'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading || !host ? (
            <div className="py-12 text-center text-sm text-text-muted">Ładowanie...</div>
          ) : (
            <>
              {/* TAB 1: SERVICES & EVIDENCE RECEIPTS */}
              {activeTab === 'services' && (
                <div className="space-y-4">
                  {(host.services || []).length === 0 ? (
                    <div className="rounded-xl border border-border-subtle bg-bg-card p-8 text-center text-sm text-text-muted">
                      Brak wykrytych usług dla tego hosta.
                    </div>
                  ) : (
                    (host.services || []).map((svc) => {
                      const isOpen = expandedServiceId === svc.id;
                      const isEditing = editingServiceId === svc.id;
                      const http = svc.http;
                      const tls = http?.tls;
                      const obsList = obsByService[svc.id];

                      return (
                        <div
                          key={svc.id}
                          className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden"
                        >
                          {/* Service header */}
                          <div
                            onClick={() => setExpandedServiceId(isOpen ? null : svc.id)}
                            className="p-4 flex items-center justify-between gap-3 cursor-pointer hover:bg-bg-hover/50 transition-colors"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-sm font-bold text-cyan-400">
                                  {svc.port}/{svc.protocol}
                                </span>
                                <span className="text-sm font-semibold text-text-primary">
                                  {svc.service_name || 'unknown'}
                                </span>
                                {(svc.product || svc.version) && (
                                  <span className="text-xs font-mono text-text-secondary">
                                    {[svc.product, svc.version].filter(Boolean).join(' ')}
                                  </span>
                                )}
                                {svc.is_admin_panel && (
                                  <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/35">
                                    ADMIN PANEL
                                  </span>
                                )}
                                {svc.is_staging_env && (
                                  <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/35">
                                    STAGING / DEV
                                  </span>
                                )}
                                {svc.is_iot && (
                                  <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/35">
                                    IoT
                                  </span>
                                )}
                                {(svc.locked_fields?.length || 0) > 0 && (
                                  <Lock className="h-3.5 w-3.5 text-violet-400" />
                                )}
                              </div>
                              {http?.title && (
                                <p className="text-xs text-text-muted mt-1 truncate">
                                  HTTP {http.status_code} · {http.title}
                                </p>
                              )}
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span
                                className={`text-xs font-mono px-2 py-0.5 rounded border ${scoreColor(
                                  svc.interestingness
                                )}`}
                              >
                                {svc.interestingness}
                              </span>
                              {isOpen ? (
                                <ChevronUp className="h-4 w-4 text-text-muted" />
                              ) : (
                                <ChevronDown className="h-4 w-4 text-text-muted" />
                              )}
                            </div>
                          </div>

                          {/* Service expanded details */}
                          {isOpen && (
                            <div className="border-t border-border-subtle p-4 space-y-5 bg-bg-primary/40">
                              {/* Quick action bar */}
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-bg-elevated border border-border-subtle text-text-secondary">
                                    Triage: {svc.triage_status || 'new'}
                                  </span>
                                  {(svc.tags || []).map((t) => (
                                    <span
                                      key={t}
                                      className="text-[11px] px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/25"
                                    >
                                      #{t}
                                    </span>
                                  ))}
                                </div>

                                <div className="flex items-center gap-2">
                                  {canWrite && (
                                    <button
                                      type="button"
                                      onClick={() =>
                                        isEditing ? setEditingServiceId(null) : startEditService(svc)
                                      }
                                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-primary"
                                    >
                                      <Lock className="h-3 w-3 text-violet-400" />
                                      {isEditing ? 'Anuluj edycję' : 'Nadpisz pola'}
                                    </button>
                                  )}
                                  {canPushDD && (
                                    <button
                                      type="button"
                                      disabled={pushingDD === svc.id}
                                      onClick={() => handlePushServiceToDD(svc)}
                                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 hover:bg-cyan-500/25 disabled:opacity-50"
                                    >
                                      <Send className="h-3 w-3" />
                                      {pushingDD === svc.id
                                        ? 'Wysyłanie...'
                                        : 'Wyślij do DefectDojo'}
                                    </button>
                                  )}
                                </div>
                              </div>

                              {/* Inline Service Override Editor */}
                              {isEditing && canWrite && (
                                <div className="rounded-lg border border-violet-500/35 bg-violet-500/5 p-3.5 space-y-3">
                                  <div className="text-xs font-semibold text-violet-300 flex items-center gap-1.5">
                                    <Lock className="h-3.5 w-3.5" />
                                    Nadpisania usługi (chronione przed kolejnymi skanami)
                                  </div>
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                                    {[
                                      { key: 'service_name', label: 'Nazwa usługi' },
                                      { key: 'product', label: 'Produkt' },
                                      { key: 'version', label: 'Wersja' },
                                      { key: 'http_title', label: 'Tytuł HTTP' },
                                    ].map((f) => {
                                      const locked = (svc.locked_fields || []).includes(f.key);
                                      const saw = svc.scanner_observed?.[f.key];
                                      return (
                                        <div key={f.key}>
                                          <div className="flex items-center justify-between mb-1">
                                            <label className="text-text-secondary font-medium flex items-center gap-1">
                                              {f.label}
                                              {locked && <Lock className="h-3 w-3 text-violet-400" />}
                                            </label>
                                            {locked && (
                                              <button
                                                type="button"
                                                onClick={() => handleUnlockServiceField(svc.id, f.key)}
                                                className="text-[10px] text-amber-400 hover:underline flex items-center gap-0.5"
                                              >
                                                <Unlock className="h-2.5 w-2.5" /> Odblokuj
                                              </button>
                                            )}
                                          </div>
                                          <input
                                            type="text"
                                            value={svcForm[f.key as keyof typeof svcForm]}
                                            onChange={(e) =>
                                              setSvcForm((prev) => ({
                                                ...prev,
                                                [f.key]: e.target.value,
                                              }))
                                            }
                                            className="w-full rounded-md border border-border-subtle bg-bg-card px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-cyan-500"
                                          />
                                          {saw !== undefined && saw !== null && saw !== '' && (
                                            <div className="text-[10px] text-amber-400 mt-0.5 font-mono">
                                              Skaner widzi: {String(saw)}
                                            </div>
                                          )}
                                        </div>
                                      );
                                    })}

                                    <div>
                                      <label className="block text-text-secondary font-medium mb-1">
                                        Status Triage
                                      </label>
                                      <select
                                        value={svcForm.triage_status}
                                        onChange={(e) =>
                                          setSvcForm((p) => ({ ...p, triage_status: e.target.value }))
                                        }
                                        className="w-full rounded-md border border-border-subtle bg-bg-card px-2.5 py-1.5 text-xs text-text-primary"
                                      >
                                        <option value="new">Nowy (new)</option>
                                        <option value="triaged">Zweryfikowany (triaged)</option>
                                        <option value="accepted_risk">Zaakceptowane ryzyko</option>
                                        <option value="false_positive">False positive</option>
                                      </select>
                                    </div>

                                    <div>
                                      <label className="block text-text-secondary font-medium mb-1">
                                        Tagi (po przecinku)
                                      </label>
                                      <input
                                        type="text"
                                        value={svcForm.tags}
                                        onChange={(e) =>
                                          setSvcForm((p) => ({ ...p, tags: e.target.value }))
                                        }
                                        className="w-full rounded-md border border-border-subtle bg-bg-card px-2.5 py-1.5 text-xs text-text-primary"
                                      />
                                    </div>
                                  </div>

                                  <div>
                                    <label className="block text-xs text-text-secondary font-medium mb-1">
                                      Notatki analityka
                                    </label>
                                    <textarea
                                      rows={2}
                                      value={svcForm.notes}
                                      onChange={(e) =>
                                        setSvcForm((p) => ({ ...p, notes: e.target.value }))
                                      }
                                      className="w-full rounded-md border border-border-subtle bg-bg-card px-2.5 py-1.5 text-xs text-text-primary"
                                    />
                                  </div>

                                  <div className="flex justify-end gap-2">
                                    <button
                                      type="button"
                                      onClick={() => setEditingServiceId(null)}
                                      className="px-3 py-1.5 rounded-md text-xs text-text-muted hover:text-text-primary"
                                    >
                                      Anuluj
                                    </button>
                                    <button
                                      type="button"
                                      disabled={savingSvc}
                                      onClick={() => handleSaveServiceOverrides(svc)}
                                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-violet-600 hover:bg-violet-500 text-white disabled:opacity-50"
                                    >
                                      <Save className="h-3.5 w-3.5" />
                                      {savingSvc ? 'Zapisywanie...' : 'Zapisz nadpisania'}
                                    </button>
                                  </div>
                                </div>
                              )}

                              {/* Detected Technologies with Noisy-OR Confidence */}
                              {(svc.technologies?.length || 0) > 0 && (
                                <div className="space-y-2">
                                  <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
                                    <Cpu className="h-3.5 w-3.5 text-cyan-400" />
                                    Wykryte Technologie (Noisy-OR Confidence)
                                  </h4>
                                  <div className="space-y-2">
                                    {svc.technologies!.map((tech, idx) => {
                                      const techKey = `${svc.id}-${idx}`;
                                      const techOpen = expandedTechKey === techKey;
                                      return (
                                        <div
                                          key={techKey}
                                          className="rounded-lg border border-border-subtle bg-bg-card p-2.5"
                                        >
                                          <div
                                            onClick={() =>
                                              setExpandedTechKey(techOpen ? null : techKey)
                                            }
                                            className="flex items-center justify-between gap-3 cursor-pointer"
                                          >
                                            <div className="flex items-center gap-2 min-w-0">
                                              <span className="text-xs font-semibold text-text-primary">
                                                {tech.name}
                                              </span>
                                              {tech.version && (
                                                <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-bg-elevated text-cyan-400">
                                                  v{tech.version}
                                                </span>
                                              )}
                                              <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-bg-elevated text-text-muted">
                                                {tech.category}
                                              </span>
                                            </div>
                                            <div className="flex items-center gap-2.5 shrink-0">
                                              <div className="w-24 h-1.5 rounded-full bg-bg-elevated overflow-hidden">
                                                <div
                                                  className="h-full bg-cyan-400"
                                                  style={{ width: `${tech.confidence}%` }}
                                                />
                                              </div>
                                              <span className="text-xs font-mono font-semibold text-cyan-400 w-10 text-right">
                                                {tech.confidence}%
                                              </span>
                                            </div>
                                          </div>
                                          {techOpen && (tech.evidence?.length || 0) > 0 && (
                                            <div className="mt-2.5 pt-2 border-t border-border-subtle space-y-1">
                                              {tech.evidence!.map((ev, eIdx) => (
                                                <div
                                                  key={eIdx}
                                                  className="flex items-center justify-between gap-2 text-[11px] font-mono"
                                                >
                                                  <span className="text-text-secondary">
                                                    <span className="text-cyan-400">[{ev.signal_type}]</span>{' '}
                                                    {ev.detail}
                                                  </span>
                                                  <span className="text-text-muted shrink-0">
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

                              {/* HTTP Evidence Receipt */}
                              {http && (
                                <div className="space-y-3">
                                  <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
                                    <Globe className="h-3.5 w-3.5 text-cyan-400" />
                                    HTTP Evidence Receipt
                                  </h4>

                                  <div className="rounded-lg border border-border-subtle bg-bg-card p-3 space-y-2.5 text-xs">
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                      <div>
                                        <span className="text-text-muted">URL: </span>
                                        <span className="font-mono text-text-primary break-all">
                                          {http.url || `${http.scheme || 'http'}://${host.ip}:${svc.port}`}
                                        </span>
                                      </div>
                                      <div>
                                        <span className="text-text-muted">Status / Czas: </span>
                                        <span className="font-mono text-cyan-400">
                                          {http.status_code}
                                        </span>
                                        {http.response_time_ms ? (
                                          <span className="font-mono text-text-muted">
                                            {' '}
                                            ({http.response_time_ms} ms)
                                          </span>
                                        ) : null}
                                      </div>
                                      {http.server_header && (
                                        <div>
                                          <span className="text-text-muted">Server: </span>
                                          <span className="font-mono text-text-primary">
                                            {http.server_header}
                                          </span>
                                        </div>
                                      )}
                                      {http.meta_generator && (
                                        <div>
                                          <span className="text-text-muted">Meta Generator: </span>
                                          <span className="font-mono text-text-primary">
                                            {http.meta_generator}
                                          </span>
                                        </div>
                                      )}
                                    </div>

                                    {/* Favicon MMH3 & SHA256 */}
                                    {(http.favicon_mmh3 || http.favicon_sha256) && (
                                      <div className="flex flex-wrap gap-2 pt-1">
                                        {http.favicon_mmh3 && (
                                          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                            Favicon MMH3: {http.favicon_mmh3}
                                          </span>
                                        )}
                                        {http.favicon_sha256 && (
                                          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-bg-elevated text-text-muted border border-border-subtle truncate max-w-full">
                                            SHA256: {http.favicon_sha256.slice(0, 24)}…
                                          </span>
                                        )}
                                      </div>
                                    )}

                                    {/* Redirect Chain */}
                                    {(http.redirect_chain?.length || 0) > 0 && (
                                      <div className="pt-2 border-t border-border-subtle">
                                        <div className="text-[11px] text-text-muted mb-1">
                                          Łańcuch przekierowań:
                                        </div>
                                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                                          {http.redirect_chain!.map((hop, i) => (
                                            <span
                                              key={i}
                                              className="px-2 py-0.5 rounded bg-bg-elevated border border-border-subtle text-text-secondary"
                                            >
                                              {hop.status_code} → {hop.url}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* Missing Security Headers */}
                                    {(http.missing_sec_headers?.length || 0) > 0 && (
                                      <div className="pt-2 border-t border-border-subtle">
                                        <div className="text-[11px] text-rose-400 font-medium mb-1.5 flex items-center gap-1">
                                          <ShieldAlert className="h-3.5 w-3.5" />
                                          Brakujące nagłówki bezpieczeństwa:
                                        </div>
                                        <div className="flex flex-wrap gap-1.5">
                                          {http.missing_sec_headers!.map((h) => (
                                            <span
                                              key={h}
                                              className="font-mono text-[11px] px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30"
                                            >
                                              {h}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* Headers Table */}
                                    {http.headers && Object.keys(http.headers).length > 0 && (
                                      <div className="pt-2 border-t border-border-subtle">
                                        <div className="text-[11px] text-text-muted mb-1.5">
                                          Nagłówki HTTP:
                                        </div>
                                        <div className="max-h-36 overflow-y-auto rounded border border-border-subtle bg-bg-primary/60 divide-y divide-border-subtle/50 font-mono text-[11px]">
                                          {Object.entries(http.headers).map(([k, v]) => (
                                            <div key={k} className="px-2.5 py-1 flex gap-2">
                                              <span className="text-cyan-400 shrink-0">{k}:</span>
                                              <span className="text-text-secondary break-all">
                                                {v}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* Cookies Table */}
                                    {(http.cookies?.length || 0) > 0 && (
                                      <div className="pt-2 border-t border-border-subtle">
                                        <div className="text-[11px] text-text-muted mb-1.5 flex items-center gap-1">
                                          <Cookie className="h-3.5 w-3.5 text-amber-400" />
                                          Ciasteczka ({http.cookies!.length}):
                                        </div>
                                        <div className="overflow-x-auto rounded border border-border-subtle">
                                          <table className="w-full text-[11px] font-mono">
                                            <thead className="bg-bg-elevated text-text-muted">
                                              <tr>
                                                <th className="text-left px-2 py-1">Nazwa</th>
                                                <th className="text-left px-2 py-1">HttpOnly</th>
                                                <th className="text-left px-2 py-1">Secure</th>
                                                <th className="text-left px-2 py-1">SameSite</th>
                                              </tr>
                                            </thead>
                                            <tbody className="divide-y divide-border-subtle/60">
                                              {http.cookies!.map((c, ci) => (
                                                <tr key={ci}>
                                                  <td className="px-2 py-1 text-text-primary">
                                                    {c.name}
                                                  </td>
                                                  <td className="px-2 py-1">
                                                    <span
                                                      className={
                                                        c.http_only
                                                          ? 'text-emerald-400'
                                                          : 'text-rose-400 font-semibold'
                                                      }
                                                    >
                                                      {c.http_only ? 'TAK' : 'BRAK'}
                                                    </span>
                                                  </td>
                                                  <td className="px-2 py-1">
                                                    <span
                                                      className={
                                                        c.secure
                                                          ? 'text-emerald-400'
                                                          : 'text-rose-400 font-semibold'
                                                      }
                                                    >
                                                      {c.secure ? 'TAK' : 'BRAK'}
                                                    </span>
                                                  </td>
                                                  <td className="px-2 py-1 text-text-secondary">
                                                    {c.same_site || '—'}
                                                  </td>
                                                </tr>
                                              ))}
                                            </tbody>
                                          </table>
                                        </div>
                                      </div>
                                    )}

                                    {/* Safe Path Hits */}
                                    {(http.safe_path_hits?.length || 0) > 0 && (
                                      <div className="pt-2 border-t border-border-subtle">
                                        <div className="text-[11px] text-text-muted mb-1.5">
                                          Wykryte ścieżki (tylko GET/HEAD):
                                        </div>
                                        <div className="space-y-1">
                                          {http.safe_path_hits!.map((hit, hi) => (
                                            <div
                                              key={hi}
                                              className="flex items-center justify-between gap-2 px-2 py-1 rounded bg-bg-elevated font-mono text-[11px]"
                                            >
                                              <span className="text-cyan-400">{hit.path}</span>
                                              <span className="text-text-secondary truncate">
                                                {hit.title || hit.snippet || ''}
                                              </span>
                                              <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 shrink-0">
                                                {hit.status_code}
                                              </span>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>

                                  {/* TLS Certificate Card */}
                                  {tls && (
                                    <div className="rounded-lg border border-border-subtle bg-bg-card p-3 space-y-2 text-xs">
                                      <div className="flex flex-wrap items-center justify-between gap-2">
                                        <span className="font-semibold text-text-primary flex items-center gap-1.5">
                                          <ShieldCheck className="h-4 w-4 text-emerald-400" />
                                          Certyfikat TLS ({tls.version})
                                        </span>
                                        <div className="flex items-center gap-1.5">
                                          {tls.is_self_signed && (
                                            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/35">
                                              SELF-SIGNED
                                            </span>
                                          )}
                                          {tls.is_expired ? (
                                            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/35">
                                              WYGASŁY
                                            </span>
                                          ) : (
                                            <span
                                              className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                                                tls.days_to_expiry <= 30
                                                  ? 'bg-rose-500/15 text-rose-400 border-rose-500/35'
                                                  : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                              }`}
                                            >
                                              Wygasa za {tls.days_to_expiry} dn.
                                            </span>
                                          )}
                                        </div>
                                      </div>

                                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 font-mono text-[11px]">
                                        <div>
                                          <span className="text-text-muted">Subject CN: </span>
                                          <span className="text-text-primary">{tls.subject_cn}</span>
                                        </div>
                                        <div>
                                          <span className="text-text-muted">Issuer: </span>
                                          <span className="text-text-primary">{tls.issuer}</span>
                                        </div>
                                        <div>
                                          <span className="text-text-muted">Ważny do: </span>
                                          <span className="text-text-secondary">
                                            {formatDateTime(tls.not_after)}
                                          </span>
                                        </div>
                                        <div className="truncate">
                                          <span className="text-text-muted">SHA256: </span>
                                          <span className="text-text-secondary">{tls.sha256}</span>
                                        </div>
                                      </div>

                                      {(tls.sans?.length || 0) > 0 && (
                                        <div className="flex flex-wrap gap-1 pt-1">
                                          {tls.sans!.map((san) => (
                                            <span
                                              key={san}
                                              className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-bg-elevated border border-border-subtle text-text-secondary"
                                            >
                                              {san}
                                            </span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* Banner if non-HTTP */}
                              {svc.banner && (
                                <div className="rounded-lg border border-border-subtle bg-bg-card p-3">
                                  <div className="text-[11px] text-text-muted mb-1 flex items-center gap-1">
                                    <FileCode2 className="h-3.5 w-3.5" /> Banner usługi
                                  </div>
                                  <pre className="font-mono text-[11px] text-text-secondary whitespace-pre-wrap break-all">
                                    {svc.banner}
                                  </pre>
                                </div>
                              )}

                              {/* Observation history button */}
                              <div>
                                <button
                                  type="button"
                                  onClick={() => handleLoadObservations(svc.id)}
                                  className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:underline"
                                >
                                  <History className="h-3.5 w-3.5" />
                                  Pokaż historię obserwacji (Evidence Receipts)
                                </button>
                                {obsList && (
                                  <div className="mt-2 space-y-1.5">
                                    {obsList.length === 0 ? (
                                      <p className="text-xs text-text-muted">
                                        Brak archiwalnych obserwacji.
                                      </p>
                                    ) : (
                                      obsList.map((o, idx) => (
                                        <div
                                          key={o.id || idx}
                                          className="p-2 rounded border border-border-subtle bg-bg-card text-[11px] font-mono flex items-center justify-between gap-2"
                                        >
                                          <span className="text-text-primary">
                                            {o.service_name || svc.service_name} {o.product || ''}{' '}
                                            {o.version || ''}
                                            {o.http?.title ? ` · "${o.http.title}"` : ''}
                                          </span>
                                          <span className="text-text-muted shrink-0">
                                            {formatDateTime(o.observed_at || o.created_at)}
                                          </span>
                                        </div>
                                      ))
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* TAB 2: HOST INLINE OVERRIDE EDITOR */}
              {activeTab === 'overview' && (
                <form onSubmit={handleSaveHostOverrides} className="space-y-4">
                  <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3 text-xs text-text-secondary flex items-start gap-2.5">
                    <Lock className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-text-primary">
                        Warstwa kuratorska (Preserved Analyst Overrides):
                      </strong>{' '}
                      Ręczne edycje działają niezależnie od statusu skanu i są trwale chronione
                      przed nadpisaniem przez kolejne skany. Gdy skaner wykryje inną wartość,
                      zobaczysz ją w etykiecie <em>„Skaner widzi”</em> z możliwością odblokowania.
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {[
                      {
                        field: 'hostname',
                        label: 'Hostname / Domena główna',
                        value: hostname,
                        setValue: setHostname,
                        placeholder: 'np. usos-test.agh.edu.pl',
                      },
                      {
                        field: 'owner',
                        label: 'Właściciel / Jednostka AGH',
                        value: owner,
                        setValue: setOwner,
                        placeholder: 'np. WIET / CBI AGH',
                      },
                    ].map((f) => {
                      const locked = isHostFieldLocked(f.field);
                      const saw = scannerSawHost(f.field);
                      return (
                        <div key={f.field}>
                          <div className="flex items-center justify-between mb-1">
                            <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                              {f.label}
                              {locked && (
                                <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/35">
                                  <Lock className="h-2.5 w-2.5" /> Zablokowane
                                </span>
                              )}
                            </label>
                            {locked && canWrite && (
                              <button
                                type="button"
                                onClick={() => handleUnlockHostField(f.field)}
                                className="text-[11px] text-amber-400 hover:underline inline-flex items-center gap-0.5"
                              >
                                <Unlock className="h-3 w-3" /> Odblokuj
                              </button>
                            )}
                          </div>
                          <input
                            type="text"
                            disabled={!canWrite}
                            value={f.value}
                            onChange={(e) => f.setValue(e.target.value)}
                            placeholder={f.placeholder}
                            className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-sm text-text-primary disabled:opacity-60 focus:outline-none focus:border-cyan-500"
                          />
                          {saw && (
                            <div className="mt-1 text-[11px] font-mono text-amber-400">
                              Skaner widzi: {saw}
                            </div>
                          )}
                        </div>
                      );
                    })}

                    {/* Environment */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                          Środowisko
                          {isHostFieldLocked('environment') && (
                            <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/35">
                              <Lock className="h-2.5 w-2.5" /> Zablokowane
                            </span>
                          )}
                        </label>
                        {isHostFieldLocked('environment') && canWrite && (
                          <button
                            type="button"
                            onClick={() => handleUnlockHostField('environment')}
                            className="text-[11px] text-amber-400 hover:underline inline-flex items-center gap-0.5"
                          >
                            <Unlock className="h-3 w-3" /> Odblokuj
                          </button>
                        )}
                      </div>
                      <select
                        disabled={!canWrite}
                        value={environment}
                        onChange={(e) => setEnvironment(e.target.value)}
                        className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-sm text-text-primary disabled:opacity-60"
                      >
                        <option value="">Nieokreślone</option>
                        <option value="prod">Produkcja (prod)</option>
                        <option value="staging">Staging (staging)</option>
                        <option value="dev">Deweloperskie (dev)</option>
                        <option value="test">Testowe (test)</option>
                      </select>
                      {scannerSawHost('environment') && (
                        <div className="mt-1 text-[11px] font-mono text-amber-400">
                          Skaner widzi: {scannerSawHost('environment')}
                        </div>
                      )}
                    </div>

                    {/* Lifecycle state */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                          Stan cyklu życia
                          {isHostFieldLocked('lifecycle_state') && (
                            <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/35">
                              <Lock className="h-2.5 w-2.5" /> Zablokowane
                            </span>
                          )}
                        </label>
                        {isHostFieldLocked('lifecycle_state') && canWrite && (
                          <button
                            type="button"
                            onClick={() => handleUnlockHostField('lifecycle_state')}
                            className="text-[11px] text-amber-400 hover:underline inline-flex items-center gap-0.5"
                          >
                            <Unlock className="h-3 w-3" /> Odblokuj
                          </button>
                        )}
                      </div>
                      <select
                        disabled={!canWrite}
                        value={lifecycleState}
                        onChange={(e) => setLifecycleState(e.target.value)}
                        className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-sm text-text-primary disabled:opacity-60"
                      >
                        <option value="NEW">NEW</option>
                        <option value="ACTIVE">ACTIVE</option>
                        <option value="INTERMITTENT">INTERMITTENT</option>
                        <option value="MISSING">MISSING</option>
                        <option value="INACTIVE">INACTIVE</option>
                        <option value="REACTIVATED">REACTIVATED</option>
                      </select>
                      {scannerSawHost('lifecycle_state') && (
                        <div className="mt-1 text-[11px] font-mono text-amber-400">
                          Skaner widzi: {scannerSawHost('lifecycle_state')}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Tags */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                        Tagi (oddzielone przecinkiem)
                        {isHostFieldLocked('tags') && (
                          <Lock className="h-3 w-3 text-violet-400" />
                        )}
                      </label>
                      {isHostFieldLocked('tags') && canWrite && (
                        <button
                          type="button"
                          onClick={() => handleUnlockHostField('tags')}
                          className="text-[11px] text-amber-400 hover:underline inline-flex items-center gap-0.5"
                        >
                          <Unlock className="h-3 w-3" /> Odblokuj
                        </button>
                      )}
                    </div>
                    <input
                      type="text"
                      disabled={!canWrite}
                      value={tagsInput}
                      onChange={(e) => setTagsInput(e.target.value)}
                      placeholder="np. krytyczny, agh-usos, do-weryfikacji"
                      className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-sm text-text-primary disabled:opacity-60"
                    />
                  </div>

                  {/* Notes */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                        Notatki analityka SOC (szyfrowane AES-256-GCM at rest)
                        {isHostFieldLocked('notes') && (
                          <Lock className="h-3 w-3 text-violet-400" />
                        )}
                      </label>
                      {isHostFieldLocked('notes') && canWrite && (
                        <button
                          type="button"
                          onClick={() => handleUnlockHostField('notes')}
                          className="text-[11px] text-amber-400 hover:underline inline-flex items-center gap-0.5"
                        >
                          <Unlock className="h-3 w-3" /> Odblokuj
                        </button>
                      )}
                    </div>
                    <textarea
                      rows={4}
                      disabled={!canWrite}
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Dodaj ustalenia, kontakt do administratora lub kontekst incydentu..."
                      className="w-full rounded-lg border border-border-subtle bg-bg-card px-3 py-2 text-sm text-text-primary disabled:opacity-60"
                    />
                  </div>

                  {canWrite ? (
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={savingHost}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                      >
                        <Save className="h-4 w-4" />
                        {savingHost ? 'Zapisywanie...' : 'Zapisz i zablokuj nadpisania'}
                      </button>
                    </div>
                  ) : (
                    <p className="text-xs text-text-muted italic">
                      Tryb tylko do odczytu — Twoja rola nie posiada uprawnienia{' '}
                      <span className="font-mono">assets:write</span>.
                    </p>
                  )}

                  {/* Technical metadata */}
                  <div className="rounded-lg border border-border-subtle bg-bg-card p-3.5 text-xs grid grid-cols-2 gap-3">
                    <div>
                      <span className="text-text-muted block">Pierwsze wykrycie</span>
                      <span className="font-mono text-text-primary">
                        {formatDateTime(host.first_seen)}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted block">Ostatnia aktywność</span>
                      <span className="font-mono text-text-primary">
                        {formatDateTime(host.last_seen)}
                      </span>
                    </div>
                    <div>
                      <span className="text-text-muted block">OS Fingerprint</span>
                      <span className="font-mono text-text-primary">{host.os_guess || '—'}</span>
                    </div>
                    <div>
                      <span className="text-text-muted block">Zmiany stanu (histereza)</span>
                      <span className="font-mono text-text-primary">
                        {host.state_transitions} przejść · {host.consecutive_misses} braków z rzędu
                      </span>
                    </div>
                  </div>
                </form>
              )}

              {/* TAB 3: TIME-OF-DAY AVAILABILITY HEATMAP */}
              {activeTab === 'heatmap' && (
                <div className="space-y-4">
                  <div className="rounded-xl border border-border-subtle bg-bg-card p-4">
                    <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                      <Clock className="h-4 w-4 text-cyan-400" />
                      Macierz Dostępności wg Pory Dnia (Time-of-Day Heatmap)
                    </h3>
                    <p className="text-xs text-text-muted mt-1">
                      Pozwala odróżnić przewidywany harmonogram wyłączania stacji roboczych /
                      laboratoriów (EXPECTED_OFF_HOURS) od anomalii pory dnia (TIME_ANOMALY).
                    </p>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
                      {heatmapSlots.map((slot) => {
                        const pct = Math.round((slot.ratio || 0) * 100);
                        const bgClass =
                          slot.total === 0
                            ? 'bg-bg-elevated border-border-subtle text-text-muted'
                            : pct >= 75
                              ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                              : pct >= 35
                                ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                                : 'bg-rose-500/20 border-rose-500/40 text-rose-300';

                        return (
                          <div
                            key={slot.slot}
                            className={`rounded-xl border p-3.5 text-center ${bgClass}`}
                          >
                            <div className="font-mono text-xs font-semibold opacity-90">
                              {slot.slot}
                            </div>
                            <div className="text-2xl font-bold font-mono mt-1">
                              {slot.total > 0 ? `${pct}%` : '—'}
                            </div>
                            <div className="text-[11px] font-mono opacity-80 mt-1">
                              {slot.seen} / {slot.total} skanów
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
                      <span className="text-text-muted">Wskaźnik stabilności hosta:</span>
                      <div className="flex items-center gap-2">
                        <div className="w-32 h-2 rounded-full bg-bg-elevated overflow-hidden">
                          <div
                            className={`h-full ${scoreBarColor(100 - host.stability_score)}`}
                            style={{ width: `${host.stability_score}%` }}
                          />
                        </div>
                        <span className="font-mono font-semibold text-text-primary">
                          {host.stability_score}%
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Recent host changes */}
                  {(host.recent_changes?.length || 0) > 0 && (
                    <div className="rounded-xl border border-border-subtle bg-bg-card p-4 space-y-2">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
                        Ostatnie zmiany i anomalie dla hosta
                      </h4>
                      {host.recent_changes!.map((ch) => (
                        <div
                          key={ch.id}
                          className="p-2.5 rounded-lg border border-border-subtle bg-bg-elevated flex items-start justify-between gap-2 text-xs"
                        >
                          <div>
                            <div className="font-medium text-text-primary flex items-center gap-1.5">
                              {ch.is_time_anomaly && (
                                <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                              )}
                              {ch.summary}
                            </div>
                            <div className="text-[11px] text-text-muted mt-0.5 font-mono">
                              {ch.event_type} · slot {ch.time_slot || '—'} ·{' '}
                              {formatDateTime(ch.created_at)}
                            </div>
                          </div>
                          {ch.is_expected_schedule && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-500/20 text-slate-300 shrink-0">
                              Harmonogram
                            </span>
                          )}
                          {ch.is_time_anomaly && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 shrink-0">
                              Anomalia pory dnia
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
