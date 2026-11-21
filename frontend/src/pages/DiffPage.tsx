import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeftRight,
  ArrowRight,
  CheckCircle2,
  Clock,
  GitCompare,
  MinusCircle,
  PlusCircle,
  RefreshCw,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import { formatDateTime, formatShortTime, severityMeta } from '../lib/format';
import { AssetInspectorDrawer } from '../components/AssetInspectorDrawer';
import type { ChangeEvent, ChangedServiceDiff, ScanDiffResponse, ScanRun } from '../types/api';

export function DiffPage() {
  const { can } = useAuth();
  const toast = useToast();

  const [scans, setScans] = useState<ScanRun[]>([]);
  const [fromId, setFromId] = useState('');
  const [toId, setToId] = useState('');
  const [diff, setDiff] = useState<ScanDiffResponse | null>(null);
  const [allChanges, setAllChanges] = useState<ChangeEvent[]>([]);
  const [anomalyOnly, setAnomalyOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [diffLoading, setDiffLoading] = useState(false);
  const [ackingId, setAckingId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);

  const canWrite = can(PERMISSIONS.ASSETS_WRITE);

  const loadInitial = useCallback(async () => {
    setLoading(true);
    try {
      const [scanList, changeList] = await Promise.all([
        api.listScans(),
        api.listChanges({ anomaly_only: anomalyOnly || undefined }),
      ]);
      setScans(scanList);
      setAllChanges(changeList);

      if (scanList.length >= 2 && !fromId && !toId) {
        // Default: second newest vs newest
        setFromId(scanList[1].id);
        setToId(scanList[0].id);
      } else if (scanList.length === 1 && !toId) {
        setFromId(scanList[0].id);
        setToId(scanList[0].id);
      }
    } catch (err) {
      toast.error('Błąd ładowania danych diff', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [anomalyOnly, fromId, toId, toast]);

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  const runDiff = useCallback(async () => {
    if (!fromId || !toId) return;
    setDiffLoading(true);
    try {
      const res = await api.diffScans(fromId, toId);
      setDiff(res);
    } catch (err) {
      toast.error('Nie udało się porównać skanów', (err as Error).message);
    } finally {
      setDiffLoading(false);
    }
  }, [fromId, toId, toast]);

  useEffect(() => {
    if (fromId && toId) {
      runDiff();
    }
  }, [fromId, toId, runDiff]);

  const handleAck = async (ch: ChangeEvent) => {
    setAckingId(ch.id);
    try {
      await api.acknowledgeChange(ch.id);
      toast.success('Potwierdzono zmianę', ch.summary);
      await Promise.all([runDiff(), loadInitial()]);
    } catch (err) {
      toast.error('Błąd potwierdzenia zmiany', (err as Error).message);
    } finally {
      setAckingId(null);
    }
  };

  const newHosts = diff?.new_hosts || [];
  const missingHosts = diff?.missing_hosts || [];
  const newServices = diff?.new_services || [];
  const closedServices = diff?.closed_services || [];
  const changedServices = diff?.changed_services || [];
  const timeAnomalies = diff?.time_anomalies || [];

  const renderBeforeAfter = (ch: { before?: Record<string, unknown>; after?: Record<string, unknown> }) => {
    const before = ch.before || {};
    const after = ch.after || {};
    const keys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)]));
    if (keys.length === 0) return null;

    return (
      <div className="mt-2.5 grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-mono">
        <div className="rounded-lg border border-rose-500/25 bg-rose-500/5 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-rose-400 font-semibold mb-1">
            Przed (Scan A)
          </div>
          {keys.map((k) => (
            <div key={k} className="break-all">
              <span className="text-text-muted">{k}: </span>
              <span className="text-rose-200">
                {before[k] !== undefined ? JSON.stringify(before[k]) : '—'}
              </span>
            </div>
          ))}
        </div>
        <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 p-2.5">
          <div className="text-[10px] uppercase tracking-wider text-emerald-400 font-semibold mb-1">
            Po (Scan B)
          </div>
          {keys.map((k) => (
            <div key={k} className="break-all">
              <span className="text-text-muted">{k}: </span>
              <span className="text-emerald-200">
                {after[k] !== undefined ? JSON.stringify(after[k]) : '—'}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <GitCompare className="h-5 w-5 text-cyan-400" />
            Porównanie Skanów i Zmiany w Czasie
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Analiza różnicowa Scan A → Scan B: nowe zasoby, znikające hosty, zmiany konfiguracji
            oraz anomalie pory dnia
          </p>
        </div>
      </div>

      {/* Scan A vs Scan B Selector */}
      <div className="rounded-xl border border-border-subtle bg-bg-card p-4 flex flex-col lg:flex-row lg:items-end gap-3">
        <div className="flex-1">
          <label className="block text-xs font-medium text-text-muted mb-1">
            Scan A (bazowy / wcześniejszy)
          </label>
          <select
            value={fromId}
            onChange={(e) => setFromId(e.target.value)}
            className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 text-xs text-text-primary"
          >
            <option value="">Wybierz skan bazowy...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.run_type}) · {formatShortTime(s.started_at)} · {s.active_hosts} hostów
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={() => {
            setFromId(toId);
            setToId(fromId);
          }}
          className="p-2 rounded-lg border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-text-secondary self-center lg:self-end"
          title="Zamień Scan A ↔ Scan B"
        >
          <ArrowLeftRight className="h-4 w-4" />
        </button>

        <div className="flex-1">
          <label className="block text-xs font-medium text-text-muted mb-1">
            Scan B (docelowy / późniejszy)
          </label>
          <select
            value={toId}
            onChange={(e) => setToId(e.target.value)}
            className="w-full rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 text-xs text-text-primary"
          >
            <option value="">Wybierz skan docelowy...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.run_type}) · {formatShortTime(s.started_at)} · {s.active_hosts} hostów
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          disabled={!fromId || !toId || diffLoading}
          onClick={runDiff}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${diffLoading ? 'animate-spin' : ''}`} />
          Porównaj
        </button>
      </div>

      {/* Diff Summary Cards */}
      {diff && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            {
              label: 'Nowe hosty',
              val: diff.summary?.new_hosts ?? newHosts.length,
              cls: 'text-emerald-400',
            },
            {
              label: 'Znikające hosty',
              val: diff.summary?.missing_hosts ?? missingHosts.length,
              cls: 'text-orange-400',
            },
            {
              label: 'Nowe usługi',
              val: diff.summary?.new_services ?? newServices.length,
              cls: 'text-cyan-400',
            },
            {
              label: 'Zamknięte usługi',
              val: diff.summary?.closed_services ?? closedServices.length,
              cls: 'text-slate-400',
            },
            {
              label: 'Zmienione usługi',
              val: diff.summary?.changed_services ?? changedServices.length,
              cls: 'text-amber-400',
            },
            {
              label: 'Anomalie pory dnia',
              val: diff.summary?.time_anomalies ?? timeAnomalies.length,
              cls: 'text-rose-400',
            },
          ].map((c) => (
            <div key={c.label} className="rounded-xl border border-border-subtle bg-bg-card p-3.5">
              <div className="text-[11px] text-text-muted">{c.label}</div>
              <div className={`text-2xl font-bold font-mono mt-1 ${c.cls}`}>{c.val}</div>
            </div>
          ))}
        </div>
      )}

      {/* Diff Sections */}
      {diff && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* New Hosts & Services */}
          <div className="rounded-xl border border-border-subtle bg-bg-card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-emerald-400 flex items-center gap-2">
              <PlusCircle className="h-4 w-4" />
              Nowe hosty ({newHosts.length}) i usługi ({newServices.length})
            </h2>
            {newHosts.length === 0 && newServices.length === 0 ? (
              <p className="text-xs text-text-muted py-4 text-center">
                Brak nowych hostów lub usług między wybranymi skanami.
              </p>
            ) : (
              <div className="space-y-2">
                {newHosts.map((h) => (
                  <div
                    key={h.id}
                    onClick={() => setInspectHostId(h.id)}
                    className="p-2.5 rounded-lg border border-emerald-500/25 bg-emerald-500/5 hover:bg-emerald-500/10 cursor-pointer flex items-center justify-between text-xs"
                  >
                    <span className="font-mono font-semibold text-text-primary">
                      + HOST {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                    </span>
                    <span className="text-[11px] text-emerald-400">{h.lifecycle_state}</span>
                  </div>
                ))}
                {newServices.map((s) => (
                  <div
                    key={s.id}
                    onClick={() => setInspectHostId(s.host_id)}
                    className="p-2.5 rounded-lg border border-cyan-500/25 bg-cyan-500/5 hover:bg-cyan-500/10 cursor-pointer flex items-center justify-between text-xs"
                  >
                    <span className="font-mono text-text-primary">
                      + USŁUGA {s.host_ip || ''}:{s.port}/{s.protocol} ({s.service_name})
                    </span>
                    <span className="text-[11px] text-cyan-400 truncate max-w-[180px]">
                      {s.http?.title || s.product || ''}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Missing Hosts & Closed Services */}
          <div className="rounded-xl border border-border-subtle bg-bg-card p-4 space-y-3">
            <h2 className="text-sm font-semibold text-orange-400 flex items-center gap-2">
              <MinusCircle className="h-4 w-4" />
              Znikające / Nieaktywne ({missingHosts.length}) i zamknięte usługi ({closedServices.length})
            </h2>
            {missingHosts.length === 0 && closedServices.length === 0 ? (
              <p className="text-xs text-text-muted py-4 text-center">
                Brak znikających hostów lub zamkniętych portów.
              </p>
            ) : (
              <div className="space-y-2">
                {missingHosts.map((h) => (
                  <div
                    key={h.id}
                    onClick={() => setInspectHostId(h.id)}
                    className="p-2.5 rounded-lg border border-orange-500/25 bg-orange-500/5 hover:bg-orange-500/10 cursor-pointer flex items-center justify-between text-xs"
                  >
                    <span className="font-mono font-semibold text-text-primary">
                      − HOST {h.ip} {h.hostname ? `(${h.hostname})` : ''}
                    </span>
                    <span className="text-[11px] font-mono text-orange-400">
                      {h.lifecycle_state}
                    </span>
                  </div>
                ))}
                {closedServices.map((s) => (
                  <div
                    key={s.id}
                    onClick={() => setInspectHostId(s.host_id)}
                    className="p-2.5 rounded-lg border border-border-subtle bg-bg-elevated flex items-center justify-between text-xs cursor-pointer"
                  >
                    <span className="font-mono text-text-secondary">
                      − USŁUGA {s.host_ip || ''}:{s.port}/{s.protocol} ({s.service_name})
                    </span>
                    <span className="text-[11px] text-text-muted">zamknięta</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Side-by-Side Changed Services & Time Anomalies */}
      {(changedServices.length > 0 || timeAnomalies.length > 0) && (
        <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <ArrowRight className="h-4 w-4 text-amber-400" />
            Zmienione usługi (Przed → Po) oraz Anomalie Pory Dnia
          </h2>
          <div className="space-y-3">
            {[...timeAnomalies, ...changedServices].map((ch: ChangedServiceDiff, idx) => {
              const sev = severityMeta(ch.severity || (ch.is_time_anomaly ? 'high' : 'medium'));
              return (
                <div
                  key={ch.id || `${ch.host_id}-${ch.port}-${idx}`}
                  className="rounded-lg border border-border-subtle bg-bg-elevated/70 p-3.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${sev.badge}`}
                      >
                        {sev.label}
                      </span>
                      <button
                        type="button"
                        onClick={() => setInspectHostId(ch.host_id)}
                        className="font-mono text-xs font-bold text-cyan-400 hover:underline"
                      >
                        {ch.host_ip}
                        {ch.port ? `:${ch.port}` : ''}
                      </button>
                      <span className="text-xs font-medium text-text-primary">{ch.summary}</span>
                      {ch.is_time_anomaly && (
                        <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/35">
                          <AlertTriangle className="h-3 w-3" /> Anomalia pory dnia ({ch.time_slot})
                        </span>
                      )}
                      {ch.is_expected_schedule && (
                        <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-500/20 text-slate-300 border border-slate-500/30">
                          <Clock className="h-3 w-3" /> Oczekiwany harmonogram
                        </span>
                      )}
                    </div>

                    {ch.acknowledged_at ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Potwierdzone ({ch.acknowledged_by})
                      </span>
                    ) : canWrite && ch.id ? (
                      <button
                        type="button"
                        disabled={ackingId === ch.id}
                        onClick={() => handleAck(ch as ChangeEvent)}
                        className="px-2.5 py-1 rounded-md text-xs font-medium border border-emerald-500/35 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {ackingId === ch.id ? '...' : 'Potwierdź (Acknowledge)'}
                      </button>
                    ) : null}
                  </div>
                  {renderBeforeAfter(ch)}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Full Change Events History */}
      <div className="rounded-xl border border-border-subtle bg-bg-card p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-text-primary">
            Dziennik Zdarzeń Zmian ({allChanges.length})
          </h2>
          <label className="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={anomalyOnly}
              onChange={(e) => setAnomalyOnly(e.target.checked)}
              className="accent-rose-500"
            />
            Tylko anomalie pory dnia (TIME_ANOMALY)
          </label>
        </div>

        {loading ? (
          <div className="py-8 text-center text-xs text-text-muted">Ładowanie...</div>
        ) : allChanges.length === 0 ? (
          <div className="py-8 text-center text-xs text-text-muted">
            Brak zarejestrowanych zdarzeń zmian.
          </div>
        ) : (
          <div className="space-y-2">
            {allChanges.slice(0, 40).map((ch) => {
              const sev = severityMeta(ch.severity);
              return (
                <div
                  key={ch.id}
                  className="rounded-lg border border-border-subtle bg-bg-elevated/60 p-3 flex flex-col gap-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${sev.badge}`}
                      >
                        {sev.label}
                      </span>
                      <span className="font-mono text-[11px] text-text-muted">{ch.event_type}</span>
                      <button
                        type="button"
                        onClick={() => setInspectHostId(ch.host_id)}
                        className="font-mono font-semibold text-cyan-400 hover:underline"
                      >
                        {ch.host_ip}
                        {ch.port ? `:${ch.port}` : ''}
                      </button>
                      <span className="text-text-primary">{ch.summary}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-text-muted">
                        {formatDateTime(ch.created_at)}
                      </span>
                      {ch.acknowledged_at ? (
                        <span className="text-[11px] text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="h-3.5 w-3.5" /> Ack
                        </span>
                      ) : canWrite ? (
                        <button
                          type="button"
                          disabled={ackingId === ch.id}
                          onClick={() => handleAck(ch)}
                          className="px-2 py-0.5 rounded text-[11px] border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
                        >
                          Acknowledge
                        </button>
                      ) : null}
                    </div>
                  </div>
                  {renderBeforeAfter(ch)}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadInitial}
      />
    </div>
  );
}
