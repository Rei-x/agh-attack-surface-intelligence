import React, { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Flame,
  GitCompare,
  Layers,
  Network,
  RefreshCw,
  Send,
  Server,
  ShieldAlert,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useLiveEvents } from '../context/LiveEventsContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import {
  formatNumber,
  formatRelativeTime,
  lifecycleMeta,
  scoreColor,
  severityMeta,
} from '../lib/format';
import { LiveTelemetryBanner } from '../components/LiveTelemetryBanner';
import { AssetInspectorDrawer } from '../components/AssetInspectorDrawer';
import type { DashboardSummary, Service } from '../types/api';

export function DashboardPage() {
  const { can } = useAuth();
  const { lastEvent } = useLiveEvents();
  const toast = useToast();
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [pushingId, setPushingId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);

  const loadSummary = useCallback(async () => {
    try {
      const data = await api.dashboardSummary();
      setSummary(data);
    } catch (err) {
      toast.error('Nie udało się załadować podsumowania', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  // Refresh dashboard automatically on scan completion or detected changes
  useEffect(() => {
    if (
      lastEvent?.type === 'scan.completed' ||
      lastEvent?.type === 'scan.paused_window' ||
      lastEvent?.type === 'change.detected'
    ) {
      loadSummary();
    }
  }, [lastEvent, loadSummary]);

  const kpis = summary?.kpis || {};
  const totalIPs = kpis.total_ips ?? kpis.scope_ips ?? summary?.total_ips ?? summary?.scope_ips ?? 0;
  const activeHosts = kpis.active_hosts ?? summary?.active_hosts ?? 0;
  const unstableHosts = kpis.unstable_hosts ?? summary?.unstable_hosts ?? 0;
  const servicesCount =
    kpis.total_services ??
    kpis.services_found ??
    summary?.total_services ??
    summary?.services_found ??
    0;
  const recentChangesCount =
    kpis.changes_last_scan ??
    kpis.recent_changes ??
    summary?.changes_last_scan ??
    summary?.recent_changes_count ??
    summary?.recent_changes?.length ??
    0;
  const interestingFindingsCount =
    kpis.interesting_findings ??
    summary?.interesting_findings_count ??
    (summary?.top_findings || summary?.top_interesting || []).filter((s) => s.interestingness >= 50)
      .length;

  const topFindings: Service[] = summary?.top_findings || summary?.top_interesting || [];
  const timeline = (summary?.timeline || []).map((pt, idx) => ({
    name: pt.label || pt.name || `#${idx + 1}`,
    active_hosts: pt.active_hosts ?? 0,
    services: pt.services_found ?? pt.services ?? 0,
    changes: pt.changes_detected ?? pt.changes ?? 0,
  }));

  const lifecycleBreakdown = summary?.lifecycle_breakdown || {};
  const lifecycleOrder = ['ACTIVE', 'NEW', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'];

  const handlePushToDefectDojo = async (svc: Service) => {
    setPushingId(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success(
        'Wysłano do DefectDojo v2',
        `Znalezisko ${svc.host_ip || ''}:${svc.port} wyeksportowane z dowodami.`
      );
    } catch (err) {
      toast.error('Błąd wysyłki do DefectDojo', (err as Error).message);
    } finally {
      setPushingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary">
            Centrum Operacyjne Powierzchni Ataku
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Ciągły monitoring zasobów sieciowych CBI AGH, wykrywanie zmian i priorytetyzacja ryzyk
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={loadSummary}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Odśwież
          </button>
          <Link
            to="/graph"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white"
          >
            <Network className="h-3.5 w-3.5" />
            Otwórz Graf
          </Link>
        </div>
      </div>

      {/* Live Scan Telemetry Banner */}
      <LiveTelemetryBanner activeScan={summary?.active_scan} onScanUpdated={loadSummary} />

      {/* 6 KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3.5">
        {[
          {
            label: 'Zakres IP',
            value: formatNumber(totalIPs),
            icon: Layers,
            accent: 'text-cyan-400',
            sub: 'adresów w zakresie',
          },
          {
            label: 'Aktywne hosty',
            value: formatNumber(activeHosts),
            icon: Server,
            accent: 'text-emerald-400',
            sub: 'ACTIVE / NEW',
          },
          {
            label: 'Hosty niestabilne',
            value: formatNumber(unstableHosts),
            icon: AlertTriangle,
            accent: 'text-amber-400',
            sub: 'INTERMITTENT / MISSING',
          },
          {
            label: 'Wykryte usługi',
            value: formatNumber(servicesCount),
            icon: Activity,
            accent: 'text-sky-400',
            sub: 'otwarte porty i HTTP/TLS',
          },
          {
            label: 'Zmiany (ostatni skan)',
            value: formatNumber(recentChangesCount),
            icon: GitCompare,
            accent: 'text-violet-400',
            sub: 'nowe / zmienione / znikające',
          },
          {
            label: 'Ciekawe znaleziska',
            value: formatNumber(interestingFindingsCount),
            icon: Flame,
            accent: 'text-rose-400',
            sub: 'Interestingness ≥ 50',
          },
        ].map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.label}
              className="rounded-xl border border-border-subtle bg-bg-card p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-text-muted">{kpi.label}</span>
                <Icon className={`h-4 w-4 ${kpi.accent}`} />
              </div>
              <div className="mt-2">
                <div className="text-2xl font-bold font-mono text-text-primary">{kpi.value}</div>
                <div className="text-[11px] text-text-muted mt-0.5 truncate">{kpi.sub}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Grid: Timeline Chart + Lifecycle Breakdown */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-8 rounded-xl border border-border-subtle bg-bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary">
                Dynamika Powierzchni Ataku w Kolejnych Skanach
              </h2>
              <p className="text-xs text-text-muted">
                Aktywne hosty, wykryte usługi oraz liczba zmian między przebiegami
              </p>
            </div>
            <Link
              to="/diff"
              className="text-xs text-cyan-400 hover:underline inline-flex items-center gap-1"
            >
              Porównaj skany <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="h-64 w-full">
            {timeline.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-text-muted border border-dashed border-border-subtle rounded-lg">
                Brak historii przebiegów — uruchom pierwszy skan lub zaimportuj dane CSV/JSON.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradHosts" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradServices" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradChanges" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: 'rgba(148,163,184,0.25)',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="services"
                    name="Usługi"
                    stroke="#06b6d4"
                    fill="url(#gradServices)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="active_hosts"
                    name="Aktywne hosty"
                    stroke="#10b981"
                    fill="url(#gradHosts)"
                    strokeWidth={2}
                  />
                  <Area
                    type="monotone"
                    dataKey="changes"
                    name="Zmiany"
                    stroke="#f59e0b"
                    fill="url(#gradChanges)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Lifecycle State Breakdown */}
        <div className="xl:col-span-4 rounded-xl border border-border-subtle bg-bg-card p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-primary">
              Maszyna Stanów Hostów (Histereza)
            </h2>
            <p className="text-xs text-text-muted mb-4">
              Podział zasobów wg stabilności i automatycznego Re-Probe
            </p>

            <div className="space-y-2.5">
              {lifecycleOrder.map((state) => {
                const count = lifecycleBreakdown[state] ?? 0;
                const total = Math.max(
                  1,
                  Object.values(lifecycleBreakdown).reduce((a, b) => a + b, 0)
                );
                const pct = Math.round((count / total) * 100);
                const meta = lifecycleMeta(state);
                return (
                  <div key={state} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-2">
                        <span className={`h-2 w-2 rounded-full ${meta.dot}`} />
                        <span className="font-mono text-text-secondary">{state}</span>
                      </span>
                      <span className="font-mono text-text-primary font-semibold">
                        {count} <span className="text-text-muted font-normal">({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-1.5 rounded-full bg-bg-elevated overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{ width: `${pct}%`, backgroundColor: meta.stroke }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between text-xs">
            <span className="text-text-muted">Szczegóły zasobów i klastry</span>
            <Link to="/assets" className="text-cyan-400 hover:underline font-medium">
              Przejdź do zasobów →
            </Link>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Interestingness Leaderboard + Recent Changes */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Interestingness Leaderboard */}
        <div className="xl:col-span-7 rounded-xl border border-border-subtle bg-bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
                Ranking Priorytetowych Znalezisk (Interestingness Leaderboard)
              </h2>
              <p className="text-xs text-text-muted">
                Panele administracyjne, staging/dev, słabe ciasteczka, wygasające TLS i anomalie
              </p>
            </div>
            <Link to="/assets?min_score=50" className="text-xs text-cyan-400 hover:underline">
              Wszystkie →
            </Link>
          </div>

          {topFindings.length === 0 ? (
            <div className="py-10 text-center text-xs text-text-muted border border-dashed border-border-subtle rounded-lg">
              Brak wysoko punktowanych znalezisk.
            </div>
          ) : (
            <div className="space-y-2.5">
              {topFindings.slice(0, 8).map((svc) => (
                <div
                  key={svc.id}
                  className="rounded-lg border border-border-subtle bg-bg-elevated/60 hover:bg-bg-hover/70 p-3.5 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div
                    className="min-w-0 flex-1 cursor-pointer"
                    onClick={() => setInspectHostId(svc.host_id)}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${scoreColor(
                          svc.interestingness
                        )}`}
                      >
                        {svc.interestingness}
                      </span>
                      <span className="font-mono text-sm font-semibold text-text-primary">
                        {svc.host_ip || svc.host_id}:{svc.port}
                      </span>
                      <span className="text-xs text-cyan-400 font-medium">
                        {svc.http?.title || svc.product || svc.service_name}
                      </span>
                      {svc.is_admin_panel && (
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 border border-rose-500/35">
                          ADMIN
                        </span>
                      )}
                      {svc.is_staging_env && (
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/35">
                          STAGING
                        </span>
                      )}
                    </div>

                    {(svc.interesting_factors?.length || 0) > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {svc.interesting_factors!.slice(0, 4).map((f, idx) => (
                          <span
                            key={idx}
                            className="text-[11px] px-1.5 py-0.5 rounded bg-bg-card border border-border-subtle text-text-secondary"
                          >
                            +{f.points} {f.reason}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setInspectHostId(svc.host_id)}
                      className="px-2.5 py-1.5 rounded-lg text-xs border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
                    >
                      Dowody
                    </button>
                    {can(PERMISSIONS.DEFECTDOJO_PUSH) && (
                      <button
                        type="button"
                        disabled={pushingId === svc.id}
                        onClick={() => handlePushToDefectDojo(svc)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 hover:bg-cyan-500/25 disabled:opacity-50"
                      >
                        <Send className="h-3 w-3" />
                        {pushingId === svc.id ? '...' : 'Wyślij do DefectDojo'}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Changes */}
        <div className="xl:col-span-5 rounded-xl border border-border-subtle bg-bg-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary">
                Ostatnie Zmiany Powierzchni Ataku
              </h2>
              <p className="text-xs text-text-muted">Wykryte różnice i anomalie pory dnia</p>
            </div>
            <button
              type="button"
              onClick={() => navigate('/diff')}
              className="text-xs text-cyan-400 hover:underline"
            >
              Diff skanów →
            </button>
          </div>

          {(summary?.recent_changes?.length || 0) === 0 ? (
            <div className="py-10 text-center text-xs text-text-muted border border-dashed border-border-subtle rounded-lg">
              Brak zarejestrowanych zmian.
            </div>
          ) : (
            <div className="space-y-2.5">
              {summary!.recent_changes!.slice(0, 8).map((ch) => {
                const sev = severityMeta(ch.severity);
                return (
                  <div
                    key={ch.id}
                    onClick={() => ch.host_id && setInspectHostId(ch.host_id)}
                    className="rounded-lg border border-border-subtle bg-bg-elevated/60 hover:bg-bg-hover/70 p-3 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 ${sev.badge}`}
                        >
                          {sev.label}
                        </span>
                        <span className="font-mono text-xs font-semibold text-text-primary truncate">
                          {ch.host_ip}
                          {ch.port ? `:${ch.port}` : ''}
                        </span>
                        {ch.is_time_anomaly && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                            TIME_ANOMALY
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] text-text-muted shrink-0">
                        {formatRelativeTime(ch.created_at)}
                      </span>
                    </div>
                    <p className="text-xs text-text-secondary mt-1">{ch.summary}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Slide-over Asset Inspector */}
      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadSummary}
      />
    </div>
  );
}
