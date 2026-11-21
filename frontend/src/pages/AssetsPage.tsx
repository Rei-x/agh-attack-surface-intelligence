import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Download,
  Layers,
  Lock,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { PERMISSIONS } from '../lib/permissions';
import { formatRelativeTime, lifecycleMeta, scoreColor } from '../lib/format';
import { AssetInspectorDrawer } from '../components/AssetInspectorDrawer';
import type { Host, ServiceCluster } from '../types/api';

export function AssetsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [searchParams] = useSearchParams();

  const [viewMode, setViewMode] = useState<'table' | 'clusters'>('table');
  const [hosts, setHosts] = useState<Host[]>([]);
  const [totalHosts, setTotalHosts] = useState(0);
  const [clusters, setClusters] = useState<ServiceCluster[]>([]);
  const [clusterGroupBy, setClusterGroupBy] = useState<string>('');
  const [loading, setLoading] = useState(true);

  // Filters
  const [q, setQ] = useState(searchParams.get('q') || '');
  const [stateFilter, setStateFilter] = useState(searchParams.get('state') || '');
  const [envFilter, setEnvFilter] = useState(searchParams.get('env') || '');
  const [tagFilter, setTagFilter] = useState(searchParams.get('tag') || '');
  const [minScore, setMinScore] = useState(Number(searchParams.get('min_score') || 0));
  const [adminOnly, setAdminOnly] = useState(false);

  const [inspectHostId, setInspectHostId] = useState<string | null>(searchParams.get('host'));

  const canDelete = can(PERMISSIONS.ASSETS_DELETE);
  const canExport = can(PERMISSIONS.EXPORT_READ);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      if (viewMode === 'table') {
        const res = await api.listHosts({
          q: q.trim() || undefined,
          state: stateFilter || undefined,
          env: envFilter || undefined,
          tag: tagFilter.trim() || undefined,
          min_score: minScore > 0 ? minScore : undefined,
          has_admin: adminOnly ? true : undefined,
          limit: 200,
        });
        setHosts(res.hosts);
        setTotalHosts(res.total);
      } else {
        const list = await api.clusters(clusterGroupBy || undefined);
        setClusters(list);
      }
    } catch (err) {
      toast.error('Błąd pobierania zasobów', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [viewMode, q, stateFilter, envFilter, tagFilter, minScore, adminOnly, clusterGroupBy, toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleDeleteHost = async (host: Host, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Usunąć host ${host.ip} wraz z powiązanymi usługami?`)) return;
    try {
      await api.deleteHost(host.id);
      toast.success('Usunięto zasób', host.ip);
      loadData();
    } catch (err) {
      toast.error('Nie udało się usunąć hosta', (err as Error).message);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      await api.exportData({
        format,
        state: stateFilter || undefined,
        tag: tagFilter.trim() || undefined,
      });
      toast.success(`Eksport ${format.toUpperCase()}`, 'Pobieranie pliku rozpoczęte.');
    } catch (err) {
      toast.error('Błąd eksportu', (err as Error).message);
    }
  };

  const openHostByIP = async (ip: string) => {
    const match = hosts.find((h) => h.ip === ip);
    if (match) {
      setInspectHostId(match.id);
      return;
    }
    try {
      const res = await api.listHosts({ q: ip, limit: 5 });
      const found = res.hosts.find((h) => h.ip === ip) || res.hosts[0];
      if (found) setInspectHostId(found.id);
    } catch {
      // ignore
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-400" />
            Zasoby: Hosty, Usługi i Grupowanie
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Inwentarz zasobów z Evidence Receipts, Noisy-OR Confidence oraz trwałymi nadpisaniami
            analityka
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* View Toggle */}
          <div className="inline-flex rounded-lg border border-border-subtle bg-bg-card p-0.5">
            <button
              type="button"
              onClick={() => setViewMode('table')}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                viewMode === 'table'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Lista Hostów ({totalHosts})
            </button>
            <button
              type="button"
              onClick={() => setViewMode('clusters')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                viewMode === 'clusters'
                  ? 'bg-cyan-500/15 text-cyan-400'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              Grupuj podobne usługi
            </button>
          </div>

          {canExport && (
            <>
              <button
                type="button"
                onClick={() => handleExport('csv')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
              >
                <Download className="h-3.5 w-3.5" /> CSV
              </button>
              <button
                type="button"
                onClick={() => handleExport('json')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
              >
                <Download className="h-3.5 w-3.5" /> JSON
              </button>
            </>
          )}

          <button
            type="button"
            onClick={loadData}
            className="p-2 rounded-lg border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
            title="Odśwież"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filters */}
      {viewMode === 'table' ? (
        <div className="rounded-xl border border-border-subtle bg-bg-card p-3.5 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="h-3.5 w-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Szukaj IP, hostname, domeny, technologii..."
              className="w-full rounded-lg border border-border-subtle bg-bg-elevated pl-8 pr-3 py-1.5 text-xs text-text-primary focus:outline-none focus:border-cyan-500"
            />
          </div>

          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-xs text-text-primary"
          >
            <option value="">Wszystkie stany</option>
            <option value="NEW">NEW</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="INTERMITTENT">INTERMITTENT</option>
            <option value="MISSING">MISSING</option>
            <option value="INACTIVE">INACTIVE</option>
            <option value="REACTIVATED">REACTIVATED</option>
          </select>

          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-xs text-text-primary"
          >
            <option value="">Środowisko: wszystkie</option>
            <option value="prod">prod</option>
            <option value="staging">staging</option>
            <option value="dev">dev</option>
            <option value="test">test</option>
          </select>

          <input
            type="text"
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            placeholder="Tag..."
            className="w-32 rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-xs text-text-primary"
          />

          <label className="flex items-center gap-2 text-xs text-text-secondary">
            <span>
              Min Score: <strong className="font-mono text-cyan-400">{minScore}</strong>
            </span>
            <input
              type="range"
              min={0}
              max={90}
              step={5}
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-24 accent-cyan-500"
            />
          </label>

          <label className="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none">
            <input
              type="checkbox"
              checked={adminOnly}
              onChange={(e) => setAdminOnly(e.target.checked)}
              className="accent-rose-500"
            />
            Tylko panele admina
          </label>
        </div>
      ) : (
        <div className="rounded-xl border border-border-subtle bg-bg-card p-3.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-text-muted">Kryterium klastrowania:</span>
            {[
              { id: '', label: 'Wszystkie grupy' },
              { id: 'favicon', label: 'Favicon MMH3' },
              { id: 'tech_stack', label: 'Stos technologiczny' },
              { id: 'http_title', label: 'Tytuł HTTP' },
              { id: 'tls_issuer', label: 'TLS Issuer' },
            ].map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setClusterGroupBy(opt.id)}
                className={`px-3 py-1 rounded-lg text-xs font-medium border transition-colors ${
                  clusterGroupBy === opt.id
                    ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/35'
                    : 'bg-bg-elevated text-text-secondary border-border-subtle hover:bg-bg-hover'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <span className="text-xs font-mono text-text-muted">{clusters.length} klastrów</span>
        </div>
      )}

      {/* TABLE VIEW */}
      {viewMode === 'table' && (
        <div className="rounded-xl border border-border-subtle bg-bg-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-bg-elevated border-b border-border-subtle text-text-muted uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="px-4 py-3">Host / IP</th>
                  <th className="px-4 py-3">Stan</th>
                  <th className="px-4 py-3">Środowisko / Właściciel</th>
                  <th className="px-4 py-3">Usługi</th>
                  <th className="px-4 py-3">Stabilność</th>
                  <th className="px-4 py-3">Interestingness</th>
                  <th className="px-4 py-3">Tagi</th>
                  <th className="px-4 py-3">Ostatnio</th>
                  {canDelete && <th className="px-4 py-3 text-right">Akcje</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/70">
                {loading ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-10 text-center text-text-muted">
                      Ładowanie zasobów...
                    </td>
                  </tr>
                ) : hosts.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-10 text-center text-text-muted">
                      Brak hostów spełniających podane kryteria.
                    </td>
                  </tr>
                ) : (
                  hosts.map((h) => {
                    const lc = lifecycleMeta(h.lifecycle_state);
                    const hasLocked = (h.locked_fields?.length || 0) > 0;
                    return (
                      <tr
                        key={h.id}
                        onClick={() => setInspectHostId(h.id)}
                        className="hover:bg-bg-hover/60 cursor-pointer transition-colors"
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-sm text-text-primary">
                              {h.ip}
                            </span>
                            {hasLocked && (
                              <span
                                title={`Zablokowane nadpisania: ${h.locked_fields!.join(', ')}`}
                                className="text-violet-400"
                              >
                                <Lock className="h-3.5 w-3.5" />
                              </span>
                            )}
                          </div>
                          {h.hostname && (
                            <div className="font-mono text-[11px] text-text-muted mt-0.5">
                              {h.hostname}
                            </div>
                          )}
                        </td>

                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center gap-1.5 font-mono text-[11px] px-2 py-0.5 rounded border ${lc.badge}`}
                          >
                            <span className={`h-1.5 w-1.5 rounded-full ${lc.dot}`} />
                            {lc.label}
                          </span>
                        </td>

                        <td className="px-4 py-3">
                          <div className="text-text-primary font-mono">
                            {h.environment || '—'}
                          </div>
                          {h.owner && (
                            <div className="text-[11px] text-text-muted">{h.owner}</div>
                          )}
                        </td>

                        <td className="px-4 py-3">
                          <span className="font-mono text-text-primary font-semibold">
                            {h.service_count ?? h.services?.length ?? 0}
                          </span>
                          <span className="text-text-muted"> usług</span>
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 rounded-full bg-bg-elevated overflow-hidden">
                              <div
                                className="h-full bg-emerald-500"
                                style={{ width: `${h.stability_score}%` }}
                              />
                            </div>
                            <span className="font-mono text-[11px] text-text-secondary">
                              {h.stability_score}%
                            </span>
                          </div>
                        </td>

                        <td className="px-4 py-3">
                          <span
                            className={`font-mono font-bold text-xs px-2 py-0.5 rounded border ${scoreColor(
                              h.interestingness
                            )}`}
                          >
                            {h.interestingness}
                          </span>
                        </td>

                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1 max-w-[200px]">
                            {(h.tags || []).slice(0, 3).map((t) => (
                              <span
                                key={t}
                                className="text-[10px] px-1.5 py-0.5 rounded bg-bg-elevated border border-border-subtle text-text-secondary"
                              >
                                #{t}
                              </span>
                            ))}
                            {(h.tags?.length || 0) > 3 && (
                              <span className="text-[10px] text-text-muted">
                                +{h.tags!.length - 3}
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="px-4 py-3 text-text-muted font-mono text-[11px]">
                          {formatRelativeTime(h.last_seen)}
                        </td>

                        {canDelete && (
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={(e) => handleDeleteHost(h, e)}
                              className="p-1.5 rounded-md text-text-muted hover:text-rose-400 hover:bg-rose-500/10"
                              title="Usuń host"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        )}
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CLUSTERS VIEW */}
      {viewMode === 'clusters' && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {loading ? (
            <div className="col-span-full py-12 text-center text-sm text-text-muted">
              Grupowanie podobnych usług...
            </div>
          ) : clusters.length === 0 ? (
            <div className="col-span-full rounded-xl border border-border-subtle bg-bg-card py-12 text-center text-sm text-text-muted">
              Brak zgrupowanych usług dla wybranego kryterium.
            </div>
          ) : (
            clusters.map((cl) => (
              <div
                key={cl.cluster_key}
                className="rounded-xl border border-border-subtle bg-bg-card p-4 flex flex-col justify-between gap-3"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                      {cl.group_by}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-mono font-semibold text-cyan-400">
                        {cl.count} usług
                      </span>
                      <span
                        className={`text-xs font-mono px-1.5 py-0.5 rounded border ${scoreColor(
                          cl.max_interestingness
                        )}`}
                      >
                        Max {cl.max_interestingness}
                      </span>
                    </div>
                  </div>

                  <h3 className="text-sm font-semibold text-text-primary mt-2 break-words">
                    {cl.label}
                  </h3>
                  <p className="text-[11px] font-mono text-text-muted mt-0.5 truncate">
                    {cl.cluster_key}
                  </p>

                  {(cl.sample_techs?.length || 0) > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2.5">
                      {cl.sample_techs!.map((t) => (
                        <span
                          key={t}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/25"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-border-subtle">
                  <div className="text-[11px] text-text-muted mb-1.5">Hosty w klastrze:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {(cl.host_ips || []).slice(0, 8).map((ip) => (
                      <button
                        key={ip}
                        type="button"
                        onClick={() => openHostByIP(ip)}
                        className="font-mono text-[11px] px-2 py-0.5 rounded bg-bg-elevated border border-border-subtle hover:border-cyan-500/40 text-text-primary"
                      >
                        {ip}
                      </button>
                    ))}
                    {(cl.host_ips?.length || 0) > 8 && (
                      <span className="text-[11px] text-text-muted self-center">
                        +{cl.host_ips.length - 8} więcej
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadData}
      />
    </div>
  );
}
