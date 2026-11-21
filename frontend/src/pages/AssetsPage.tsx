import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RiArrowLeftSLine,
  RiArrowRightSLine,
  RiDeleteBinLine,
  RiDownload2Line,
  RiLockLine,
  RiQuestionLine,
  RiRefreshLine,
  RiSearchLine,
} from '@remixicon/react';
import { api, ApiError } from '@/lib/api';
import { AssetQueryHelp, TriageBadge } from '@/components/AssetQueryHelp';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveEvents, useLiveRefresh } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import { formatNumber, formatRelativeTime, lifecycleMeta, scoreColor } from '@/lib/format';
import { cn } from '@/lib/utils';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { Empty, PageHeader, Pill, SimpleSelect } from '@/components/common';
import { ServiceLogo, ServiceLogoFor } from '@/components/ServiceLogo';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { Host, ServiceCluster } from '@/types/api';
import { PeckLoader } from '@/components/Woodpecker';

const ALL = '__all__';

const STATE_OPTIONS = [
  { value: ALL, label: 'Wszystkie stany' },
  { value: 'NEW', label: 'NEW' },
  { value: 'ACTIVE', label: 'ACTIVE' },
  { value: 'INTERMITTENT', label: 'INTERMITTENT' },
  { value: 'MISSING', label: 'MISSING' },
  { value: 'INACTIVE', label: 'INACTIVE' },
  { value: 'REACTIVATED', label: 'REACTIVATED' },
];

const ENV_OPTIONS = [
  { value: ALL, label: 'Wszystkie środowiska' },
  { value: 'prod', label: 'prod' },
  { value: 'staging', label: 'staging' },
  { value: 'dev', label: 'dev' },
  { value: 'test', label: 'test' },
];

const CLUSTER_OPTIONS = [
  { value: ALL, label: 'Wszystkie grupy' },
  { value: 'favicon', label: 'Favicon MMH3' },
  { value: 'tech_stack', label: 'Stos technologiczny' },
  { value: 'http_title', label: 'Tytuł HTTP' },
  { value: 'tls_issuer', label: 'TLS Issuer' },
];

const PAGE_SIZE_OPTIONS = [
  { value: '25', label: '25 / str.' },
  { value: '50', label: '50 / str.' },
  { value: '100', label: '100 / str.' },
];

const toSel = (v: string) => (v === '' ? ALL : v);
const fromSel = (v: string) => (v === ALL ? '' : v);

export function AssetsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [searchParams] = useSearchParams();

  const [viewMode, setViewMode] = useState<'table' | 'clusters'>('table');
  const [hosts, setHosts] = useState<Host[]>([]);
  const [totalHosts, setTotalHosts] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalPages, setTotalPages] = useState(1);
  const [clusters, setClusters] = useState<ServiceCluster[]>([]);
  const [clusterGroupBy, setClusterGroupBy] = useState<string>('');
  const [loading, setLoading] = useState(true);

  // Filters
  const [q, setQ] = useState(searchParams.get('q') || '');
  const [debouncedQ, setDebouncedQ] = useState(q.trim());
  const [stateFilter, setStateFilter] = useState(searchParams.get('state') || '');
  const [envFilter, setEnvFilter] = useState(searchParams.get('env') || '');
  const [tagFilter, setTagFilter] = useState(searchParams.get('tag') || '');
  const [minScore, setMinScore] = useState(Number(searchParams.get('min_score') || 0));
  const [adminOnly, setAdminOnly] = useState(false);
  const [queryError, setQueryError] = useState('');
  const [showQueryHelp, setShowQueryHelp] = useState(false);

  const [inspectHostId, setInspectHostId] = useState<string | null>(searchParams.get('host'));

  const canDelete = can(PERMISSIONS.ASSETS_DELETE);
  const canExport = can(PERMISSIONS.EXPORT_READ);

  const { recentIPs } = useLiveEvents();

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedQ(q.trim()), 300);
    return () => window.clearTimeout(t);
  }, [q]);

  // Any filter change resets to the first page.
  useEffect(() => {
    setPage(1);
  }, [debouncedQ, stateFilter, envFilter, tagFilter, minScore, adminOnly, pageSize]);

  const loadData = useCallback(async (silent?: boolean) => {
    if (!silent) setLoading(true);
    try {
      if (viewMode === 'table') {
        const res = await api.listHosts({
          q: debouncedQ || undefined,
          state: stateFilter || undefined,
          env: envFilter || undefined,
          tag: tagFilter.trim() || undefined,
          min_score: minScore > 0 ? minScore : undefined,
          has_admin: adminOnly ? true : undefined,
          page,
          limit: pageSize,
        });
        setQueryError('');
        setHosts(res.hosts);
        setTotalHosts(res.total);
        setTotalPages(Math.max(1, res.total_pages));
        if (res.page > res.total_pages && res.total > 0) setPage(res.total_pages);
      } else {
        const list = await api.clusters(clusterGroupBy || undefined);
        setClusters(list);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 400 && viewMode === 'table') {
        // Query-language syntax error: show inline under the search box, not as a toast.
        setQueryError(err.message);
        setHosts([]);
        setTotalHosts(0);
      } else if (!silent) {
        toast.error('Błąd pobierania', (err as Error).message);
      }
    } finally {
      if (!silent) setLoading(false);
    }
  }, [viewMode, debouncedQ, page, pageSize, stateFilter, envFilter, tagFilter, minScore, adminOnly, clusterGroupBy, toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useLiveRefresh(() => loadData(true));

  const handleDeleteHost = async (host: Host, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Usunąć host ${host.ip} wraz z usługami?`)) return;
    try {
      await api.deleteHost(host.id);
      toast.success('Usunięto', host.ip);
      loadData();
    } catch (err) {
      toast.error('Błąd usuwania', (err as Error).message);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      await api.exportData({
        format,
        state: stateFilter || undefined,
        tag: tagFilter.trim() || undefined,
      });
      toast.success(`Eksport ${format.toUpperCase()}`);
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

  const colCount = canDelete ? 9 : 8;

  return (
    <div>
      <PageHeader
        title="Zasoby"
        meta={
          viewMode === 'table' ? (
            <span className="font-mono tabular-nums">{formatNumber(totalHosts)} hostów</span>
          ) : (
            <span className="font-mono tabular-nums">{clusters.length} klastrów</span>
          )
        }
        actions={
          <>
            {canExport && (
              <>
                <Button variant="outline" size="sm" onClick={() => handleExport('csv')}>
                  <RiDownload2Line data-icon="inline-start" /> CSV
                </Button>
                <Button variant="outline" size="sm" onClick={() => handleExport('json')}>
                  <RiDownload2Line data-icon="inline-start" /> JSON
                </Button>
              </>
            )}
            <Button variant="outline" size="icon-sm" onClick={() => loadData()} aria-label="Odśwież">
              <RiRefreshLine className={cn(loading && 'animate-spin')} />
            </Button>
          </>
        }
      />

      <Tabs
        value={viewMode}
        onValueChange={(v) => setViewMode(v as 'table' | 'clusters')}
        className="gap-0"
      >
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-border">
          <TabsList variant="line" className="-mb-px">
            <TabsTrigger value="table">
              Hosty <span className="font-mono text-muted-foreground tabular-nums">{formatNumber(totalHosts)}</span>
            </TabsTrigger>
            <TabsTrigger value="clusters">Klastry</TabsTrigger>
          </TabsList>
        </div>

        {/* HOSTS */}
        <TabsContent value="table" className="pt-5">
          <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-3">
            <div className="relative min-w-[240px] flex-1">
              <RiSearchLine className="pointer-events-none absolute top-1/2 left-0 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="port:3389 tag:wi cidr:10.66.0.0/24 cert:expired, IP, hostname…"
                className="pr-7 pl-6 font-mono"
                aria-invalid={queryError ? true : undefined}
              />
              <button
                type="button"
                onClick={() => setShowQueryHelp((v) => !v)}
                className={cn(
                  'absolute top-1/2 right-0 -translate-y-1/2 text-muted-foreground hover:text-foreground',
                  showQueryHelp && 'text-primary'
                )}
                aria-label="Składnia wyszukiwania"
                title="Składnia wyszukiwania"
              >
                <RiQuestionLine className="size-4" />
              </button>
            </div>
            <SimpleSelect
              size="sm"
              className="w-44"
              value={toSel(stateFilter)}
              onValueChange={(v) => setStateFilter(fromSel(v))}
              options={STATE_OPTIONS}
            />
            <SimpleSelect
              size="sm"
              className="w-44"
              value={toSel(envFilter)}
              onValueChange={(v) => setEnvFilter(fromSel(v))}
              options={ENV_OPTIONS}
            />
            <Input
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              placeholder="Tag"
              className="w-28"
            />
            <label className="flex items-center gap-2 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
              Min score
              <input
                type="range"
                min={0}
                max={90}
                step={5}
                value={minScore}
                onChange={(e) => setMinScore(Number(e.target.value))}
                className="w-24 accent-primary"
              />
              <span className="w-6 font-mono text-xs text-foreground tabular-nums">{minScore}</span>
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-[10px] font-semibold tracking-widest text-muted-foreground uppercase select-none">
              <Switch checked={adminOnly} onCheckedChange={(checked) => setAdminOnly(checked)} />
              Panele admina
            </label>
          </div>

          {queryError && (
            <p className="-mt-2 mb-3 font-mono text-xs text-destructive">{queryError}</p>
          )}
          {showQueryHelp && (
            <AssetQueryHelp
              onPick={(snippet) => setQ((prev) => (prev.trim() ? `${prev.trim()} ${snippet}` : snippet))}
            />
          )}

          <div className="border border-border bg-card">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Host</TableHead>
                  <TableHead>Stan</TableHead>
                  <TableHead>Środowisko</TableHead>
                  <TableHead className="text-right">Usługi</TableHead>
                  <TableHead>Stabilność</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Tagi</TableHead>
                  <TableHead>Ostatnio</TableHead>
                  {canDelete && <TableHead className="w-10 pr-4" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && hosts.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={colCount}>
                      <PeckLoader />
                    </TableCell>
                  </TableRow>
                ) : hosts.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={colCount}>
                      <Empty bird>Dzięcioł jeszcze nic tu nie wystukał</Empty>
                    </TableCell>
                  </TableRow>
                ) : (
                  hosts.map((h) => {
                    const lc = lifecycleMeta(h.lifecycle_state);
                    const hasLocked = (h.locked_fields?.length || 0) > 0;
                    return (
                      <TableRow
                        key={`${h.id}-${recentIPs[h.ip] ?? ''}`}
                        onClick={() => setInspectHostId(h.id)}
                        className={cn('group cursor-pointer', recentIPs[h.ip] && 'animate-live-row')}
                      >
                        <TableCell className="pl-4">
                          <div className="flex items-center gap-1.5">
                            {recentIPs[h.ip] && (
                              <span className="size-1.5 shrink-0 animate-pulse bg-emerald-500" aria-hidden />
                            )}
                            <span className="font-mono text-sm font-medium text-foreground">
                              {h.ip}
                            </span>
                            {hasLocked && (
                              <span
                                title={`Overrides: ${h.locked_fields!.join(', ')}`}
                                className="text-muted-foreground"
                              >
                                <RiLockLine className="size-3.5" />
                              </span>
                            )}
                          </div>
                          {h.hostname && (
                            <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                              {h.hostname}
                            </div>
                          )}
                        </TableCell>

                        <TableCell>
                          <div className="flex flex-wrap items-center gap-1">
                            <Pill className={lc.badge} dot>
                              {lc.label}
                            </Pill>
                            <TriageBadge triage={h.triage} />
                          </div>
                        </TableCell>

                        <TableCell>
                          <div className="font-mono text-xs text-foreground">
                            {h.environment || '—'}
                          </div>
                          {h.owner && (
                            <div className="text-[11px] text-muted-foreground">{h.owner}</div>
                          )}
                        </TableCell>

                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            {[...(h.services || [])]
                              .sort((a, b) => b.interestingness - a.interestingness)
                              .slice(0, 4)
                              .map((s) => (
                                <ServiceLogoFor key={s.id} service={s} size="xs" />
                              ))}
                            <span className="ml-1 min-w-5 font-mono text-xs tabular-nums">
                              {h.service_count ?? h.services?.length ?? 0}
                            </span>
                          </div>
                        </TableCell>

                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="h-1 w-14 bg-muted">
                              <div
                                className="h-full bg-foreground/60"
                                style={{ width: `${h.stability_score}%` }}
                              />
                            </div>
                            <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                              {h.stability_score}%
                            </span>
                          </div>
                        </TableCell>

                        <TableCell>
                          <Pill className={cn('font-mono tabular-nums', scoreColor(h.interestingness))}>
                            {h.interestingness}
                          </Pill>
                        </TableCell>

                        <TableCell>
                          <div className="flex max-w-[200px] flex-wrap gap-1">
                            {(h.tags || []).slice(0, 3).map((t) => (
                              <Pill key={t} className="normal-case tracking-normal font-normal">
                                #{t}
                              </Pill>
                            ))}
                            {(h.tags?.length || 0) > 3 && (
                              <span className="self-center text-[10px] text-muted-foreground">
                                +{h.tags!.length - 3}
                              </span>
                            )}
                          </div>
                        </TableCell>

                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {formatRelativeTime(h.last_seen)}
                        </TableCell>

                        {canDelete && (
                          <TableCell className="pr-4 text-right">
                            <Button
                              variant="ghost"
                              size="icon-xs"
                              onClick={(e) => handleDeleteHost(h, e)}
                              aria-label="Usuń host"
                              title="Usuń host"
                              className="text-muted-foreground opacity-0 group-hover:opacity-100 hover:text-destructive focus-visible:opacity-100"
                            >
                              <RiDeleteBinLine />
                            </Button>
                          </TableCell>
                        )}
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5">
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {totalHosts === 0
                  ? '0 hostów'
                  : `${formatNumber((page - 1) * pageSize + 1)}–${formatNumber(
                      Math.min(page * pageSize, totalHosts)
                    )} z ${formatNumber(totalHosts)} hostów`}
              </span>
              <div className="flex items-center gap-2">
                <SimpleSelect
                  size="sm"
                  className="w-28"
                  value={String(pageSize)}
                  onValueChange={(v) => setPageSize(Number(v) || 50)}
                  options={PAGE_SIZE_OPTIONS}
                />
                <Button
                  variant="outline"
                  size="icon-sm"
                  disabled={page <= 1 || loading}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  aria-label="Poprzednia strona"
                >
                  <RiArrowLeftSLine />
                </Button>
                <span className="min-w-16 text-center font-mono text-xs tabular-nums">
                  {formatNumber(page)} / {formatNumber(totalPages)}
                </span>
                <Button
                  variant="outline"
                  size="icon-sm"
                  disabled={page >= totalPages || loading}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  aria-label="Następna strona"
                >
                  <RiArrowRightSLine />
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* CLUSTERS */}
        <TabsContent value="clusters" className="pt-5">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <SimpleSelect
              size="sm"
              className="w-56"
              value={toSel(clusterGroupBy)}
              onValueChange={(v) => setClusterGroupBy(fromSel(v))}
              options={CLUSTER_OPTIONS}
            />
          </div>

          <div className="border border-border bg-card">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Klaster</TableHead>
                  <TableHead>Kryterium</TableHead>
                  <TableHead className="text-right">Usługi</TableHead>
                  <TableHead>Max score</TableHead>
                  <TableHead>Technologie</TableHead>
                  <TableHead className="pr-4">Hosty</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && clusters.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={6}>
                      <PeckLoader />
                    </TableCell>
                  </TableRow>
                ) : clusters.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={6}>
                      <Empty>Brak klastrów</Empty>
                    </TableCell>
                  </TableRow>
                ) : (
                  clusters.map((cl) => (
                    <TableRow key={cl.cluster_key} className="align-top">
                      <TableCell className="max-w-[320px] pl-4 whitespace-normal">
                        <div className="flex items-start gap-2.5">
                          <ServiceLogo names={[...(cl.sample_techs || []), cl.label]} size="md" />
                          <div className="min-w-0">
                            <div className="text-sm font-medium break-words text-foreground">
                              {cl.label}
                            </div>
                            <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                              {cl.cluster_key}
                            </div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Pill className="font-mono">{cl.group_by}</Pill>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {cl.count}
                      </TableCell>
                      <TableCell>
                        <Pill className={cn('font-mono tabular-nums', scoreColor(cl.max_interestingness))}>
                          {cl.max_interestingness}
                        </Pill>
                      </TableCell>
                      <TableCell className="max-w-[220px] whitespace-normal">
                        <div className="flex flex-wrap gap-1">
                          {(cl.sample_techs || []).map((t) => (
                            <span
                              key={t}
                              className="inline-flex h-6 items-center gap-1.5 border border-border bg-muted/40 pr-1.5 text-[11px]"
                            >
                              <ServiceLogo name={t} size={22} className="-my-px -ml-px" />
                              {t}
                            </span>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="max-w-[320px] pr-4 whitespace-normal">
                        <div className="flex flex-wrap gap-1">
                          {(cl.host_ips || []).slice(0, 8).map((ip) => (
                            <button
                              key={ip}
                              type="button"
                              onClick={() => openHostByIP(ip)}
                              className="border border-border px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-primary hover:text-primary"
                            >
                              {ip}
                            </button>
                          ))}
                          {(cl.host_ips?.length || 0) > 8 && (
                            <span className="self-center text-[11px] text-muted-foreground">
                              +{cl.host_ips.length - 8}
                            </span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadData}
      />
    </div>
  );
}
