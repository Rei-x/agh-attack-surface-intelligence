import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  RiArrowDownSLine,
  RiArrowLeftSLine,
  RiArrowRightSLine,
  RiArrowUpSLine,
  RiCloseLine,
  RiDeleteBinLine,
  RiDownload2Line,
  RiLockLine,
  RiMore2Line,
  RiQuestionLine,
  RiRefreshLine,
  RiSearchLine,
  RiSparklingLine,
} from '@remixicon/react';
import { api, ApiError } from '@/lib/api';
import { AssetQueryHelp, TriageBadge } from '@/components/AssetQueryHelp';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { useLiveEvents, useLiveRefresh } from '@/context/LiveEventsContext';
import { PERMISSIONS } from '@/lib/permissions';
import { envLabel, formatNumber, formatRelativeTime, lifecycleMeta, plural, scoreColor } from '@/lib/format';
import { hostIdentity, identityLabel } from '@/lib/identity';
import { cn } from '@/lib/utils';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { Empty, PageHeader, Pill, SimpleSelect } from '@/components/common';
import { ServiceLogo, ServiceLogoFor } from '@/components/ServiceLogo';
import { CATEGORY_META, CategoryBadges, hostFlags, serviceFlags, type CategoryKind } from '@/components/CategoryBadge';
import { ProductInventory } from '@/components/ProductInventory';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { Host, InventoryResponse, Service, ServiceCluster } from '@/types/api';
import { PeckLoader } from '@/components/Woodpecker';

const ALL = '__all__';

const STATE_OPTIONS = [
  { value: ALL, label: 'All states' },
  ...['NEW', 'ACTIVE', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'].map((s) => ({
    value: s,
    label: lifecycleMeta(s).label,
  })),
];

const ENV_OPTIONS = [
  { value: ALL, label: 'All environments' },
  { value: 'prod', label: 'Production' },
  { value: 'staging', label: 'Staging' },
  { value: 'dev', label: 'Development' },
  { value: 'test', label: 'Test' },
];

const CLUSTER_OPTIONS = [
  { value: ALL, label: 'All groupings' },
  { value: 'favicon', label: 'Favicon MMH3' },
  { value: 'tech_stack', label: 'Technology stack' },
  { value: 'http_title', label: 'HTTP title' },
  { value: 'tls_issuer', label: 'TLS issuer' },
];

const PAGE_SIZE_OPTIONS = [
  { value: '25', label: '25 / page' },
  { value: '50', label: '50 / page' },
  { value: '100', label: '100 / page' },
];

/** One-click filters: each just sets the asset query. Counts come from /inventory. */
const QUICK_FILTERS: Array<{ key: string; label: string; query: string; kind?: CategoryKind }> = [
  { key: 'admin', label: 'Admin panels', query: 'admin:true', kind: 'admin' },
  { key: 'eol', label: 'EOL', query: 'eol:true', kind: 'eol' },
  { key: 'vuln', label: 'Known CVE', query: 'vuln:true', kind: 'cve' },
  { key: 'db', label: 'Exposed DB', query: 'db:true', kind: 'db' },
  { key: 'staging', label: 'Staging', query: 'staging:true', kind: 'staging' },
  { key: 'iot', label: 'IoT / BMC', query: 'iot:true', kind: 'iot' },
  { key: 'cleartext', label: 'Telnet / FTP', query: 'cleartext:true', kind: 'cleartext' },
  { key: 'cert_expired', label: 'Expired certs', query: 'cert:expired', kind: 'cert' },
  { key: 'new', label: 'New since last scan', query: 'state:new' },
];

const CLUSTER_PAGE = 20;

const toSel = (v: string) => (v === '' ? ALL : v);
const fromSel = (v: string) => (v === ALL ? '' : v);

type ViewMode = 'table' | 'products' | 'clusters';

interface QTerm {
  key: string;
  value: string;
  negate: boolean;
}

function parseTerms(q: string): QTerm[] {
  const out: QTerm[] = [];
  const re = /(-?)([a-z]+):(?:"([^"]*)"|“([^”]*)”|'([^']*)'|(\S+))/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q))) {
    out.push({ key: m[2].toLowerCase(), value: (m[3] ?? m[4] ?? m[5] ?? m[6] ?? '').toLowerCase(), negate: m[1] === '-' });
  }
  return out;
}

const FLAG_KEYS: Record<string, CategoryKind> = {
  admin: 'admin',
  eol: 'eol',
  vuln: 'cve',
  cve: 'cve',
  db: 'db',
  iot: 'iot',
  staging: 'staging',
  cleartext: 'cleartext',
};

function serviceMatches(svc: Service, terms: QTerm[]): boolean {
  const flags = new Set(serviceFlags(svc).map((f) => f.kind));
  return terms.every((t) => {
    const vals = t.value.split(',').filter(Boolean);
    let ok: boolean;
    switch (t.key) {
      case 'tech':
      case 'product': {
        const hay = [svc.product, ...(svc.technologies || []).map((x) => x.name), ...(svc.matched_signatures || [])]
          .filter(Boolean)
          .map((s) => s!.toLowerCase());
        ok = vals.some((v) => hay.some((h) => h.includes(v)));
        break;
      }
      case 'port':
        ok = vals.some((v) => Number(v) === svc.port);
        break;
      case 'title':
        ok = (svc.http?.title || '').toLowerCase().includes(t.value);
        break;
      case 'version':
        ok = [svc.version, ...(svc.technologies || []).map((x) => x.version)].some((v) =>
          vals.some((x) => (v || '').toLowerCase().includes(x))
        );
        break;
      case 'service':
        ok = vals.some((v) => (svc.service_name || '').toLowerCase().includes(v));
        break;
      case 'cert':
        ok = vals.includes('expired') ? Boolean(svc.http?.tls?.is_expired) : Boolean(svc.http?.tls);
        break;
      default: {
        const kind = FLAG_KEYS[t.key];
        if (!kind) return true; // host-level term
        ok = flags.has(kind) === (t.value !== 'false');
      }
    }
    return ok !== t.negate;
  });
}

const SERVICE_KEYS = new Set(['tech', 'product', 'port', 'title', 'version', 'service', 'cert', ...Object.keys(FLAG_KEYS)]);

/** Services of a host that satisfy the service-level terms of the query (for the match hint). */
function matchedServices(host: Host, q: string): Service[] {
  const terms = parseTerms(q).filter((t) => SERVICE_KEYS.has(t.key));
  if (terms.length === 0) return [];
  return (host.services || []).filter((s) => serviceMatches(s, terms));
}

function serviceShortLabel(s: Service, q = ""): string {
  const terms = parseTerms(q);
  if (terms.some((t) => t.key === "eol" && t.value !== "false") && s.outdated?.length) {
    return s.outdated.map((o) => `${o.product} ${o.version.split(" ")[0]} (EOL)`).join(", ");
  }
  if (terms.some((t) => (t.key === "vuln" || t.key === "cve") && t.value !== "false") && s.known_vulns?.length) {
    return s.known_vulns.map((v) => `${v.product} ${v.version.split(" ")[0]} ${v.id}`).join(", ");
  }
  const want = terms.filter((t) => t.key === "tech" || t.key === "product").flatMap((t) => t.value.split(","));
  const hit = want.length ? (s.technologies || []).find((t) => want.some((w) => t.name.toLowerCase().includes(w))) : undefined;
  if (hit) return [hit.name, (hit.version || "").split(" ")[0]].filter(Boolean).join(" ");
  const tech = [...(s.technologies || [])]
    .filter((t) => !['admin_panel', 'staging', 'custom', 'interesting_header', 'interesting_cookie'].includes(t.category))
    .sort((a, b) => b.confidence - a.confidence)[0];
  const name = tech?.name || s.product || s.service_name;
  const ver = tech?.version || (tech && s.product && !tech.version ? '' : s.version) || '';
  return [name, ver.split(' ')[0]].filter(Boolean).join(' ');
}

export function AssetsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();

  const initialView = searchParams.get('view');
  const [viewMode, setViewMode] = useState<ViewMode>(
    initialView === 'products' || initialView === 'clusters' ? initialView : 'table'
  );
  const [hosts, setHosts] = useState<Host[]>([]);
  const [totalHosts, setTotalHosts] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalPages, setTotalPages] = useState(1);
  const [clusters, setClusters] = useState<ServiceCluster[]>([]);
  const [clusterGroupBy, setClusterGroupBy] = useState<string>('');
  const [clusterLimit, setClusterLimit] = useState(CLUSTER_PAGE);
  const [inventory, setInventory] = useState<InventoryResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const [q, setQ] = useState(searchParams.get('q') || '');
  const [debouncedQ, setDebouncedQ] = useState(q.trim());
  const [stateFilter, setStateFilter] = useState(searchParams.get('state') || '');
  const [envFilter, setEnvFilter] = useState(searchParams.get('env') || '');
  const [minScore, setMinScore] = useState(Number(searchParams.get('min_score') || 0));
  const [queryError, setQueryError] = useState('');
  const [showQueryHelp, setShowQueryHelp] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<Host | null>(null);
  const [deleting, setDeleting] = useState(false);

  const inspectHostId = searchParams.get('host');

  const canDelete = can(PERMISSIONS.ASSETS_DELETE);
  const canExport = can(PERMISSIONS.EXPORT_READ);

  const { recentIPs } = useLiveEvents();

  /** Patch URL params (replace, so typing doesn't flood history). */
  const patchParams = useCallback(
    (patch: Record<string, string | null>, push = false) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch)) {
            if (v === null || v === '') next.delete(k);
            else next.set(k, v);
          }
          return next;
        },
        { replace: !push }
      );
    },
    [setSearchParams]
  );

  // Links into /assets?q=… while already on the page (badges, dashboard) update the filters.
  const urlQ = searchParams.get('q') || '';
  const urlState = searchParams.get('state') || '';
  const lastWrittenQ = useRef(urlQ);
  useEffect(() => {
    if (urlQ !== lastWrittenQ.current) {
      lastWrittenQ.current = urlQ;
      setQ(urlQ);
      setDebouncedQ(urlQ.trim());
    }
  }, [urlQ]);
  useEffect(() => {
    setStateFilter(urlState);
  }, [urlState]);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedQ(q.trim()), 300);
    return () => window.clearTimeout(t);
  }, [q]);

  useEffect(() => {
    if (debouncedQ !== (searchParams.get('q') || '')) {
      lastWrittenQ.current = debouncedQ;
      patchParams({ q: debouncedQ || null });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);

  useEffect(() => {
    setPage(1);
  }, [debouncedQ, stateFilter, envFilter, minScore, pageSize]);

  const loadInventory = useCallback(async () => {
    try {
      setInventory(await api.inventory());
    } catch {
      // the list still works without counts
    }
  }, []);

  useEffect(() => {
    loadInventory();
  }, [loadInventory]);

  const loadData = useCallback(
    async (silent?: boolean) => {
      if (viewMode === 'products') {
        setLoading(false);
        return;
      }
      if (!silent) setLoading(true);
      try {
        if (viewMode === 'table') {
          const res = await api.listHostSummaries({
            q: debouncedQ || undefined,
            state: stateFilter || undefined,
            env: envFilter || undefined,
            min_score: minScore > 0 ? minScore : undefined,
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
          toast.error('Could not load assets', (err as Error).message);
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [viewMode, debouncedQ, page, pageSize, stateFilter, envFilter, minScore, clusterGroupBy, toast]
  );

  useEffect(() => {
    loadData();
  }, [loadData]);

  useLiveRefresh(() => {
    loadData(true);
    loadInventory();
  });

  const switchView = (v: ViewMode) => {
    setViewMode(v);
    patchParams({ view: v === 'table' ? null : v });
  };

  const applyQuery = (next: string) => {
    setQ(next);
    setDebouncedQ(next.trim());
    lastWrittenQ.current = next.trim();
    patchParams({ q: next.trim() || null, view: null }, true);
    setViewMode('table');
  };

  const openHost = (id: string | null) => patchParams({ host: id }, Boolean(id));

  const handleDeleteHost = async () => {
    if (!confirmDelete) return;
    setDeleting(true);
    try {
      await api.deleteHost(confirmDelete.id);
      toast.success('Host deleted', confirmDelete.ip);
      setConfirmDelete(null);
      loadData();
      loadInventory();
    } catch (err) {
      toast.error('Could not delete host', (err as Error).message);
    } finally {
      setDeleting(false);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      await api.exportData({
        format,
        state: stateFilter || undefined,
      });
      toast.success(`Exported ${format.toUpperCase()}`);
    } catch (err) {
      toast.error('Export failed', (err as Error).message);
    }
  };

  const openHostByIP = async (ip: string) => {
    const match = hosts.find((h) => h.ip === ip);
    if (match) {
      openHost(match.id);
      return;
    }
    try {
      const res = await api.listHostSummaries({ q: ip, limit: 5 });
      const found = res.hosts.find((h) => h.ip === ip) || res.hosts[0];
      if (found) openHost(found.id);
    } catch {
      // ignore
    }
  };

  const quickCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const qf of inventory?.quick_filters || []) m[qf.key] = qf.count;
    return m;
  }, [inventory]);

  const activeChip = QUICK_FILTERS.find((c) => c.query === q.trim());
  const colCount = canDelete ? 9 : 8;

  return (
    <div>
      <PageHeader
        title="Assets"
        meta={
          <span className="font-mono tabular-nums">
            {viewMode === 'table'
              ? plural(totalHosts, 'host')
              : viewMode === 'products'
                ? plural(inventory?.products.length || 0, 'product')
                : plural(clusters.length, 'cluster')}
          </span>
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
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => {
                loadData();
                loadInventory();
              }}
              aria-label="Refresh"
            >
              <RiRefreshLine className={cn(loading && 'animate-spin')} />
            </Button>
          </>
        }
      />

      <Tabs value={viewMode} onValueChange={(v) => switchView(v as ViewMode)} className="gap-0">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-border">
          <TabsList variant="line" className="-mb-px">
            <TabsTrigger value="table">
              Hosts <span className="font-mono text-muted-foreground tabular-nums">{formatNumber(inventory?.total_hosts ?? totalHosts)}</span>
            </TabsTrigger>
            <TabsTrigger value="products">
              Products{' '}
              <span className="font-mono text-muted-foreground tabular-nums">
                {inventory ? formatNumber(inventory.products.length) : ''}
              </span>
            </TabsTrigger>
            <TabsTrigger value="clusters">Clusters</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="table" className="pt-5">
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            {QUICK_FILTERS.map((c) => {
              const active = activeChip?.key === c.key;
              const count = quickCounts[c.key];
              const meta = c.kind ? CATEGORY_META[c.kind] : null;
              const Icon = meta?.icon ?? RiSparklingLine;
              return (
                <button
                  key={c.key}
                  type="button"
                  onClick={() => applyQuery(active ? '' : c.query)}
                  aria-pressed={active}
                  title={meta?.hint || 'Hosts first seen in the latest scan'}
                  disabled={count === 0 && !active}
                  className={cn(
                    'inline-flex h-7 items-center gap-1.5 border px-2 text-[11px] font-medium transition-colors disabled:opacity-40',
                    active
                      ? 'border-foreground bg-foreground text-background'
                      : 'border-border bg-card text-foreground hover:border-foreground/40'
                  )}
                >
                  <Icon className={cn('size-3.5', !active && (meta ? meta.tone.split(' ').slice(0, 2).join(' ') : 'text-sky-600 dark:text-sky-400'))} />
                  {c.label}
                  {count !== undefined && (
                    <span className={cn('font-mono tabular-nums', active ? 'opacity-70' : 'text-muted-foreground')}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-3">
            <div className="relative min-w-[280px] flex-1">
              <RiSearchLine className="pointer-events-none absolute top-1/2 left-0 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder='IP, hostname, or tech:wordpress port:3389 eol:true'
                className="pr-24 pl-6 font-mono"
                aria-invalid={queryError ? true : undefined}
              />
              <div className="absolute top-1/2 right-0 flex -translate-y-1/2 items-center gap-1">
                {q && (
                  <button
                    type="button"
                    onClick={() => applyQuery('')}
                    className="text-muted-foreground hover:text-foreground"
                    aria-label="Clear search"
                  >
                    <RiCloseLine className="size-4" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowQueryHelp((v) => !v)}
                  className={cn(
                    'inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground',
                    showQueryHelp && 'text-foreground'
                  )}
                  aria-expanded={showQueryHelp}
                >
                  <RiQuestionLine className="size-4" />
                  Syntax
                  {showQueryHelp ? <RiArrowUpSLine className="size-3.5" /> : <RiArrowDownSLine className="size-3.5" />}
                </button>
              </div>
            </div>
            <SimpleSelect
              size="sm"
              className="w-40"
              value={toSel(stateFilter)}
              onValueChange={(v) => {
                setStateFilter(fromSel(v));
                patchParams({ state: fromSel(v) || null });
              }}
              options={STATE_OPTIONS}
            />
            <SimpleSelect
              size="sm"
              className="w-40"
              value={toSel(envFilter)}
              onValueChange={(v) => setEnvFilter(fromSel(v))}
              options={ENV_OPTIONS}
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
                className="w-24 accent-foreground"
              />
              <span className="w-6 font-mono text-xs text-foreground tabular-nums">{minScore}</span>
            </label>
          </div>

          {queryError && <p className="-mt-2 mb-3 font-mono text-xs text-destructive">{queryError}</p>}
          {showQueryHelp && (
            <AssetQueryHelp onPick={(snippet) => setQ((prev) => (prev.trim() ? `${prev.trim()} ${snippet}` : snippet))} />
          )}

          <div className="border border-border bg-card">
            <Table className="table-fixed">
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[17%] pl-4">Host</TableHead>
                  <TableHead className="w-[19%]">Device / OS</TableHead>
                  <TableHead className="w-[12%]">State</TableHead>
                  <TableHead className="w-[14%]">Owner</TableHead>
                  <TableHead className="w-[14%]">Services</TableHead>
                  <TableHead className="w-[11%]">Risk</TableHead>
                  <TableHead className="w-16">Score</TableHead>
                  <TableHead className="w-20">Last seen</TableHead>
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
                      <Empty bird>{q ? 'No host matches this query' : 'Nothing pecked here yet'}</Empty>
                    </TableCell>
                  </TableRow>
                ) : (
                  hosts.map((h) => (
                    <HostRow
                      key={`${h.id}-${recentIPs[h.ip] ?? ''}`}
                      host={h}
                      q={debouncedQ}
                      live={Boolean(recentIPs[h.ip])}
                      canDelete={canDelete}
                      onOpen={() => openHost(h.id)}
                      onDelete={() => setConfirmDelete(h)}
                      onQuery={applyQuery}
                    />
                  ))
                )}
              </TableBody>
            </Table>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-2.5">
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {totalHosts === 0
                  ? '0 hosts'
                  : `${formatNumber((page - 1) * pageSize + 1)}-${formatNumber(
                      Math.min(page * pageSize, totalHosts)
                    )} of ${plural(totalHosts, 'host')}`}
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
                  aria-label="Previous page"
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
                  aria-label="Next page"
                >
                  <RiArrowRightSLine />
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="products" className="pt-5">
          <ProductInventory products={inventory?.products || null} loading={!inventory} onQuery={applyQuery} />
        </TabsContent>

        <TabsContent value="clusters" className="pt-5">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <SimpleSelect
              size="sm"
              className="w-56"
              value={toSel(clusterGroupBy)}
              onValueChange={(v) => {
                setClusterGroupBy(fromSel(v));
                setClusterLimit(CLUSTER_PAGE);
              }}
              options={CLUSTER_OPTIONS}
            />
            <span className="text-xs text-muted-foreground">
              Services that share a favicon, technology stack, page title or TLS issuer, likely the same
              deployment.
            </span>
          </div>

          <div className="border border-border bg-card">
            <Table className="table-fixed">
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[30%] pl-4">Cluster</TableHead>
                  <TableHead className="w-28">Grouped by</TableHead>
                  <TableHead className="w-20 text-right">Services</TableHead>
                  <TableHead className="w-24">Max score</TableHead>
                  <TableHead className="w-[20%]">Technologies</TableHead>
                  <TableHead className="pr-4">Hosts</TableHead>
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
                      <Empty>No clusters</Empty>
                    </TableCell>
                  </TableRow>
                ) : (
                  clusters.slice(0, clusterLimit).map((cl) => (
                    <TableRow key={cl.cluster_key}>
                      <TableCell className="pl-4">
                        <div className="flex min-w-0 items-center gap-2.5">
                          <ServiceLogo names={[...(cl.sample_techs || []), cl.label]} size="sm" />
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium text-foreground" title={cl.label}>
                              {cl.label}
                            </div>
                            <div className="truncate font-mono text-[11px] text-muted-foreground" title={cl.cluster_key}>
                              {cl.cluster_key}
                            </div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Pill className="font-mono">{cl.group_by}</Pill>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{cl.count}</TableCell>
                      <TableCell>
                        <Pill className={cn('font-mono tabular-nums', scoreColor(cl.max_interestingness))}>
                          {cl.max_interestingness}
                        </Pill>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 overflow-hidden">
                          {(cl.sample_techs || []).slice(0, 5).map((t) => (
                            <ServiceLogo key={t} name={t} size="xs" />
                          ))}
                          {(cl.sample_techs?.length || 0) > 5 && (
                            <span className="text-[11px] text-muted-foreground">+{(cl.sample_techs?.length || 0) - 5}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="pr-4">
                        <div className="flex items-center gap-1 overflow-hidden">
                          {(cl.host_ips || []).slice(0, 4).map((ip) => (
                            <button
                              key={ip}
                              type="button"
                              onClick={() => openHostByIP(ip)}
                              className="shrink-0 border border-border px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-foreground/40"
                            >
                              {ip}
                            </button>
                          ))}
                          {(cl.host_ips?.length || 0) > 4 && (
                            <span className="shrink-0 text-[11px] text-muted-foreground">+{cl.host_ips.length - 4}</span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {clusters.length > clusterLimit && (
              <div className="flex items-center justify-between border-t border-border px-4 py-2.5 text-xs text-muted-foreground">
                <span>
                  Showing {clusterLimit} of {clusters.length}
                </span>
                <Button variant="outline" size="xs" onClick={() => setClusterLimit((n) => n + CLUSTER_PAGE)}>
                  Show more
                </Button>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>

      <Dialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete host {confirmDelete?.ip}?</DialogTitle>
            <DialogDescription>
              The host, its {plural(confirmDelete?.service_count || 0, 'service')}, overrides and triage decisions are
              removed. It reappears as NEW if a later scan finds it again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={deleting} onClick={handleDeleteHost}>
              <RiDeleteBinLine data-icon="inline-start" />
              {deleting ? 'Deleting…' : 'Delete host'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AssetInspectorDrawer hostId={inspectHostId} onClose={() => openHost(null)} onUpdated={loadData} />
    </div>
  );
}

function HostRow({
  host: h,
  q,
  live,
  canDelete,
  onOpen,
  onDelete,
  onQuery,
}: {
  host: Host;
  q: string;
  live: boolean;
  canDelete: boolean;
  onOpen: () => void;
  onDelete: () => void;
  onQuery: (q: string) => void;
}) {
  const lc = lifecycleMeta(h.lifecycle_state);
  const hasLocked = (h.locked_fields?.length || 0) > 0;
  const id = hostIdentity(h);
  const idLabel = identityLabel(id);
  const flags = hostFlags(h.services);
  const matched = q ? matchedServices(h, q) : [];
  const services = [...(h.services || [])].sort((a, b) => b.interestingness - a.interestingness);
  const unstable = h.stability_score < 100 && h.total_scans_checked > 1;

  return (
    <TableRow onClick={onOpen} className={cn('group cursor-pointer', live && 'animate-live-row')}>
      <TableCell className="pl-4">
        <div className="flex items-center gap-1.5">
          {live && <span className="size-1.5 shrink-0 animate-pulse bg-emerald-500" aria-hidden />}
          <span className="font-mono text-sm font-medium text-foreground">{h.ip}</span>
          {hasLocked && (
            <span title={`Analyst overrides: ${h.locked_fields!.join(', ')}`} className="text-muted-foreground">
              <RiLockLine className="size-3.5" />
            </span>
          )}
        </div>
        {h.hostname && (
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={h.hostname}>
            {h.hostname}
          </div>
        )}
        {matched.length > 0 && (
          <div
            className="mt-0.5 truncate text-[11px] text-sky-700 dark:text-sky-300"
            title={matched.map((s) => `:${s.port} ${serviceShortLabel(s, q)}`).join('\n')}
          >
            ↳ {matched.slice(0, 2).map((s) => `${serviceShortLabel(s, q)} :${s.port}`).join(', ')}
            {matched.length > 2 && ` +${matched.length - 2}`}
          </div>
        )}
      </TableCell>

      <TableCell>
        {idLabel || id.os ? (
          <div className="flex min-w-0 items-center gap-2" title={id.evidence ? `From ${id.evidence}` : undefined}>
            <ServiceLogo names={id.logoNames} size="xs" title={false} />
            <div className="min-w-0">
              <div className="truncate text-xs text-foreground">{idLabel || id.os}</div>
              <div className="truncate text-[11px] text-muted-foreground">
                {[id.kind, idLabel && id.os && !id.os.startsWith(id.product || '¤') ? id.os : null].filter(Boolean).join(' · ') ||
                  ''}
              </div>
            </div>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground/60">unidentified</span>
        )}
      </TableCell>

      <TableCell>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-wider uppercase">
            <span className={cn('size-2 shrink-0', lc.dot)} aria-hidden />
            {lc.label}
          </span>
          <TriageBadge triage={h.triage} />
        </div>
        {unstable && (
          <div className="mt-0.5 font-mono text-[11px] text-amber-700 dark:text-amber-400" title="Share of scans in which the host answered">
            seen {h.total_scans_seen}/{h.total_scans_checked} scans
          </div>
        )}
      </TableCell>

      <TableCell>
        {h.owner ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onQuery(`owner:${h.owner!.includes(' ') ? `"${h.owner}"` : h.owner}`);
            }}
            className="block max-w-full truncate text-left text-xs text-foreground hover:underline"
            title={`All hosts owned by ${h.owner}`}
          >
            {h.owner}
          </button>
        ) : (
          <span className="text-xs text-muted-foreground/60">no owner</span>
        )}
        <div className="truncate text-[11px] text-muted-foreground">
          {h.environment ? envLabel(h.environment) : ''}
          {(h.tags?.length || 0) > 0 && (
            <span title={h.tags!.map((t) => `#${t}`).join(' ')}>
              {h.environment ? ' · ' : ''}
              {h.tags!.slice(0, 2).map((t) => `#${t}`).join(' ')}
              {h.tags!.length > 2 && ` +${h.tags!.length - 2}`}
            </span>
          )}
        </div>
      </TableCell>

      <TableCell>
        <div className="flex items-center gap-1 overflow-hidden">
          {services.slice(0, 3).map((s) => (
            <ServiceLogoFor key={s.id} service={s} size="xs" />
          ))}
          <span className="ml-1 font-mono text-xs tabular-nums" title={services.map((s) => `${s.port}/${s.service_name}`).join(", ")}>
            {h.service_count ?? services.length}
          </span>
        </div>
      </TableCell>

      <TableCell>
        <CategoryBadges flags={flags} size="xs" max={4} />
      </TableCell>

      <TableCell>
        <Pill className={cn('font-mono tabular-nums', scoreColor(h.interestingness))}>{h.interestingness}</Pill>
      </TableCell>

      <TableCell className="font-mono text-[11px] text-muted-foreground">{formatRelativeTime(h.last_seen)}</TableCell>

      {canDelete && (
        <TableCell className="pr-4 text-right" onClick={(e: React.MouseEvent) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button variant="ghost" size="icon-xs" aria-label="Host actions" className="text-muted-foreground" />
              }
            >
              <RiMore2Line />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              <DropdownMenuItem onClick={onOpen}>Open details</DropdownMenuItem>
              <DropdownMenuItem variant="destructive" onClick={onDelete}>
                <RiDeleteBinLine />
                Delete host…
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </TableCell>
      )}
    </TableRow>
  );
}
