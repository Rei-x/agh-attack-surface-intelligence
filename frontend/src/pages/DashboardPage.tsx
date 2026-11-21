import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { RiArrowRightUpLine, RiNodeTree, RiRefreshLine, RiSendPlaneLine } from '@remixicon/react';
import { Bar, BarChart, CartesianGrid, Cell, Label, Line, LineChart, Pie, PieChart, XAxis, YAxis } from 'recharts';
import {
  ChartContainer,
  ChartLegend,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '@/components/ui/chart';
import { AGH_COLORS } from '@/components/AghLogo';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useLiveRefresh } from '@/context/LiveEventsContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { useDefectDojoStatus } from '@/lib/defectdojo';
import {
  assetsLink,
  eolLabel,
  formatNumber,
  formatRelativeTime,
  lifecycleMeta,
  plural,
  scoreColor,
  severityMeta,
  translateFactor,
} from '@/lib/format';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Empty, PageHeader, Pill, Stat, StatStrip } from '@/components/common';
import { LiveTelemetryBanner } from '@/components/LiveTelemetryBanner';
import { DigestCard } from '@/components/DigestCard';
import { NotifyOwnerButton } from '@/components/NotifyOwnerDialog';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { ServiceLogo, ServiceLogoFor } from '@/components/ServiceLogo';
import { CategoryBadges, serviceFlags } from '@/components/CategoryBadge';
import { PolicyViolationsCard } from '@/components/PolicyViolationsCard';
import { changeOwner } from '@/components/EolBadges';
import type { DashboardSummary, InventoryProduct, InventoryResponse, Service } from '@/types/api';

type SeriesKey = 'active_hosts' | 'services_found' | 'changes_detected';
const SERIES_KEYS: SeriesKey[] = ['active_hosts', 'services_found', 'changes_detected'];

const timelineConfig = {
  active_hosts: {
    label: 'Active hosts',
    theme: { light: AGH_COLORS.green, dark: '#2fb47c' },
  },
  services_found: { label: 'Services', color: 'var(--chart-2)' },
  changes_detected: {
    label: 'Changes',
    theme: { light: '#b45309', dark: '#f59e0b' },
  },
} satisfies ChartConfig;

const LIFECYCLE_ORDER = ['ACTIVE', 'NEW', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'];
const lifecycleConfig = Object.fromEntries(
  LIFECYCLE_ORDER.map((s) => [s, { label: lifecycleMeta(s).label, color: lifecycleMeta(s).stroke }])
) satisfies ChartConfig;

const RISK_LABEL_W = 150;
const riskConfig = { score: { label: 'Max score' } } satisfies ChartConfig;

function scoreFill(score: number): string {
  if (score >= 90) return '#f43f5e';
  if (score >= 75) return '#f97316';
  if (score >= 50) return '#f59e0b';
  if (score >= 25) return '#0ea5e9';
  return '#a8a29e';
}

/** Products ranked by their riskiest service, across all hosts (from the inventory). */
function buildRiskRows(products: InventoryProduct[]): InventoryProduct[] {
  return [...products]
    .filter((p) => p.max_score > 0)
    .sort((a, b) => b.max_score - a.max_score || b.host_count - a.host_count)
    .slice(0, 6);
}

const cardTitleCls = 'text-xs tracking-widest text-muted-foreground';

export function DashboardPage() {
  const { can } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [inventory, setInventory] = useState<InventoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [pushingId, setPushingId] = useState<string | null>(null);
  // The open host lives in the URL (?host=) so a drawer view can be shared as a link.
  const [searchParams, setSearchParams] = useSearchParams();
  const inspectHostId = searchParams.get('host');
  const setInspectHostId = (id: string | null) =>
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) next.set('host', id);
        else next.delete('host');
        return next;
      },
      { replace: !id }
    );
  const [hiddenSeries, setHiddenSeries] = useState<Set<SeriesKey>>(new Set());

  const toggleSeries = (key: SeriesKey) =>
    setHiddenSeries((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const loadSummary = useCallback(async () => {
    try {
      const [data, inv] = await Promise.all([api.dashboardSummary(), api.inventory().catch(() => null)]);
      setSummary(data);
      if (inv) setInventory(inv);
    } catch (err) {
      toast.error('Could not load the overview', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  // Silent background refresh on live data changes
  useLiveRefresh(loadSummary);

  const kpis = summary?.kpis || {};
  const rawIPs = kpis.total_ips ?? kpis.scope_ips ?? summary?.total_ips ?? summary?.scope_ips ?? 0;
  // Overlapping scan profiles (a /22 inside a /18) are counted once.
  const totalIPs = inventory?.scope?.ips ?? rawIPs;
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
    scan_id: pt.scan_id,
    active_hosts: pt.active_hosts ?? 0,
    services_found: pt.services_found ?? pt.services ?? 0,
    changes_detected: pt.changes_detected ?? pt.changes ?? 0,
  }));

  const openTimelinePoint = (idx: number) => {
    const cur = timeline[idx];
    if (!cur?.scan_id) return;
    const prev = idx > 0 ? timeline[idx - 1]?.scan_id : undefined;
    navigate(prev ? `/diff?from=${prev}&to=${cur.scan_id}` : `/scans?scan=${cur.scan_id}`);
  };

  const lifecycleBreakdown = summary?.lifecycle_breakdown || {};
  const lifecycleData = LIFECYCLE_ORDER.map((state) => ({
    state,
    value: lifecycleBreakdown[state] ?? 0,
    fill: `var(--color-${state})`,
  }));
  const lifecycleSum = lifecycleData.reduce((a, d) => a + d.value, 0);

  const riskRows = useMemo(() => buildRiskRows(inventory?.products || []), [inventory]);

  const canPush = can(PERMISSIONS.DEFECTDOJO_PUSH);
  const dd = useDefectDojoStatus(canPush);

  const handlePushToDefectDojo = async (svc: Service) => {
    setPushingId(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success('Sent to DefectDojo', `${svc.host_ip || ''}:${svc.port}`);
    } catch (err) {
      toast.error('DefectDojo push failed', (err as Error).message);
    } finally {
      setPushingId(null);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        className="pb-0"
        title="Overview"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={loadSummary}>
              <RiRefreshLine className={cn(loading && 'animate-spin')} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" nativeButton={false} render={<Link to="/graph" />}>
              <RiNodeTree />
              Graph
            </Button>
          </>
        }
      />

      <LiveTelemetryBanner activeScan={summary?.active_scan} onScanUpdated={loadSummary} />

      <StatStrip>
        <Stat
          label="IP scope"
          value={formatNumber(totalIPs)}
          to="/scans"
          title={
            inventory?.scope && inventory.scope.raw_ips !== inventory.scope.ips
              ? `${formatNumber(inventory.scope.raw_ips)} before merging overlapping ranges`
              : 'Addresses covered by enabled scan profiles'
          }
        />
        <Stat
          label="Active hosts"
          value={formatNumber(activeHosts)}
          to={assetsLink('state:active,new,reactivated')}
        />
        <Stat
          label="Unstable"
          value={formatNumber(unstableHosts)}
          tone={unstableHosts > 0 ? 'warning' : undefined}
          to={assetsLink('state:intermittent,missing')}
        />
        <Stat label="Services" value={formatNumber(servicesCount)} to="/assets?view=products" />
        <Stat label="Changes" value={formatNumber(recentChangesCount)} to="/diff" title="Changes detected by the last scan" />
        <Stat
          label="Score ≥ 50"
          value={formatNumber(interestingFindingsCount)}
          tone={interestingFindingsCount > 0 ? 'warning' : undefined}
          to={assetsLink('score:>=50')}
          title="Services scoring 50 or more (accepted risks excluded)"
        />
      </StatStrip>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Card size="sm" className="xl:col-span-8">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Scan history</CardTitle>
            <CardAction>
              <Button variant="link" size="xs" className="px-0" nativeButton={false} render={<Link to="/diff" />}>
                Diff <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {timeline.length === 0 ? (
              <Empty bird className="h-64">No history yet · not a single peck</Empty>
            ) : (
              <>
                <ChartContainer config={timelineConfig} className="aspect-auto h-60 w-full">
                  <LineChart
                    data={timeline}
                    margin={{ top: 6, right: 8, left: -20, bottom: 0 }}
                    onClick={(s) => {
                      const idx = Number(s?.activeTooltipIndex ?? s?.activeIndex);
                      if (Number.isFinite(idx)) openTimelinePoint(idx);
                    }}
                    className="cursor-pointer"
                  >
                    <CartesianGrid vertical={false} strokeDasharray="3 3" />
                    <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} minTickGap={24} />
                    <YAxis tickLine={false} axisLine={false} allowDecimals={false} tickMargin={4} />
                    <ChartTooltip cursor={{ stroke: 'var(--border)' }} content={<ChartTooltipContent indicator="line" />} />
                    {SERIES_KEYS.map((key) => (
                      <Line
                        key={key}
                        dataKey={key}
                        type="linear"
                        hide={hiddenSeries.has(key)}
                        stroke={`var(--color-${key})`}
                        strokeWidth={1.75}
                        strokeDasharray={key === 'changes_detected' ? '4 3' : undefined}
                        dot={{ r: 3, strokeWidth: 0, fill: `var(--color-${key})` }}
                        activeDot={{ r: 5, strokeWidth: 0 }}
                        isAnimationActive={false}
                      />
                    ))}
                    <ChartLegend
                      verticalAlign="top"
                      align="right"
                      content={() => (
                        <div className="flex flex-wrap justify-end gap-1 pb-3">
                          {SERIES_KEYS.map((key) => {
                            const off = hiddenSeries.has(key);
                            return (
                              <button
                                key={key}
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleSeries(key);
                                }}
                                aria-pressed={!off}
                                className={cn(
                                  'flex items-center gap-1.5 px-1.5 py-0.5 text-[11px] transition-opacity hover:bg-muted',
                                  off ? 'text-muted-foreground opacity-50' : 'text-foreground'
                                )}
                              >
                                <span className="size-2" style={{ backgroundColor: `var(--color-${key})` }} />
                                {timelineConfig[key].label}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    />
                  </LineChart>
                </ChartContainer>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  Click a scan to see what changed since the previous one.
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card size="sm" className="xl:col-span-4">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Host states</CardTitle>
            <CardAction>
              <Button variant="link" size="xs" className="px-0" nativeButton={false} render={<Link to="/assets" />}>
                Assets <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-5 sm:flex-row xl:flex-col 2xl:flex-row">
            <ChartContainer config={lifecycleConfig} className="aspect-square h-44 shrink-0">
              <PieChart>
                {lifecycleSum > 0 && (
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel nameKey="state" />} />
                )}
                <Pie
                  data={lifecycleSum > 0 ? lifecycleData : [{ state: 'EMPTY', value: 1, fill: 'var(--muted)' }]}
                  dataKey="value"
                  nameKey="state"
                  innerRadius="70%"
                  outerRadius="100%"
                  paddingAngle={lifecycleSum > 0 ? 1.5 : 0}
                  stroke="none"
                  onClick={(d) => {
                    const st = (d as { state?: string })?.state;
                    if (st && st !== 'EMPTY') navigate(`/assets?state=${st}`);
                  }}
                  className="cursor-pointer"
                >
                  {(lifecycleSum > 0 ? lifecycleData : [{ fill: 'var(--muted)' }]).map((d, i) => (
                    <Cell key={i} fill={d.fill} />
                  ))}
                  <Label
                    content={({ viewBox }) =>
                      viewBox && 'cx' in viewBox && 'cy' in viewBox ? (
                        <text x={viewBox.cx} y={viewBox.cy} textAnchor="middle" dominantBaseline="middle">
                          <tspan
                            x={viewBox.cx}
                            y={Number(viewBox.cy) - 6}
                            className="fill-foreground font-mono text-2xl font-semibold tabular-nums"
                          >
                            {formatNumber(lifecycleSum)}
                          </tspan>
                          <tspan
                            x={viewBox.cx}
                            y={Number(viewBox.cy) + 15}
                            className="fill-muted-foreground text-[10px] tracking-widest uppercase"
                          >
                            {lifecycleSum === 1 ? 'host' : 'hosts'}
                          </tspan>
                        </text>
                      ) : null
                    }
                  />
                </Pie>
              </PieChart>
            </ChartContainer>
            <ul className="grid w-full grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-1 xl:grid-cols-2 2xl:grid-cols-1">
              {lifecycleData.map((d) => (
                <li key={d.state}>
                  <Link
                    to={`/assets?state=${d.state}`}
                    className={cn(
                      'flex items-center justify-between gap-2 px-1 py-0.5 text-[11px] transition-colors hover:bg-muted',
                      d.value === 0 && 'opacity-50'
                    )}
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="size-2 shrink-0" style={{ backgroundColor: lifecycleMeta(d.state).stroke }} />
                      <span className="truncate font-mono text-muted-foreground">{lifecycleMeta(d.state).label}</span>
                    </span>
                    <span className="font-mono tabular-nums">{d.value}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Card size="sm" className="xl:col-span-7">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Top findings</CardTitle>
            <CardAction className="flex items-center gap-3">
              {(summary?.accepted_risk_count || 0) > 0 && (
                <Button
                  variant="link"
                  size="xs"
                  className="px-0 text-muted-foreground"
                  nativeButton={false}
                  render={<Link to={assetsLink('triage:accepted_risk,false_positive')} />}
                  title="Accepted risks and false positives are left out of the priorities"
                >
                  {summary!.accepted_risk_count} accepted
                </Button>
              )}
              <Button
                variant="link"
                size="xs"
                className="px-0"
                nativeButton={false}
                render={<Link to={assetsLink('score:>=50')} />}
              >
                All <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {topFindings.length === 0 ? (
              <Empty bird>All quiet in the hollow · no findings</Empty>
            ) : (
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-9 w-16 pl-5 text-[10px]">Score</TableHead>
                    <TableHead className="h-9 w-40 text-[10px]">Endpoint</TableHead>
                    <TableHead className="h-9 text-[10px]">Service</TableHead>
                    <TableHead className="h-9 w-32 text-[10px]">Risk</TableHead>
                    <TableHead className="h-9 w-20 pr-5" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {topFindings.slice(0, 8).map((svc) => (
                    <TableRow
                      key={svc.id}
                      className="cursor-pointer"
                      onClick={() => setInspectHostId(svc.host_id)}
                    >
                      <TableCell className="pl-5">
                        <Pill
                          className={cn('font-mono', scoreColor(svc.interestingness))}
                          title={svc.interesting_factors?.map((f) => `+${f.points} ${translateFactor(f.reason)}`).join('\n')}
                        >
                          {svc.interestingness}
                        </Pill>
                      </TableCell>
                      <TableCell className="truncate font-mono text-xs font-medium">
                        {svc.host_ip || svc.host_id}:{svc.port}
                      </TableCell>
                      <TableCell>
                        <div className="flex min-w-0 items-center gap-2">
                          <ServiceLogoFor service={svc} size="sm" />
                          <span className="truncate text-xs text-muted-foreground">
                            {svc.http?.title || [svc.product, svc.version].filter(Boolean).join(' ') || svc.service_name}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <CategoryBadges flags={serviceFlags(svc)} size="xs" max={5} />
                      </TableCell>
                      <TableCell className="pr-5 text-right" onClick={(e) => e.stopPropagation()}>
                        <NotifyOwnerButton icon hostId={svc.host_id} serviceId={svc.id} />
                        {canPush && (
                          <Tooltip>
                            <TooltipTrigger
                              render={
                                <span className="inline-flex">
                                  <Button
                                    variant="ghost"
                                    size="icon-xs"
                                    disabled={!dd.ready || pushingId === svc.id}
                                    onClick={() => handlePushToDefectDojo(svc)}
                                    aria-label="Push to DefectDojo now"
                                    className="text-muted-foreground"
                                  >
                                    <RiSendPlaneLine className={cn(pushingId === svc.id && 'animate-pulse')} />
                                  </Button>
                                </span>
                              }
                            />
                            <TooltipContent>
                              {dd.ready ? 'Push to DefectDojo now (findings are also synced automatically)' : dd.reason}
                            </TooltipContent>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {(summary?.expired_acceptances?.length || 0) > 0 && (
              <div className="mx-5 mt-3 border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs">
                <div className="mb-1.5 font-semibold text-amber-700 dark:text-amber-300">
                  Expired risk acceptances ({summary!.expired_acceptances!.length}) · review again
                </div>
                <div className="flex flex-wrap gap-1">
                  {summary!.expired_acceptances!.slice(0, 12).map((ea) => (
                    <button
                      key={`${ea.host_id}-${ea.service_id || 'host'}`}
                      type="button"
                      onClick={() => setInspectHostId(ea.host_id)}
                      title={ea.triage?.reason}
                      className="border border-border bg-card px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-foreground/40"
                    >
                      {ea.host_ip}
                      {ea.port ? `:${ea.port}` : ''}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-6 xl:col-span-5">
          <PolicyViolationsCard titleClassName={cardTitleCls} />
          <DigestCard onOpenHost={setInspectHostId} />
          <Card size="sm">
            <CardHeader>
              <CardTitle className={cardTitleCls}>Risk by technology</CardTitle>
              <CardAction>
                <Button
                  variant="link"
                  size="xs"
                  className="px-0"
                  nativeButton={false}
                  render={<Link to="/assets?view=products" />}
                >
                  Products <RiArrowRightUpLine />
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent>
              {riskRows.length === 0 ? (
                <Empty>No data</Empty>
              ) : (
                <ChartContainer
                  config={riskConfig}
                  className="aspect-auto w-full"
                  style={{ height: riskRows.length * 32 }}
                >
                  <BarChart
                    data={riskRows}
                    layout="vertical"
                    margin={{ top: 0, right: 84, left: 0, bottom: 0 }}
                    barSize={14}
                  >
                    <XAxis type="number" dataKey="max_score" domain={[0, 100]} hide />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={RISK_LABEL_W}
                      tickLine={false}
                      axisLine={false}
                      tick={({ x, y, index }) => {
                        const row = riskRows[index];
                        if (!row) return <g />;
                        return (
                          <foreignObject x={Number(x) - RISK_LABEL_W} y={Number(y) - 11} width={RISK_LABEL_W - 8} height={22}>
                            <Link to={assetsLink(row.query)} className="flex h-full items-center gap-2 hover:underline">
                              <ServiceLogo names={row.logo_names} size="xs" title={false} />
                              <span className="truncate text-[11px] text-muted-foreground" title={row.name}>
                                {row.name.replace(/\s*\(.*\)$/, "")}
                              </span>
                            </Link>
                          </foreignObject>
                        );
                      }}
                    />
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          hideIndicator
                          formatter={(_v, _n, item) => {
                            const row = item.payload as InventoryProduct;
                            return (
                              <div className="flex w-full flex-col gap-0.5 font-mono tabular-nums">
                                <span>max score {row.max_score}</span>
                                <span className="text-muted-foreground">{plural(row.host_count, 'host')}</span>
                                {row.eol_count > 0 && <span className="text-muted-foreground">{row.eol_count} EOL</span>}
                              </div>
                            );
                          }}
                        />
                      }
                    />
                    <Bar
                      dataKey="max_score"
                      isAnimationActive={false}
                      radius={2}
                      background={{ fill: 'var(--muted)', radius: 2 }}
                      className="cursor-pointer"
                      onClick={(d) => {
                        const row = (d as { payload?: InventoryProduct })?.payload;
                        if (row) navigate(assetsLink(row.query));
                      }}
                      label={({ x, y, width, height, index }) => {
                        const row = riskRows[Number(index)];
                        if (!row) return null;
                        return (
                          <text
                            x={Number(x) + Number(width) + 6}
                            y={Number(y) + Number(height) / 2}
                            dominantBaseline="middle"
                            className="fill-foreground font-mono text-[11px]"
                          >
                            {row.max_score}
                            <tspan className="fill-muted-foreground"> · {row.host_count === 1 ? "1 host" : `${row.host_count} hosts`}</tspan>
                          </text>
                        );
                      }}
                    >
                      {riskRows.map((r) => (
                        <Cell key={r.name} fill={scoreFill(r.max_score)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ChartContainer>
              )}
            </CardContent>
          </Card>

          <Card size="sm">
            <CardHeader>
              <CardTitle className={cardTitleCls}>Recent changes</CardTitle>
              <CardAction>
                <Button variant="link" size="xs" className="px-0" onClick={() => navigate('/diff')}>
                  Diff <RiArrowRightUpLine />
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent className="px-0">
              {(summary?.recent_changes?.length || 0) === 0 ? (
                <Empty bird>Knock, knock… nothing changed</Empty>
              ) : (
                <ul className="divide-y divide-border border-t border-border">
                  {summary!.recent_changes!.slice(0, 5).map((ch) => {
                    const sev = severityMeta(ch.severity);
                    const owner = changeOwner(ch.after);
                    return (
                      <li
                        key={ch.id}
                        onClick={() => ch.host_id && setInspectHostId(ch.host_id)}
                        className="flex cursor-pointer flex-col gap-1 px-5 py-2.5 transition-colors hover:bg-muted/50"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex min-w-0 items-center gap-2">
                            <Pill className={sev.badge}>{sev.label}</Pill>
                            <span className="truncate font-mono text-xs font-medium">
                              {ch.host_ip}
                              {ch.port ? `:${ch.port}` : ''}
                            </span>
                            {ch.is_time_anomaly && (
                              <Pill tone="warning" title="Appeared outside the host's usual time window">
                                Off-hours
                              </Pill>
                            )}
                          </div>
                          <span className="shrink-0 text-[11px] text-muted-foreground">
                            {formatRelativeTime(ch.created_at)}
                          </span>
                        </div>
                        <p className="truncate text-xs text-muted-foreground">
                          {eolLabel(ch.summary)}
                          {owner && ` · owner: ${owner}`}
                        </p>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadSummary}
      />
    </div>
  );
}
