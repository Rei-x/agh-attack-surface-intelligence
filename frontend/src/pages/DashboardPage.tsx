import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { RiArrowRightUpLine, RiNodeTree, RiRefreshLine, RiSendPlaneLine } from '@remixicon/react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Label, Pie, PieChart, XAxis, YAxis } from 'recharts';
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
import {
  formatNumber,
  formatRelativeTime,
  lifecycleMeta,
  scoreColor,
  severityMeta,
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
import { Empty, PageHeader, Pill, Stat, StatStrip } from '@/components/common';
import { LiveTelemetryBanner } from '@/components/LiveTelemetryBanner';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import { ServiceLogo, ServiceLogoFor, serviceLogoNames } from '@/components/ServiceLogo';
import { EolBadges, changeOwner } from '@/components/EolBadges';
import type { DashboardSummary, Service } from '@/types/api';

type SeriesKey = 'active_hosts' | 'services_found' | 'changes_detected';
const SERIES_KEYS: SeriesKey[] = ['active_hosts', 'services_found', 'changes_detected'];

const timelineConfig = {
  active_hosts: {
    label: 'Aktywne hosty',
    theme: { light: AGH_COLORS.green, dark: '#2fb47c' },
  },
  services_found: { label: 'Usługi', color: 'var(--chart-2)' },
  changes_detected: {
    label: 'Zmiany',
    theme: { light: AGH_COLORS.crimson, dark: '#f0506e' },
  },
} satisfies ChartConfig;

const LIFECYCLE_ORDER = ['ACTIVE', 'NEW', 'INTERMITTENT', 'MISSING', 'INACTIVE', 'REACTIVATED'];
const lifecycleConfig = Object.fromEntries(
  LIFECYCLE_ORDER.map((s) => [s, { label: s, color: lifecycleMeta(s).stroke }])
) satisfies ChartConfig;

const RISK_LABEL_W = 136;
const riskConfig ={ score: { label: 'Max score' }, count: { label: 'Usługi' } } satisfies ChartConfig;

function scoreFill(score: number): string {
  if (score >= 75) return '#f43f5e';
  if (score >= 50) return '#f59e0b';
  if (score >= 25) return '#0ea5e9';
  return '#a8a29e';
}

interface RiskRow {
  name: string;
  score: number;
  count: number;
  logoNames: string[];
  port?: number;
}

/** Group top findings by technology → max score + count. */
function buildRiskRows(services: Service[]): RiskRow[] {
  const rows = new Map<string, RiskRow>();
  for (const svc of services) {
    const name = (svc.product || svc.service_name || `port ${svc.port}`).trim();
    const key = name.toLowerCase();
    const row = rows.get(key);
    if (row) {
      row.count += 1;
      row.score = Math.max(row.score, svc.interestingness);
    } else {
      rows.set(key, {
        name,
        score: svc.interestingness,
        count: 1,
        logoNames: serviceLogoNames(svc),
        port: svc.port,
      });
    }
  }
  return [...rows.values()].sort((a, b) => b.score - a.score || b.count - a.count).slice(0, 6);
}

const cardTitleCls = 'text-xs tracking-widest text-muted-foreground';

export function DashboardPage() {
  const { can } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [pushingId, setPushingId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);
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
      const data = await api.dashboardSummary();
      setSummary(data);
    } catch (err) {
      toast.error('Błąd ładowania podsumowania', (err as Error).message);
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
    services_found: pt.services_found ?? pt.services ?? 0,
    changes_detected: pt.changes_detected ?? pt.changes ?? 0,
  }));

  const lifecycleBreakdown = summary?.lifecycle_breakdown || {};
  const lifecycleData = LIFECYCLE_ORDER.map((state) => ({
    state,
    value: lifecycleBreakdown[state] ?? 0,
    fill: `var(--color-${state})`,
  }));
  const lifecycleSum = lifecycleData.reduce((a, d) => a + d.value, 0);

  const riskRows = buildRiskRows(topFindings);

  const handlePushToDefectDojo = async (svc: Service) => {
    setPushingId(svc.id);
    try {
      await api.pushDefectDojoFindings({
        service_ids: [svc.id],
        severity: svc.interestingness >= 75 ? 'High' : svc.interestingness >= 50 ? 'Medium' : 'Low',
      });
      toast.success('Wysłano do DefectDojo', `${svc.host_ip || ''}:${svc.port}`);
    } catch (err) {
      toast.error('Błąd wysyłki do DefectDojo', (err as Error).message);
    } finally {
      setPushingId(null);
    }
  };

  const canPush = can(PERMISSIONS.DEFECTDOJO_PUSH);

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        className="pb-0"
        title="Przegląd"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={loadSummary}>
              <RiRefreshLine className={cn(loading && 'animate-spin')} />
              Odśwież
            </Button>
            <Button size="sm" nativeButton={false} render={<Link to="/graph" />}>
              <RiNodeTree />
              Graf
            </Button>
          </>
        }
      />

      <LiveTelemetryBanner activeScan={summary?.active_scan} onScanUpdated={loadSummary} />

      <StatStrip>
        <Stat label="Zakres IP" value={formatNumber(totalIPs)} />
        <Stat label="Aktywne hosty" value={formatNumber(activeHosts)} />
        <Stat
          label="Niestabilne"
          value={formatNumber(unstableHosts)}
          tone={unstableHosts > 0 ? 'warning' : undefined}
        />
        <Stat label="Usługi" value={formatNumber(servicesCount)} />
        <Stat label="Zmiany" value={formatNumber(recentChangesCount)} />
        <Stat
          label="Score ≥ 50"
          value={formatNumber(interestingFindingsCount)}
          tone={interestingFindingsCount > 0 ? 'danger' : undefined}
        />
      </StatStrip>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Card size="sm" className="xl:col-span-8">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Historia skanów</CardTitle>
            <CardAction>
              <Button variant="link" size="xs" className="px-0" nativeButton={false} render={<Link to="/diff" />}>
                Diff <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            {timeline.length === 0 ? (
              <Empty bird className="h-64">Brak historii · dzięcioł jeszcze nie stukał</Empty>
            ) : (
              <ChartContainer config={timelineConfig} className="aspect-auto h-64 w-full">
                <AreaChart data={timeline} margin={{ top: 0, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    {SERIES_KEYS.map((key) => (
                      <linearGradient key={key} id={`fill-${key}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={`var(--color-${key})`} stopOpacity={0.32} />
                        <stop offset="100%" stopColor={`var(--color-${key})`} stopOpacity={0.02} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} minTickGap={24} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} tickMargin={4} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="line" />} />
                  {SERIES_KEYS.map((key) => (
                    <Area
                      key={key}
                      dataKey={key}
                      type="monotone"
                      hide={hiddenSeries.has(key)}
                      stroke={`var(--color-${key})`}
                      strokeWidth={1.75}
                      strokeDasharray={key === 'changes_detected' ? '4 3' : undefined}
                      fill={`url(#fill-${key})`}
                      activeDot={{ r: 3, strokeWidth: 0 }}
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
                              onClick={() => toggleSeries(key)}
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
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card size="sm" className="xl:col-span-4">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Stany hostów</CardTitle>
            <CardAction>
              <Button variant="link" size="xs" className="px-0" nativeButton={false} render={<Link to="/assets" />}>
                Zasoby <RiArrowRightUpLine />
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
                            hostów
                          </tspan>
                        </text>
                      ) : null
                    }
                  />
                </Pie>
              </PieChart>
            </ChartContainer>
            <ul className="grid w-full grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-1 xl:grid-cols-2 2xl:grid-cols-1">
              {lifecycleData.map((d) => (
                <li
                  key={d.state}
                  className={cn(
                    'flex items-center justify-between gap-2 text-[11px]',
                    d.value === 0 && 'opacity-50'
                  )}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="size-2 shrink-0" style={{ backgroundColor: lifecycleMeta(d.state).stroke }} />
                    <span className="truncate font-mono text-muted-foreground">{d.state}</span>
                  </span>
                  <span className="font-mono tabular-nums">{d.value}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Card size="sm" className="xl:col-span-7">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Priorytety</CardTitle>
            <CardAction className="flex items-center gap-3">
              {(summary?.accepted_risk_count || 0) > 0 && (
                <Button
                  variant="link"
                  size="xs"
                  className="px-0 text-muted-foreground"
                  nativeButton={false}
                  render={<Link to={`/assets?q=${encodeURIComponent('triage:accepted_risk,false_positive')}`} />}
                  title="Zaakceptowane ryzyka i false positive są pominięte w priorytetach"
                >
                  {summary!.accepted_risk_count} zaakceptowanych
                </Button>
              )}
              <Button
                variant="link"
                size="xs"
                className="px-0"
                nativeButton={false}
                render={<Link to="/assets?min_score=50" />}
              >
                Wszystkie <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {topFindings.length === 0 ? (
              <Empty bird>Cisza w dziupli · brak znalezisk</Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="h-9 w-14 pl-5 text-[10px]">Score</TableHead>
                    <TableHead className="h-9 text-[10px]">Endpoint</TableHead>
                    <TableHead className="h-9 text-[10px]">Usługa</TableHead>
                    <TableHead className="h-9 pr-5 text-right text-[10px]" />
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
                        <Pill className={cn('font-mono', scoreColor(svc.interestingness))}>
                          {svc.interestingness}
                        </Pill>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-medium">
                        {svc.host_ip || svc.host_id}:{svc.port}
                      </TableCell>
                      <TableCell className="max-w-[16rem]">
                        <div className="flex items-center gap-2">
                          <ServiceLogoFor service={svc} size="sm" />
                          <span
                            className="truncate text-xs text-muted-foreground"
                            title={
                              svc.interesting_factors
                                ?.map((f) => `+${f.points} ${f.reason}`)
                                .join('\n') || undefined
                            }
                          >
                            {svc.http?.title || svc.product || svc.service_name}
                          </span>
                          {svc.is_admin_panel && <Pill tone="danger">Admin</Pill>}
                          {svc.is_staging_env && <Pill tone="warning">Staging</Pill>}
                          <EolBadges service={svc} />
                        </div>
                      </TableCell>
                      <TableCell className="pr-5 text-right">
                        <div
                          className="flex items-center justify-end gap-1"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Button
                            variant="ghost"
                            size="xs"
                            onClick={() => setInspectHostId(svc.host_id)}
                          >
                            Dowody
                          </Button>
                          {canPush && (
                            <Button
                              variant="outline"
                              size="xs"
                              disabled={pushingId === svc.id}
                              onClick={() => handlePushToDefectDojo(svc)}
                              title="Wyślij do DefectDojo"
                            >
                              <RiSendPlaneLine className={cn(pushingId === svc.id && 'animate-pulse')} />
                              DefectDojo
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {(summary?.expired_acceptances?.length || 0) > 0 && (
              <div className="mx-5 mt-3 border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs">
                <div className="mb-1.5 font-semibold text-amber-700 dark:text-amber-300">
                  Wygasłe akceptacje ryzyka ({summary!.expired_acceptances!.length}) · do ponownej oceny
                </div>
                <div className="flex flex-wrap gap-1">
                  {summary!.expired_acceptances!.slice(0, 12).map((ea) => (
                    <button
                      key={`${ea.host_id}-${ea.service_id || 'host'}`}
                      type="button"
                      onClick={() => setInspectHostId(ea.host_id)}
                      title={ea.triage?.reason}
                      className="border border-border bg-card px-1.5 py-0.5 font-mono text-[11px] text-foreground transition-colors hover:border-primary hover:text-primary"
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
        <Card size="sm">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Ryzyko wg technologii</CardTitle>
          </CardHeader>
          <CardContent>
            {riskRows.length === 0 ? (
              <Empty>Brak danych</Empty>
            ) : (
              <ChartContainer
                config={riskConfig}
                className="aspect-auto w-full"
                style={{ height: riskRows.length * 32 }}
              >
                <BarChart
                  data={riskRows}
                  layout="vertical"
                  margin={{ top: 0, right: 28, left: 0, bottom: 0 }}
                  barSize={14}
                >
                  <XAxis type="number" dataKey="score" domain={[0, 100]} hide />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={RISK_LABEL_W}
                    tickLine={false}
                    axisLine={false}
                    tick={({ x, y, payload, index }) => {
                      const row = riskRows[index];
                      return (
                        <foreignObject x={Number(x) - RISK_LABEL_W} y={Number(y) - 11} width={RISK_LABEL_W - 8} height={22}>
                          <div className="flex h-full items-center gap-2">
                            <ServiceLogo names={row?.logoNames} port={row?.port} size="xs" title={false} />
                            <span className="truncate text-[11px] text-muted-foreground">{payload.value}</span>
                          </div>
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
                          const row = item.payload as RiskRow;
                          return (
                            <div className="flex w-full justify-between gap-4 font-mono tabular-nums">
                              <span className="text-muted-foreground">score {row.score}</span>
                              <span>{row.count}×</span>
                            </div>
                          );
                        }}
                      />
                    }
                  />
                  <Bar
                    dataKey="score"
                    radius={2}
                    background={{ fill: 'var(--muted)', radius: 2 }}
                    label={{ position: 'right', offset: 6, className: 'fill-foreground font-mono text-[11px]' }}
                  >
                    {riskRows.map((r) => (
                      <Cell key={r.name} fill={scoreFill(r.score)} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card size="sm">
          <CardHeader>
            <CardTitle className={cardTitleCls}>Ostatnie zmiany</CardTitle>
            <CardAction>
              <Button variant="link" size="xs" className="px-0" onClick={() => navigate('/diff')}>
                Diff <RiArrowRightUpLine />
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {(summary?.recent_changes?.length || 0) === 0 ? (
              <Empty bird>Stuk, stuk… bez zmian</Empty>
            ) : (
              <ul className="divide-y divide-border border-t border-border">
                {summary!.recent_changes!.slice(0, 5).map((ch) => {
                  const sev = severityMeta(ch.severity);
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
                          {ch.is_time_anomaly && <Pill tone="danger">TIME_ANOMALY</Pill>}
                        </div>
                        <span className="shrink-0 text-[11px] text-muted-foreground">
                          {formatRelativeTime(ch.created_at)}
                        </span>
                      </div>
                      <p className="truncate text-xs text-muted-foreground">
                        {ch.summary}
                        {changeOwner(ch.after) && ` · właściciel: ${changeOwner(ch.after)}`}
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
