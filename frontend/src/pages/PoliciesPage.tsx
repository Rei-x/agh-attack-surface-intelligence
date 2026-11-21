import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  RiAddLine,
  RiArrowRightSLine,
  RiCodeLine,
  RiDeleteBinLine,
  RiRefreshLine,
  RiShieldCheckLine,
  RiShieldCrossLine,
} from '@remixicon/react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/context/ToastContext';
import { PERMISSIONS } from '@/lib/permissions';
import { assetsLink, formatNumber, formatRelativeTime, plural, queryTerm } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  policiesApi,
  policySeverityTone,
  ruleLabel,
  zonesToYaml,
  type PoliciesResponse,
  type PolicyCategoryMeta,
  type PolicyViolation,
  type PolicyZone,
  type ViolationsResponse,
} from '@/lib/policies';
import { Empty, Field, PageHeader, Pill, SimpleSelect, Stat, StatStrip } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const CUSTOM = 'custom';
const ROWS_PER_GROUP = 6;

type GroupBy = 'zone' | 'owner';

/**
 * Zone policies: where things may run. Each network zone has rules (allowed ports,
 * forbidden categories, no services at all). Every scan is checked against them and
 * breaches show up here, in Diff, the webhook and DefectDojo.
 */
export function PoliciesPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'zones' ? 'zones' : 'violations';
  const [config, setConfig] = useState<PoliciesResponse | null>(null);
  const [violations, setViolations] = useState<ViolationsResponse | null>(null);
  const [showResolved, setShowResolved] = useState(false);
  const toast = useToast();

  const loadViolations = useCallback(
    async (resolved = showResolved) => {
      try {
        setViolations(await policiesApi.violations(resolved ? 'all' : 'open'));
      } catch (err) {
        toast.error('Violations', (err as Error).message);
      }
    },
    [showResolved, toast]
  );

  const loadConfig = useCallback(async () => {
    try {
      setConfig(await policiesApi.list());
    } catch (err) {
      toast.error('Policies', (err as Error).message);
    }
  }, [toast]);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);
  useEffect(() => {
    loadViolations();
  }, [loadViolations]);

  const open = violations?.violations.filter((v) => v.status === 'open').length ?? config?.open_count ?? 0;

  return (
    <div>
      <PageHeader
        title="Policies"
        meta={
          violations?.evaluated_at && !violations.evaluated_at.startsWith('0001')
            ? `${plural(open, 'open violation')} · checked ${formatRelativeTime(violations.evaluated_at)}`
            : undefined
        }
      />
      <Tabs
        value={tab}
        onValueChange={(v) => setParams((p) => {
          const n = new URLSearchParams(p);
          if (v === 'zones') n.set('tab', 'zones');
          else n.delete('tab');
          return n;
        })}
        className="gap-6"
      >
        <TabsList variant="line">
          <TabsTrigger value="violations">Violations{open > 0 ? ` · ${formatNumber(open)}` : ''}</TabsTrigger>
          <TabsTrigger value="zones">Zones{config ? ` · ${config.zones.length}` : ''}</TabsTrigger>
        </TabsList>
        <TabsContent value="violations">
          <ViolationsView
            data={violations}
            categories={config?.categories || []}
            zonesCount={config?.zones.length ?? 0}
            showResolved={showResolved}
            onShowResolved={(v) => setShowResolved(v)}
            onRefresh={() => loadViolations()}
            onGoZones={() => setParams({ tab: 'zones' })}
          />
        </TabsContent>
        <TabsContent value="zones">
          {config && (
            <ZonesEditor
              config={config}
              openByZone={Object.fromEntries((violations?.by_zone || []).map((g) => [g.key, g.open]))}
              onSaved={(next) => {
                setConfig(next);
                loadViolations();
              }}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ------------------------------------------------------------------ violations */

function ViolationsView({
  data,
  categories,
  zonesCount,
  showResolved,
  onShowResolved,
  onRefresh,
  onGoZones,
}: {
  data: ViolationsResponse | null;
  categories: PolicyCategoryMeta[];
  zonesCount: number;
  showResolved: boolean;
  onShowResolved: (v: boolean) => void;
  onRefresh: () => void;
  onGoZones: () => void;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const [groupBy, setGroupBy] = useState<GroupBy>('zone');
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const groups = useMemo(() => {
    const m = new Map<string, { label: string; items: PolicyViolation[] }>();
    for (const v of data?.violations || []) {
      const key = groupBy === 'zone' ? v.zone_id : v.owner || '';
      const label = groupBy === 'zone' ? v.zone_name : v.owner || 'No owner';
      const g = m.get(key) || { label, items: [] };
      g.items.push(v);
      m.set(key, g);
    }
    return [...m.entries()]
      .map(([key, g]) => {
        const openItems = g.items.filter((v) => v.status === 'open');
        // Worst first: critical, then high, then volume.
        const weight = openItems.reduce((w, v) => w + ({ critical: 1e6, high: 1e3, medium: 1, low: 0 }[v.severity] ?? 0), 0);
        return { key, ...g, open: openItems.length, weight };
      })
      .sort((a, b) => b.weight - a.weight || a.label.localeCompare(b.label));
  }, [data, groupBy]);

  const recheck = async () => {
    setBusy(true);
    try {
      const res = await policiesApi.evaluate();
      toast.success('Checked', res.changes ? plural(res.changes, 'change') : 'No changes');
      onRefresh();
    } catch (err) {
      toast.error('Check failed', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!data) return <Empty bird>Loading</Empty>;
  const sev = data.by_severity || {};
  const openTotal = data.violations.filter((v) => v.status === 'open').length;

  return (
    <div className="space-y-6">
      <StatStrip>
        <Stat label="Open" value={formatNumber(openTotal)} to={assetsLink('violation:true')} title="Hosts with open violations" />
        <Stat
          label="Critical / high"
          value={`${formatNumber(sev.critical || 0)} / ${formatNumber(sev.high || 0)}`}
          tone={(sev.critical || 0) > 0 ? 'danger' : undefined}
        />
        <Stat label="Zones affected" value={formatNumber(data.by_zone.length)} hint={`of ${formatNumber(zonesCount)}`} />
        <Stat label="Owners" value={formatNumber(data.by_owner.length)} />
        <Stat label="Resolved (30 days)" value={formatNumber(data.resolved_count)} tone={data.resolved_count > 0 ? 'success' : undefined} />
      </StatStrip>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Group by</span>
          <div className="inline-flex border border-border">
            {(['zone', 'owner'] as GroupBy[]).map((g) => (
              <button
                key={g}
                type="button"
                onClick={() => setGroupBy(g)}
                className={cn(
                  'h-7 px-3 text-[11px] font-semibold tracking-wider uppercase transition-colors',
                  groupBy === g ? 'bg-foreground text-background' : 'text-muted-foreground hover:bg-muted'
                )}
              >
                {g}
              </button>
            ))}
          </div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Switch checked={showResolved} onCheckedChange={onShowResolved} />
            Show resolved
          </label>
        </div>
        {can(PERMISSIONS.ASSETS_WRITE) && (
          <Button variant="outline" size="xs" disabled={busy} onClick={recheck}>
            <RiRefreshLine data-icon="inline-start" /> Check now
          </Button>
        )}
      </div>

      {groups.length === 0 ? (
        zonesCount === 0 ? (
          <Card size="sm">
            <CardContent>
              <Empty icon={RiShieldCheckLine}>
                No zones yet. Define where services may run, for example a user network with no servers.{' '}
                <button type="button" className="font-semibold text-foreground underline underline-offset-2" onClick={onGoZones}>
                  Set up zones
                </button>
              </Empty>
            </CardContent>
          </Card>
        ) : (
          <Card size="sm">
            <CardContent>
              <Empty icon={RiShieldCheckLine}>Every service follows the policy of its zone.</Empty>
            </CardContent>
          </Card>
        )
      ) : (
        <div className="space-y-4">
          {groups.map((g) => (
            <Card key={g.key || 'none'} size="sm" className="gap-0 py-0">
              <CardHeader className="border-b border-border py-3">
                <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                  <RiShieldCrossLine className="size-4 text-muted-foreground" />
                  {g.label}
                  <span className="text-xs font-normal text-muted-foreground">{plural(g.open, 'open violation')}</span>
                </CardTitle>
                <CardAction className="flex items-center gap-1.5">
                  {SEV_ORDER.map((s) => {
                    const n = g.items.filter((v) => v.status === 'open' && v.severity === s).length;
                    return n > 0 ? (
                      <Pill key={s} tone={policySeverityTone(s)}>
                        {n} {s}
                      </Pill>
                    ) : null;
                  })}
                  {groupBy === 'zone' && g.key && (
                    <Link
                      to={assetsLink(`violation:true ${queryTerm('policy', g.label)}`)}
                      className="ml-1 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase hover:text-foreground"
                    >
                      Assets
                    </Link>
                  )}
                </CardAction>
              </CardHeader>
              <div className="divide-y divide-border">
                {(expanded[g.key] ? g.items : g.items.slice(0, ROWS_PER_GROUP)).map((v) => (
                  <ViolationRow key={v.id} v={v} categories={categories} showZone={groupBy === 'owner'} showOwner={groupBy === 'zone'} />
                ))}
              </div>
              {g.items.length > ROWS_PER_GROUP && (
                <button
                  type="button"
                  onClick={() => setExpanded((e) => ({ ...e, [g.key]: !e[g.key] }))}
                  className="w-full border-t border-border py-2 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase hover:bg-muted/50 hover:text-foreground"
                >
                  {expanded[g.key] ? 'Show fewer' : `Show all ${formatNumber(g.items.length)}`}
                </button>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function ViolationRow({
  v,
  categories,
  showZone,
  showOwner,
}: {
  v: PolicyViolation;
  categories: PolicyCategoryMeta[];
  showZone: boolean;
  showOwner: boolean;
}) {
  const navigate = useNavigate();
  const resolved = v.status === 'resolved';
  const go = () => navigate(`/assets?host=${encodeURIComponent(v.host_id)}`);
  return (
    <div
      role="link"
      tabIndex={0}
      onClick={go}
      onKeyDown={(e) => e.key === 'Enter' && go()}
      className={cn(
        'group grid cursor-pointer grid-cols-[5.5rem_minmax(0,1fr)_auto] items-start gap-3 px-5 py-3 transition-colors outline-none hover:bg-muted/50 focus-visible:bg-muted/50 sm:grid-cols-[5.5rem_13rem_minmax(0,1fr)_auto]',
        resolved && 'opacity-60'
      )}
    >
      <div className="pt-0.5">
        {resolved ? <Pill tone="success">Resolved</Pill> : <Pill tone={policySeverityTone(v.severity)}>{v.severity}</Pill>}
      </div>
      <div className="min-w-0">
        <div className="truncate font-mono text-xs font-semibold">
          {v.host_ip}
          {v.port ? `:${v.port}` : ''}
          <span className="ml-1.5 font-sans font-normal text-muted-foreground">{v.service_name}</span>
        </div>
        {v.hostname && <div className="truncate text-[11px] text-muted-foreground">{v.hostname}</div>}
      </div>
      <div className="col-span-3 min-w-0 sm:col-span-1">
        <div className="flex flex-wrap items-center gap-1.5">
          {v.rules.map((r, i) => (
            <span
              key={r}
              className={cn(
                'inline-flex h-5 items-center border px-1.5 text-[10px] font-semibold tracking-wider uppercase',
                i === 0 ? 'border-foreground/30 text-foreground' : 'border-border text-muted-foreground'
              )}
            >
              {ruleLabel(r, categories)}
            </span>
          ))}
        </div>
        <div className="mt-1 line-clamp-2 text-xs text-muted-foreground">{v.evidence.join(' · ')}</div>
      </div>
      <div className="row-start-1 col-start-3 flex items-center gap-2 text-right text-[11px] text-muted-foreground sm:col-start-4">
        <div className="hidden min-w-0 sm:block">
          {showOwner && <div className="max-w-[12rem] truncate">{v.owner || 'No owner'}</div>}
          {showZone && <div className="max-w-[12rem] truncate">{v.zone_name}</div>}
          <div title={`First seen ${v.first_seen}`}>
            {resolved && v.resolved_at ? `resolved ${formatRelativeTime(v.resolved_at)}` : `since ${formatRelativeTime(v.first_seen)}`}
          </div>
        </div>
        <RiArrowRightSLine className="size-4 opacity-40 group-hover:opacity-100" />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ zones editor */

function emptyZone(): PolicyZone {
  return { name: 'New zone', cidrs: [], enabled: true, preset: CUSTOM, rules: { no_services: false, require_tls: false, forbidden: [] } };
}

function sameRules(a: PolicyZone['rules'], b: PolicyZone['rules']): boolean {
  const norm = (r: PolicyZone['rules']) =>
    JSON.stringify({
      n: !!r.no_services,
      p: [...(r.allowed_ports || [])].sort((x, y) => x - y),
      f: [...(r.forbidden || [])].sort(),
      t: !!r.require_tls,
      m: r.max_risk || 0,
    });
  return norm(a) === norm(b);
}

function ZonesEditor({
  config,
  openByZone,
  onSaved,
}: {
  config: PoliciesResponse;
  openByZone: Record<string, number>;
  onSaved: (next: PoliciesResponse) => void;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const canWrite = can(PERMISSIONS.ASSETS_WRITE);
  const [zones, setZones] = useState<PolicyZone[]>(config.zones);
  const [cidrText, setCidrText] = useState<string[]>(config.zones.map((z) => z.cidrs.join(', ')));
  const [sel, setSel] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [yaml, setYaml] = useState(false);

  useEffect(() => {
    setZones(config.zones);
    setCidrText(config.zones.map((z) => z.cidrs.join(', ')));
    setDirty(false);
    setSel((s) => Math.min(s, Math.max(config.zones.length - 1, 0)));
  }, [config]);

  const patch = (idx: number, p: Partial<PolicyZone>) => {
    setZones((prev) => prev.map((z, i) => (i === idx ? { ...z, ...p } : z)));
    setDirty(true);
  };
  const patchRules = (idx: number, p: Partial<PolicyZone['rules']>) => {
    setZones((prev) =>
      prev.map((z, i) => {
        if (i !== idx) return z;
        const rules = { ...z.rules, ...p };
        const preset = config.presets.find((ps) => ps.id === z.preset);
        return { ...z, rules, preset: preset && sameRules(preset.rules, rules) ? z.preset : CUSTOM };
      })
    );
    setDirty(true);
  };

  const parsedZones = (): PolicyZone[] =>
    zones.map((z, i) => ({
      ...z,
      cidrs: (cidrText[i] || '')
        .split(/[\s,;]+/)
        .map((c) => c.trim())
        .filter(Boolean),
    }));

  const save = async () => {
    setBusy(true);
    try {
      const res = await policiesApi.save(parsedZones());
      toast.success('Policies saved', res.changes ? `${plural(res.changes, 'change')} · ${plural(res.open_count, 'open violation')}` : 'No change in violations');
      onSaved({ ...config, zones: res.zones, open_count: res.open_count });
    } catch (err) {
      toast.error('Could not save', (err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const z = zones[sel];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          Each host follows the most specific enabled zone that contains its IP. Changes apply to the whole inventory on save.
        </p>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="xs" onClick={() => setYaml(true)} disabled={zones.length === 0}>
            <RiCodeLine data-icon="inline-start" /> View as YAML
          </Button>
          {canWrite && (
            <Button
              variant="outline"
              size="xs"
              onClick={() => {
                setZones((p) => [...p, emptyZone()]);
                setCidrText((p) => [...p, '']);
                setSel(zones.length);
                setDirty(true);
              }}
            >
              <RiAddLine data-icon="inline-start" /> Add zone
            </Button>
          )}
          {canWrite && (
            <Button size="xs" disabled={busy || !dirty} onClick={save}>
              Save changes
            </Button>
          )}
        </div>
      </div>

      {zones.length === 0 ? (
        <Card size="sm">
          <CardContent>
            <Empty icon={RiShieldCheckLine}>No zones. Add one and start from a preset.</Empty>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(16rem,22rem)_minmax(0,1fr)]">
          <div className="divide-y divide-border self-start bg-card ring-1 ring-foreground/5">
            {zones.map((zz, i) => {
              const preset = config.presets.find((p) => p.id === zz.preset);
              const openN = zz.id ? openByZone[zz.id] || 0 : 0;
              return (
                <button
                  key={zz.id || `new-${i}`}
                  type="button"
                  onClick={() => setSel(i)}
                  className={cn(
                    'block w-full px-4 py-3 text-left transition-colors hover:bg-muted/50',
                    i === sel && 'bg-muted/70 shadow-[inset_2px_0_0_var(--foreground)]',
                    !zz.enabled && 'opacity-60'
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-semibold">{zz.name || 'Untitled'}</span>
                    {openN > 0 ? (
                      <Pill tone="warning">{openN} open</Pill>
                    ) : zz.enabled ? (
                      <Pill tone="success">OK</Pill>
                    ) : (
                      <Pill>Off</Pill>
                    )}
                  </div>
                  <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">{cidrText[i] || 'no CIDR yet'}</div>
                  <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{preset ? preset.name : 'Custom rules'}</div>
                </button>
              );
            })}
          </div>

          {z && (
            <Card size="sm">
              <CardHeader>
                <CardTitle className="text-sm">{z.name || 'Untitled zone'}</CardTitle>
                {canWrite && (
                  <CardAction className="flex items-center gap-3">
                    <label className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Switch checked={z.enabled} onCheckedChange={(c) => patch(sel, { enabled: c })} />
                      Enabled
                    </label>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label="Delete zone"
                      className="text-muted-foreground hover:text-destructive"
                      onClick={() => {
                        setZones((p) => p.filter((_, i) => i !== sel));
                        setCidrText((p) => p.filter((_, i) => i !== sel));
                        setSel((s) => Math.max(0, s - 1));
                        setDirty(true);
                      }}
                    >
                      <RiDeleteBinLine />
                    </Button>
                  </CardAction>
                )}
              </CardHeader>
              <CardContent>
                <fieldset disabled={!canWrite} className="space-y-5">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Name">
                      <Input value={z.name} onChange={(e) => patch(sel, { name: e.target.value })} />
                    </Field>
                    <Field label="Networks" hint="CIDRs or single IPs, separated by commas">
                      <Input
                        className="font-mono"
                        value={cidrText[sel] || ''}
                        placeholder="10.66.16.0/20"
                        onChange={(e) => {
                          const v = e.target.value;
                          setCidrText((p) => p.map((c, i) => (i === sel ? v : c)));
                          setDirty(true);
                        }}
                      />
                    </Field>
                    <Field label="Description" className="sm:col-span-2">
                      <Textarea
                        rows={2}
                        value={z.description || ''}
                        placeholder="What belongs here"
                        onChange={(e) => patch(sel, { description: e.target.value })}
                      />
                    </Field>
                    <Field label="Preset" hint="Picking a preset replaces the rules below">
                      <SimpleSelect
                        value={z.preset || CUSTOM}
                        disabled={!canWrite}
                        onValueChange={(id) => {
                          const p = config.presets.find((ps) => ps.id === id);
                          if (p) {
                            patch(sel, {
                              preset: id,
                              rules: { ...p.rules, allowed_ports: [...(p.rules.allowed_ports || [])], forbidden: [...(p.rules.forbidden || [])] },
                            });
                          } else {
                            patch(sel, { preset: CUSTOM });
                          }
                        }}
                        options={[
                          ...config.presets.map((p) => ({ value: p.id, label: p.name })),
                          { value: CUSTOM, label: 'Custom rules' },
                        ]}
                      />
                    </Field>
                    <Field label="Fallback owner" hint="Used when the host has no owner rule">
                      <Input value={z.owner || ''} placeholder="admin@agh.edu.pl" onChange={(e) => patch(sel, { owner: e.target.value })} />
                    </Field>
                  </div>

                  <RuleRow
                    title="No services allowed"
                    hint="Any listening service is a violation (user and student networks)"
                    checked={z.rules.no_services}
                    onChange={(c) => patchRules(sel, { no_services: c })}
                  />

                  <div className={cn('space-y-2', z.rules.no_services && 'pointer-events-none opacity-40')}>
                    <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Allowed ports</div>
                    <PortChips
                      ports={z.rules.allowed_ports || []}
                      onChange={(ports) => patchRules(sel, { allowed_ports: ports })}
                      disabled={!canWrite}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">Not allowed here</div>
                    <div className="flex flex-wrap gap-1.5">
                      {config.categories.map((c) => {
                        const on = (z.rules.forbidden || []).includes(c.id);
                        return (
                          <button
                            key={c.id}
                            type="button"
                            title={c.description}
                            aria-pressed={on}
                            onClick={() =>
                              patchRules(sel, {
                                forbidden: on ? (z.rules.forbidden || []).filter((x) => x !== c.id) : [...(z.rules.forbidden || []), c.id],
                              })
                            }
                            className={cn(
                              'inline-flex h-7 items-center gap-1.5 border px-2.5 text-[11px] font-semibold tracking-wider uppercase transition-colors',
                              on ? 'border-foreground bg-foreground text-background' : 'border-border text-muted-foreground hover:bg-muted'
                            )}
                          >
                            {on && <RiShieldCrossLine className="size-3.5" />}
                            {c.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="grid items-start gap-4 sm:grid-cols-2">
                    <RuleRow
                      title="TLS required on web"
                      hint="Plain HTTP without a redirect to HTTPS is a violation"
                      checked={z.rules.require_tls}
                      onChange={(c) => patchRules(sel, { require_tls: c })}
                    />
                    <Field label="Max risk score" hint="0 means no limit">
                      <Input
                        type="number"
                        min={0}
                        max={100}
                        value={z.rules.max_risk || 0}
                        onChange={(e) => patchRules(sel, { max_risk: Math.max(0, Math.min(100, Number(e.target.value) || 0)) })}
                      />
                    </Field>
                  </div>
                </fieldset>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      <Dialog open={yaml} onOpenChange={setYaml}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Policies as YAML</DialogTitle>
          </DialogHeader>
          <pre className="max-h-[60vh] overflow-auto bg-muted p-4 font-mono text-[11px] leading-relaxed">{zonesToYaml(parsedZones())}</pre>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RuleRow({
  title,
  hint,
  checked,
  onChange,
}: {
  title: string;
  hint: string;
  checked: boolean;
  onChange: (c: boolean) => void;
}) {
  return (
    <label className="flex items-start justify-between gap-4 border border-border px-3 py-2.5">
      <span className="min-w-0">
        <span className="block text-xs font-semibold">{title}</span>
        <span className="block text-[11px] text-muted-foreground">{hint}</span>
      </span>
      <Switch checked={checked} onCheckedChange={onChange} />
    </label>
  );
}

function PortChips({ ports, onChange, disabled }: { ports: number[]; onChange: (p: number[]) => void; disabled?: boolean }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const next = [...ports];
    for (const part of draft.split(/[\s,;]+/)) {
      const n = Number(part);
      if (Number.isInteger(n) && n >= 1 && n <= 65535 && !next.includes(n)) next.push(n);
    }
    next.sort((a, b) => a - b);
    onChange(next);
    setDraft('');
  };
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {ports.length === 0 && <span className="text-xs text-muted-foreground">Any port</span>}
      {ports.map((p) => (
        <span key={p} className="inline-flex h-7 items-center gap-1 border border-border bg-muted pr-1 pl-2.5 font-mono text-xs">
          {p}
          {!disabled && (
            <button
              type="button"
              aria-label={`Remove port ${p}`}
              className="px-1 text-muted-foreground hover:text-foreground"
              onClick={() => onChange(ports.filter((x) => x !== p))}
            >
              ×
            </button>
          )}
        </span>
      ))}
      {!disabled && (
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              add();
            }
          }}
          onBlur={() => draft.trim() && add()}
          placeholder="Add port"
          className="h-7 w-28 font-mono text-xs"
        />
      )}
    </div>
  );
}
