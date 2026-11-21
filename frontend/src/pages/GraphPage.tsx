import { createContext, memo, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Background,
  BackgroundVariant,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  RiArrowRightSLine,
  RiCloseLine,
  RiExternalLinkLine,
  RiFocus3Line,
  RiLockLine,
  RiRefreshLine,
  RiSearchLine,
  RiSendPlaneLine,
  RiStackLine,
} from '@remixicon/react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';
import { useToast } from '@/context/ToastContext';
import { useLiveEvents, useLiveRefresh } from '@/context/LiveEventsContext';
import { formatNumber, lifecycleMeta, scoreBarColor, scoreColor } from '@/lib/format';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Pill, SimpleSelect } from '@/components/common';
import { ServiceLogo } from '@/components/ServiceLogo';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import type { GraphMode, GraphNode, GraphQuery, GraphResponse } from '@/types/api';
import { PeckSpinner } from '@/components/Woodpecker';

/* ────────────────────────────────────────────────────────────────────────── */
/* Types & helpers                                                           */
/* ────────────────────────────────────────────────────────────────────────── */

type Column = 'scope' | 'host' | 'service' | 'tech';
type FlowNodeData = { g: GraphNode; column?: Column; title?: string };
type FlowNode = Node<FlowNodeData>;

type QuickFilter = 'all' | 'risk' | 'adminstaging' | 'active';

const QUICK_FILTERS: { value: QuickFilter; label: string }[] = [
  { value: 'all', label: 'Wszystkie' },
  { value: 'risk', label: 'Ryzyko ≥ 50' },
  { value: 'adminstaging', label: 'Admin / Staging' },
  { value: 'active', label: 'Aktywne' },
];

const MODES: { value: GraphMode; label: string }[] = [
  { value: 'auto', label: 'Auto' },
  { value: 'clustered', label: 'Klastrowy' },
  { value: 'detailed', label: 'Szczegółowy' },
];

const COL_X: Record<Column, number> = { scope: 0, host: 330, service: 700, tech: 1090 };
const COL_W: Record<Column, number> = { scope: 260, host: 280, service: 300, tech: 250 };
const COL_TITLE: Record<Column, string> = {
  scope: 'Zakres',
  host: 'Host / Podsieć',
  service: 'Usługa',
  tech: 'Technologia',
};
const GAP = 14;
const GROUP_GAP = 34;
const RISK_HIGH = '#f43f5e';

const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v));
const num = (v: unknown): number => (typeof v === 'number' ? v : Number(v) || 0);

function columnOf(n: GraphNode): Column {
  if (n.kind === 'scope') return 'scope';
  if (n.kind === 'host') return 'host';
  if (n.kind === 'service') return 'service';
  return 'tech';
}

function isCluster(n: GraphNode) {
  return Boolean(n.meta?.is_cluster);
}

function heightOf(n: GraphNode): number {
  const c = columnOf(n);
  if (c === 'host') return isCluster(n) ? 118 : 86;
  if (c === 'scope') return 76;
  if (c === 'service') return 78;
  return 66;
}

function hostIdOf(n: GraphNode | null | undefined): string | null {
  if (!n) return null;
  const hid = n.meta?.host_id;
  if (typeof hid === 'string' && hid) return hid;
  if (n.kind === 'host' && !isCluster(n)) return n.id.replace(/^host:/, '');
  return null;
}

/** Strip the "(42×)" suffix and ":443" prefix from a clustered service label. */
function serviceName(n: GraphNode): string {
  const m = n.meta || {};
  const name = str(m.product) || str(m.service_name);
  if (name) return name;
  return n.label.replace(/^:\d+(\/\w+)?\s*/, '').replace(/\s*\(\d+×\)\s*$/, '');
}

function mergeGraphs(a: GraphResponse, b: GraphResponse): GraphResponse {
  const nodes = new Map(a.nodes.map((n) => [n.id, n]));
  for (const n of b.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n);
  const edges = new Map(a.edges.map((e) => [e.id, e]));
  for (const e of b.edges) if (!edges.has(e.id)) edges.set(e.id, e);
  const subnets = new Map(a.subnets.map((s) => [s.subnet, s]));
  for (const s of b.subnets) if (!subnets.has(s.subnet)) subnets.set(s.subnet, s);
  return {
    ...a,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    matched_hosts: Math.max(a.matched_hosts, b.matched_hosts),
    shown_hosts: Math.max(a.shown_hosts, b.shown_hosts),
    clustered: a.clustered || b.clustered,
    subnets: [...subnets.values()],
  };
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Layout: Scope → Host/Subnet → Service → Tech, sorted by risk, no overlap   */
/* ────────────────────────────────────────────────────────────────────────── */

function layoutGraph(data: GraphResponse): { nodes: FlowNode[]; edges: Edge[] } {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const parentsOf = new Map<string, string[]>();
  const childrenOf = new Map<string, string[]>();
  for (const e of data.edges) {
    if (!byId.has(e.source) || !byId.has(e.target)) continue;
    (parentsOf.get(e.target) ?? parentsOf.set(e.target, []).get(e.target)!).push(e.source);
    (childrenOf.get(e.source) ?? childrenOf.set(e.source, []).get(e.source)!).push(e.target);
  }
  const score = (id: string) => byId.get(id)?.interestingness || 0;
  const byRisk = (a: string, b: string) => score(b) - score(a) || a.localeCompare(b);
  const firstParent = (id: string, col: Column) =>
    (parentsOf.get(id) || []).find((p) => byId.get(p) && columnOf(byId.get(p)!) === col);

  const cols: Record<Column, GraphNode[]> = { scope: [], host: [], service: [], tech: [] };
  for (const n of data.nodes) cols[columnOf(n)].push(n);

  const pos = new Map<string, { y: number; h: number }>();
  const center = (id: string) => {
    const p = pos.get(id)!;
    return p.y + p.h / 2;
  };

  // Hosts grouped by scope; scopes ordered by their riskiest host.
  const hostsByScope = new Map<string, string[]>();
  const orphanHosts: string[] = [];
  for (const h of cols.host) {
    const s = firstParent(h.id, 'scope');
    if (s) (hostsByScope.get(s) ?? hostsByScope.set(s, []).get(s)!).push(h.id);
    else orphanHosts.push(h.id);
  }
  const scopeRisk = (s: string) => Math.max(0, ...(hostsByScope.get(s) || []).map(score));
  const scopes = cols.scope.map((s) => s.id).sort((a, b) => scopeRisk(b) - scopeRisk(a) || a.localeCompare(b));

  const servicesOf = (hostId: string) =>
    (childrenOf.get(hostId) || [])
      .filter((c) => byId.get(c) && columnOf(byId.get(c)!) === 'service' && firstParent(c, 'host') === hostId)
      .sort(byRisk);

  let cursor = 0;
  const placeHostBlock = (hostId: string) => {
    const host = byId.get(hostId)!;
    const hh = heightOf(host);
    const svcs = servicesOf(hostId);
    const svcH = svcs.reduce((acc, s) => acc + heightOf(byId.get(s)!) + GAP, 0) - (svcs.length ? GAP : 0);
    const blockH = Math.max(hh, svcH);
    let y = cursor + (blockH - svcH) / 2;
    for (const s of svcs) {
      const h = heightOf(byId.get(s)!);
      pos.set(s, { y, h });
      y += h + GAP;
    }
    pos.set(hostId, { y: cursor + (blockH - hh) / 2, h: hh });
    cursor += blockH + GAP;
  };

  for (const s of scopes) {
    const hosts = (hostsByScope.get(s) || []).sort(byRisk);
    const start = cursor;
    hosts.forEach(placeHostBlock);
    const sh = heightOf(byId.get(s)!);
    const end = hosts.length ? cursor - GAP : start + sh;
    pos.set(s, { y: Math.max(start, (start + end) / 2 - sh / 2), h: sh });
    if (!hosts.length) cursor = start + sh + GAP;
    cursor += GROUP_GAP - GAP;
  }
  orphanHosts.sort(byRisk).forEach(placeHostBlock);
  // Services without a host parent (defensive)
  for (const s of cols.service) {
    if (pos.has(s.id)) continue;
    const h = heightOf(s);
    pos.set(s.id, { y: cursor, h });
    cursor += h + GAP;
  }

  // Tech: barycenter of parent services, then sweep to remove overlaps.
  const techs = cols.tech
    .map((t) => {
      const ps = (parentsOf.get(t.id) || []).filter((p) => pos.has(p));
      const bary = ps.length ? ps.reduce((a, p) => a + center(p), 0) / ps.length : Number.MAX_SAFE_INTEGER;
      return { id: t.id, bary, h: heightOf(t) };
    })
    .sort((a, b) => a.bary - b.bary);
  let prevBottom = -Infinity;
  for (const t of techs) {
    const desired = t.bary === Number.MAX_SAFE_INTEGER ? prevBottom + GAP : t.bary - t.h / 2;
    const y = Math.max(desired, prevBottom + GAP);
    pos.set(t.id, { y, h: t.h });
    prevBottom = y + t.h;
  }

  const nodes: FlowNode[] = [];
  const present = new Set<Column>();
  let minY = Infinity;
  for (const n of data.nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    const col = columnOf(n);
    present.add(col);
    minY = Math.min(minY, p.y);
    nodes.push({
      id: n.id,
      type: col,
      position: { x: COL_X[col], y: p.y },
      data: { g: n },
      width: COL_W[col],
      height: p.h,
    });
  }
  if (!Number.isFinite(minY)) minY = 0;
  for (const col of ['scope', 'host', 'service', 'tech'] as Column[]) {
    if (!present.has(col)) continue;
    nodes.push({
      id: `lane:${col}`,
      type: 'lane',
      position: { x: COL_X[col], y: minY - 56 },
      data: { g: { id: `lane:${col}`, kind: 'lane', label: COL_TITLE[col] }, column: col, title: COL_TITLE[col] },
      width: COL_W[col],
      height: 28,
      draggable: false,
      selectable: false,
      focusable: false,
    });
  }

  const edges: Edge[] = data.edges
    .filter((e) => pos.has(e.source) && pos.has(e.target))
    .map((e) => ({ id: e.id, source: e.source, target: e.target }));

  return { nodes, edges };
}

/* ────────────────────────────────────────────────────────────────────────── */
/* Node components                                                            */
/* ────────────────────────────────────────────────────────────────────────── */

interface GraphCtx {
  isFresh: (n: GraphNode) => boolean;
  drill: (subnet: string) => void;
}
const GraphContext = createContext<GraphCtx>({ isFresh: () => false, drill: () => {} });

const handleCls = '!size-1.5 !min-w-0 !min-h-0 !rounded-none !border-0 !bg-border';

function NodeShell({
  selected,
  accent,
  fresh,
  className,
  children,
}: {
  selected?: boolean;
  accent?: string;
  fresh?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        'relative h-full w-full border bg-card text-card-foreground shadow-xs transition-[box-shadow,border-color] hover:border-foreground/30',
        selected ? 'border-primary ring-2 ring-primary/30' : 'border-border',
        className
      )}
    >
      {accent && <span className="absolute inset-y-0 left-0 w-[3px]" style={{ backgroundColor: accent }} />}
      {fresh && (
        <>
          <span className="pointer-events-none absolute -inset-1 animate-ping border-2 border-emerald-500/60" />
          <span className="pointer-events-none absolute -inset-1 border border-emerald-500" />
        </>
      )}
      {children}
    </div>
  );
}

function RiskBar({ value, className }: { value: number; className?: string }) {
  return (
    <div className={cn('h-1 w-full bg-muted', className)}>
      <div className={cn('h-full', scoreBarColor(value))} style={{ width: `${Math.min(100, Math.max(3, value))}%` }} />
    </div>
  );
}

const LaneNode = memo(function LaneNode({ data }: NodeProps<FlowNode>) {
  return (
    <div className="flex h-full items-end border-b border-dashed border-border pb-1 text-[10px] font-semibold tracking-[0.2em] text-muted-foreground uppercase">
      {data.title}
    </div>
  );
});

const ScopeNode = memo(function ScopeNode({ data, selected }: NodeProps<FlowNode>) {
  const g = data.g;
  const m = g.meta || {};
  const hostCount = num(m.host_count);
  const subnetCount = num(m.subnet_count);
  return (
    <NodeShell selected={selected} accent="var(--primary)">
      <div className="flex h-full items-center gap-3 px-3.5">
        <ServiceLogo kind="scope" size="lg" />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <span className="truncate font-mono text-xs font-semibold" title={g.label}>
            {str(m.subnet) || g.label.replace(/\s*\(\d+ hostów\)\s*$/, '')}
          </span>
          <div className="flex items-center gap-1.5">
            {hostCount > 0 && <Pill tone="primary">{formatNumber(hostCount)} hostów</Pill>}
            {subnetCount > 0 && <Pill>{formatNumber(subnetCount)} /24</Pill>}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className={handleCls} />
    </NodeShell>
  );
});

const HostNode = memo(function HostNode({ data, selected }: NodeProps<FlowNode>) {
  const { isFresh, drill } = useContext(GraphContext);
  const g = data.g;
  const m = g.meta || {};
  const score = g.interestingness || 0;
  const lc = lifecycleMeta(g.state);

  if (isCluster(g)) {
    const subnet = str(m.subnet);
    const hostCount = num(m.host_count);
    const highRisk = num(m.high_risk_count);
    const active = num(m.active_count);
    return (
      <NodeShell selected={selected} accent={highRisk > 0 ? RISK_HIGH : lc.stroke}>
        <Handle type="target" position={Position.Left} className={handleCls} />
        <div className="flex h-full flex-col justify-between gap-1.5 py-2.5 pr-3 pl-3.5">
          <div className="flex items-center gap-2.5">
            <span className="flex size-8 shrink-0 items-center justify-center border border-primary/30 bg-primary/10 text-primary">
              <RiStackLine className="size-4" />
            </span>
            <div className="flex min-w-0 flex-1 flex-col">
              <span className="truncate font-mono text-xs font-semibold">{subnet}</span>
              <span className="truncate text-[11px] text-muted-foreground tabular-nums">
                {formatNumber(hostCount)} hostów ·{' '}
                <span className={cn(highRisk > 0 && 'font-semibold text-rose-600 dark:text-rose-400')}>
                  {formatNumber(highRisk)} wysokiego ryzyka
                </span>
              </span>
            </div>
            <Pill className={cn('font-mono', scoreColor(score))}>{score}</Pill>
          </div>
          <RiskBar value={score} />
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground tabular-nums">{formatNumber(active)} aktywnych</span>
            <button
              type="button"
              className="nodrag nopan inline-flex items-center gap-0.5 text-[11px] font-semibold text-primary hover:underline"
              onClick={(e) => {
                e.stopPropagation();
                drill(subnet);
              }}
            >
              Rozwiń podsieć <RiArrowRightSLine className="size-3.5" />
            </button>
          </div>
        </div>
        <Handle type="source" position={Position.Right} className={handleCls} />
      </NodeShell>
    );
  }

  const ip = str(m.ip) || g.label.split(' ')[0];
  const hostname = str(m.hostname);
  const locked = Array.isArray(m.locked_fields) && m.locked_fields.length > 0;
  const live = g.state === 'ACTIVE' || g.state === 'NEW' || g.state === 'REACTIVATED';
  const svcCount = num(m.service_count);
  return (
    <NodeShell selected={selected} accent={score >= 60 ? RISK_HIGH : lc.stroke} fresh={isFresh(g)}>
      <Handle type="target" position={Position.Left} className={handleCls} />
      <div className="flex h-full flex-col justify-center gap-1.5 pr-3 pl-3.5">
        <div className="flex items-center gap-2">
          <span className="relative flex size-2.5 shrink-0">
            {live && <span className="absolute inset-0 animate-ping opacity-60" style={{ backgroundColor: lc.stroke }} />}
            <span className="relative size-2.5" style={{ backgroundColor: lc.stroke }} />
          </span>
          <span className="truncate font-mono text-[13px] font-semibold">{ip}</span>
          {locked && <RiLockLine className="size-3 shrink-0 text-amber-500" aria-label="Pola zablokowane" />}
          <span className="flex-1" />
          <Pill className={cn('font-mono', scoreColor(score))}>{score}</Pill>
        </div>
        <div className="flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
          <span className="truncate">{hostname || lc.label}</span>
          {svcCount > 0 && <span className="shrink-0 tabular-nums">{svcCount} usł.</span>}
        </div>
        <RiskBar value={score} />
      </div>
      <Handle type="source" position={Position.Right} className={handleCls} />
    </NodeShell>
  );
});

const ServiceNode = memo(function ServiceNode({ data, selected }: NodeProps<FlowNode>) {
  const { isFresh } = useContext(GraphContext);
  const g = data.g;
  const m = g.meta || {};
  const score = g.interestingness || 0;
  const port = num(m.port);
  const name = serviceName(g);
  const count = num(m.count);
  const isAdmin = Boolean(m.is_admin_panel);
  const isStaging = Boolean(m.is_staging_env);
  const isIoT = Boolean(m.is_iot);
  const tlsWarn = Boolean(m.tls_warning);
  return (
    <NodeShell
      selected={selected}
      accent={score >= 70 ? RISK_HIGH : score >= 45 ? '#f59e0b' : undefined}
      fresh={isFresh(g)}
    >
      <Handle type="target" position={Position.Left} className={handleCls} />
      <div className="flex h-full items-center gap-2.5 pr-3 pl-3.5">
        <ServiceLogo
          names={[str(m.product), str(m.service_name), str(m.http_title), name]}
          port={port}
          isAdmin={isAdmin}
          isStaging={isStaging}
          isIoT={isIoT}
          size={30}
        />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex min-w-0 items-center gap-1.5">
            {port > 0 && (
              <span className="shrink-0 border border-border bg-muted px-1 font-mono text-[10px] font-semibold tabular-nums">
                :{port}
              </span>
            )}
            <span className="truncate text-xs font-semibold" title={name}>
              {name || '—'}
            </span>
            {count > 1 && (
              <span className="ml-auto shrink-0 font-mono text-[10px] font-semibold text-primary tabular-nums">
                {formatNumber(count)}×
              </span>
            )}
          </div>
          <div className="flex min-w-0 items-center gap-1 overflow-hidden">
            {isAdmin && <Pill tone="warning">Admin</Pill>}
            {isStaging && <Pill tone="violet">Staging</Pill>}
            {isIoT && <Pill tone="info">IoT</Pill>}
            {tlsWarn && <Pill tone="danger">TLS!</Pill>}
            {!isAdmin && !isStaging && !isIoT && !tlsWarn && (
              <span className="truncate text-[10px] text-muted-foreground">
                {str(m.version) || str(m.http_title) || str(m.protocol) || 'tcp'}
              </span>
            )}
            <Pill className={cn('ml-auto font-mono', scoreColor(score))}>{score}</Pill>
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className={handleCls} />
    </NodeShell>
  );
});

const TechNode = memo(function TechNode({ data, selected }: NodeProps<FlowNode>) {
  const g = data.g;
  const m = g.meta || {};
  const conf = num(m.confidence) || g.interestingness || 0;
  const version = str(m.version);
  const name = str(m.name) || (version ? g.label.replace(new RegExp(`\\s*${version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`), '') : g.label);
  const isSig = g.kind === 'signature';
  return (
    <NodeShell selected={selected}>
      <Handle type="target" position={Position.Left} className={handleCls} />
      <div className="flex h-full items-center gap-2.5 px-3">
        <ServiceLogo names={[name, str(m.category)]} size={28} />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex min-w-0 items-baseline gap-1.5">
            <span className="truncate text-xs font-semibold" title={g.label}>
              {name}
            </span>
            {version && <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{version}</span>}
            {isSig && <span className="ml-auto shrink-0 text-[9px] font-semibold tracking-wider text-violet-500 uppercase">Syg.</span>}
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-1 flex-1 bg-muted">
              <div className="h-full bg-primary" style={{ width: `${Math.min(100, conf)}%` }} />
            </div>
            <span className="font-mono text-[10px] text-muted-foreground tabular-nums">{conf}%</span>
          </div>
        </div>
      </div>
    </NodeShell>
  );
});

const NODE_TYPES: NodeTypes = {
  lane: LaneNode,
  scope: ScopeNode,
  host: HostNode,
  service: ServiceNode,
  tech: TechNode,
};

/* ────────────────────────────────────────────────────────────────────────── */
/* Page                                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

export function GraphPage() {
  return (
    <ReactFlowProvider>
      <GraphCanvas />
    </ReactFlowProvider>
  );
}

function GraphCanvas() {
  const toast = useToast();
  const { can } = useAuth();
  const { theme } = useTheme();
  const { fitView } = useReactFlow();
  const [searchParams, setSearchParams] = useSearchParams();

  const subnet = searchParams.get('subnet') || '';
  const modeParam = searchParams.get('mode');
  const mode: GraphMode = modeParam === 'clustered' || modeParam === 'detailed' ? modeParam : 'auto';

  const [searchInput, setSearchInput] = useState(searchParams.get('q') || '');
  const [q, setQ] = useState(searchInput);
  const [quick, setQuick] = useState<QuickFilter>('all');

  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  const [hoverId, setHoverId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);
  const [pushing, setPushing] = useState(false);

  // Live: fresh node detection
  const { recentIPs } = useLiveEvents();
  const knownIds = useRef<Set<string> | null>(null);
  const [freshIds, setFreshIds] = useState<Record<string, number>>({});

  useEffect(() => {
    const t = window.setTimeout(() => setQ(searchInput.trim()), 300);
    return () => window.clearTimeout(t);
  }, [searchInput]);

  const query = useMemo<GraphQuery>(() => {
    const base: GraphQuery = {
      mode,
      subnet: subnet || undefined,
      q: q || undefined,
      limit: subnet || mode === 'detailed' ? 150 : 60,
    };
    if (quick === 'risk') base.min_score = 50;
    if (quick === 'active') base.state = 'ACTIVE';
    return base;
  }, [mode, subnet, q, quick]);

  const reqSeq = useRef(0);
  const loadGraph = useCallback(
    async (silent?: boolean) => {
      const seq = ++reqSeq.current;
      if (!silent) setLoading(true);
      try {
        let data: GraphResponse;
        if (quick === 'adminstaging') {
          const [a, s] = await Promise.all([
            api.graph({ ...query, admin_only: true }),
            api.graph({ ...query, staging_only: true }),
          ]);
          data = mergeGraphs(a, s);
        } else {
          data = await api.graph(query);
        }
        if (seq !== reqSeq.current) return;
        if (knownIds.current && silent) {
          const now = Date.now();
          const added = data.nodes.filter((n) => !knownIds.current!.has(n.id));
          if (added.length) {
            setFreshIds((prev) => {
              const out = { ...prev };
              for (const n of added) out[n.id] = now;
              return out;
            });
          }
        }
        knownIds.current = new Set(data.nodes.map((n) => n.id));
        setGraph(data);
      } catch (err) {
        if (!silent && seq === reqSeq.current) toast.error('Błąd ładowania grafu', (err as Error).message);
      } finally {
        if (!silent && seq === reqSeq.current) setLoading(false);
      }
    },
    [query, quick, toast]
  );

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  useLiveRefresh(() => loadGraph(true));

  useEffect(() => {
    if (Object.keys(freshIds).length === 0) return;
    const t = window.setTimeout(() => {
      const now = Date.now();
      setFreshIds((prev) => Object.fromEntries(Object.entries(prev).filter(([, at]) => now - at < 15000)));
    }, 3000);
    return () => window.clearTimeout(t);
  }, [freshIds]);

  const isFresh = useCallback(
    (n: GraphNode) => {
      if (freshIds[n.id]) return true;
      const m = n.meta || {};
      const ip = str(m.ip) || str(m.host_ip);
      return !!ip && !isCluster(n) && !!recentIPs[ip];
    },
    [freshIds, recentIPs]
  );

  // Layout whenever data changes; refit only when the structural query changes.
  const lastFitKey = useRef('');
  useEffect(() => {
    if (!graph) return;
    const { nodes: n, edges: e } = layoutGraph(graph);
    setNodes(n);
    setEdges(e);
    const key = JSON.stringify(query) + quick + graph.mode;
    if (key !== lastFitKey.current) {
      lastFitKey.current = key;
      requestAnimationFrame(() => fitView({ padding: 0.12, duration: 450, maxZoom: 1.1 }));
    }
  }, [graph, query, quick, setNodes, fitView]);

  useEffect(() => {
    if (selectedId && !nodes.some((n) => n.id === selectedId)) setSelectedId(null);
  }, [nodes, selectedId]);

  // Graph adjacency for attack-path highlighting
  const adjacency = useMemo(() => {
    const up = new Map<string, string[]>();
    const down = new Map<string, string[]>();
    for (const e of edges) {
      (down.get(e.source) ?? down.set(e.source, []).get(e.source)!).push(e.target);
      (up.get(e.target) ?? up.set(e.target, []).get(e.target)!).push(e.source);
    }
    return { up, down };
  }, [edges]);

  const focusId = hoverId ?? selectedId;
  const path = useMemo(() => {
    if (!focusId) return null;
    const set = new Set<string>([focusId]);
    const walk = (start: string, adj: Map<string, string[]>) => {
      const stack = [start];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const nxt of adj.get(cur) || []) {
          if (!set.has(nxt)) {
            set.add(nxt);
            stack.push(nxt);
          }
        }
      }
    };
    walk(focusId, adjacency.up);
    walk(focusId, adjacency.down);
    return set;
  }, [focusId, adjacency]);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n.data.g])), [nodes]);

  const displayNodes = useMemo(
    () =>
      nodes.map((n) => {
        const dim = path && n.type !== 'lane' && !path.has(n.id);
        const cls = cn('transition-opacity duration-200', dim && 'opacity-20');
        return n.className === cls ? n : { ...n, className: cls };
      }),
    [nodes, path]
  );

  const displayEdges = useMemo(
    () =>
      edges.map((e) => {
        const s = nodeById.get(e.source);
        const t = nodeById.get(e.target);
        const risky = [s, t].some(
          (n) => n && (n.kind === 'host' || n.kind === 'service') && (n.interestingness || 0) >= 60
        );
        const fresh = Boolean((t && isFresh(t)) || (s && isFresh(s)));
        const lit = path ? path.has(e.source) && path.has(e.target) : false;
        const dim = path && !lit;
        return {
          ...e,
          animated: risky || fresh || lit,
          style: {
            stroke: lit ? 'var(--primary)' : fresh ? '#10b981' : risky ? RISK_HIGH : 'var(--muted-foreground)',
            strokeWidth: lit ? 2 : risky ? 1.5 : 1,
            opacity: dim ? 0.08 : lit ? 1 : risky ? 0.7 : 0.35,
            transition: 'opacity 200ms',
          },
          zIndex: lit ? 1 : 0,
        } satisfies Edge;
      }),
    [edges, nodeById, path, isFresh]
  );

  const drill = useCallback(
    (sn: string) => {
      setSelectedId(null);
      setHoverId(null);
      const next = new URLSearchParams(searchParams);
      next.set('subnet', sn);
      next.set('mode', 'detailed');
      setSearchParams(next);
    },
    [searchParams, setSearchParams]
  );

  const clearSubnet = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('subnet');
    next.delete('mode');
    setSearchParams(next);
  };

  const setMode = (m: GraphMode) => {
    const next = new URLSearchParams(searchParams);
    if (m === 'auto') next.delete('mode');
    else next.set('mode', m);
    setSearchParams(next);
  };

  const ctx = useMemo<GraphCtx>(() => ({ isFresh, drill }), [isFresh, drill]);

  const selected = selectedId ? nodeById.get(selectedId) || null : null;
  const selectedHostId = hostIdOf(selected);

  const selectedServiceIds = useMemo(() => {
    if (!selected) return [];
    if (selected.kind === 'service') {
      const id = str(selected.meta?.service_id);
      return id ? [id] : [];
    }
    if (selected.kind === 'host' && !isCluster(selected)) {
      return (adjacency.down.get(selected.id) || [])
        .map((id) => nodeById.get(id))
        .filter((n): n is GraphNode => !!n && n.kind === 'service')
        .map((n) => str(n.meta?.service_id))
        .filter(Boolean);
    }
    return [];
  }, [selected, adjacency, nodeById]);

  const pushToDojo = async () => {
    if (!selectedServiceIds.length) return;
    setPushing(true);
    try {
      await api.pushDefectDojoFindings({ service_ids: selectedServiceIds });
      toast.success('Wysłano do DefectDojo', `${selectedServiceIds.length} usług(i)`);
    } catch (err) {
      toast.error('Błąd wysyłki do DefectDojo', (err as Error).message);
    } finally {
      setPushing(false);
    }
  };

  const minimapColor = useCallback((n: Node) => {
    const g = (n.data as FlowNodeData | undefined)?.g;
    if (!g || n.type === 'lane') return 'transparent';
    if (g.kind === 'scope') return '#3b82f6';
    const s = g.interestingness || 0;
    if (g.kind === 'host' || g.kind === 'service') {
      if (s >= 60) return RISK_HIGH;
      if (s >= 45) return '#f59e0b';
      return g.kind === 'host' ? lifecycleMeta(g.state).stroke : '#a8a29e';
    }
    return '#78716c';
  }, []);

  const subnetOptions = useMemo(
    () =>
      (graph?.subnets || []).slice(0, 200).map((s) => ({
        value: s.subnet,
        label: `${s.subnet} · ${formatNumber(s.host_count)}${s.high_risk_count ? ` · ${s.high_risk_count}⚠` : ''}`,
      })),
    [graph?.subnets]
  );

  const totalHosts = graph?.matched_hosts ?? 0;
  const statusLabel = graph
    ? `${formatNumber(totalHosts)} hostów · ${graph.clustered ? 'tryb klastrowy' : 'tryb szczegółowy'}${
        !graph.clustered && graph.shown_hosts < graph.matched_hosts
          ? ` · pokazano ${formatNumber(graph.shown_hosts)}`
          : ''
      }`
    : 'Ładowanie…';

  const metaEntries = selected
    ? Object.entries(selected.meta || {}).filter(
        ([k, v]) =>
          !['is_cluster', 'host_id', 'service_id', 'locked_fields'].includes(k) &&
          v !== '' &&
          v !== null &&
          v !== false &&
          !(Array.isArray(v) && v.length === 0)
      )
    : [];

  return (
    <div className="relative h-[calc(100vh-8.5rem)] w-full overflow-hidden bg-background ring-1 ring-foreground/5">
      <GraphContext.Provider value={ctx}>
        <ReactFlow<FlowNode>
          nodes={displayNodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          nodeTypes={NODE_TYPES}
          forceColorMode={theme === 'dark' ? 'dark' : 'light'}
          nodesConnectable={false}
          edgesFocusable={false}
          onlyRenderVisibleElements
          preventScrolling
          zoomOnScroll
          zoomOnDoubleClick={false}
          minZoom={0.05}
          maxZoom={2}
          fitView
          fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
          proOptions={{ hideAttribution: true }}
          onNodeMouseEnter={(_, n) => n.type !== 'lane' && setHoverId(n.id)}
          onNodeMouseLeave={() => setHoverId(null)}
          onNodeClick={(_, n) => n.type !== 'lane' && setSelectedId(n.id)}
          onNodeDoubleClick={(_, n) => {
            const g = (n.data as FlowNodeData).g;
            if (isCluster(g) && g.kind === 'host') drill(str(g.meta?.subnet));
            else {
              const hid = hostIdOf(g);
              if (hid) setInspectHostId(hid);
            }
          }}
          onPaneClick={() => setSelectedId(null)}
          className="!bg-background"
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1.2} color="var(--border)" />
          <MiniMap
            pannable
            zoomable
            nodeColor={minimapColor}
            nodeStrokeWidth={0}
            maskColor={theme === 'dark' ? 'rgba(12,10,9,0.7)' : 'rgba(250,250,249,0.7)'}
            className="!m-3 !border !border-border !bg-card"
            style={{ width: 180, height: 120 }}
          />

          {/* Floating toolbar */}
          <Panel position="top-left" className="!m-3 max-w-[calc(100%-1.5rem)]">
            <div className="flex flex-wrap items-center gap-2 border border-border bg-card/95 p-1.5 shadow-sm backdrop-blur">
              <div className="relative w-52">
                <RiSearchLine className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="IP, host, usługa, technologia…"
                  className="h-7 pl-7 text-xs"
                />
              </div>
              <div className="flex items-center">
                {QUICK_FILTERS.map((f) => (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => setQuick(f.value)}
                    className={cn(
                      '-ml-px h-7 border px-2 text-[11px] font-semibold whitespace-nowrap transition-colors first:ml-0',
                      quick === f.value
                        ? 'relative z-10 border-primary bg-primary/10 text-primary'
                        : 'border-border text-muted-foreground hover:bg-muted hover:text-foreground'
                    )}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
              <div className="flex items-center bg-muted p-0.5">
                {MODES.map((m) => (
                  <button
                    key={m.value}
                    type="button"
                    onClick={() => setMode(m.value)}
                    className={cn(
                      'h-6 px-2 text-[11px] font-semibold transition-colors',
                      mode === m.value ? 'bg-card text-foreground shadow-xs' : 'text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
              {subnetOptions.length > 1 && !subnet && (
                <SimpleSelect
                  size="sm"
                  value=""
                  placeholder="Podsieć /24…"
                  onValueChange={(v) => v && drill(v)}
                  options={subnetOptions}
                  className="h-7 w-44 text-xs"
                />
              )}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <div className="flex h-7 items-center gap-1 border border-border bg-card/95 px-2 text-[11px] backdrop-blur">
                <button
                  type="button"
                  onClick={clearSubnet}
                  className={cn('font-semibold', subnet ? 'text-primary hover:underline' : 'text-foreground')}
                >
                  Wszystkie
                </button>
                {subnet && (
                  <>
                    <span className="text-muted-foreground">/</span>
                    <span className="font-mono font-semibold">{subnet}</span>
                    <button
                      type="button"
                      onClick={clearSubnet}
                      aria-label="Wyczyść podsieć"
                      className="ml-0.5 text-muted-foreground hover:text-foreground"
                    >
                      <RiCloseLine className="size-3.5" />
                    </button>
                  </>
                )}
              </div>
              <span className="flex h-7 items-center gap-1.5 border border-border bg-card/95 px-2 font-mono text-[11px] tabular-nums backdrop-blur">
                {loading ? (
                  <PeckSpinner className="h-3" />
                ) : (
                  <span className={cn('size-1.5', graph?.clustered ? 'bg-primary' : 'bg-emerald-500')} />
                )}
                {statusLabel}
              </span>
              <Button
                variant="outline"
                size="sm"
                className="h-7 bg-card/95 text-[11px]"
                onClick={() => fitView({ padding: 0.12, duration: 450, maxZoom: 1.1 })}
              >
                <RiFocus3Line />
                Dopasuj widok
              </Button>
              <Button
                variant="outline"
                size="icon-sm"
                className="size-7 bg-card/95"
                onClick={() => loadGraph()}
                aria-label="Odśwież"
              >
                <RiRefreshLine className={cn(loading && 'animate-spin')} />
              </Button>
            </div>
          </Panel>

          {/* Node inspector overlay */}
          {selected && (
            <Panel position="top-right" className="!m-3 w-80">
              <div className="flex max-h-[calc(100vh-14rem)] flex-col border border-border bg-card/95 shadow-md backdrop-blur">
                <div className="flex items-start gap-3 border-b border-border p-3">
                  {selected.kind === 'host' && isCluster(selected) ? (
                    <span className="flex size-8 shrink-0 items-center justify-center border border-primary/30 bg-primary/10 text-primary">
                      <RiStackLine className="size-4" />
                    </span>
                  ) : (
                    <ServiceLogo
                      kind={selected.kind === 'scope' ? 'scope' : selected.kind === 'host' ? 'host' : undefined}
                      names={
                        selected.kind === 'service'
                          ? [str(selected.meta?.product), str(selected.meta?.service_name), str(selected.meta?.http_title)]
                          : selected.kind === 'host'
                            ? []
                            : [str(selected.meta?.name), selected.label]
                      }
                      port={num(selected.meta?.port)}
                      isAdmin={Boolean(selected.meta?.is_admin_panel)}
                      isStaging={Boolean(selected.meta?.is_staging_env)}
                      isIoT={Boolean(selected.meta?.is_iot)}
                      size="lg"
                    />
                  )}
                  <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                    <h3 className="font-mono text-xs font-semibold break-all">{selected.label}</h3>
                    <div className="flex flex-wrap items-center gap-1">
                      <Pill>{selected.kind}</Pill>
                      {selected.state && selected.kind === 'host' && (
                        <Pill className={lifecycleMeta(selected.state).badge}>{lifecycleMeta(selected.state).label}</Pill>
                      )}
                      {selected.interestingness ? (
                        <Pill className={cn('font-mono', scoreColor(selected.interestingness))}>
                          {selected.interestingness}
                        </Pill>
                      ) : null}
                    </div>
                  </div>
                  <Button variant="ghost" size="icon-xs" aria-label="Zamknij" onClick={() => setSelectedId(null)}>
                    <RiCloseLine />
                  </Button>
                </div>
                <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
                  {metaEntries.length > 0 && (
                    <dl className="flex flex-col gap-1 font-mono text-[11px]">
                      {metaEntries.map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-3">
                          <dt className="shrink-0 text-muted-foreground">{k}</dt>
                          <dd className="text-right break-all">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                    Ścieżka ataku · {path ? path.size - 1 : 0} powiązanych węzłów
                  </span>
                </div>
                <div className="flex flex-col gap-2 border-t border-border p-3">
                  {selected.kind === 'host' && isCluster(selected) && (
                    <Button size="sm" onClick={() => drill(str(selected.meta?.subnet))}>
                      <RiArrowRightSLine />
                      Rozwiń podsieć
                    </Button>
                  )}
                  {selectedHostId && (
                    <Button size="sm" onClick={() => setInspectHostId(selectedHostId)}>
                      <RiExternalLinkLine />
                      Pełny inspektor
                    </Button>
                  )}
                  {selectedServiceIds.length > 0 && can(PERMISSIONS.DEFECTDOJO_PUSH) && (
                    <Button size="sm" variant="outline" disabled={pushing} onClick={pushToDojo}>
                      {pushing ? <PeckSpinner className="h-3.5" /> : <RiSendPlaneLine />}
                      Wyślij do DefectDojo
                    </Button>
                  )}
                </div>
              </div>
            </Panel>
          )}

          {!loading && graph && graph.nodes.length === 0 && (
            <Panel position="top-center" className="!top-1/2 -translate-y-1/2">
              <div className="border border-border bg-card px-4 py-3 text-xs text-muted-foreground">
                Brak węzłów dla wybranych filtrów
              </div>
            </Panel>
          )}
        </ReactFlow>
      </GraphContext.Provider>

      <AssetInspectorDrawer hostId={inspectHostId} onClose={() => setInspectHostId(null)} onUpdated={() => loadGraph(true)} />
    </div>
  );
}
