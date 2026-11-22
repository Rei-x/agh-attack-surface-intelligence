import { createContext, memo, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
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
import { formatNumber, lifecycleMeta, plural, scoreColor } from '@/lib/format';
import { PERMISSIONS } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Pill, SimpleSelect } from '@/components/common';
import { ServiceLogo } from '@/components/ServiceLogo';
import { AssetInspectorDrawer } from '@/components/AssetInspectorDrawer';
import type { GraphHostRef, GraphMode, GraphNode, GraphQuery, GraphResponse } from '@/types/api';
import { PeckSpinner } from '@/components/Woodpecker';

type Column = 'scope' | 'host' | 'service' | 'tech';
type FlowNodeData = { g: GraphNode; column?: Column; title?: string };
type FlowNode = Node<FlowNodeData>;

type QuickFilter = 'all' | 'risk' | 'adminstaging' | 'active';

const QUICK_FILTERS: { value: QuickFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'risk', label: 'Risk ≥ 50' },
  { value: 'adminstaging', label: 'Admin / staging' },
  { value: 'active', label: 'Active' },
];

const MODES: { value: GraphMode; label: string }[] = [
  { value: 'auto', label: 'Auto' },
  { value: 'clustered', label: 'Clustered' },
  { value: 'detailed', label: 'Detailed' },
];

const COL_X: Record<Column, number> = { scope: 0, host: 330, service: 700, tech: 1090 };
const COL_W: Record<Column, number> = { scope: 260, host: 280, service: 300, tech: 250 };
const COL_TITLE: Record<Column, string> = {
  scope: 'Scope',
  host: 'Host / subnet',
  service: 'Service',
  tech: 'Technology',
};
// Room at the top for the floating toolbar so it never covers the lane headers.
const FIT_PADDING = { top: '124px', right: '32px', bottom: '32px', left: '32px' } as const;
const GAP = 14;
const GROUP_GAP = 34;
const RISK_CRITICAL = '#f43f5e';

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

/** Assets-page query listing what a node stands for ('' when a single host is better). */
function assetsQueryFor(n: GraphNode): string {
  const m = n.meta || {};
  if (n.kind === 'technology' || n.kind === 'signature') {
    const name = str(m.name) || n.label;
    return /\s/.test(name) ? `tech:"${name.replace(/"/g, '')}"` : `tech:${name}`;
  }
  if (n.kind === 'service' && isCluster(n)) {
    const sub = str(m.subnet);
    return `port:${num(m.port)}${sub ? ` cidr:${sub}` : ''}`;
  }
  if (n.kind === 'host' && isCluster(n)) return `cidr:${str(m.subnet)}`;
  if (n.kind === 'block') return `cidr:${str(m.cidr) || n.label}`;
  if (n.kind === 'scope' && str(m.subnet)) return `cidr:${str(m.subnet)}`;
  return '';
}

const CATEGORY_LABEL: Record<string, string> = {
  cms: 'CMS',
  framework: 'Framework',
  server: 'Web server',
  iot: 'IoT / device',
  bmc: 'Server management (BMC)',
  admin_panel: 'Admin panel',
  staging: 'Staging / dev',
  custom: 'Custom signature',
};

/** Human-readable facts for the side panel (instead of a raw meta dump). */
function nodeFacts(n: GraphNode): { label: string; value: string }[] {
  const m = n.meta || {};
  const out: { label: string; value: string }[] = [];
  const add = (label: string, value: unknown) => {
    const v = str(value).trim();
    if (v && v !== '0') out.push({ label, value: v });
  };
  if (n.kind === 'block') {
    add('Hosts', formatNumber(num(m.host_count)));
    add('Active', formatNumber(num(m.active_count)));
    add('Score 50 or more', formatNumber(num(m.high_risk_count)));
    if (num(m.prefix) < 24) add('/24 subnets', formatNumber(num(m.subnet_count)));
    const techs = groupTechs(n);
    if (techs.length) add('Top technologies', techs.map((t) => t.name.replace(/\s*\(.*\)$/, '')).join(', '));
  } else if (n.kind === 'host' && isCluster(n)) {
    add('Hosts', formatNumber(num(m.host_count)));
    add('Active', formatNumber(num(m.active_count)));
    add('High risk (score ≥ 50)', formatNumber(num(m.high_risk_count)));
  } else if (n.kind === 'host') {
    add('Hostname', m.hostname);
    add('Owner', m.owner || 'none (no CIDR rule)');
    add('Environment', m.environment);
    add('Open services', m.service_count);
    if (Array.isArray(m.ports)) add('Ports', (m.ports as unknown[]).map(num).join(', '));
    add('Title', m.title);
    add('Stability', num(m.stability_score) ? `${num(m.stability_score)}%` : '');
  } else if (n.kind === 'service') {
    add('Port', num(m.port) ? `${num(m.port)}/${str(m.protocol) || 'tcp'}` : '');
    add('Product', [str(m.product), str(m.version)].filter(Boolean).join(' '));
    add('HTTP title', m.http_title);
    if (isCluster(n)) add('Subnet', m.subnet);
  } else if (n.kind === 'technology' || n.kind === 'signature') {
    add('Category', CATEGORY_LABEL[str(m.category)] || m.category);
    add('Version', m.version);
    add('Best confidence', num(m.confidence) ? `${num(m.confidence)}%` : '');
  } else if (n.kind === 'scope') {
    add('Hosts', num(m.host_count) ? formatNumber(num(m.host_count)) : '');
    add('/24 subnets', m.subnet_count);
  }
  return out;
}

/** Columns scope → host/subnet → service → tech, sorted by risk, without overlaps. */
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

const BLOCK_W = 232;
const BLOCK_H = 128;
const BLOCK_GAP = 16;
const LANE_W = 224;
const LANE_H = 48;
const LANE_GAP = 8;
const LANE_DX = 96;

const HOST_W = 208;
const HOST_H = 92;
const HOST_GAP = 12;

/** Card grid + technology lane: overview blocks, the /24s of a block, or the hosts of a /24. */
function isAggregateLevel(data: GraphResponse | null): boolean {
  return data?.level === 'overview' || data?.level === 'block' || (data?.level === 'subnet' && data.mode === 'grid');
}

/**
 * Lays the cards out in the column count that gives the largest fit-view zoom for the canvas
 * size (so labels stay readable at 1280 as well as 1920), with the lane on the right.
 */
function layoutAggregate(data: GraphResponse, view: { w: number; h: number }): { nodes: FlowNode[]; edges: Edge[] } {
  const groups = data.nodes.filter((n) => n.kind === 'block' || n.kind === 'host');
  const techs = data.nodes.filter((n) => n.kind !== 'block' && n.kind !== 'host');
  const hostGrid = groups.some((n) => n.kind === 'host');
  const cardW = hostGrid ? HOST_W : BLOCK_W;
  const cardH = hostGrid ? HOST_H : BLOCK_H;
  const gap = hostGrid ? HOST_GAP : BLOCK_GAP;
  const laneH = techs.length ? techs.length * (LANE_H + LANE_GAP) - LANE_GAP : 0;
  const laneW = techs.length ? LANE_DX + LANE_W : 0;
  // Canvas minus the fit-view padding (toolbar on top) and the lane header row.
  const availW = Math.max(320, view.w - 64);
  const availH = Math.max(240, view.h - 124 - 32 - 44);
  let cols = 1;
  let best = 0;
  for (let c = 1; c <= Math.max(1, groups.length); c++) {
    const r = Math.ceil(groups.length / c);
    const w = c * cardW + (c - 1) * gap + laneW;
    const h = Math.max(r * cardH + (r - 1) * gap, laneH);
    const zoom = Math.min(availW / w, availH / h);
    if (zoom > best + 0.001) {
      best = zoom;
      cols = c;
    }
  }
  const rows = Math.max(1, Math.ceil(groups.length / cols));
  const gridW = cols * cardW + (cols - 1) * gap;
  const gridH = rows * cardH + (rows - 1) * gap;
  const gridY = Math.max(0, (laneH - gridH) / 2);
  const laneY = Math.max(0, (gridH - laneH) / 2);
  const laneX = gridW + LANE_DX;

  const nodes: FlowNode[] = [];
  groups.forEach((g, i) => {
    nodes.push({
      id: g.id,
      type: g.kind === 'host' ? 'hostcard' : 'block',
      position: { x: (i % cols) * (cardW + gap), y: gridY + Math.floor(i / cols) * (cardH + gap) },
      data: { g },
      width: cardW,
      height: cardH,
    });
  });
  techs.forEach((t, i) => {
    nodes.push({
      id: t.id,
      type: 'lanetech',
      position: { x: laneX, y: laneY + i * (LANE_H + LANE_GAP) },
      data: { g: t },
      width: LANE_W,
      height: LANE_H,
    });
  });
  const prefix = data.group_prefix || 24;
  const headers: { id: string; title: string; x: number; w: number }[] = [
    {
      id: 'lane:groups',
      title: hostGrid ? 'Hosts by risk' : data.level === 'block' ? 'Subnets /24' : `Blocks /${prefix}`,
      x: 0,
      w: gridW,
    },
  ];
  if (techs.length) headers.push({ id: 'lane:techs', title: 'Top technologies', x: laneX, w: LANE_W });
  const top = Math.min(gridY, techs.length ? laneY : gridY);
  for (const h of headers) {
    nodes.push({
      id: h.id,
      type: 'lane',
      position: { x: h.x, y: top - 44 },
      data: { g: { id: h.id, kind: 'lane', label: h.title }, title: h.title },
      width: h.w,
      height: 28,
      draggable: false,
      selectable: false,
      focusable: false,
    });
  }

  const ids = new Set(nodes.map((n) => n.id));
  const edges: Edge[] = data.edges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e) => ({ id: e.id, source: e.source, target: e.target, data: { weight: e.weight || 0 } }));
  return { nodes, edges };
}

interface GraphCtx {
  isFresh: (n: GraphNode) => boolean;
  drill: (subnet: string) => void;
  /** Open a block (its /24 subnets) or a /24 group card (its hosts). */
  openGroup: (n: GraphNode) => void;
  /** Open the asset inspector for a host. */
  inspect: (hostId: string) => void;
}
const GraphContext = createContext<GraphCtx>({
  isFresh: () => false,
  drill: () => {},
  openGroup: () => {},
  inspect: () => {},
});

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
        selected ? 'border-foreground/70 ring-2 ring-foreground/20' : 'border-border',
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
  // Neutral bar: colour is reserved for the score pill (one red marker per card).
  return (
    <div className={cn("h-1 w-full bg-muted", className)}>
      <div className="h-full bg-foreground/45" style={{ width: `${Math.min(100, Math.max(3, value))}%` }} />
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
    <NodeShell selected={selected}>
      <div className="flex h-full items-center gap-3 px-3.5">
        <ServiceLogo kind="scope" size="lg" />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <span className="truncate font-mono text-xs font-semibold" title={g.label}>
            {str(m.subnet) || g.label.replace(/\s*\(\d+ hosts?\)\s*$/, "")}
          </span>
          <div className="flex items-center gap-1.5">
            {hostCount > 0 && <Pill tone="primary">{formatNumber(hostCount)} hosts</Pill>}
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
      <NodeShell selected={selected} accent={lc.stroke}>
        <Handle type="target" position={Position.Left} className={handleCls} />
        <div className="flex h-full flex-col justify-between gap-1.5 py-2.5 pr-3 pl-3.5">
          <div className="flex items-center gap-2.5">
            <span className="flex size-8 shrink-0 items-center justify-center border border-border bg-muted text-muted-foreground">
              <RiStackLine className="size-4" />
            </span>
            <div className="flex min-w-0 flex-1 flex-col">
              <span className="truncate font-mono text-xs font-semibold">{subnet}</span>
              <span className="truncate text-[11px] text-muted-foreground tabular-nums">
                {formatNumber(hostCount)} hosts ·{" "}
                <span className={cn(highRisk > 0 && "font-semibold text-foreground")}>
                  {formatNumber(highRisk)} high risk
                </span>
              </span>
            </div>
            <Pill className={cn('font-mono', scoreColor(score))}>{score}</Pill>
          </div>
          <RiskBar value={score} />
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground tabular-nums">{formatNumber(active)} active</span>
            <button
              type="button"
              className="nodrag nopan inline-flex items-center gap-0.5 text-[11px] font-semibold text-foreground hover:underline"
              onClick={(e) => {
                e.stopPropagation();
                drill(subnet);
              }}
            >
              Expand subnet <RiArrowRightSLine className="size-3.5" />
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
    <NodeShell selected={selected} accent={lc.stroke} fresh={isFresh(g)}>
      <Handle type="target" position={Position.Left} className={handleCls} />
      <div className="flex h-full flex-col justify-center gap-1.5 pr-3 pl-3.5">
        <div className="flex items-center gap-2">
          <span className="relative flex size-2.5 shrink-0">
            {live && <span className="absolute inset-0 animate-ping opacity-60" style={{ backgroundColor: lc.stroke }} />}
            <span className="relative size-2.5" style={{ backgroundColor: lc.stroke }} />
          </span>
          <span className="truncate font-mono text-[13px] font-semibold">{ip}</span>
          {locked && <RiLockLine className="size-3 shrink-0 text-amber-500" aria-label="Analyst-locked fields" />}
          <span className="flex-1" />
          <Pill className={cn('font-mono', scoreColor(score))}>{score}</Pill>
        </div>
        <div className="flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
          <span className="truncate">{hostname || lc.label}</span>
          {svcCount > 0 && <span className="shrink-0 tabular-nums">{svcCount} svc</span>}
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
    <NodeShell selected={selected} fresh={isFresh(g)}>
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
              {name || "unknown"}
            </span>
            {count > 1 && (
              <span className="ml-auto shrink-0 font-mono text-[10px] font-semibold text-muted-foreground tabular-nums">
                {formatNumber(count)}×
              </span>
            )}
          </div>
          <div className="flex min-w-0 items-center gap-1 overflow-hidden">
            {isAdmin && <Pill tone="warning">Admin</Pill>}
            {isStaging && <Pill tone="violet">Staging</Pill>}
            {isIoT && <Pill tone="info">IoT</Pill>}
            {tlsWarn && <Pill tone="warning">TLS</Pill>}
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
            {isSig && <span className="ml-auto shrink-0 text-[9px] font-semibold tracking-wider text-violet-500 uppercase">Sig</span>}
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-1 flex-1 bg-muted">
              <div className="h-full bg-foreground/75" style={{ width: `${Math.min(100, conf)}%` }} />
            </div>
            <span className="font-mono text-[10px] text-muted-foreground tabular-nums">{conf}%</span>
          </div>
        </div>
      </div>
    </NodeShell>
  );
});

type Severity = { critical: number; high: number; medium: number; low: number };
const SEVERITY_BANDS: { key: keyof Severity; label: string; fill: string }[] = [
  { key: 'critical', label: 'critical', fill: 'bg-rose-500' },
  { key: 'high', label: 'high', fill: 'bg-orange-400' },
  { key: 'medium', label: 'medium', fill: 'bg-amber-400' },
  { key: 'low', label: 'low', fill: 'bg-stone-300 dark:bg-stone-600' },
];

function severityOf(n: GraphNode): Severity {
  const s = (n.meta?.severity || {}) as Partial<Severity>;
  return { critical: num(s.critical), high: num(s.high), medium: num(s.medium), low: num(s.low) };
}

/** Stacked host-count bar per risk band: red only for the critical share. */
function SeverityBar({ sev, className }: { sev: Severity; className?: string }) {
  const total = sev.critical + sev.high + sev.medium + sev.low;
  return (
    <div className={cn('flex h-1.5 w-full gap-px bg-muted', className)}>
      {total > 0 &&
        SEVERITY_BANDS.map((b) =>
          sev[b.key] > 0 ? (
            <span key={b.key} className={b.fill} style={{ width: `${(sev[b.key] / total) * 100}%` }} />
          ) : null
        )}
    </div>
  );
}

function groupTechs(n: GraphNode): { name: string; hosts: number }[] {
  const list = n.meta?.top_techs;
  return Array.isArray(list)
    ? list.map((t) => ({ name: str((t as { name?: unknown }).name), hosts: num((t as { hosts?: unknown }).hosts) }))
    : [];
}

const BlockNode = memo(function BlockNode({ data, selected }: NodeProps<FlowNode>) {
  const { openGroup } = useContext(GraphContext);
  const g = data.g;
  const m = g.meta || {};
  const score = g.interestingness || 0;
  const cidr = str(m.cidr) || g.label;
  const hostCount = num(m.host_count);
  const subnets = num(m.subnet_count);
  const sev = severityOf(g);
  const isSubnet = num(m.prefix) >= 24;
  const techs = groupTechs(g);
  return (
    <NodeShell selected={selected}>
      <div className="flex h-full flex-col gap-2 px-3 py-2.5">
        <div className="flex items-start gap-2">
          <div className="flex min-w-0 flex-1 flex-col">
            <span className="truncate font-mono text-sm font-semibold" title={cidr}>
              {cidr}
            </span>
            <span className="truncate text-xs text-muted-foreground tabular-nums">
              {plural(hostCount, 'host')}
              {isSubnet ? ` · ${formatNumber(num(m.active_count))} active` : ` · ${subnets} × /24`}
            </span>
          </div>
          <Pill className={cn('font-mono tabular-nums', scoreColor(score))} title="Top risk score">
            {score}
          </Pill>
        </div>
        <div className="flex flex-col gap-1">
          <SeverityBar sev={sev} />
          <span className="truncate text-[11px] text-muted-foreground tabular-nums">
            {formatNumber(sev.critical)} critical · {formatNumber(sev.high)} high
          </span>
        </div>
        <div className="mt-auto flex items-center gap-1.5">
          {techs.map((t) => (
            <span key={t.name} title={`${t.name} · ${plural(t.hosts, 'host')}`} className="flex">
              <ServiceLogo names={[t.name]} size={22} title={false} />
            </span>
          ))}
          <span className="flex-1" />
          <button
            type="button"
            className="nodrag nopan inline-flex items-center gap-0.5 text-xs font-semibold text-foreground hover:underline"
            onClick={(e) => {
              e.stopPropagation();
              openGroup(g);
            }}
          >
            Open <RiArrowRightSLine className="size-3.5" />
          </button>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className={handleCls} />
    </NodeShell>
  );
});

const LaneTechNode = memo(function LaneTechNode({ data, selected }: NodeProps<FlowNode>) {
  const g = data.g;
  const m = g.meta || {};
  const name = str(m.name) || g.label;
  const score = num(m.max_score) || g.interestingness || 0;
  const hosts = num(m.host_count);
  return (
    <NodeShell selected={selected}>
      <Handle type="target" position={Position.Left} className={handleCls} />
      <div className="grid h-full grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-2.5 px-2.5">
        <ServiceLogo names={[name, str(m.category)]} size={28} title={false} />
        <div className="flex min-w-0 flex-col">
          <span className="truncate text-[13px] font-semibold" title={name}>
            {name.replace(/\s*\(.*\)$/, '')}
          </span>
          <span className="truncate text-[11px] text-muted-foreground tabular-nums">{plural(hosts, 'host')}</span>
        </div>
        <Pill className={cn('font-mono tabular-nums', scoreColor(score))} title="Top risk score">
          {score}
        </Pill>
      </div>
    </NodeShell>
  );
});

const HostCardNode = memo(function HostCardNode({ data, selected }: NodeProps<FlowNode>) {
  const { isFresh, inspect } = useContext(GraphContext);
  const g = data.g;
  const m = g.meta || {};
  const score = g.interestingness || 0;
  const lc = lifecycleMeta(g.state);
  const ports = Array.isArray(m.ports) ? (m.ports as unknown[]).map(num) : [];
  const shown = ports.slice(0, 3);
  const techs = groupTechs(g).slice(0, 2);
  const sub = str(m.hostname) || str(m.title) || str(m.owner) || lc.label;
  return (
    <NodeShell selected={selected} accent={lc.stroke} fresh={isFresh(g)}>
      <div className="flex h-full flex-col justify-between gap-1 py-2 pr-2.5 pl-3.5">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-sm font-semibold">{str(m.ip) || g.label}</span>
          <span className="flex-1" />
          <Pill className={cn('font-mono tabular-nums', scoreColor(score))}>{score}</Pill>
        </div>
        <span className="truncate text-xs text-muted-foreground" title={sub}>
          {sub}
        </span>
        <div className="flex min-w-0 items-center gap-1">
          {techs.map((t) => (
            <span key={t.name} title={t.name} className="flex">
              <ServiceLogo names={[t.name]} size={20} title={false} />
            </span>
          ))}
          {shown.map((p) => (
            <span
              key={p}
              className="shrink-0 border border-border bg-muted px-1 font-mono text-[11px] leading-[18px] font-semibold tabular-nums"
            >
              :{p}
            </span>
          ))}
          {ports.length > shown.length && (
            <span className="shrink-0 font-mono text-[11px] text-muted-foreground">+{ports.length - shown.length}</span>
          )}
          <span className="flex-1" />
          <button
            type="button"
            aria-label="Host details"
            className="nodrag nopan inline-flex shrink-0 items-center text-muted-foreground hover:text-foreground"
            onClick={(e) => {
              e.stopPropagation();
              inspect(str(m.host_id));
            }}
          >
            <RiArrowRightSLine className="size-4" />
          </button>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className={handleCls} />
    </NodeShell>
  );
});

const NODE_TYPES: NodeTypes = {
  hostcard: HostCardNode,
  lane: LaneNode,
  scope: ScopeNode,
  host: HostNode,
  service: ServiceNode,
  tech: TechNode,
  block: BlockNode,
  lanetech: LaneTechNode,
};

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
  const navigate = useNavigate();

  const subnet = searchParams.get('subnet') || '';
  const block = subnet ? '' : searchParams.get('block') || '';
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
      block: block || undefined,
      q: q || undefined,
      limit: subnet || mode === 'detailed' ? 150 : 60,
    };
    if (quick === 'risk') base.min_score = 50;
    if (quick === 'active') base.state = 'ACTIVE';
    if (quick === 'adminstaging') base.admin_or_staging = true;
    return base;
  }, [mode, subnet, block, q, quick]);

  const reqSeq = useRef(0);
  const loadGraph = useCallback(
    async (silent?: boolean) => {
      const seq = ++reqSeq.current;
      if (!silent) setLoading(true);
      try {
        const data = await api.graph(query);
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
        if (!silent && seq === reqSeq.current) toast.error("Could not load the graph", (err as Error).message);
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
  const canvasRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!graph) return;
    const el = canvasRef.current;
    const view = { w: el?.clientWidth || 1200, h: el?.clientHeight || 760 };
    const { nodes: n, edges: e } = isAggregateLevel(graph) ? layoutAggregate(graph, view) : layoutGraph(graph);
    setNodes(n);
    setEdges(e);
    const key = JSON.stringify(query) + quick + graph.mode + (graph.level || '');
    if (key !== lastFitKey.current) {
      lastFitKey.current = key;
      requestAnimationFrame(() => fitView({ padding: FIT_PADDING, duration: 450, maxZoom: 1.1 }));
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

  // Edges stay thin and neutral; only the hovered / selected path is emphasised. Aggregated
  // edges scale their width with the number of hosts behind them.
  const maxWeight = useMemo(
    () => Math.max(1, ...edges.map((e) => num((e.data as { weight?: number } | undefined)?.weight))),
    [edges]
  );
  const displayEdges = useMemo(
    () =>
      edges.map((e) => {
        const s = nodeById.get(e.source);
        const t = nodeById.get(e.target);
        const weight = num((e.data as { weight?: number } | undefined)?.weight);
        const base = weight ? 0.75 + 2.25 * Math.sqrt(weight / maxWeight) : 1;
        const fresh = Boolean((t && isFresh(t)) || (s && isFresh(s)));
        const lit = path ? path.has(e.source) && path.has(e.target) : false;
        const dim = path && !lit;
        return {
          ...e,
          animated: fresh,
          style: {
            stroke: lit ? 'var(--foreground)' : fresh ? '#10b981' : 'var(--muted-foreground)',
            strokeWidth: lit ? Math.max(1.5, base) : base,
            opacity: dim ? 0.04 : lit ? 0.85 : weight ? 0.1 : 0.3,
            transition: 'opacity 200ms',
          },
          zIndex: lit ? 1 : 0,
        } satisfies Edge;
      }),
    [edges, nodeById, path, isFresh, maxWeight]
  );

  // Navigation between levels lives in the URL (?block=, ?subnet=) so Back works and a level
  // can be shared as a link.
  const goTo = useCallback(
    (target: { block?: string; subnet?: string }) => {
      setSelectedId(null);
      setHoverId(null);
      const next = new URLSearchParams(searchParams);
      next.delete('block');
      next.delete('subnet');
      if (target.block) next.set('block', target.block);
      if (target.subnet) next.set('subnet', target.subnet);
      setSearchParams(next);
    },
    [searchParams, setSearchParams]
  );
  const drill = useCallback((sn: string) => goTo({ subnet: sn }), [goTo]);
  const openGroup = useCallback(
    (n: GraphNode) => {
      const m = n.meta || {};
      const cidr = str(m.cidr) || n.label;
      if (str(m.drill) === 'subnet' || num(m.prefix) >= 24) goTo({ subnet: cidr });
      else goTo({ block: cidr });
    },
    [goTo]
  );
  const clearSubnet = () => goTo({});

  const setMode = (m: GraphMode) => {
    const next = new URLSearchParams(searchParams);
    if (m === 'auto') next.delete('mode');
    else next.set('mode', m);
    setSearchParams(next);
  };

  const inspect = useCallback((id: string) => id && setInspectHostId(id), []);
  const ctx = useMemo<GraphCtx>(() => ({ isFresh, drill, openGroup, inspect }), [isFresh, drill, openGroup, inspect]);

  const selected = selectedId ? nodeById.get(selectedId) || null : null;
  const selectedHostId = hostIdOf(selected);

  // Every service behind the selection: a clustered service / technology node carries the
  // full membership (service_ids), not one representative.
  const selectedServiceIds = useMemo(() => {
    if (!selected) return [];
    const ids = selected.meta?.service_ids;
    if (Array.isArray(ids) && ids.length) return ids.map(str).filter(Boolean);
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
      toast.success('Sent to DefectDojo', `${selectedServiceIds.length} service(s)`);
    } catch (err) {
      toast.error('DefectDojo push failed', (err as Error).message);
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
      if (s >= 90) return RISK_CRITICAL;
      if (s >= 75) return '#fb923c';
      if (s >= 50) return '#fbbf24';
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

  const aggregate = isAggregateLevel(graph);
  const totalHosts = graph?.matched_hosts ?? 0;
  const groupCount = aggregate ? (graph?.nodes || []).filter((n) => n.kind === 'block').length : 0;
  const statusLabel = graph
    ? graph.level === 'subnet' && aggregate
      ? plural(totalHosts, 'host')
      : aggregate
      ? `${formatNumber(totalHosts)} hosts · ${groupCount} ${graph.level === 'block' ? 'subnets' : 'blocks'}${
          graph.hidden_groups ? ` · ${graph.hidden_groups} more hidden` : ''
        }`
      : `${formatNumber(totalHosts)} hosts · ${graph.clustered ? 'clustered' : 'detailed'}${
          !graph.clustered && graph.shown_hosts < graph.matched_hosts
            ? ` · showing ${formatNumber(graph.shown_hosts)}`
            : ''
        }`
    : 'Loading…';
  // Breadcrumb: All > block > subnet. The server reports the block that holds a subnet.
  const crumbBlock = block || (subnet ? graph?.block || '' : '');

  const memberHosts: GraphHostRef[] = Array.isArray(selected?.meta?.hosts)
    ? (selected!.meta!.hosts as GraphHostRef[])
    : [];
  const memberCount = num(selected?.meta?.host_count) || memberHosts.length;
  const openHost = (id: string) => navigate(`/assets?host=${encodeURIComponent(id)}`);
  const assetsQuery = selected ? assetsQueryFor(selected) : '';
  const facts = selected ? nodeFacts(selected) : [];

  return (
    <div ref={canvasRef} className="relative h-[calc(100vh-8.5rem)] w-full overflow-hidden bg-background ring-1 ring-foreground/5">
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
          fitViewOptions={{ padding: FIT_PADDING, maxZoom: 1.1 }}
          proOptions={{ hideAttribution: true }}
          onNodeMouseEnter={(_, n) => n.type !== 'lane' && setHoverId(n.id)}
          onNodeMouseLeave={() => setHoverId(null)}
          onNodeClick={(_, n) => n.type !== 'lane' && setSelectedId(n.id)}
          onNodeDoubleClick={(_, n) => {
            const g = (n.data as FlowNodeData).g;
            if (g.kind === 'block') openGroup(g);
            else if (isCluster(g) && g.kind === 'host') drill(str(g.meta?.subnet));
            else {
              const hid = hostIdOf(g);
              if (hid) setInspectHostId(hid);
            }
          }}
          onPaneClick={() => setSelectedId(null)}
          className="!bg-background"
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1.2} color="var(--border)" />
          {!aggregate && (
          <MiniMap
            pannable
            zoomable
            nodeColor={minimapColor}
            nodeStrokeWidth={0}
            maskColor={theme === 'dark' ? 'rgba(12,10,9,0.7)' : 'rgba(250,250,249,0.7)'}
            className="!m-3 !border !border-border !bg-card"
            style={{ width: 180, height: 120 }}
          />
          )}

          <Panel position="top-left" className={cn('!m-3', selected ? 'max-w-[calc(100%-22.5rem)]' : 'max-w-[calc(100%-1.5rem)]')}>
            <div className="flex flex-wrap items-center gap-2 border border-border bg-card/95 p-1.5 shadow-sm backdrop-blur">
              <div className="relative w-52">
                <RiSearchLine className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="IP, host, service, technology…"
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
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {subnetOptions.length > 1 && !subnet && (
                <div className="border border-border bg-card/95 px-1 backdrop-blur">
                  <SimpleSelect
                    size="sm"
                    value=""
                    placeholder="Jump to subnet…"
                    onValueChange={(v) => v && drill(v)}
                    options={subnetOptions}
                    className="h-7 w-40 border-b-transparent py-0 text-xs data-[size=sm]:h-[26px]"
                  />
                </div>
              )}
              <nav
                aria-label="Graph level"
                className="flex h-7 items-center gap-1 border border-border bg-card/95 px-2 text-[11px] backdrop-blur"
              >
                <button
                  type="button"
                  onClick={clearSubnet}
                  className={cn('font-semibold', crumbBlock || subnet ? 'text-primary hover:underline' : 'text-foreground')}
                >
                  All
                </button>
                {crumbBlock && (
                  <>
                    <RiArrowRightSLine className="size-3.5 text-muted-foreground" />
                    <button
                      type="button"
                      onClick={() => goTo({ block: crumbBlock })}
                      disabled={!subnet}
                      className={cn('font-mono font-semibold', subnet ? 'text-primary hover:underline' : 'text-foreground')}
                    >
                      {crumbBlock}
                    </button>
                  </>
                )}
                {subnet && (
                  <>
                    <RiArrowRightSLine className="size-3.5 text-muted-foreground" />
                    <span className="font-mono font-semibold">{subnet}</span>
                  </>
                )}
                {(crumbBlock || subnet) && (
                  <button
                    type="button"
                    onClick={clearSubnet}
                    aria-label="Back to all"
                    className="ml-0.5 text-muted-foreground hover:text-foreground"
                  >
                    <RiCloseLine className="size-3.5" />
                  </button>
                )}
              </nav>
              <span className="flex h-7 items-center gap-1.5 border border-border bg-card/95 px-2 font-mono text-[11px] tabular-nums backdrop-blur">
                {loading ? (
                  <PeckSpinner className="h-3" />
                ) : (
                  <span className={cn('size-1.5', graph?.clustered ? 'bg-muted-foreground' : 'bg-emerald-500')} />
                )}
                {statusLabel}
              </span>
              <Button
                variant="outline"
                size="sm"
                className="h-7 bg-card/95 text-[11px]"
                onClick={() => fitView({ padding: FIT_PADDING, duration: 450, maxZoom: 1.1 })}
              >
                <RiFocus3Line />
                Fit view
              </Button>
              <Button
                variant="outline"
                size="icon-sm"
                className="size-7 bg-card/95"
                onClick={() => loadGraph()}
                aria-label="Refresh"
              >
                <RiRefreshLine className={cn(loading && 'animate-spin')} />
              </Button>
            </div>
          </Panel>

          {selected && (
            <Panel position="top-right" className="!m-3 w-80">
              <div className="flex max-h-[calc(100vh-14rem)] flex-col border border-border bg-card/95 shadow-md backdrop-blur">
                <div className="flex items-start gap-3 border-b border-border p-3">
                  {selected.kind === 'block' || (selected.kind === 'host' && isCluster(selected)) ? (
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
                      <Pill>
                        {selected.kind === 'block'
                          ? num(selected.meta?.prefix) >= 24
                            ? 'subnet'
                            : 'block'
                          : selected.kind}
                      </Pill>
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
                  <Button variant="ghost" size="icon-xs" aria-label="Close" onClick={() => setSelectedId(null)}>
                    <RiCloseLine />
                  </Button>
                </div>
                <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
                  {selected.kind === 'block' && (
                    <div className="flex flex-col gap-1.5">
                      <SeverityBar sev={severityOf(selected)} className="h-2" />
                      <div className="grid grid-cols-4 gap-1 text-[10px] text-muted-foreground tabular-nums">
                        {SEVERITY_BANDS.map((b) => (
                          <span key={b.key} className="flex min-w-0 items-center gap-1">
                            <span className={cn('size-1.5 shrink-0', b.fill)} />
                            <span className="truncate">
                              {formatNumber(severityOf(selected)[b.key])} {b.label}
                            </span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {facts.length > 0 && (
                    <dl className="flex flex-col gap-1 text-[11px]">
                      {facts.map((f) => (
                        <div key={f.label} className="flex justify-between gap-3">
                          <dt className="shrink-0 text-muted-foreground">{f.label}</dt>
                          <dd className="min-w-0 truncate text-right font-medium" title={f.value}>
                            {f.value}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  {memberHosts.length > 0 && (
                    <div className="flex flex-col gap-1.5">
                      <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
                        {formatNumber(memberCount)} {memberCount === 1 ? 'host' : 'hosts'}
                        {memberCount > memberHosts.length ? ` · top ${memberHosts.length} by score` : ''}
                      </span>
                      <ul className="-mx-1 flex flex-col">
                        {memberHosts.map((h) => (
                          <li key={h.host_id}>
                            <button
                              type="button"
                              onClick={() => openHost(h.host_id)}
                              className="flex w-full items-center gap-2 px-1 py-1 text-left hover:bg-muted"
                              title="Open in Assets"
                            >
                              <span className="flex min-w-0 flex-1 flex-col">
                                <span className="truncate font-mono text-[11px] font-semibold">
                                  {h.ip}
                                  {h.port ? <span className="text-muted-foreground">:{h.port}</span> : null}
                                </span>
                                {(h.title || h.hostname || h.owner) && (
                                  <span className="truncate text-[10px] text-muted-foreground">
                                    {h.title || h.hostname || h.owner}
                                  </span>
                                )}
                              </span>
                              <Pill className={cn('shrink-0 font-mono', scoreColor(h.score))}>{h.score}</Pill>
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <span className="text-[10px] text-muted-foreground">
                    Attack path: {path ? path.size - 1 : 0} connected nodes highlighted
                  </span>
                </div>
                <div className="flex flex-col gap-2 border-t border-border p-3">
                  {selected.kind === 'block' && (
                    <Button size="sm" onClick={() => openGroup(selected)}>
                      <RiArrowRightSLine />
                      Open {num(selected.meta?.prefix) >= 24 ? 'subnet' : 'block'}
                    </Button>
                  )}
                  {selected.kind === 'host' && isCluster(selected) && (
                    <Button size="sm" onClick={() => drill(str(selected.meta?.subnet))}>
                      <RiArrowRightSLine />
                      Expand subnet
                    </Button>
                  )}
                  {selectedHostId && (
                    <Button size="sm" onClick={() => setInspectHostId(selectedHostId)}>
                      <RiExternalLinkLine />
                      Open host details
                    </Button>
                  )}
                  {assetsQuery && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate(`/assets?q=${encodeURIComponent(assetsQuery)}`)}
                    >
                      <RiExternalLinkLine />
                      Show in Assets
                    </Button>
                  )}
                  {selectedServiceIds.length > 0 && can(PERMISSIONS.DEFECTDOJO_PUSH) && (
                    <Button size="sm" variant="ghost" disabled={pushing} onClick={pushToDojo}>
                      {pushing ? <PeckSpinner className="h-3.5" /> : <RiSendPlaneLine />}
                      Push {selectedServiceIds.length === 1 ? "1 service" : `${selectedServiceIds.length} services`} to DefectDojo
                    </Button>
                  )}
                </div>
              </div>
            </Panel>
          )}

          {!loading && graph && graph.nodes.length === 0 && (
            <Panel position="top-center" className="!top-1/2 -translate-y-1/2">
              <div className="border border-border bg-card px-4 py-3 text-xs text-muted-foreground">
                No nodes match these filters
              </div>
            </Panel>
          )}
        </ReactFlow>
      </GraphContext.Provider>

      <AssetInspectorDrawer hostId={inspectHostId} onClose={() => setInspectHostId(null)} onUpdated={() => loadGraph(true)} />
    </div>
  );
}
