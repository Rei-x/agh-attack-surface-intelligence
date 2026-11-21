import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Crosshair,
  ExternalLink,
  Filter,
  Maximize2,
  Network,
  RefreshCw,
  Search,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import { api } from '../lib/api';
import { useToast } from '../context/ToastContext';
import { lifecycleMeta, scoreColor } from '../lib/format';
import { AssetInspectorDrawer } from '../components/AssetInspectorDrawer';
import type { GraphEdge, GraphNode } from '../types/api';

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
  layer: number;
}

const LAYER_X: Record<string, number> = {
  scope: 110,
  host: 380,
  service: 680,
  technology: 990,
  signature: 990,
};

const LAYER_LABELS = [
  { x: 110, title: 'ZAKRES / DOMENA' },
  { x: 380, title: 'HOST (STAN)' },
  { x: 680, title: 'USŁUGA (PORT)' },
  { x: 990, title: 'TECHNOLOGIA / SYGNATURA' },
];

export function GraphPage() {
  const toast = useToast();

  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState('');
  const [minScore, setMinScore] = useState(0);
  const [adminStagingOnly, setAdminStagingOnly] = useState(false);
  const [showTechLayer, setShowTechLayer] = useState(true);

  // Pan & Zoom state
  const [zoom, setZoom] = useState(0.95);
  const [pan, setPan] = useState({ x: 30, y: 20 });
  const dragging = useRef(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  // Selection
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [inspectHostId, setInspectHostId] = useState<string | null>(null);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.graph();
      setNodes(data.nodes || []);
      setEdges(data.edges || []);
    } catch (err) {
      toast.error('Nie udało się załadować grafu', (err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // Filter & layout calculation
  const { positionedNodes, visibleEdges, nodeMap, canvasHeight } = useMemo(() => {
    const q = search.trim().toLowerCase();

    // First filter hosts/services according to criteria, then keep connected ancestors/descendants
    const rawMap = new Map<string, GraphNode>();
    for (const n of nodes) rawMap.set(n.id, n);

    const adjOut = new Map<string, string[]>();
    const adjIn = new Map<string, string[]>();
    for (const e of edges) {
      if (!adjOut.has(e.source)) adjOut.set(e.source, []);
      adjOut.get(e.source)!.push(e.target);
      if (!adjIn.has(e.target)) adjIn.set(e.target, []);
      adjIn.get(e.target)!.push(e.source);
    }

    const keptIds = new Set<string>();
    const hasFilters = Boolean(q || stateFilter || minScore > 0 || adminStagingOnly);

    const addAncestors = (id: string) => {
      const stack = [id];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const parent of adjIn.get(cur) || []) {
          if (!keptIds.has(parent)) {
            keptIds.add(parent);
            stack.push(parent);
          }
        }
      }
    };

    const addDescendants = (id: string) => {
      const stack = [id];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const child of adjOut.get(cur) || []) {
          if (!keptIds.has(child)) {
            keptIds.add(child);
            stack.push(child);
          }
        }
      }
    };

    if (!hasFilters) {
      for (const n of nodes) keptIds.add(n.id);
    } else {
      for (const n of nodes) {
        const meta = n.meta || {};
        const isAdmin = Boolean(meta.is_admin_panel || meta.admin);
        const isStaging = Boolean(
          meta.is_staging_env || meta.staging || meta.environment === 'staging' || meta.environment === 'dev'
        );

        let match = true;
        if (q && !n.label.toLowerCase().includes(q) && !JSON.stringify(meta).toLowerCase().includes(q)) {
          match = false;
        }
        if (stateFilter && n.kind === 'host' && n.state !== stateFilter) {
          match = false;
        }
        if (stateFilter && n.kind !== 'host') {
          match = false;
        }
        if (minScore > 0 && (n.interestingness || 0) < minScore) {
          match = false;
        }
        if (adminStagingOnly && !(isAdmin || isStaging)) {
          match = false;
        }

        if (match) {
          keptIds.add(n.id);
          addAncestors(n.id);
          addDescendants(n.id);
        }
      }
    }

    const filteredNodes = nodes.filter((n) => {
      if (!keptIds.has(n.id)) return false;
      if (!showTechLayer && (n.kind === 'technology' || n.kind === 'signature')) return false;
      return true;
    });

    const filteredIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = edges.filter(
      (e) => filteredIds.has(e.source) && filteredIds.has(e.target)
    );

    // Group by layer
    const groups: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [] };
    for (const n of filteredNodes) {
      const layer =
        n.kind === 'scope'
          ? 0
          : n.kind === 'host'
            ? 1
            : n.kind === 'service'
              ? 2
              : 3;
      groups[layer].push(n);
    }

    // Sort nodes nicely inside each layer
    groups[1].sort((a, b) => (b.interestingness || 0) - (a.interestingness || 0));
    groups[2].sort((a, b) => (b.interestingness || 0) - (a.interestingness || 0));

    const maxCount = Math.max(
      groups[0].length,
      groups[1].length,
      groups[2].length,
      groups[3].length,
      1
    );
    const rowSpacing = 66;
    const totalHeight = Math.max(520, maxCount * rowSpacing + 120);

    const positioned: PositionedNode[] = [];
    const pMap = new Map<string, PositionedNode>();

    for (const layerIdx of [0, 1, 2, 3]) {
      const list = groups[layerIdx];
      const layerX =
        layerIdx === 0
          ? LAYER_X.scope
          : layerIdx === 1
            ? LAYER_X.host
            : layerIdx === 2
              ? LAYER_X.service
              : LAYER_X.technology;
      const startY = Math.max(84, (totalHeight - (list.length - 1) * rowSpacing) / 2);
      list.forEach((n, idx) => {
        const pn: PositionedNode = {
          ...n,
          x: layerX,
          y: startY + idx * rowSpacing,
          layer: layerIdx,
        };
        positioned.push(pn);
        pMap.set(pn.id, pn);
      });
    }

    return {
      positionedNodes: positioned,
      visibleEdges: filteredEdges,
      nodeMap: pMap,
      canvasHeight: totalHeight,
    };
  }, [nodes, edges, search, stateFilter, minScore, adminStagingOnly, showTechLayer]);

  const selectedNode = selectedNodeId ? nodeMap.get(selectedNodeId) || null : null;

  const connectedEdges = useMemo(() => {
    if (!selectedNodeId) return [];
    return visibleEdges.filter((e) => e.source === selectedNodeId || e.target === selectedNodeId);
  }, [selectedNodeId, visibleEdges]);

  const connectedNodeIds = useMemo(() => {
    const set = new Set<string>();
    if (selectedNodeId) {
      set.add(selectedNodeId);
      for (const e of connectedEdges) {
        set.add(e.source);
        set.add(e.target);
      }
    }
    return set;
  }, [selectedNodeId, connectedEdges]);

  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if ((e.target as HTMLElement).closest('[data-node]')) return;
    dragging.current = true;
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!dragging.current) return;
    setPan({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  };

  const handleMouseUp = () => {
    dragging.current = false;
  };

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.1 : -0.1;
    setZoom((z) => Math.max(0.35, Math.min(2.2, Number((z + delta).toFixed(2)))));
  };

  const resetView = () => {
    setZoom(0.95);
    setPan({ x: 30, y: 20 });
  };

  const getNodeColors = (node: GraphNode) => {
    if (node.kind === 'scope') {
      return { fill: '#172554', stroke: '#38bdf8', text: '#e0f2fe' };
    }
    if (node.kind === 'host') {
      const lc = lifecycleMeta(node.state);
      const highRisk = (node.interestingness || 0) >= 60;
      return {
        fill: '#0f172a',
        stroke: highRisk ? '#f43f5e' : lc.stroke,
        text: '#f8fafc',
      };
    }
    if (node.kind === 'service') {
      const score = node.interestingness || 0;
      const stroke = score >= 70 ? '#f43f5e' : score >= 45 ? '#f59e0b' : '#06b6d4';
      return { fill: '#0b1324', stroke, text: '#e2e8f0' };
    }
    return { fill: '#1e1b4b', stroke: '#a78bfa', text: '#ede9fe' };
  };

  const resolveHostIdFromNode = (node: GraphNode): string | null => {
    if (node.meta?.host_id && typeof node.meta.host_id === 'string') return node.meta.host_id;
    if (node.kind === 'host') {
      if (node.meta?.id && typeof node.meta.id === 'string') return node.meta.id;
      return node.id.replace(/^host:/, '');
    }
    return null;
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-text-primary flex items-center gap-2">
            <Network className="h-5 w-5 text-cyan-400" />
            Interaktywny Graf Powierzchni Ataku
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Topologia warstwowa: Zakres → Host (stan) → Usługa (port) → Technologia / Sygnatura
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={loadGraph}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-border-subtle bg-bg-card hover:bg-bg-hover text-text-secondary"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Odśwież graf
          </button>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="rounded-xl border border-border-subtle bg-bg-card p-3.5 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="h-3.5 w-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Szukaj IP, domeny, usługi, technologii..."
            className="w-full rounded-lg border border-border-subtle bg-bg-elevated pl-8 pr-3 py-1.5 text-xs text-text-primary focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-1.5 text-xs">
          <Filter className="h-3.5 w-3.5 text-text-muted" />
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1.5 text-xs text-text-primary"
          >
            <option value="">Wszystkie stany</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="NEW">NEW</option>
            <option value="INTERMITTENT">INTERMITTENT</option>
            <option value="MISSING">MISSING</option>
            <option value="INACTIVE">INACTIVE</option>
            <option value="REACTIVATED">REACTIVATED</option>
          </select>
        </div>

        <label className="flex items-center gap-2 text-xs text-text-secondary">
          <span>Min Score: <strong className="font-mono text-cyan-400">{minScore}</strong></span>
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
            checked={adminStagingOnly}
            onChange={(e) => setAdminStagingOnly(e.target.checked)}
            className="accent-rose-500 rounded"
          />
          Tylko Admin / Staging
        </label>

        <label className="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showTechLayer}
            onChange={(e) => setShowTechLayer(e.target.checked)}
            className="accent-cyan-500 rounded"
          />
          Warstwa Technologii
        </label>
      </div>

      {/* Graph Canvas + Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-9 rounded-xl border border-border-subtle bg-bg-card overflow-hidden relative min-h-[580px] soc-grid-bg">
          {/* Zoom Controls */}
          <div className="absolute top-3 right-3 z-10 flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-secondary/90 backdrop-blur p-1">
            <button
              type="button"
              onClick={() => setZoom((z) => Math.min(2.2, Number((z + 0.15).toFixed(2))))}
              className="p-1.5 rounded hover:bg-bg-hover text-text-secondary"
              title="Przybliż"
            >
              <ZoomIn className="h-4 w-4" />
            </button>
            <span className="text-[11px] font-mono px-1.5 text-text-muted">
              {Math.round(zoom * 100)}%
            </span>
            <button
              type="button"
              onClick={() => setZoom((z) => Math.max(0.35, Number((z - 0.15).toFixed(2))))}
              className="p-1.5 rounded hover:bg-bg-hover text-text-secondary"
              title="Oddal"
            >
              <ZoomOut className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={resetView}
              className="p-1.5 rounded hover:bg-bg-hover text-text-secondary"
              title="Resetuj widok"
            >
              <Maximize2 className="h-4 w-4" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute bottom-3 left-3 z-10 flex flex-wrap items-center gap-3 rounded-lg border border-border-subtle bg-bg-secondary/90 backdrop-blur px-3 py-1.5 text-[11px] text-text-muted">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> ACTIVE
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> INTERMITTENT / Ryzyko
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500" /> Wysoki priorytet (≥60)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-violet-400" /> Technologia / Sygnatura
            </span>
            <span className="font-mono text-text-secondary">
              {positionedNodes.length} węzłów · {visibleEdges.length} krawędzi
            </span>
          </div>

          {positionedNodes.length === 0 ? (
            <div className="h-[580px] flex items-center justify-center text-sm text-text-muted">
              {loading
                ? 'Budowanie grafu topologii...'
                : 'Brak węzłów spełniających bieżące filtry.'}
            </div>
          ) : (
            <svg
              className="w-full h-[580px] cursor-grab active:cursor-grabbing select-none"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
            >
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Column headers */}
                {LAYER_LABELS.map((col, idx) => {
                  if (idx === 3 && !showTechLayer) return null;
                  return (
                    <g key={col.title}>
                      <line
                        x1={col.x}
                        y1={36}
                        x2={col.x}
                        y2={canvasHeight}
                        stroke="rgba(148,163,184,0.1)"
                        strokeDasharray="4 4"
                      />
                      <text
                        x={col.x}
                        y={22}
                        textAnchor="middle"
                        fill="#94a3b8"
                        fontSize={10}
                        fontFamily="JetBrains Mono, monospace"
                        fontWeight={600}
                      >
                        {col.title}
                      </text>
                    </g>
                  );
                })}

                {/* Edges (Cubic Bezier) */}
                {visibleEdges.map((edge) => {
                  const s = nodeMap.get(edge.source);
                  const t = nodeMap.get(edge.target);
                  if (!s || !t) return null;
                  const sx = s.x + 86;
                  const sy = s.y;
                  const tx = t.x - 86;
                  const ty = t.y;
                  const midX = (sx + tx) / 2;
                  const isHighlighted =
                    selectedNodeId &&
                    (edge.source === selectedNodeId || edge.target === selectedNodeId);
                  const dimmed = selectedNodeId && !isHighlighted;

                  return (
                    <path
                      key={edge.id}
                      d={`M ${sx} ${sy} C ${midX} ${sy}, ${midX} ${ty}, ${tx} ${ty}`}
                      fill="none"
                      stroke={isHighlighted ? '#38bdf8' : 'rgba(148,163,184,0.3)'}
                      strokeWidth={isHighlighted ? 2.2 : 1.2}
                      opacity={dimmed ? 0.2 : 0.9}
                    />
                  );
                })}

                {/* Nodes */}
                {positionedNodes.map((node) => {
                  const colors = getNodeColors(node);
                  const isSelected = selectedNodeId === node.id;
                  const dimmed = selectedNodeId && !connectedNodeIds.has(node.id);
                  const label =
                    node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;

                  return (
                    <g
                      key={node.id}
                      data-node="true"
                      transform={`translate(${node.x}, ${node.y})`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedNodeId(node.id);
                      }}
                      className="cursor-pointer"
                      opacity={dimmed ? 0.28 : 1}
                    >
                      {isSelected && (
                        <rect
                          x={-92}
                          y={-25}
                          width={184}
                          height={50}
                          rx={11}
                          fill="none"
                          stroke="#38bdf8"
                          strokeWidth={2.5}
                          opacity={0.75}
                        />
                      )}
                      <rect
                        x={-86}
                        y={-20}
                        width={172}
                        height={40}
                        rx={8}
                        fill={colors.fill}
                        stroke={colors.stroke}
                        strokeWidth={isSelected ? 2 : 1.4}
                      />
                      <text
                        x={-74}
                        y={-3}
                        fill={colors.text}
                        fontSize={11}
                        fontFamily="JetBrains Mono, monospace"
                        fontWeight={600}
                      >
                        {label}
                      </text>
                      <text
                        x={-74}
                        y={12}
                        fill="#94a3b8"
                        fontSize={9}
                        fontFamily="Inter, sans-serif"
                      >
                        {node.kind.toUpperCase()}
                        {node.state ? ` · ${node.state}` : ''}
                        {node.interestingness ? ` · Score ${node.interestingness}` : ''}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}
        </div>

        {/* Side Inspector Panel */}
        <div className="xl:col-span-3 rounded-xl border border-border-subtle bg-bg-card p-4 flex flex-col justify-between min-h-[580px]">
          {!selectedNode ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-4 text-text-muted">
              <Crosshair className="h-8 w-8 mb-3 opacity-40" />
              <p className="text-sm font-medium text-text-secondary">Wybierz węzeł na grafie</p>
              <p className="text-xs mt-1">
                Kliknij dowolny zakres, host, usługę lub technologię, aby zobaczyć szczegóły,
                powiązania i otworzyć pełny inspektor dowodów.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                    {selectedNode.kind}
                  </span>
                  {selectedNode.interestingness ? (
                    <span
                      className={`text-xs font-mono px-2 py-0.5 rounded border ${scoreColor(
                        selectedNode.interestingness
                      )}`}
                    >
                      Score: {selectedNode.interestingness}
                    </span>
                  ) : null}
                </div>
                <h3 className="text-base font-bold font-mono text-text-primary mt-2 break-all">
                  {selectedNode.label}
                </h3>
                {selectedNode.state && (
                  <span
                    className={`inline-block mt-1.5 text-[11px] font-mono px-2 py-0.5 rounded border ${
                      lifecycleMeta(selectedNode.state).badge
                    }`}
                  >
                    {selectedNode.state}
                  </span>
                )}
              </div>

              {selectedNode.meta && Object.keys(selectedNode.meta).length > 0 && (
                <div className="rounded-lg border border-border-subtle bg-bg-elevated p-3 space-y-1.5 text-xs">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                    Metadane węzła
                  </div>
                  {Object.entries(selectedNode.meta).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2 font-mono text-[11px]">
                      <span className="text-text-muted">{k}:</span>
                      <span className="text-text-primary text-right break-all">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-2">
                  Powiązania ({connectedEdges.length})
                </div>
                <div className="space-y-1.5 max-h-52 overflow-y-auto">
                  {connectedEdges.map((edge) => {
                    const otherId =
                      edge.source === selectedNode.id ? edge.target : edge.source;
                    const other = nodeMap.get(otherId);
                    if (!other) return null;
                    return (
                      <button
                        key={edge.id}
                        type="button"
                        onClick={() => setSelectedNodeId(other.id)}
                        className="w-full text-left px-2.5 py-1.5 rounded-lg border border-border-subtle bg-bg-elevated hover:bg-bg-hover text-xs flex items-center justify-between gap-2"
                      >
                        <span className="font-mono text-text-primary truncate">{other.label}</span>
                        <span className="text-[10px] text-text-muted uppercase shrink-0">
                          {other.kind}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {resolveHostIdFromNode(selectedNode) && (
                <button
                  type="button"
                  onClick={() => setInspectHostId(resolveHostIdFromNode(selectedNode))}
                  className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  Otwórz pełny Asset Inspector
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      <AssetInspectorDrawer
        hostId={inspectHostId}
        onClose={() => setInspectHostId(null)}
        onUpdated={loadGraph}
      />
    </div>
  );
}
