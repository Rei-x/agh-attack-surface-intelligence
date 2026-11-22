import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from './AuthContext';
import type { LiveEvent } from '../types/api';

export interface LiveHost {
  ip: string;
  hostname?: string;
  ports: number[];
  services?: number;
  titles?: string[];
  at: string;
}

export interface LiveChunk {
  chunk_id?: string;
  chunk_index?: number;
  status?: string;
  ip_count?: number;
  active_hosts?: number;
  services?: number;
  duration_ms?: number;
}

export interface LiveThrottle {
  scan_run_id?: string;
  reason: string;
  host?: string;
  old_rate: number;
  new_rate: number;
  count: number;
  at: string;
}

export interface ActiveScanLive {
  scan_run_id?: string;
  name?: string;
  status: string;
  scanned_ips: number;
  total_ips: number;
  completed_chunks: number;
  total_chunks: number;
  active_hosts: number;
  services_found: number;
  hosts_per_sec: number;
  eta_seconds: number;
  window_open?: boolean;
  latestHost: LiveHost | null;
  updatedAt: string;
}

interface LiveEventsContextValue {
  connected: boolean;
  clients: number;
  lastEventAt: string | null;
  pulseTick: number;
  liveFeed: LiveEvent[];
  /** Backwards-compatible aliases */
  events: LiveEvent[];
  lastEvent: LiveEvent | null;
  activeScan: ActiveScanLive | null;
  /** Live chunk state keyed by chunk_id (and `#index`). */
  liveChunks: Record<string, LiveChunk>;
  /** IPs discovered / changed recently (cleared after ~15s). */
  recentIPs: Record<string, number>;
  dataVersion: number;
  throttled: boolean;
  /** Last noise-governor backoff (reason, rates) and how many happened this session per run. */
  lastThrottle: LiveThrottle | null;
  clearEvents: () => void;
}

const LiveEventsContext = createContext<LiveEventsContextValue>({
  connected: false,
  clients: 0,
  lastEventAt: null,
  pulseTick: 0,
  liveFeed: [],
  events: [],
  lastEvent: null,
  activeScan: null,
  liveChunks: {},
  recentIPs: {},
  dataVersion: 0,
  throttled: false,
  lastThrottle: null,
  clearEvents: () => {},
});

const EVENT_TYPES = [
  'stream.connected',
  'stream.heartbeat',
  'scan.started',
  'scan.chunk',
  'scan.host_discovered',
  'scan.progress',
  'scan.paused_window',
  'scan.paused',
  'scan.completed',
  'change.detected',
  'governor.throttle',
  'message',
];

const DATA_EVENTS = new Set([
  'scan.host_discovered',
  'scan.chunk',
  'scan.completed',
  'change.detected',
  'scan.paused_window',
]);

const FEED_LIMIT = 40;
const RECENT_IP_TTL = 15000;

const num = (v: unknown, fallback = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : fallback);

function emptyScan(): ActiveScanLive {
  return {
    status: 'RUNNING',
    scanned_ips: 0,
    total_ips: 0,
    completed_chunks: 0,
    total_chunks: 0,
    active_hosts: 0,
    services_found: 0,
    hosts_per_sec: 0,
    eta_seconds: 0,
    latestHost: null,
    updatedAt: new Date().toISOString(),
  };
}

export function LiveEventsProvider({ children }: { children: React.ReactNode }) {
  const { token, user } = useAuth();
  const [connected, setConnected] = useState(false);
  const [clients, setClients] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);
  const [pulseTick, setPulseTick] = useState(0);
  const [liveFeed, setLiveFeed] = useState<LiveEvent[]>([]);
  const [activeScan, setActiveScan] = useState<ActiveScanLive | null>(null);
  const [liveChunks, setLiveChunks] = useState<Record<string, LiveChunk>>({});
  const [recentIPs, setRecentIPs] = useState<Record<string, number>>({});
  const [dataVersion, setDataVersion] = useState(0);
  const [throttled, setThrottled] = useState(false);
  const [lastThrottle, setLastThrottle] = useState<LiveThrottle | null>(null);

  const throttleTimer = useRef<number | null>(null);
  const dataTimer = useRef<number | null>(null);

  useEffect(() => {
    if (Object.keys(recentIPs).length === 0) return;
    const t = window.setInterval(() => {
      const now = Date.now();
      setRecentIPs((prev) => {
        const next: Record<string, number> = {};
        let changed = false;
        for (const [ip, at] of Object.entries(prev)) {
          if (now - at < RECENT_IP_TTL) next[ip] = at;
          else changed = true;
        }
        return changed ? next : prev;
      });
    }, 2000);
    return () => window.clearInterval(t);
  }, [recentIPs]);

  useEffect(() => {
    if (!token || !user) {
      setConnected(false);
      return;
    }

    let closed = false;
    let es: EventSource | null = null;
    let retryTimer: number | null = null;

    const bumpData = () => {
      if (dataTimer.current) window.clearTimeout(dataTimer.current);
      dataTimer.current = window.setTimeout(() => setDataVersion((v) => v + 1), 300);
    };

    const markIP = (ip?: unknown) => {
      if (typeof ip !== 'string' || !ip) return;
      setRecentIPs((prev) => ({ ...prev, [ip]: Date.now() }));
    };

    const handle = (evt: LiveEvent) => {
      const p = evt.payload || {};
      setLastEventAt(evt.timestamp);
      setPulseTick((t) => t + 1);

      if (evt.type === 'stream.connected' || evt.type === 'stream.heartbeat') {
        setClients(num(p.clients));
        if (evt.type === 'stream.connected') setConnected(true);
        return;
      }

      setLiveFeed((prev) => [evt, ...prev].slice(0, FEED_LIMIT));
      if (DATA_EVENTS.has(evt.type)) bumpData();

      switch (evt.type) {
        case 'scan.started':
          setLiveChunks({});
          setActiveScan({
            ...emptyScan(),
            scan_run_id: evt.scan_run_id,
            name: p.name as string | undefined,
            total_ips: num(p.total_ips),
            total_chunks: num(p.total_chunks),
            eta_seconds: num(p.eta_seconds),
          });
          break;
        case 'scan.progress':
          setActiveScan((prev) => {
            const base = prev && (!evt.scan_run_id || !prev.scan_run_id || prev.scan_run_id === evt.scan_run_id)
              ? prev
              : { ...emptyScan(), scan_run_id: evt.scan_run_id };
            return {
              ...base,
              scan_run_id: base.scan_run_id || evt.scan_run_id,
              status: p.window_open === false ? 'PAUSED_WINDOW' : base.status === 'COMPLETED' ? 'RUNNING' : base.status,
              scanned_ips: num(p.scanned_ips, base.scanned_ips),
              total_ips: num(p.total_ips, base.total_ips),
              completed_chunks: num(p.completed_chunks, base.completed_chunks),
              total_chunks: num(p.total_chunks, base.total_chunks),
              active_hosts: num(p.active_hosts, base.active_hosts),
              services_found: num(p.services_found, base.services_found),
              hosts_per_sec: num(p.hosts_per_sec, base.hosts_per_sec),
              eta_seconds: num(p.eta_seconds, base.eta_seconds),
              window_open: typeof p.window_open === 'boolean' ? p.window_open : base.window_open,
              updatedAt: evt.timestamp,
            };
          });
          break;
        case 'scan.chunk': {
          const chunk: LiveChunk = {
            chunk_id: p.chunk_id as string | undefined,
            chunk_index: typeof p.chunk_index === 'number' ? p.chunk_index : undefined,
            status: p.status as string | undefined,
            ip_count: num(p.ip_count),
            active_hosts: num(p.active_hosts),
            services: num(p.services),
            duration_ms: num(p.duration_ms),
          };
          setLiveChunks((prev) => {
            const next = { ...prev };
            if (chunk.chunk_id) next[chunk.chunk_id] = chunk;
            if (chunk.chunk_index !== undefined) next[`#${chunk.chunk_index}`] = chunk;
            return next;
          });
          break;
        }
        case 'scan.host_discovered': {
          const host: LiveHost = {
            ip: String(p.ip || ''),
            hostname: p.hostname as string | undefined,
            ports: Array.isArray(p.ports) ? (p.ports as number[]) : [],
            services: num(p.services),
            titles: Array.isArray(p.titles) ? (p.titles as string[]) : [],
            at: evt.timestamp,
          };
          markIP(host.ip);
          setActiveScan((prev) => ({ ...(prev || { ...emptyScan(), scan_run_id: evt.scan_run_id }), latestHost: host }));
          break;
        }
        case 'scan.paused_window':
          setActiveScan((prev) => (prev ? { ...prev, status: 'PAUSED_WINDOW', window_open: false } : prev));
          break;
        case 'scan.paused':
          setActiveScan((prev) => (prev ? { ...prev, status: 'PAUSED_USER' } : prev));
          break;
        case 'scan.completed':
          setActiveScan((prev) => (prev ? { ...prev, status: 'COMPLETED', eta_seconds: 0 } : prev));
          break;
        case 'change.detected':
          markIP(p.host_ip);
          break;
        case 'governor.throttle':
          setThrottled(true);
          setLastThrottle((prev) => ({
            scan_run_id: evt.scan_run_id,
            reason: String(p.reason || ''),
            host: p.host ? String(p.host) : undefined,
            old_rate: num(p.old_rate),
            new_rate: num(p.new_rate),
            count: prev && prev.scan_run_id === evt.scan_run_id ? prev.count + 1 : 1,
            at: evt.timestamp,
          }));
          if (throttleTimer.current) window.clearTimeout(throttleTimer.current);
          throttleTimer.current = window.setTimeout(() => setThrottled(false), 15000);
          break;
      }
    };

    const parse = (rawType: string, rawData: string) => {
      try {
        const parsed = JSON.parse(rawData) as Partial<LiveEvent>;
        handle({
          type: parsed.type || rawType || 'event',
          scan_run_id: parsed.scan_run_id,
          timestamp: parsed.timestamp || new Date().toISOString(),
          payload: parsed.payload || (parsed as unknown as Record<string, unknown>),
        });
      } catch {
        // ignore non-JSON lines
      }
    };

    const connect = () => {
      if (closed) return;
      // Replayed events arrive on every (re)connect: reset the feed to avoid duplicates.
      setLiveFeed([]);
      es = new EventSource(`/api/v1/events/stream?token=${encodeURIComponent(token)}`);
      es.onopen = () => {
        if (!closed) setConnected(true);
      };
      es.onerror = () => {
        if (closed) return;
        setConnected(false);
        es?.close();
        retryTimer = window.setTimeout(connect, 4000);
      };
      for (const name of EVENT_TYPES) {
        es.addEventListener(name, (e) => {
          const data = (e as MessageEvent).data;
          if (typeof data === 'string' && data.trim()) parse(name, data);
        });
      }
    };

    connect();

    return () => {
      closed = true;
      es?.close();
      if (retryTimer) window.clearTimeout(retryTimer);
      if (throttleTimer.current) window.clearTimeout(throttleTimer.current);
      if (dataTimer.current) window.clearTimeout(dataTimer.current);
    };
  }, [token, user]);

  const value = useMemo<LiveEventsContextValue>(
    () => ({
      connected,
      clients,
      lastEventAt,
      pulseTick,
      liveFeed,
      events: liveFeed,
      lastEvent: liveFeed[0] ?? null,
      activeScan,
      liveChunks,
      recentIPs,
      dataVersion,
      throttled,
      lastThrottle,
      clearEvents: () => setLiveFeed([]),
    }),
    [connected, clients, lastEventAt, pulseTick, liveFeed, activeScan, liveChunks, recentIPs, dataVersion, throttled, lastThrottle]
  );

  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

export function useLiveEvents() {
  return useContext(LiveEventsContext);
}

/** Calls `fn` (silently) whenever live data changes. Skips the initial mount. */
export function useLiveRefresh(fn: () => void) {
  const { dataVersion } = useLiveEvents();
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (dataVersion === 0) return;
    fnRef.current();
  }, [dataVersion]);
}

/** One-line human summary of an event for compact mono feeds. */
export function describeEvent(evt: LiveEvent): { tag: string; text: string; tone?: 'danger' | 'warning' | 'success' | 'info' } {
  const p = evt.payload || {};
  switch (evt.type) {
    case 'scan.host_discovered': {
      const ports = Array.isArray(p.ports) ? (p.ports as number[]) : [];
      const titles = Array.isArray(p.titles) ? (p.titles as string[]).filter(Boolean) : [];
      const portStr = ports.slice(0, 3).map((x) => `:${x}`).join(' ');
      return { tag: 'HOST', text: [p.ip, [portStr, titles[0]].filter(Boolean).join(' ')].filter(Boolean).join(' · '), tone: 'success' };
    }
    case 'change.detected': {
      const sev = String(p.severity || '').toUpperCase();
      return {
        tag: 'CHANGE',
        text: [sev, p.event_type, p.host_ip].filter(Boolean).join(' · '),
        tone: sev === 'HIGH' || sev === 'CRITICAL' ? 'danger' : 'warning',
      };
    }
    case 'scan.chunk':
      return {
        tag: 'CHUNK',
        text: `#${p.chunk_index ?? '?'} · ${p.status ?? ''} · ${num(p.active_hosts)} hosts · ${num(p.duration_ms)}ms`,
      };
    case 'scan.progress':
      return {
        tag: 'PROG',
        text: `${num(p.scanned_ips)}/${num(p.total_ips)} IP · ${num(p.hosts_per_sec).toFixed(1)} IP/s`,
      };
    case 'scan.started':
      return { tag: 'START', text: `${p.name ?? ''} · ${num(p.total_ips)} IP`, tone: 'info' };
    case 'scan.completed':
      return { tag: 'DONE', text: String(p.name ?? evt.scan_run_id ?? ''), tone: 'success' };
    case 'scan.paused_window':
      return { tag: 'WINDOW', text: 'paused · outside window', tone: 'warning' };
    case 'scan.paused':
      return { tag: 'PAUSE', text: String(p.name ?? evt.scan_run_id ?? ''), tone: 'warning' };
    case 'governor.throttle':
      return {
        tag: 'GOV',
        text: `${p.host ?? ''} · ${p.old_rate ?? '?'}→${p.new_rate ?? '?'} · ${p.reason ?? ''}`,
        tone: 'warning',
      };
    default:
      return { tag: evt.type.split('.').pop()?.toUpperCase() || 'EVT', text: '' };
  }
}
