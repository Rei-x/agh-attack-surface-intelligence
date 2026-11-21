import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { useAuth } from './AuthContext';
import type { LiveEvent } from '../types/api';

interface LiveEventsContextValue {
  connected: boolean;
  events: LiveEvent[];
  lastEvent: LiveEvent | null;
  throttled: boolean;
  clearEvents: () => void;
}

const LiveEventsContext = createContext<LiveEventsContextValue>({
  connected: false,
  events: [],
  lastEvent: null,
  throttled: false,
  clearEvents: () => {},
});

const KNOWN_EVENTS = [
  'stream.connected',
  'scan.progress',
  'scan.chunk',
  'scan.paused_window',
  'scan.completed',
  'scan.started',
  'change.detected',
  'governor.throttle',
  'message',
];

export function LiveEventsProvider({ children }: { children: React.ReactNode }) {
  const { token, user } = useAuth();
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [lastEvent, setLastEvent] = useState<LiveEvent | null>(null);
  const [throttled, setThrottled] = useState(false);
  const throttleTimer = useRef<number | null>(null);

  useEffect(() => {
    if (!token || !user) {
      setConnected(false);
      return;
    }

    let closed = false;
    let es: EventSource | null = null;
    let retryTimer: number | null = null;

    const pushEvent = (rawType: string, rawData: string) => {
      try {
        const parsed = JSON.parse(rawData) as Partial<LiveEvent>;
        const evt: LiveEvent = {
          type: parsed.type || rawType || 'event',
          scan_run_id: parsed.scan_run_id,
          timestamp: parsed.timestamp || new Date().toISOString(),
          payload: parsed.payload || (parsed as unknown as Record<string, unknown>),
        };
        setLastEvent(evt);
        setEvents((prev) => [evt, ...prev].slice(0, 120));
        if (evt.type === 'governor.throttle') {
          setThrottled(true);
          if (throttleTimer.current) window.clearTimeout(throttleTimer.current);
          throttleTimer.current = window.setTimeout(() => setThrottled(false), 15000);
        }
      } catch {
        // ignore heartbeat / non-JSON comment lines
      }
    };

    const connect = () => {
      if (closed) return;
      const url = `/api/v1/events/stream?token=${encodeURIComponent(token)}`;
      es = new EventSource(url);

      es.onopen = () => {
        if (!closed) setConnected(true);
      };

      es.onerror = () => {
        if (!closed) {
          setConnected(false);
          es?.close();
          retryTimer = window.setTimeout(connect, 4000);
        }
      };

      for (const name of KNOWN_EVENTS) {
        es.addEventListener(name, (e) => {
          const msg = e as MessageEvent;
          if (typeof msg.data === 'string' && msg.data.trim()) {
            pushEvent(name, msg.data);
          }
        });
      }
    };

    connect();

    return () => {
      closed = true;
      es?.close();
      if (retryTimer) window.clearTimeout(retryTimer);
      if (throttleTimer.current) window.clearTimeout(throttleTimer.current);
    };
  }, [token, user]);

  return (
    <LiveEventsContext.Provider
      value={{
        connected,
        events,
        lastEvent,
        throttled,
        clearEvents: () => setEvents([]),
      }}
    >
      {children}
    </LiveEventsContext.Provider>
  );
}

export function useLiveEvents() {
  return useContext(LiveEventsContext);
}
