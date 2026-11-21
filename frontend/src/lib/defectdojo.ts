import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

export interface DefectDojoStatus {
  /** URL and API token are set, so a push can work. */
  ready: boolean;
  /** Why pushing is unavailable (tooltip text). */
  reason: string;
  url?: string;
}

let cached: Promise<DefectDojoStatus> | null = null;
let cachedAt = 0;

function load(): Promise<DefectDojoStatus> {
  if (!cached || Date.now() - cachedAt > 60_000) {
    cachedAt = Date.now();
    cached = api
      .getDefectDojoConfig()
      .then((c) => {
        if (!c.url) return { ready: false, reason: 'DefectDojo is not configured (Admin → Integrations: URL missing)' };
        if (!c.has_api_token) return { ready: false, reason: 'DefectDojo API token is missing (Admin → Integrations)', url: c.url };
        return { ready: true, reason: '', url: c.url };
      })
      .catch(() => ({ ready: false, reason: 'DefectDojo configuration is not readable' }));
  }
  return cached;
}

/** DefectDojo readiness for enabling/disabling the manual push actions. */
export function useDefectDojoStatus(enabled: boolean): DefectDojoStatus {
  const [status, setStatus] = useState<DefectDojoStatus>({ ready: false, reason: 'Checking DefectDojo…' });
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    load().then((s) => alive && setStatus(s));
    return () => {
      alive = false;
    };
  }, [enabled]);
  return status;
}
