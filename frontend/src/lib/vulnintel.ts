import { ApiError, getStoredToken } from '@/lib/api';

/** Known-vulnerability summary of one product on a service (backend internal/vulndb). */
export interface CVERef {
  id: string;
  cvss: number;
  severity: string;
  epss: number;
  epss_percentile: number;
  kev: boolean;
  kev_date_added?: string;
  summary: string;
  possible?: boolean;
  range?: string;
  url: string;
}

export interface VulnSummary {
  product: string;
  version: string;
  via: string;
  cpe?: string;
  total: number;
  possible: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  max_cvss: number;
  kev: number;
  ransomware?: boolean;
  max_epss: number;
  max_epss_percentile: number;
  confidence: 'high' | 'medium' | 'low' | string;
  confidence_note: string;
  distro_backport?: boolean;
  top: CVERef[];
  cve_ids: string[];
  data_as_of: string;
}

/** Result of a safe verification check (backend internal/verify). */
export interface VerifiedFinding {
  check_id: string;
  name: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | string;
  service_id: string;
  host_ip: string;
  port: number;
  request: string;
  evidence: string;
  remediation: string;
  references?: string[];
  default_creds?: boolean;
  checked_at: string;
  scan_run_id?: string;
}

export interface VerifyProfileConfig {
  enabled: boolean;
  default_creds: boolean;
  updated_by?: string;
  updated_at?: string;
}

export interface VerifyRunSummary {
  profile_id: string;
  profile_name: string;
  scan_run_id?: string;
  trigger: string;
  started_at: string;
  finished_at: string;
  stats: {
    targets: number;
    checks_run: number;
    findings: number;
    skipped_default_creds: number;
    out_of_scope: number;
    errors: number;
    default_creds_tried: number;
  };
  by_severity: Record<string, number>;
  checks: string[];
  error?: string;
}

export interface VerifyProfileView {
  profile_id: string;
  profile_name: string;
  config: VerifyProfileConfig;
  last_run?: VerifyRunSummary;
  remote_agent?: boolean;
}

export interface VerifyHostScope {
  host_id: string;
  ip: string;
  profiles: VerifyProfileView[];
  checks: number;
}

export interface VerifyCheck {
  id: string;
  name: string;
  severity: string;
  kind: 'http' | 'network' | 'builtin';
  requires?: string;
  description: string;
  remediation: string;
  references?: string[];
  tags?: string[];
  source: string;
  yaml: string;
}

export interface VulnDBInfo {
  origin: string;
  generated_at: string;
  cves: number;
  kev: number;
  products: number;
  sources: {
    nvd: string;
    nvd_fetched: string;
    kev: string;
    kev_version: string;
    kev_count: number;
    epss: string;
    epss_model: string;
    epss_date: string;
  };
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  const token = getStoredToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body) headers.set('Content-Type', 'application/json');
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const err = body && typeof body === 'object' ? (body as { error?: string }).error : undefined;
    throw new ApiError(res.status, err || `HTTP ${res.status}`, body);
  }
  return body as T;
}

export const vulnApi = {
  info: () => call<VulnDBInfo>('/api/v1/vulndb'),
  checks: () => call<VerifyCheck[]>('/api/v1/verify/checks'),
  profiles: () => call<VerifyProfileView[]>('/api/v1/verify/profiles'),
  saveProfile: (id: string, cfg: { enabled: boolean; default_creds: boolean }) =>
    call<VerifyProfileView>(`/api/v1/verify/profiles/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(cfg),
    }),
  hostScope: (hostId: string) => call<VerifyHostScope>(`/api/v1/verify/hosts/${encodeURIComponent(hostId)}`),
  runHost: (hostId: string, profileId?: string) =>
    call<VerifyRunSummary>('/api/v1/verify/run', {
      method: 'POST',
      body: JSON.stringify({ host_id: hostId, profile_id: profileId || '' }),
    }),
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

/** Tailwind tone per severity (same palette as CategoryBadge: rose for the worst). */
export function severityTone(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical':
      return 'text-rose-700 dark:text-rose-300 border-rose-500/40 bg-rose-500/15';
    case 'high':
      return 'text-orange-700 dark:text-orange-300 border-orange-500/40 bg-orange-500/10';
    case 'medium':
      return 'text-amber-700 dark:text-amber-300 border-amber-500/40 bg-amber-500/10';
    case 'low':
      return 'text-sky-700 dark:text-sky-300 border-sky-500/30 bg-sky-500/10';
    default:
      return 'text-muted-foreground border-border bg-muted/40';
  }
}

export function cvssSeverity(score: number): string {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function pct(x: number, digits = 0): string {
  return `${(x * 100).toFixed(digits)}%`;
}

/** Worst summary first: KEV, then CVSS. */
export function worstVuln(vulns: VulnSummary[] | undefined): VulnSummary | undefined {
  if (!vulns?.length) return undefined;
  return [...vulns].sort((a, b) => (b.kev > 0 ? 1 : 0) - (a.kev > 0 ? 1 : 0) || b.max_cvss - a.max_cvss)[0];
}
