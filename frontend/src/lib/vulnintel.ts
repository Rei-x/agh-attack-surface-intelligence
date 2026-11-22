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
  /** Protocol the vulnerable code needs (http2, http3). */
  requires?: string;
  /**
   * Protocol precondition (set with `requires`): applicable | not_applicable | unverified.
   * Distribution package (VulnSummary.package): backport_possible | fixed_by_distro (both in
   * `backported`) | distro_unfixed (counted: the package predates the distribution fix).
   */
  applicability?:
    | 'applicable'
    | 'not_applicable'
    | 'unverified'
    | 'backport_possible'
    | 'fixed_by_distro'
    | 'distro_unfixed'
    | string;
  applicability_note?: string;
  checked_at?: string;
}

/** Distribution package read from the banner, e.g. Debian 12, revision 2+deb12u3. */
export interface DistroPackage {
  distro?: string;
  release?: string;
  codename?: string;
  revision?: string;
  upstream?: string;
  release_inferred?: boolean;
  /** "Debian 12", "Ubuntu 22.04", "CentOS"; "" when only a build marker was seen. */
  label: string;
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
  /** Matches ruled out by the protocol probe (e.g. HTTP/2 off); excluded from every count. */
  suppressed?: CVERef[];
  suppressed_count?: number;
  /** Counted CVEs whose protocol precondition was not checked. */
  unverified?: number;
  /** Set when the version is a distribution build. */
  package?: DistroPackage;
  /**
   * Matches on a distribution package whose fix may be backported (or is, per the distro
   * fix table); excluded from every count, the KEV badge, the score and queries.
   */
  backported?: CVERef[];
  backported_count?: number;
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

/** Summaries with at least one CVE left after suppression (protocol probe). */
export function liveVulns(vulns: VulnSummary[] | undefined): VulnSummary[] {
  return (vulns || []).filter((v) => v.total > 0);
}

/** Matches ruled out by the protocol probe, over all products of a service. */
export function suppressedCount(vulns: VulnSummary[] | undefined): number {
  return (vulns || []).reduce((n, v) => n + (v.suppressed_count ?? v.suppressed?.length ?? 0), 0);
}

/** Matches on distribution packages (fix possibly backported), over all products of a service. */
export function backportedCount(vulns: VulnSummary[] | undefined): number {
  return (vulns || []).reduce((n, v) => n + (v.backported_count ?? v.backported?.length ?? 0), 0);
}

/** "Debian 12 package", or "distribution package" when the release (or the mix) is unknown. */
export function packageName(vulns: VulnSummary[] | undefined): string {
  const labels = new Set(
    (vulns || []).filter((v) => (v.backported_count ?? v.backported?.length ?? 0) > 0).map((v) => v.package?.label || '')
  );
  const [only] = [...labels];
  return labels.size === 1 && only ? `${only} package` : 'distribution package';
}

/** "33 likely backported (Debian 12 package)". */
export function backportedLabel(vulns: VulnSummary[] | undefined): string {
  return `${backportedCount(vulns)} likely backported (${packageName(vulns)})`;
}

/** Worst summary first: KEV, then CVSS (suppressed-only summaries left out). */
export function worstVuln(vulns: VulnSummary[] | undefined): VulnSummary | undefined {
  const live = liveVulns(vulns);
  if (!live.length) return undefined;
  return [...live].sort((a, b) => (b.kev > 0 ? 1 : 0) - (a.kev > 0 ? 1 : 0) || b.max_cvss - a.max_cvss)[0];
}

const PROTO_LABEL: Record<string, string> = { http2: 'HTTP/2', http3: 'HTTP/3' };

/** Short applicability label, e.g. "not applicable: HTTP/2 off". */
export function applicabilityLabel(c: CVERef): string {
  const proto = PROTO_LABEL[c.requires || ''] || c.requires || 'protocol';
  switch (c.applicability) {
    case 'not_applicable':
      return `not applicable: ${proto} off`;
    case 'applicable':
      return `${proto} on`;
    case 'unverified':
      return `version match, unverified (needs ${proto})`;
    case 'backport_possible':
      return 'fixes may be backported, not confirmed';
    case 'fixed_by_distro':
      return 'fixed by distribution';
    case 'distro_unfixed':
      return 'distribution fix not installed';
  }
  return '';
}

/** "01:12" (today) or "21 Nov 01:12" in the viewer's time zone. */
export function checkedTime(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
  return d.toDateString() === new Date().toDateString()
    ? hm
    : `${d.toLocaleDateString([], { day: 'numeric', month: 'short' })} ${hm}`;
}
