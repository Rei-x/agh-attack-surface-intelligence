import { ApiError, getStoredToken } from '@/lib/api';

/** Zone policies (backend internal/policy, /api/v1/policies). */

export type PolicyCategory = 'admin_panel' | 'cleartext_admin' | 'database' | 'iot_bmc' | 'eol' | 'staging';

export interface PolicyRules {
  no_services: boolean;
  allowed_ports?: number[];
  forbidden?: string[];
  require_tls: boolean;
  max_risk?: number;
}

export interface PolicyZone {
  id?: string;
  name: string;
  description?: string;
  cidrs: string[];
  preset?: string;
  owner?: string;
  enabled: boolean;
  rules: PolicyRules;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface PolicyPreset {
  id: string;
  name: string;
  description: string;
  rules: PolicyRules;
}

export interface PolicyCategoryMeta {
  id: string;
  label: string;
  description: string;
  severity: string;
}

export interface PolicyViolation {
  id: string;
  zone_id: string;
  zone_name: string;
  rule: string;
  rules: string[];
  severity: string;
  summary: string;
  evidence: string[];
  host_id: string;
  host_ip: string;
  hostname?: string;
  service_id?: string;
  port?: number;
  protocol?: string;
  service_name?: string;
  owner?: string;
  status: 'open' | 'resolved';
  first_seen: string;
  last_seen: string;
  resolved_at?: string;
}

export interface ViolationGroup {
  key: string;
  label: string;
  open: number;
  severity: Record<string, number>;
}

export interface PoliciesResponse {
  zones: PolicyZone[];
  presets: PolicyPreset[];
  categories: PolicyCategoryMeta[];
  evaluated_at?: string;
  open_count: number;
}

export interface ViolationsResponse {
  violations: PolicyViolation[];
  total: number;
  resolved_count: number;
  by_severity: Record<string, number>;
  by_zone: ViolationGroup[];
  by_owner: ViolationGroup[];
  evaluated_at?: string;
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
    const msg = err || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, body);
  }
  return body as T;
}

export const policiesApi = {
  list: () => call<PoliciesResponse>('/api/v1/policies'),
  save: (zones: PolicyZone[]) =>
    call<{ zones: PolicyZone[]; changes: number; open_count: number }>('/api/v1/policies', {
      method: 'PUT',
      body: JSON.stringify({ zones }),
    }),
  evaluate: () =>
    call<{ changes: number; open_count: number }>('/api/v1/policies/evaluate', { method: 'POST' }),
  violations: (status: 'open' | 'resolved' | 'all' = 'open') =>
    call<ViolationsResponse>(`/api/v1/policies/violations?status=${status}`),
};

/** Short label of a rule id ("forbidden:database" -> "Exposed database"). */
export function ruleLabel(rule: string, categories: PolicyCategoryMeta[] = []): string {
  switch (rule) {
    case 'no_services':
      return 'No services allowed';
    case 'port_not_allowed':
      return 'Port not allowed';
    case 'tls_required':
      return 'TLS required';
    case 'max_risk':
      return 'Risk above limit';
  }
  if (rule.startsWith('forbidden:')) {
    const id = rule.slice('forbidden:'.length);
    return categories.find((c) => c.id === id)?.label || id;
  }
  return rule;
}

/** Severity tone: red only for critical. */
export function policySeverityTone(sev: string): 'danger' | 'orange' | 'warning' | 'info' | 'neutral' {
  switch (sev) {
    case 'critical':
      return 'danger';
    case 'high':
      return 'orange';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'neutral';
  }
}

/** Read-only YAML view of the zones (no dependency, just enough for display). */
export function zonesToYaml(zones: PolicyZone[]): string {
  const q = (s: string) => (/^[\w./@-]+$/.test(s) ? s : JSON.stringify(s));
  const lines: string[] = ['zones:'];
  for (const z of zones) {
    lines.push(`  - name: ${q(z.name)}`);
    if (z.description) lines.push(`    description: ${q(z.description)}`);
    lines.push(`    enabled: ${z.enabled}`);
    if (z.preset) lines.push(`    preset: ${z.preset}`);
    if (z.owner) lines.push(`    owner: ${q(z.owner)}`);
    lines.push(`    cidrs: [${z.cidrs.map(q).join(', ')}]`);
    lines.push('    rules:');
    lines.push(`      no_services: ${z.rules.no_services}`);
    if (z.rules.allowed_ports?.length) lines.push(`      allowed_ports: [${z.rules.allowed_ports.join(', ')}]`);
    if (z.rules.forbidden?.length) lines.push(`      forbidden: [${z.rules.forbidden.join(', ')}]`);
    lines.push(`      require_tls: ${z.rules.require_tls}`);
    if (z.rules.max_risk) lines.push(`      max_risk: ${z.rules.max_risk}`);
  }
  return lines.join('\n') + '\n';
}
