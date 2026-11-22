import { useEffect, useState } from 'react';
import { ApiError, getStoredToken } from '@/lib/api';

/* ---------- types ---------- */

export type TicketStatus = 'open' | 'notified' | 'acknowledged' | 'fixed' | 'reopened' | 'accepted_risk';

export interface TicketHistory {
  at: string;
  by: string;
  action: string;
  from?: string;
  to?: string;
  note?: string;
  scan_id?: string;
  fixed_reason?: FixReason;
}

/** What closed a fixed ticket. Only "upgraded" means the software was patched. */
export type FixReason = 'service_removed' | 'upgraded' | 'issue_gone' | 'manual';

export interface Ticket {
  id: string;
  host_id: string;
  host_ip: string;
  hostname?: string;
  service_id?: string;
  port?: number;
  protocol?: string;
  service?: string;
  kind: string;
  issue_key: string;
  title: string;
  evidence?: string;
  action: string;
  severity: string;
  owner?: string;
  owner_email?: string;
  status: TicketStatus;
  overdue: boolean;
  verified: boolean;
  due_at?: string;
  /** Due day in the instance timezone (YYYY-MM-DD). */
  due_date?: string;
  fixed_reason?: FixReason;
  /** Product and version seen after an upgrade ("nginx 1.30.1"). */
  fixed_detail?: string;
  fix_outcome?: string;
  subject?: string;
  body?: string;
  /** Language of subject and body (pl, en). */
  language?: string;
  channel?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  notified_at?: string;
  acknowledged_at?: string;
  fixed_at?: string;
  fixed_scan_id?: string;
  last_checked_at?: string;
  last_check_scan_id?: string;
  last_check_note?: string;
  defectdojo_unique_id?: string;
  history: TicketHistory[];
  age_days?: number;
  past_due?: boolean;
}

export interface TicketStats {
  open: number;
  overdue: number;
  fixed: number;
  fixed_last_24h: number;
  accepted_risk: number;
  by_status: Record<string, number>;
  fixed_by?: Record<string, number>;
  median_days_to_fix: number;
}

export interface Issue {
  kind: string;
  key: string;
  title: string;
  evidence: string;
  action: string;
  advice: string;
  severity: string;
  due_days: number;
}

export interface Channels {
  email: boolean;
  webhook: boolean;
  webhook_source?: string;
  webhook_format: string;
}

/** How the default due date was derived (DefectDojo SLA). */
export interface SlaInfo {
  severity: string;
  days: number;
  start: string;
  expires: string;
  from_defectdojo: boolean;
  expired: boolean;
  due: string;
}

export interface Draft {
  host_id: string;
  host_ip: string;
  hostname?: string;
  service_id?: string;
  port?: number;
  protocol?: string;
  service?: string;
  owner: string;
  owner_email: string;
  issues: Issue[];
  issue_key: string;
  action: string;
  due_at: string;
  /** Due day in the instance timezone (YYYY-MM-DD): shown and sent back as is. */
  due_date: string;
  sla: SlaInfo;
  subject: string;
  body: string;
  language: string;
  default_language: string;
  languages: string[];
  timezone: string;
  channels: Channels;
  existing?: Ticket;
}

export interface Delivery {
  channel: string;
  delivered: boolean;
  target?: string;
  error?: string;
  mailto?: string;
}

export interface SendResult {
  ticket: Ticket;
  delivery: Delivery;
  created: boolean;
}

export interface DeliverySettings {
  smtp: { host: string; port: number; username?: string; password?: string; has_password: boolean; from: string };
  smtp_from_env: boolean;
  webhook_url?: string;
  has_webhook_url: boolean;
  webhook_masked?: string;
  webhook_format: string;
  use_alert_webhook: boolean;
  notice_language?: string;
  timezone?: string;
  /** Overrides only; empty means the DefectDojo defaults. */
  sla_days?: Record<string, number>;
}

/** Non-secret notice settings every role can read. */
export interface NoticeSettings {
  notice_language: string;
  languages: string[];
  timezone: string;
  sla_days: Record<string, number>;
  default_sla_days: Record<string, number>;
}

export interface DigestCounts {
  new_hosts: number;
  gone_hosts: number;
  new_services: number;
  closed_services: number;
  risky: number;
  fixed: number;
  overdue: number;
  open_tickets: number;
}

export interface DigestHost {
  host_id: string;
  ip: string;
  hostname?: string;
  owner?: string;
  summary?: string;
}

export interface DigestService {
  host_id: string;
  service_id?: string;
  ip: string;
  port: number;
  service?: string;
  owner?: string;
  severity?: string;
}

export interface DigestRisk {
  host_id: string;
  service_id?: string;
  ip: string;
  port: number;
  kind: string;
  title: string;
  owner?: string;
  score: number;
  ticket_status?: string;
}

export interface DigestTicket {
  id: string;
  host_id: string;
  where: string;
  title: string;
  owner?: string;
  due_at?: string;
  due_date?: string;
  note?: string;
  fixed_reason?: FixReason;
  outcome?: string;
}

export interface DigestOwner {
  owner: string;
  new_hosts?: DigestHost[];
  gone_hosts?: DigestHost[];
  new_services?: DigestService[];
  risky?: DigestRisk[];
  fixed?: DigestTicket[];
  overdue?: DigestTicket[];
}

export interface Digest {
  id: string;
  created_at: string;
  since: string;
  scan_run_id?: string;
  scan_name?: string;
  headline: string;
  counts: DigestCounts;
  new_hosts: DigestHost[];
  gone_hosts: DigestHost[];
  new_services: DigestService[];
  closed_services: DigestService[];
  risky: DigestRisk[];
  top_risks: DigestRisk[];
  owners: DigestOwner[];
  fixed: DigestTicket[];
  overdue: DigestTicket[];
  preview?: boolean;
  delivered: boolean;
  delivered_at?: string;
  delivery?: string[];
}

export interface DigestSummary {
  id: string;
  created_at: string;
  headline: string;
  counts: DigestCounts;
  delivered: boolean;
  scan_name?: string;
}

export interface DigestSettings {
  enabled: boolean;
  recipients: string[];
  webhook_url?: string;
  has_webhook_url: boolean;
  webhook_masked?: string;
  webhook_format?: string;
  send_at: string;
  timezone: string;
  only_scheduled: boolean;
  app_url?: string;
  last_delivered_day?: string;
}

/* ---------- requests ---------- */

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  const token = getStoredToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const msg =
      (body && typeof body === 'object' ? (body as { error?: string }).error : undefined) || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, body);
  }
  return body as T;
}

const post = <T,>(path: string, payload?: unknown) =>
  call<T>(path, { method: 'POST', body: JSON.stringify(payload ?? {}) });

export const remediationApi = {
  listTickets: (params: { status?: string; owner?: string; host_id?: string; active?: boolean } = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '' && v !== false) qs.set(k, String(v));
    });
    const q = qs.toString();
    return call<{ tickets: Ticket[]; stats: TicketStats; owners: string[]; timezone?: string }>(
      `/api/v1/remediation/tickets${q ? `?${q}` : ''}`
    );
  },
  draft: (hostId: string, serviceId?: string, issueKey?: string, lang?: string) => {
    const qs = new URLSearchParams({ host_id: hostId });
    if (serviceId) qs.set('service_id', serviceId);
    if (issueKey) qs.set('issue_key', issueKey);
    if (lang) qs.set('lang', lang);
    return call<Draft>(`/api/v1/remediation/draft?${qs}`);
  },
  create: (payload: {
    host_id: string;
    service_id?: string;
    issue_key: string;
    owner?: string;
    owner_email?: string;
    subject: string;
    body: string;
    language?: string;
    /** YYYY-MM-DD in the instance timezone. */
    due_date?: string;
    channel: string;
  }) => post<SendResult>('/api/v1/remediation/tickets', payload),
  notify: (id: string, payload: { channel: string; subject?: string; body?: string; to?: string }) =>
    post<SendResult>(`/api/v1/remediation/tickets/${id}/notify`, payload),
  setStatus: (id: string, payload: { status?: string; note?: string; due_date?: string }) =>
    post<Ticket>(`/api/v1/remediation/tickets/${id}/status`, payload),
  verify: () =>
    post<{ scan_run_id: string; outcomes: { ticket_id: string; action: string; reason: string; fixed_reason?: FixReason }[] }>(
    '/api/v1/remediation/verify'
  ),
  channels: () =>
    call<{ available: Channels; notices?: NoticeSettings; settings?: DeliverySettings }>('/api/v1/remediation/channels'),
  saveChannels: (payload: Partial<DeliverySettings> & { clear_password?: boolean; clear_webhook?: boolean }) =>
    call<{ available: Channels; notices?: NoticeSettings; settings?: DeliverySettings }>('/api/v1/remediation/channels', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  testChannels: (to?: string) => post<Delivery>('/api/v1/remediation/channels/test', { to }),

  latestDigest: () => call<Digest>('/api/v1/digest/latest'),
  getDigest: (id: string) => call<Digest>(`/api/v1/digest/${id}`),
  listDigests: () => call<{ digests: DigestSummary[] }>('/api/v1/digest'),
  buildDigest: (deliver = false) => post<Digest>('/api/v1/digest/build', { deliver }),
  deliverDigest: (id: string) => post<Digest>(`/api/v1/digest/${id}/deliver`),
  digestSettings: () => call<{ settings: DigestSettings; available: Channels }>('/api/v1/digest/settings'),
  saveDigestSettings: (payload: Partial<DigestSettings> & { clear_webhook?: boolean }) =>
    call<{ settings: DigestSettings; available: Channels }>('/api/v1/digest/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  downloadDigestMarkdown: async (id: string) => {
    const token = getStoredToken();
    const res = await fetch(`/api/v1/digest/${id}/markdown`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
    const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'digest.md';
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

/* ---------- labels ---------- */

export const STATUS_META: Record<TicketStatus, { label: string; tone: 'neutral' | 'info' | 'warning' | 'success' | 'violet' | 'orange' }> = {
  open: { label: 'Open', tone: 'neutral' },
  notified: { label: 'Notified', tone: 'info' },
  acknowledged: { label: 'Acknowledged', tone: 'violet' },
  reopened: { label: 'Reopened', tone: 'orange' },
  fixed: { label: 'Fixed', tone: 'success' },
  accepted_risk: { label: 'Accepted risk', tone: 'neutral' },
};

export const ACTIVE_STATUSES: TicketStatus[] = ['open', 'notified', 'acknowledged', 'reopened'];

export function isActive(s: TicketStatus): boolean {
  return ACTIVE_STATUSES.includes(s);
}

/** Ticket kind to CategoryBadge kind (undefined: no matching badge). */
export function kindCategory(kind: string): 'cve' | 'eol' | 'admin' | 'cleartext' | 'staging' | 'db' | undefined {
  switch (kind) {
    case 'known-vuln':
      return 'cve';
    case 'eol':
      return 'eol';
    case 'admin-panel':
      return 'admin';
    case 'cleartext-admin':
      return 'cleartext';
    case 'staging':
      return 'staging';
    default:
      return undefined;
  }
}

export const KIND_LABEL: Record<string, string> = {
  'known-vuln': 'Known CVE',
  eol: 'End of life',
  'admin-panel': 'Admin panel',
  'cleartext-admin': 'Cleartext login',
  'risky-exposure': 'Exposed service',
  staging: 'Staging',
  other: 'Review',
};

export const ACTION_LABEL: Record<string, string> = { patch: 'Patch', remove: 'Remove', restrict: 'Restrict' };

export const LANGUAGE_LABEL: Record<string, string> = { pl: 'Polski', en: 'English' };

export const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

/** What each fix outcome means, for tooltips. A closed port is not a patch. */
export const FIX_REASON_HINT: Record<FixReason, string> = {
  service_removed:
    'The scanner no longer reaches the service (port closed or filtered, or the host is gone). It may be firewalled rather than removed, so this is not a confirmed patch.',
  upgraded: 'The service still answers, now with a supported version (or one outside the affected range).',
  issue_gone: 'The service still answers but the issue is no longer detected.',
  manual: 'An analyst marked it fixed; no scan confirmed it.',
};

/** Status label of a fixed ticket: "Fixed: service removed", "Fixed: upgraded to nginx 1.30.1". */
export function fixLabel(t: { fixed_reason?: FixReason | string; fixed_detail?: string; verified?: boolean }): string {
  switch (t.fixed_reason) {
    case 'service_removed':
      return 'Fixed: service removed';
    case 'upgraded':
      return t.fixed_detail ? `Fixed: upgraded to ${t.fixed_detail}` : 'Fixed: upgraded';
    case 'issue_gone':
      return 'Fixed: issue no longer detected';
    case 'manual':
      return 'Fixed (marked by an analyst)';
  }
  return t.verified ? 'Fix verified' : 'Fixed';
}

/** History label of a status change, with the fix outcome for verified fixes. */
export function fixHistoryLabel(reason?: FixReason | string): string {
  switch (reason) {
    case 'service_removed':
      return 'Verified: service no longer reachable';
    case 'upgraded':
      return 'Verified: upgraded';
    case 'issue_gone':
      return 'Verified: issue no longer detected';
  }
  return 'Verified fixed';
}

/* ---------- shared ticket index (badges) ---------- */

let indexPromise: Promise<Ticket[]> | null = null;
let indexAt = 0;
const listeners = new Set<() => void>();

function loadIndex(force = false): Promise<Ticket[]> {
  if (force || !indexPromise || Date.now() - indexAt > 30_000) {
    indexAt = Date.now();
    indexPromise = remediationApi
      .listTickets()
      .then((r) => r.tickets)
      .catch(() => []);
  }
  return indexPromise;
}

/** Refresh every mounted badge (after a ticket was created or changed). */
export function invalidateTickets(): void {
  indexPromise = null;
  listeners.forEach((fn) => fn());
}

/** All tickets, shared between badges on the page. */
export function useTicketIndex(enabled = true): Ticket[] {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const run = () => loadIndex().then((t) => alive && setTickets(t));
    run();
    listeners.add(run);
    return () => {
      alive = false;
      listeners.delete(run);
    };
  }, [enabled]);
  return tickets;
}

/** The most relevant ticket for a service (active first, then the latest fix). */
export function ticketForService(tickets: Ticket[], serviceId: string): Ticket | undefined {
  const mine = tickets.filter((t) => t.service_id === serviceId);
  return mine.find((t) => isActive(t.status)) || mine.find((t) => t.status === 'fixed');
}

export function formatDay(value?: string): string {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
}

/** "FTIMS admins <admin@ftims.agh.edu.pl>" -> "FTIMS admins"; empty -> "Unassigned". */
export function ownerLabel(owner?: string): string {
  const name = (owner || '').replace(/\s*<[^>]*>\s*$/, '').trim();
  return name || 'Unassigned';
}
