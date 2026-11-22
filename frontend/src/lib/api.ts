import type {
  Agent,
  AgentEnrollToken,
  CreatedAgentToken,
  AuditLog,
  ChangeEvent,
  CryptoStatusResponse,
  DashboardSummary,
  DefectDojoConfig,
  DefectDojoExport,
  DemoAccount,
  GraphQuery,
  GraphResponse,
  HealthResponse,
  Host,
  HostPage,
  InventoryResponse,
  LoginResponse,
  Role,
  ScanDiffResponse,
  ScanProfile,
  ScanRun,
  Service,
  ServiceCluster,
  ServiceObservation,
  Signature,
  SignatureTestResult,
  SignatureValidationResult,
  Target,
  TargetEstimate,
  TargetExclusion,
  User,
  HostTimelineEntry,
  TagRule,
  WebhookConfig,
  DefectDojoStatus,
  DefectDojoServiceStatus,
} from '../types/api';

/** Body of the "triage" override: accepted_risk / false_positive need a reason. */
export interface TriagePatch {
  status: string;
  reason?: string;
  expires_at?: string;
}

const TOKEN_KEY = 'dzieciol_token';

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // ignore storage errors
  }
}

export class ApiError extends Error {
  status: number;
  body?: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

export function unwrapList<T>(data: unknown, keys: string[] = ['items', 'data']): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>;
    for (const k of keys) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

async function request<T>(
  path: string,
  options: RequestInit & { skipAuth?: boolean; rawResponse?: boolean } = {}
): Promise<T> {
  const { skipAuth, rawResponse, headers, ...rest } = options;
  const reqHeaders = new Headers(headers || {});

  if (!skipAuth) {
    const token = getStoredToken();
    if (token) {
      reqHeaders.set('Authorization', `Bearer ${token}`);
    }
  }

  if (rest.body && !(rest.body instanceof FormData) && !reqHeaders.has('Content-Type')) {
    reqHeaders.set('Content-Type', 'application/json');
  }

  const res = await fetch(path, {
    ...rest,
    headers: reqHeaders,
  });

  if (res.status === 401 && !skipAuth) {
    setStoredToken(null);
    if (unauthorizedHandler) unauthorizedHandler();
  }

  if (!res.ok) {
    let message = `HTTP error ${res.status}`;
    let parsed: unknown = undefined;
    try {
      const text = await res.text();
      if (text) {
        try {
          parsed = JSON.parse(text);
          const pObj = parsed as Record<string, unknown>;
          const errStr = (pObj.error || pObj.message || pObj.detail) as string | undefined;
          if (errStr) message = errStr;
        } catch {
          message = text;
        }
      }
    } catch {
      // ignore
    }
    if (res.status === 403 && !message.includes('403') && !message.toLowerCase().includes('uprawnie')) {
      message = `Missing permission (403 Forbidden): ${message}`;
    }
    throw new ApiError(res.status, message, parsed);
  }

  if (rawResponse) {
    return res as unknown as T;
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

function buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      qs.set(k, String(v));
    }
  }
  const str = qs.toString();
  return str ? `?${str}` : '';
}

/** scb = OWASP secureCodeBox findings.json (also auto-detected server-side for json). */
export type ImportFormat = 'csv' | 'json' | 'nmap' | 'scb' | 'passive';
/** json/csv = inventory; nmap = nmap XML; urls = httpx/nuclei list; ecs = NDJSON for ELK/Splunk;
 * scb = OWASP secureCodeBox findings.json. */
export type ExportFormat = 'json' | 'csv' | 'nmap' | 'urls' | 'ecs' | 'scb';
const EXPORT_EXT: Record<ExportFormat, string> = {
  json: '.json',
  csv: '.csv',
  nmap: '-nmap.xml',
  urls: '-urls.txt',
  ecs: '-ecs.ndjson',
  scb: '-scb-findings.json',
};

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  // 503 = degraded (DB down / disk full): still return the body so the UI can show why.
  health: () =>
    request<HealthResponse>('/api/v1/health', { skipAuth: true }).catch((e: unknown) => {
      if (e instanceof ApiError && e.status === 503 && e.body) return e.body as HealthResponse;
      throw e;
    }),
  demoAccounts: async (): Promise<DemoAccount[]> => {
    const res = await request<unknown>('/api/v1/auth/demo-accounts', { skipAuth: true });
    return unwrapList<DemoAccount>(res, ['accounts', 'demo_accounts', 'items', 'data']);
  },
  login: (username: string, password: string) =>
    request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      skipAuth: true,
      body: JSON.stringify({ username, password }),
    }),
  me: async (): Promise<User> => {
    const res = await request<unknown>('/api/v1/auth/me');
    if (res && typeof res === 'object' && 'user' in (res as Record<string, unknown>)) {
      return (res as { user: User }).user;
    }
    return res as User;
  },

  dashboardSummary: () => request<DashboardSummary>('/api/v1/dashboard/summary'),
  graph: async (params?: GraphQuery): Promise<GraphResponse> => {
    const res = await request<Partial<GraphResponse> | undefined>(
      `/api/v1/graph${buildQuery({ ...(params || {}) })}`
    );
    return {
      nodes: res?.nodes || [],
      edges: res?.edges || [],
      total_hosts: res?.total_hosts ?? 0,
      matched_hosts: res?.matched_hosts ?? 0,
      shown_hosts: res?.shown_hosts ?? 0,
      clustered: Boolean(res?.clustered),
      mode: res?.mode || params?.mode || 'auto',
      limit: res?.limit ?? params?.limit ?? 50,
      level: res?.level,
      block_prefix: res?.block_prefix,
      group_prefix: res?.group_prefix,
      block: res?.block,
      hidden_groups: res?.hidden_groups,
      subnets: res?.subnets || [],
    };
  },
  clusters: async (groupBy?: string): Promise<ServiceCluster[]> => {
    const res = await request<unknown>(`/api/v1/clusters${buildQuery({ group_by: groupBy })}`);
    return unwrapList<ServiceCluster>(res, ['clusters', 'items', 'data']);
  },

  listTargets: async (): Promise<Target[]> => {
    const res = await request<unknown>('/api/v1/targets');
    return unwrapList<Target>(res, ['targets', 'items', 'data']);
  },
  createTarget: (payload: Partial<Target>) =>
    request<Target>('/api/v1/targets', { method: 'POST', body: JSON.stringify(payload) }),
  deleteTarget: (id: string) => request<void>(`/api/v1/targets/${id}`, { method: 'DELETE' }),

  estimateTargets: (payload: {
    targets: string[];
    exclusions?: string[];
    ports?: string;
    allowed_ports?: string;
    max_rate_pps?: number;
    concurrency?: number;
    chunk_target_sec?: number;
    window_enabled?: boolean;
    window_start?: string;
    window_end?: string;
    timezone?: string;
  }) =>
    request<TargetEstimate>('/api/v1/targets/estimate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listExclusions: async (): Promise<TargetExclusion[]> => {
    const res = await request<unknown>('/api/v1/exclusions');
    return unwrapList<TargetExclusion>(res, ['exclusions', 'items', 'data']);
  },
  createExclusion: (payload: { value: string; reason?: string }) =>
    request<TargetExclusion>('/api/v1/exclusions', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteExclusion: (id: string) => request<void>(`/api/v1/exclusions/${id}`, { method: 'DELETE' }),

  listProfiles: async (): Promise<ScanProfile[]> => {
    const res = await request<unknown>('/api/v1/profiles');
    return unwrapList<ScanProfile>(res, ['profiles', 'items', 'data']);
  },
  createProfile: (payload: Partial<ScanProfile>) =>
    request<ScanProfile>('/api/v1/profiles', { method: 'POST', body: JSON.stringify(payload) }),
  updateProfile: (id: string, payload: Partial<ScanProfile>) =>
    request<ScanProfile>(`/api/v1/profiles/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteProfile: (id: string) => request<void>(`/api/v1/profiles/${id}`, { method: 'DELETE' }),
  // Starts a saved profile now; 409 if that profile already has an active run.
  runProfile: (id: string) => request<ScanRun>(`/api/v1/profiles/${id}/run`, { method: 'POST' }),

  listScans: async (): Promise<ScanRun[]> => {
    const res = await request<unknown>('/api/v1/scans');
    return unwrapList<ScanRun>(res, ['scans', 'runs', 'items', 'data']);
  },
  getScan: (id: string) => request<ScanRun>(`/api/v1/scans/${id}`),
  startScan: (payload: {
    profile_id?: string;
    name?: string;
    notes?: string;
    targets?: string[];
    allowed_ports?: string;
    max_rate_pps?: number;
    window_enabled?: boolean;
    window_start?: string;
    window_end?: string;
    timezone?: string;
  }) => request<ScanRun>('/api/v1/scans', { method: 'POST', body: JSON.stringify(payload) }),
  updateScan: (id: string, payload: { name?: string; notes?: string }) =>
    request<ScanRun>(`/api/v1/scans/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  pauseScan: (id: string) => request<ScanRun>(`/api/v1/scans/${id}/pause`, { method: 'POST' }),
  resumeScan: (id: string) => request<ScanRun>(`/api/v1/scans/${id}/resume`, { method: 'POST' }),
  stopScan: (id: string) => request<ScanRun>(`/api/v1/scans/${id}/stop`, { method: 'POST' }),
  deleteScan: (id: string) => request<void>(`/api/v1/scans/${id}`, { method: 'DELETE' }),

  listHosts: async (params?: {
    q?: string;
    state?: string;
    tag?: string;
    min_score?: number;
    env?: string;
    has_admin?: boolean;
    page?: number;
    limit?: number;
  }): Promise<HostPage> => {
    const res = await request<unknown>(`/api/v1/hosts${buildQuery(params || {})}`);
    const hosts = unwrapList<Host>(res, ['hosts', 'items', 'data']);
    const obj = (res && typeof res === 'object' ? res : {}) as Record<string, unknown>;
    const total = 'total' in obj ? Number(obj.total) : hosts.length;
    const limit = 'limit' in obj ? Number(obj.limit) : params?.limit || hosts.length || 50;
    const page = 'page' in obj ? Number(obj.page) : params?.page || 1;
    const totalPages =
      'total_pages' in obj
        ? Number(obj.total_pages)
        : Math.max(1, Math.ceil(total / Math.max(1, limit)));
    return { hosts, total, page, limit, total_pages: totalPages };
  },
  getHost: (id: string) => request<Host>(`/api/v1/hosts/${id}`),
  patchHostOverrides: (
    id: string,
    payload: {
      hostname?: string;
      environment?: string;
      owner?: string;
      notes?: string;
      tags?: string[];
      lifecycle_state?: string;
      triage?: TriagePatch | null;
      unlock_fields?: string[];
    }
  ) =>
    request<Host>(`/api/v1/hosts/${id}/overrides`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  deleteHost: (id: string) => request<void>(`/api/v1/hosts/${id}`, { method: 'DELETE' }),

  listServices: async (params?: {
    q?: string;
    host_id?: string;
    min_score?: number;
    admin_only?: boolean;
    triage_status?: string;
  }): Promise<Service[]> => {
    const res = await request<unknown>(`/api/v1/services${buildQuery(params || {})}`);
    return unwrapList<Service>(res, ['services', 'items', 'data']);
  },
  patchServiceOverrides: (
    id: string,
    payload: {
      service_name?: string;
      product?: string;
      version?: string;
      http_title?: string;
      notes?: string;
      tags?: string[];
      triage_status?: string;
      triage?: TriagePatch | null;
      unlock_fields?: string[];
    }
  ) =>
    request<Service>(`/api/v1/services/${id}/overrides`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  getServiceObservations: async (id: string): Promise<ServiceObservation[]> => {
    const res = await request<unknown>(`/api/v1/services/${id}/observations`);
    return unwrapList<ServiceObservation>(res, ['observations', 'items', 'data']);
  },

  getHostTimeline: async (id: string, port?: number): Promise<HostTimelineEntry[]> => {
    const res = await request<unknown>(`/api/v1/hosts/${id}/timeline${buildQuery({ port })}`);
    return unwrapList<HostTimelineEntry>(res, ['entries', 'items', 'data']);
  },

  listTagRules: async (): Promise<TagRule[]> => {
    const res = await request<unknown>('/api/v1/tag-rules');
    return unwrapList<TagRule>(res, ['rules', 'items', 'data']);
  },
  saveTagRules: async (rules: TagRule[]): Promise<TagRule[]> => {
    const res = await request<unknown>('/api/v1/tag-rules', {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    });
    return unwrapList<TagRule>(res, ['rules', 'items', 'data']);
  },
  applyTagRules: () =>
    request<{ updated: number; checked: number }>('/api/v1/tag-rules/apply', { method: 'POST' }),
  getWebhook: () => request<WebhookConfig>('/api/v1/integrations/webhook'),
  saveWebhook: (payload: {
    url?: string;
    clear_url?: boolean;
    enabled?: boolean;
    min_severity?: string;
    notify_state_changes?: boolean;
  }) =>
    request<WebhookConfig>('/api/v1/integrations/webhook', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  testWebhook: (url?: string) =>
    request<{ ok: boolean }>('/api/v1/integrations/webhook/test', {
      method: 'POST',
      body: JSON.stringify(url ? { url } : {}),
    }),

  listChanges: async (params?: {
    scan_id?: string;
    severity?: string;
    type?: string;
    anomaly_only?: boolean;
  }): Promise<ChangeEvent[]> => {
    const res = await request<unknown>(`/api/v1/changes${buildQuery(params || {})}`);
    return unwrapList<ChangeEvent>(res, ['changes', 'events', 'items', 'data']);
  },
  diffScans: (fromId: string, toId: string) =>
    request<ScanDiffResponse>(`/api/v1/scans/diff${buildQuery({ from: fromId, to: toId })}`),
  acknowledgeChange: (id: string) =>
    request<ChangeEvent>(`/api/v1/changes/${id}/acknowledge`, { method: 'POST' }),

  ingestManual: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>('/api/v1/ingest/manual', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  ingestImportFile: (file: File, format: ImportFormat, scanName?: string) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('format', format);
    if (scanName) fd.append('scan_name', scanName);
    return request<Record<string, unknown>>('/api/v1/ingest/import', {
      method: 'POST',
      body: fd,
    });
  },
  exportData: async (params: {
    format: ExportFormat;
    scan_id?: string;
    state?: string;
    tag?: string;
  }) => {
    const res = await request<Response>(`/api/v1/export${buildQuery(params)}`, {
      rawResponse: true,
    });
    const ext = EXPORT_EXT[params.format];
    saveBlob(await res.blob(), `dzieciol-export-${new Date().toISOString().slice(0, 10)}${ext}`);
  },
  /** Merged raw nmap XML (-oX) of one scan run. */
  downloadScanNmapXml: async (scanId: string) => {
    const res = await request<Response>(`/api/v1/scans/${scanId}/nmap.xml`, { rawResponse: true });
    saveBlob(await res.blob(), `dzieciol-run-${scanId}-nmap.xml`);
  },

  listSignatures: async (): Promise<Signature[]> => {
    const res = await request<unknown>('/api/v1/signatures');
    return unwrapList<Signature>(res, ['signatures', 'items', 'data']);
  },
  createSignature: (payload: Partial<Signature>) =>
    request<Signature>('/api/v1/signatures', { method: 'POST', body: JSON.stringify(payload) }),
  updateSignature: (id: string, payload: Partial<Signature>) =>
    request<Signature>(`/api/v1/signatures/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteSignature: (id: string) =>
    request<void>(`/api/v1/signatures/${id}`, { method: 'DELETE' }),
  validateSignature: (payload: Partial<Signature>) =>
    request<SignatureValidationResult>('/api/v1/signatures/validate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  testSignature: (payload: Partial<Signature>) =>
    request<SignatureTestResult>('/api/v1/signatures/test', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  importSignatures: (payload: unknown) =>
    request<Record<string, unknown>>('/api/v1/signatures/import', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  exportSignatures: async () => {
    const res = await request<Response>('/api/v1/signatures/export', { rawResponse: true });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dzieciol-signatures-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  getDefectDojoConfig: () => request<DefectDojoConfig>('/api/v1/integrations/defectdojo'),
  updateDefectDojoConfig: (payload: Partial<DefectDojoConfig>) =>
    request<DefectDojoConfig>('/api/v1/integrations/defectdojo', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  testDefectDojo: (payload?: Partial<DefectDojoConfig>) =>
    request<Record<string, unknown>>('/api/v1/integrations/defectdojo/test', {
      method: 'POST',
      body: payload ? JSON.stringify(payload) : undefined,
    }),
  pushDefectDojoFindings: (payload: {
    service_ids?: string[];
    change_ids?: string[];
    engagement_id?: number;
    severity?: string;
  }) =>
    request<Record<string, unknown>>('/api/v1/integrations/defectdojo/push-findings', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  pushDefectDojoNmap: (payload: { scan_run_id: string; engagement_id?: number }) =>
    request<Record<string, unknown>>('/api/v1/integrations/defectdojo/push-nmap', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  listDefectDojoHistory: async (): Promise<DefectDojoExport[]> => {
    const res = await request<unknown>('/api/v1/integrations/defectdojo/history');
    return unwrapList<DefectDojoExport>(res, ['exports', 'history', 'items', 'data']);
  },

  listAgents: async (): Promise<{ agents: Agent[]; offline_after_sec: number }> => {
    const res = await request<{ agents?: Agent[]; offline_after_sec?: number }>('/api/v1/agents');
    return { agents: res?.agents ?? [], offline_after_sec: res?.offline_after_sec ?? 90 };
  },
  updateAgent: (id: string, payload: { name?: string; site?: string; disabled?: boolean }) =>
    request<Agent>(`/api/v1/agents/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteAgent: (id: string) => request<void>(`/api/v1/agents/${id}`, { method: 'DELETE' }),
  listAgentTokens: async (): Promise<AgentEnrollToken[]> => {
    const res = await request<unknown>('/api/v1/agents/tokens');
    return unwrapList<AgentEnrollToken>(res, ['tokens', 'items']);
  },
  createAgentToken: (payload: { name?: string; site?: string; ttl_hours?: number }) =>
    request<CreatedAgentToken>('/api/v1/agents/tokens', { method: 'POST', body: JSON.stringify(payload) }),
  revokeAgentToken: (id: string) => request<void>(`/api/v1/agents/tokens/${id}`, { method: 'DELETE' }),

  listUsers: async (): Promise<User[]> => {
    const res = await request<unknown>('/api/v1/admin/users');
    return unwrapList<User>(res, ['users', 'items', 'data']);
  },
  createUser: (payload: {
    username: string;
    email?: string;
    password: string;
    role_id?: string;
    role_slug?: string;
    active?: boolean;
  }) => request<User>('/api/v1/admin/users', { method: 'POST', body: JSON.stringify(payload) }),
  updateUser: (
    id: string,
    payload: {
      email?: string;
      password?: string;
      role_id?: string;
      role_slug?: string;
      active?: boolean;
    }
  ) =>
    request<User>(`/api/v1/admin/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteUser: (id: string) => request<void>(`/api/v1/admin/users/${id}`, { method: 'DELETE' }),

  listRoles: async (): Promise<Role[]> => {
    const res = await request<unknown>('/api/v1/admin/roles');
    return unwrapList<Role>(res, ['roles', 'items', 'data']);
  },
  createRole: (payload: {
    slug: string;
    name: string;
    description?: string;
    permissions: string[];
  }) => request<Role>('/api/v1/admin/roles', { method: 'POST', body: JSON.stringify(payload) }),
  updateRole: (
    id: string,
    payload: { name?: string; description?: string; permissions?: string[] }
  ) =>
    request<Role>(`/api/v1/admin/roles/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteRole: (id: string) => request<void>(`/api/v1/admin/roles/${id}`, { method: 'DELETE' }),
  listPermissions: async (): Promise<string[]> => {
    const res = await request<unknown>('/api/v1/admin/permissions');
    return unwrapList<string>(res, ['permissions', 'items', 'data']);
  },

  cryptoStatus: () => request<CryptoStatusResponse>('/api/v1/admin/crypto/status'),
  rotateCryptoKey: () =>
    request<Record<string, unknown>>('/api/v1/admin/crypto/rotate', { method: 'POST' }),

  listAuditLogs: async (params?: { limit?: number; status?: string; action?: string }): Promise<AuditLog[]> => {
    const res = await request<unknown>(`/api/v1/admin/audit${buildQuery(params || {})}`);
    return unwrapList<AuditLog>(res, ['logs', 'audit', 'items', 'data']);
  },

  // Light host list (no evidence/headers/history) for the asset table: ?fields=summary.
  listHostSummaries: async (params?: {
    q?: string;
    state?: string;
    tag?: string;
    min_score?: number;
    env?: string;
    has_admin?: boolean;
    page?: number;
    limit?: number;
  }): Promise<HostPage> => {
    const res = await request<Record<string, unknown>>(
      `/api/v1/hosts${buildQuery({ ...(params || {}), fields: 'summary' })}`
    );
    const hosts = unwrapList<Host>(res, ['hosts']);
    const total = Number(res.total ?? hosts.length);
    const limit = Number(res.limit ?? params?.limit ?? 50);
    return {
      hosts,
      total,
      page: Number(res.page ?? params?.page ?? 1),
      limit,
      total_pages: Number(res.total_pages ?? Math.max(1, Math.ceil(total / Math.max(1, limit)))),
    };
  },
  /** Product inventory, quick-filter counts and de-duplicated scan scope. */
  inventory: () => request<InventoryResponse>('/api/v1/inventory'),
  defectDojoStatus: () => request<DefectDojoStatus>('/api/v1/integrations/defectdojo/status'),
  defectDojoServiceStatus: (hostId?: string) =>
    request<DefectDojoServiceStatus>(
      `/api/v1/integrations/defectdojo/services${buildQuery({ host_id: hostId })}`
    ),
  syncDefectDojoNow: () =>
    request<Record<string, unknown>>('/api/v1/integrations/defectdojo/sync', { method: 'POST' }),
};
