export type HostLifecycleState =
  | 'NEW'
  | 'ACTIVE'
  | 'INTERMITTENT'
  | 'MISSING'
  | 'INACTIVE'
  | 'REACTIVATED';

export type ScanStatus =
  | 'QUEUED'
  | 'CALIBRATING'
  | 'RUNNING'
  | 'PAUSED_WINDOW'
  | 'PAUSED_USER'
  | 'COMPLETED'
  | 'FAILED'
  | 'STOPPED';

export type ScanType = 'ACTIVE' | 'MANUAL' | 'IMPORT_CSV' | 'IMPORT_JSON' | 'PASSIVE';

export type ChunkStatus = 'PENDING' | 'RUNNING' | 'DONE' | 'PAUSED' | 'FAILED';

export interface HealthResponse {
  status: string;
  version?: string;
  db?: string;
  nmap_available?: boolean;
  encryption_active?: boolean;
  key_version?: string;
}

export interface Role {
  id: string;
  slug: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
  created_at?: string;
}

export interface User {
  id: string;
  username: string;
  email?: string;
  role_id?: string;
  role?: string;
  role_slug?: string;
  role_name?: string;
  permissions: string[];
  active?: boolean;
  created_at?: string;
}

export interface DemoAccount {
  username: string;
  password: string;
  role?: string;
  role_slug?: string;
  role_name?: string;
  label?: string;
  description?: string;
  permissions?: string[];
}

export interface LoginResponse {
  token: string;
  user: User;
}

export interface Target {
  id: string;
  value: string;
  kind: string;
  label?: string;
  tags?: string[];
  enabled: boolean;
  created_by?: string;
  created_at?: string;
}

export interface TargetExclusion {
  id: string;
  value: string;
  reason?: string;
  created_by?: string;
  created_at?: string;
}

export interface TargetEstimate {
  total_ips: number;
  excluded_ips: number;
  effective_ips: number;
  recommended_chunk_size: number;
  chunk_count: number;
  estimated_seconds: number;
  fits_in_window: boolean;
  estimated_windows?: number;
}

export interface ScanProfile {
  id: string;
  name: string;
  description?: string;
  targets: string[];
  allowed_ports: string;
  max_rate_pps: number;
  http_rps: number;
  concurrency: number;
  chunk_target_sec: number;
  schedule_cron?: string;
  window_enabled: boolean;
  window_start: string;
  window_end: string;
  timezone: string;
  missing_threshold: number;
  grace_period_hours: number;
  retry_unstable_count: number;
  enable_http_fingerprint: boolean;
  /** Picture of every web service (headless Chromium on the scanning host). Missing = on. */
  capture_screenshots?: boolean;
  user_agent?: string;
  enabled: boolean;
  /** Remote scanning agent executing this profile ('' = this server). */
  agent_id?: string;
  created_at?: string;
  updated_at?: string;
  schedule?: ProfileSchedule;
}

export interface AgentCapabilities {
  nmap: boolean;
  nmap_version?: string;
  privileged: boolean;
  os?: string;
  arch?: string;
  hostname?: string;
  allow_cidrs?: string[];
}

export interface Agent {
  id: string;
  name: string;
  site: string;
  version: string;
  status: 'online' | 'offline' | 'disabled' | string;
  remote_ip: string;
  capabilities: AgentCapabilities;
  current_run_id?: string;
  last_seen_at?: string;
  enrolled_at: string;
  enrolled_by?: string;
  disabled: boolean;
}

export interface AgentEnrollToken {
  id: string;
  name: string;
  site: string;
  prefix: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  used_at?: string;
  agent_id?: string;
}

export interface CreatedAgentToken {
  token: string;
  enroll_token: AgentEnrollToken;
  server_url: string;
  install_command: string;
  run_command: string;
}

export interface ScheduleRunRef {
  id: string;
  name: string;
  status: ScanStatus | string;
  triggered_by: string;
  started_at: string;
  finished_at?: string;
}

/** Recurring-scan status computed by the backend scheduler (GET /profiles). */
export interface ProfileSchedule {
  scheduled: boolean;
  cron?: string;
  timezone?: string;
  cron_error?: string;
  next_slot_at?: string;
  next_run_at?: string;
  deferred_by_window: boolean;
  pending_catch_up: boolean;
  will_skip: boolean;
  last_fire_at?: string;
  last_skip_at?: string;
  last_skip_reason?: string;
  last_run?: ScheduleRunRef;
  active_run?: ScheduleRunRef;
}

export interface ScanChunk {
  id: string;
  scan_run_id: string;
  chunk_index: number;
  targets?: string[];
  ip_count: number;
  status: ChunkStatus | string;
  active_hosts: number;
  services_found: number;
  duration_ms: number;
  error?: string;
  started_at?: string;
  finished_at?: string;
  /** Exact nmap command lines executed for this chunk (or pure-Go fallback description). */
  nmap_commands?: string[];
  /** This chunk's share of the global --max-rate budget. */
  max_rate_pps?: number;
  worker?: number;
}

export interface ScanRun {
  id: string;
  profile_id?: string;
  name: string;
  run_type: ScanType | string;
  status: ScanStatus | string;
  notes?: string;
  total_ips: number;
  scanned_ips: number;
  total_chunks: number;
  completed_chunks: number;
  active_hosts: number;
  services_found: number;
  changes_detected: number;
  hosts_per_sec: number;
  eta_seconds: number;
  duration_ms: number;
  window_paused_count: number;
  has_raw_nmap_xml?: boolean;
  triggered_by?: string;
  started_at: string;
  finished_at?: string;
  chunks?: ScanChunk[];
  telemetry?: ScanTelemetry;
}

export interface RedirectHop {
  url: string;
  status_code: number;
}

export interface CookieInfo {
  name: string;
  value?: string;
  path?: string;
  domain?: string;
  http_only: boolean;
  secure: boolean;
  same_site?: string;
  flags?: string[];
}

export interface TLSInfo {
  version: string;
  cipher_suite?: string;
  subject_cn: string;
  issuer: string;
  sans?: string[];
  not_before: string;
  not_after: string;
  days_to_expiry: number;
  is_self_signed: boolean;
  is_expired: boolean;
  sha256: string;
  jarm?: string;
}

export interface SafePathHit {
  path: string;
  status_code: number;
  title?: string;
  snippet?: string;
}

export interface HTTPFingerprint {
  url?: string;
  scheme?: string;
  status_code: number;
  title?: string;
  server_header?: string;
  headers?: Record<string, string>;
  missing_sec_headers?: string[];
  interesting_headers?: string[];
  cookies?: CookieInfo[];
  redirect_chain?: RedirectHop[];
  tls?: TLSInfo;
  favicon_mmh3?: string;
  favicon_sha256?: string;
  meta_generator?: string;
  footer_version?: string;
  body_snippet?: string;
  safe_path_hits?: SafePathHit[];
  response_time_ms?: number;
}

export interface TechEvidence {
  signal_type: string;
  detail: string;
  weight: number;
}

export interface DetectedTechnology {
  name: string;
  category: string;
  version?: string;
  confidence: number;
  evidence?: TechEvidence[];
  explanation?: string;
}

export interface InterestingnessFactor {
  reason: string;
  points: number;
}

export interface TimeSlotStat {
  slot: string;
  seen: number;
  total: number;
  ratio: number;
  alpha?: number;
  beta?: number;
  p_up?: number;
  streak_misses?: number;
  updated_at?: string;
}

export interface LivenessEstimate {
  p_alive: number;
  p_up_slot: number;
  slot: string;
  streak_misses: number;
  threshold: number;
  reason: string;
  model: string;
}

export interface OutdatedComponent {
  product: string;
  version: string;
  branch: string;
  eol_date: string;
  days_since_eol: number;
  latest_in_branch?: string;
  supported_branch?: string;
  via: string;
  distro_packaged?: boolean;
  label: string;
  evidence: string;
  source: string;
  data_as_of: string;
}

export interface VulnHint {
  id: string;
  name: string;
  product: string;
  version: string;
  affected: string;
  distro_packaged?: boolean;
  evidence: string;
  references: string[];
}

export interface Service {
  id: string;
  host_id: string;
  host_ip?: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string;
  product?: string;
  version?: string;
  cpe?: string;
  banner?: string;
  http?: HTTPFingerprint;
  technologies?: DetectedTechnology[];
  matched_signatures?: string[];
  is_admin_panel: boolean;
  is_staging_env: boolean;
  is_iot: boolean;
  /** End-of-life components (offline table, derived by the backend). */
  outdated?: OutdatedComponent[];
  /** Passive, version-only hints at well-known CVEs. */
  known_vulns?: VulnHint[];
  /** Known CVEs from the offline NVD / CISA KEV / EPSS snapshot (derived by the backend). */
  vulns?: import('../lib/vulnintel').VulnSummary[];
  /** Findings confirmed by safe verification checks (Verify deep mode). */
  verified?: import('../lib/vulnintel').VerifiedFinding[];
  cluster_key?: string;
  interestingness: number;
  interesting_factors?: InterestingnessFactor[];
  triage_status: string;
  triage?: TriageInfo;
  notes?: string;
  tags?: string[];
  locked_fields?: string[];
  scanner_observed?: Record<string, unknown>;
  first_seen?: string;
  last_seen?: string;
}

export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  domains?: string[];
  os_guess?: string;
  lifecycle_state: HostLifecycleState | string;
  environment?: string;
  owner?: string;
  notes?: string;
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
  total_scans_seen: number;
  total_scans_checked: number;
  consecutive_misses: number;
  state_transitions: number;
  stability_score: number;
  interestingness: number;
  interesting_factors?: InterestingnessFactor[];
  time_of_day_stats?: TimeSlotStat[];
  liveness?: LivenessEstimate;
  locked_fields?: string[];
  scanner_observed?: Record<string, unknown>;
  services?: Service[];
  service_count: number;
  recent_changes?: ChangeEvent[];
  triage_status?: string;
  triage?: TriageInfo;
}

export interface ChangeEvent {
  id: string;
  scan_run_id: string;
  prev_scan_run_id?: string;
  host_id: string;
  host_ip: string;
  service_id?: string;
  port?: number;
  event_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | string;
  summary: string;
  time_slot?: string;
  is_expected_schedule?: boolean;
  is_time_anomaly?: boolean;
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  acknowledged_by?: string;
  acknowledged_at?: string;
  created_at: string;
}

export interface SignatureMatcher {
  type: string;
  key?: string;
  pattern: string;
  regex: boolean;
  status_codes?: number[];
  version_group?: number;
}

export interface Signature {
  id: string;
  name: string;
  description: string;
  category: string;
  match_mode: 'any' | 'all' | string;
  matchers: SignatureMatcher[];
  confidence_weight: number;
  interesting_points: number;
  tags?: string[];
  is_builtin: boolean;
  enabled: boolean;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SignatureValidationResult {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
  reason?: string;
}

export interface SignatureTestMatch {
  host_id?: string;
  host_ip: string;
  service_id?: string;
  port: number;
  service_name?: string;
  http_title?: string;
  version?: string;
  confidence?: number;
  matched_rules?: string[];
  evidence?: TechEvidence[];
}

export interface SignatureTestResult {
  matches: SignatureTestMatch[];
  tested_services?: number;
  total_matches?: number;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  username: string;
  role_slug: string;
  action: string;
  resource: string;
  resource_id?: string;
  status: 'success' | 'denied' | 'error' | string;
  details?: Record<string, unknown>;
  ip_address?: string;
  created_at: string;
}

export interface DefectDojoConfig {
  url: string;
  api_token?: string;
  has_api_token?: boolean;
  product_id: number;
  engagement_id: number;
  verify_tls: boolean;
  auto_push_nmap: boolean;
  auto_push_findings?: boolean;
}

export interface DefectDojoExport {
  id: string;
  export_type: string;
  source_id: string;
  title: string;
  external_id?: string;
  external_url?: string;
  status: string;
  error_message?: string;
  exported_by: string;
  created_at: string;
}

export interface LiveEvent {
  type: string;
  scan_run_id?: string;
  timestamp: string;
  payload?: Record<string, unknown>;
}

export interface ServiceCluster {
  cluster_key: string;
  group_by: string;
  label: string;
  count: number;
  host_ips: string[];
  service_ids: string[];
  max_interestingness: number;
  sample_techs?: string[];
}

export interface GraphNode {
  id: string;
  kind: 'scope' | 'host' | 'service' | 'technology' | 'signature' | string;
  label: string;
  state?: string;
  interestingness?: number;
  meta?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  /** Hosts behind an aggregated (block to technology) edge. */
  weight?: number;
}

export interface GraphSubnetSummary {
  subnet: string;
  host_count: number;
  active_count: number;
  high_risk_count: number;
  max_score: number;
}

export type GraphMode = 'auto' | 'clustered' | 'detailed';

export interface GraphQuery {
  mode?: GraphMode;
  limit?: number;
  subnet?: string;
  /** CIDR of an overview block: the response lists its /24 subnets. */
  block?: string;
  q?: string;
  state?: string;
  min_score?: number;
  admin_only?: boolean;
  staging_only?: boolean;
  admin_or_staging?: boolean;
}

/** overview: address blocks; block: /24s of one block; subnet: one /24; detailed: top hosts. */
export type GraphLevel = 'overview' | 'block' | 'subnet' | 'detailed';

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_hosts: number;
  matched_hosts: number;
  shown_hosts: number;
  clustered: boolean;
  mode: GraphMode | string;
  level?: GraphLevel;
  /** Prefix of overview blocks (stable per data set), e.g. 22. */
  block_prefix?: number;
  /** Prefix of group nodes on an aggregated level. */
  group_prefix?: number;
  /** Block being shown, or the block holding the shown subnet. */
  block?: string;
  hidden_groups?: number;
  limit: number;
  subnets: GraphSubnetSummary[];
}

export interface HostPage {
  hosts: Host[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface DashboardTimelinePoint {
  scan_id?: string;
  label?: string;
  name?: string;
  started_at?: string;
  timestamp?: string;
  active_hosts: number;
  services_found?: number;
  services?: number;
  changes_detected?: number;
  changes?: number;
}

export interface DashboardSummary {
  kpis?: {
    total_ips?: number;
    scope_ips?: number;
    total_hosts?: number;
    active_hosts?: number;
    unstable_hosts?: number;
    total_services?: number;
    services_found?: number;
    recent_changes?: number;
    changes_last_scan?: number;
    interesting_findings?: number;
  };
  total_ips?: number;
  scope_ips?: number;
  total_hosts?: number;
  active_hosts?: number;
  unstable_hosts?: number;
  total_services?: number;
  services_found?: number;
  recent_changes_count?: number;
  changes_last_scan?: number;
  interesting_findings_count?: number;
  active_scan?: ScanRun | null;
  timeline?: DashboardTimelinePoint[];
  top_findings?: Service[];
  top_interesting?: Service[];
  lifecycle_breakdown?: Record<string, number>;
  recent_changes?: ChangeEvent[];
  accepted_risk_count?: number;
  expired_acceptances?: ExpiredAcceptance[];
}

export interface ChangedServiceDiff {
  id?: string;
  host_id: string;
  host_ip: string;
  port?: number;
  protocol?: string;
  severity?: string;
  summary: string;
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  time_slot?: string;
  is_time_anomaly?: boolean;
  is_expected_schedule?: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface ScanDiffResponse {
  from_scan?: ScanRun;
  to_scan?: ScanRun;
  from_scan_id?: string;
  to_scan_id?: string;
  new_hosts?: Host[];
  missing_hosts?: Host[];
  new_services?: Service[];
  closed_services?: Service[];
  changed_services?: ChangedServiceDiff[];
  time_anomalies?: ChangeEvent[];
  changes?: ChangeEvent[];
  summary?: {
    new_hosts?: number;
    missing_hosts?: number;
    new_services?: number;
    closed_services?: number;
    changed_services?: number;
    time_anomalies?: number;
    total_changes?: number;
  };
}

export interface CryptoStatusResponse {
  active?: boolean;
  encryption_active?: boolean;
  algorithm?: string;
  blind_index?: string;
  key_version?: string;
  active_kid?: string;
  rotated_at?: string;
  encrypted_tables?: string[];
  sample?: {
    table?: string;
    column?: string;
    record_id?: string;
    raw_ciphertext?: string;
    ciphertext?: string;
    decrypted_value?: string;
    plaintext?: string;
    aad?: string;
    blind_index?: string;
  };
  samples?: Array<{
    table?: string;
    column?: string;
    record_id?: string;
    raw_ciphertext?: string;
    ciphertext?: string;
    decrypted_value?: string;
    plaintext?: string;
    aad?: string;
    blind_index?: string;
  }>;
}

export interface ServiceObservation {
  id?: string;
  scan_run_id?: string;
  observed_at?: string;
  created_at?: string;
  port?: number;
  protocol?: string;
  service_name?: string;
  product?: string;
  version?: string;
  banner?: string;
  http?: HTTPFingerprint;
}

/** Analyst risk decision (accepted risk / false positive) with reason, author and expiry. */
export interface TriageInfo {
  status: 'accepted_risk' | 'false_positive' | string;
  reason: string;
  by: string;
  at: string;
  expires_at?: string;
  expired: boolean;
}

export interface ExpiredAcceptance {
  host_id: string;
  host_ip: string;
  service_id?: string;
  port?: number;
  service_name?: string;
  triage: TriageInfo;
}

export interface HostTimelineEntry {
  kind: 'change' | 'observation' | 'first_seen' | string;
  at: string;
  until?: string;
  count?: number;
  event_type?: string;
  severity?: string;
  summary: string;
  service_id?: string;
  port?: number;
  protocol?: string;
  scan_run_id?: string;
  details?: Record<string, unknown>;
}

export interface TagRule {
  id?: string;
  cidr: string;
  tags: string[];
  owner?: string;
  environment?: string;
  description?: string;
  enabled: boolean;
  created_by?: string;
  created_at?: string;
}

export interface WebhookConfig {
  has_url: boolean;
  url_masked?: string;
  enabled: boolean;
  min_severity: 'info' | 'low' | 'medium' | 'high' | string;
  notify_state_changes: boolean;
  last_status?: string;
  last_error?: string;
  last_sent_at?: string;
}

/** One product row of GET /api/v1/inventory; `query` lists the hosts behind it. */
export interface InventoryProduct {
  name: string;
  category?: string;
  query: string;
  logo_names: string[];
  host_count: number;
  service_count: number;
  eol_count: number;
  vuln_count: number;
  admin_count: number;
  new_count: number;
  max_score: number;
  versions: Array<{ version: string; count: number }>;
  ports: number[];
}

export interface InventoryQuickFilter {
  key: string;
  query: string;
  count: number;
}

export interface InventoryResponse {
  products: InventoryProduct[];
  quick_filters: InventoryQuickFilter[];
  /** Scan scope with overlapping CIDRs merged (raw_ips = naive sum). */
  scope: { ips: number; raw_ips: number; targets: number };
  total_hosts: number;
}

/** One member host of a clustered service / technology graph node. */
export interface GraphHostRef {
  host_id: string;
  ip: string;
  hostname?: string;
  title?: string;
  score: number;
  service_id?: string;
  port?: number;
  owner?: string;
}

export interface ThrottleEntry {
  at: string;
  host?: string;
  /** timeout_burst, http_429, rst_burst; "_host" suffix = only that host was slowed down */
  reason: string;
  old_rate: number;
  new_rate: number;
  errors?: number;
}

export interface WindowEntry {
  at: string;
  kind: 'paused' | 'resumed' | string;
  next_open?: string;
}

/** Persisted rate-control history of a scan run. */
export interface ScanTelemetry {
  configured_pps?: number;
  configured_http_rps?: number;
  nmap_peak_pps?: number;
  http_rate_rps?: number;
  http_initial_rps?: number;
  throttle_count: number;
  timeouts: number;
  http_429: number;
  rst: number;
  throttles?: ThrottleEntry[];
  window_events?: WindowEntry[];
  updated_at?: string;
}

export interface DefectDojoFindingRef {
  service_id?: string;
  host_id?: string;
  kind: string;
  title: string;
  severity?: string;
  finding_id?: number;
  url?: string;
  test_id?: number;
  /** active, false_positive, risk_accepted, mitigated */
  state: string;
  pushed_at: string;
}

export interface DefectDojoSyncState {
  last_sync_at?: string;
  last_status?: string;
  last_error?: string;
  last_run_id?: string;
  test_id?: number;
  test_url?: string;
  product_id?: number;
  product_url?: string;
  findings: number;
  triage_synced: number;
  nmap_test_url?: string;
  nmap_pushed_at?: string;
}

export interface DefectDojoStatus {
  configured: boolean;
  url: string;
  auto_push_nmap: boolean;
  auto_push_findings: boolean;
  sync: DefectDojoSyncState;
  last_export?: DefectDojoExport;
}

export interface DefectDojoServiceStatus {
  services: Record<string, DefectDojoFindingRef[]>;
  hosts: Record<string, DefectDojoFindingRef[]>;
  last_sync_at?: string;
}
