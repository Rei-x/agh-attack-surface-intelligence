-- AegisASI PostgreSQL 17 Schema (Encryption At Rest + Dynamic RBAC + Overrides)

CREATE TABLE IF NOT EXISTS crypto_keys (
    kid TEXT PRIMARY KEY,
    wrapped_dek TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email_enc TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS target_exclusions (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_ports TEXT NOT NULL DEFAULT '80,443',
    max_rate_pps INTEGER NOT NULL DEFAULT 500,
    http_rps INTEGER NOT NULL DEFAULT 25,
    concurrency INTEGER NOT NULL DEFAULT 32,
    chunk_target_sec INTEGER NOT NULL DEFAULT 60,
    schedule_cron TEXT NOT NULL DEFAULT '',
    window_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    window_start TEXT NOT NULL DEFAULT '22:00',
    window_end TEXT NOT NULL DEFAULT '06:00',
    timezone TEXT NOT NULL DEFAULT 'Europe/Warsaw',
    missing_threshold INTEGER NOT NULL DEFAULT 3,
    grace_period_hours INTEGER NOT NULL DEFAULT 48,
    retry_unstable_count INTEGER NOT NULL DEFAULT 2,
    enable_http_fingerprint BOOLEAN NOT NULL DEFAULT TRUE,
    user_agent TEXT NOT NULL DEFAULT 'AegisASI-CBI-AGH/1.0',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    run_type TEXT NOT NULL,
    status TEXT NOT NULL,
    notes_enc TEXT NOT NULL DEFAULT '',
    total_ips INTEGER NOT NULL DEFAULT 0,
    scanned_ips INTEGER NOT NULL DEFAULT 0,
    total_chunks INTEGER NOT NULL DEFAULT 0,
    completed_chunks INTEGER NOT NULL DEFAULT 0,
    active_hosts INTEGER NOT NULL DEFAULT 0,
    services_found INTEGER NOT NULL DEFAULT 0,
    changes_detected INTEGER NOT NULL DEFAULT 0,
    hosts_per_sec DOUBLE PRECISION NOT NULL DEFAULT 0,
    eta_seconds BIGINT NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    window_paused_count INTEGER NOT NULL DEFAULT 0,
    raw_nmap_xml_enc TEXT NOT NULL DEFAULT '',
    has_raw_nmap_xml BOOLEAN NOT NULL DEFAULT FALSE,
    triggered_by TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at DESC);

CREATE TABLE IF NOT EXISTS scan_chunks (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    active_hosts INTEGER NOT NULL DEFAULT 0,
    services_found INTEGER NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scan_chunks_run ON scan_chunks(scan_run_id, chunk_index);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    ip_hmac TEXT NOT NULL UNIQUE,
    ip_enc TEXT NOT NULL,
    hostname_enc TEXT NOT NULL DEFAULT '',
    domains_enc TEXT NOT NULL DEFAULT '',
    os_guess_enc TEXT NOT NULL DEFAULT '',
    lifecycle_state TEXT NOT NULL DEFAULT 'NEW',
    environment TEXT NOT NULL DEFAULT 'unknown',
    owner TEXT NOT NULL DEFAULT '',
    notes_enc TEXT NOT NULL DEFAULT '',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_scans_seen INTEGER NOT NULL DEFAULT 0,
    total_scans_checked INTEGER NOT NULL DEFAULT 0,
    consecutive_misses INTEGER NOT NULL DEFAULT 0,
    state_transitions INTEGER NOT NULL DEFAULT 0,
    stability_score INTEGER NOT NULL DEFAULT 100,
    interestingness INTEGER NOT NULL DEFAULT 0,
    interesting_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    time_of_day_stats JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip_hmac ON hosts(ip_hmac);
CREATE INDEX IF NOT EXISTS idx_hosts_state ON hosts(lifecycle_state);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    cpe TEXT NOT NULL DEFAULT '',
    banner_enc TEXT NOT NULL DEFAULT '',
    http_enc TEXT NOT NULL DEFAULT '',
    technologies JSONB NOT NULL DEFAULT '[]'::jsonb,
    matched_signatures JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_admin_panel BOOLEAN NOT NULL DEFAULT FALSE,
    is_staging_env BOOLEAN NOT NULL DEFAULT FALSE,
    is_iot BOOLEAN NOT NULL DEFAULT FALSE,
    cluster_key TEXT NOT NULL DEFAULT '',
    interestingness INTEGER NOT NULL DEFAULT 0,
    interesting_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    triage_status TEXT NOT NULL DEFAULT 'new',
    notes_enc TEXT NOT NULL DEFAULT '',
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);

CREATE TABLE IF NOT EXISTS service_observations (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    banner_enc TEXT NOT NULL DEFAULT '',
    http_enc TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_service_obs_service ON service_observations(service_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS asset_overrides (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    field TEXT NOT NULL,
    value_enc TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_type, entity_id, field)
);
CREATE INDEX IF NOT EXISTS idx_asset_overrides_entity ON asset_overrides(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS change_events (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL,
    prev_scan_run_id TEXT NOT NULL DEFAULT '',
    host_id TEXT NOT NULL DEFAULT '',
    host_ip_enc TEXT NOT NULL DEFAULT '',
    service_id TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    summary TEXT NOT NULL DEFAULT '',
    time_slot TEXT NOT NULL DEFAULT '',
    is_expected_schedule BOOLEAN NOT NULL DEFAULT FALSE,
    is_time_anomaly BOOLEAN NOT NULL DEFAULT FALSE,
    before_enc TEXT NOT NULL DEFAULT '',
    after_enc TEXT NOT NULL DEFAULT '',
    acknowledged_by TEXT NOT NULL DEFAULT '',
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_change_events_scan ON change_events(scan_run_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    scan_run_id TEXT PRIMARY KEY REFERENCES scan_runs(id) ON DELETE CASCADE,
    payload_enc TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS signatures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'custom',
    match_mode TEXT NOT NULL DEFAULT 'any',
    matchers JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_weight DOUBLE PRECISION NOT NULL DEFAULT 0.7,
    interesting_points INTEGER NOT NULL DEFAULT 10,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defectdojo_config (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL DEFAULT '',
    api_token_enc TEXT NOT NULL DEFAULT '',
    product_id INTEGER NOT NULL DEFAULT 0,
    engagement_id INTEGER NOT NULL DEFAULT 0,
    verify_tls BOOLEAN NOT NULL DEFAULT TRUE,
    auto_push_nmap BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defectdojo_exports (
    id TEXT PRIMARY KEY,
    export_type TEXT NOT NULL,
    source_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL DEFAULT '',
    external_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'success',
    error_message TEXT NOT NULL DEFAULT '',
    exported_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    role_slug TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'success',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Chunk-level transparency: exact nmap command lines, per-process rate share, worker slot.
ALTER TABLE scan_chunks ADD COLUMN IF NOT EXISTS nmap_commands JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE scan_chunks ADD COLUMN IF NOT EXISTS max_rate_pps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_chunks ADD COLUMN IF NOT EXISTS worker INTEGER NOT NULL DEFAULT 0;

-- Recurring scan scheduler state (survives restarts; one row per profile).
CREATE TABLE IF NOT EXISTS scan_schedule_state (
    profile_id TEXT PRIMARY KEY,
    cron TEXT NOT NULL DEFAULT '',
    anchor_at TIMESTAMPTZ,
    last_fire_at TIMESTAMPTZ,
    last_run_id TEXT NOT NULL DEFAULT '',
    last_skip_at TIMESTAMPTZ,
    last_skip_reason TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Host timeline lookups (GET /api/v1/hosts/{id}/timeline).
CREATE INDEX IF NOT EXISTS idx_change_events_host ON change_events(host_id, created_at DESC);

-- Small encrypted key/value settings (CIDR tag rules, alert webhook incl. its secret URL).
-- value_enc is an AES-256-GCM envelope bound to AAD "app_settings:<key>:value".
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value_enc TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
