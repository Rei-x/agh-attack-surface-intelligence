# AegisASI — System Architecture

> **Attack Surface Intelligence Platform for Centrum Bezpieczeństwa Informacji AGH (CBI AGH)**

AegisASI is a single Go binary (`aegis`) with an embedded React/TypeScript SOC dashboard. Data lives in an encrypted single-file store (`~/.aegis/aegis-store.enc`) by default, or in PostgreSQL 17 when `DATABASE_URL` is set; both apply the same per-field envelope encryption. It is purpose-built for continuous, safe, auditable attack surface discovery across large university networks (10,000–65,536+ IPs) with minimal operational overhead.

---

## 1. High-Level System Architecture

```mermaid
flowchart TB
    subgraph Client["SOC Analysts & Operators"]
        UI["React 19 + TypeScript SPA<br/>(Dashboard, Graph, Assets, Diff, Studio, Admin)"]
        CLI["aegis CLI (scan, import, export, diff)<br/>Automation / CI / E2E Scripts"]
    end

    subgraph App["AegisASI Single Binary (Go 1.24)"]
        API["REST API + SSE Event Bus<br/>(JWT HS256 + Dynamic RBAC + Audit Log)"]
        ING["Unified Ingestion Pipeline<br/>(Active / Manual / CSV / JSON / Passive)"]
        ENG["Chunked Scan Engine<br/>(Target Normalizer, Scope/Deny Gate,<br/>WindowGuard, Target Noise Governor)"]
        FP["Safe HTTP/HTTPS/TLS Fingerprinter<br/>(GET/HEAD only, Favicon MMH3, TLS X.509)"]
        SIG["Signature Studio Engine<br/>(55+ Built-ins, Safety Validator,<br/>Retroactive Playground)"]
        INT["Intelligence Engine<br/>(Host Hysteresis FSM, Time-of-Day Matrix,<br/>Noisy-OR Confidence, Interestingness)"]
        VAULT["Crypto Vault<br/>(AES-256-GCM Envelope AEAD + AAD +<br/>HMAC-SHA256 Blind Indexes)"]
        DD["DefectDojo v2 Client<br/>(Nmap XML + Deduplicated Findings)"]
        SCH["Scheduler<br/>(ScanProfile.ScheduleCron + time window)"]
        HUB["Agent Hub<br/>(enrollment, job leases, chunk ingest)"]
        NTF["Alert Webhook<br/>(Slack / Teams / Discord)"]
    end

    subgraph Storage["Persistence"]
        FS[("Encrypted file store (default)<br/>AES-256-GCM sealed snapshot")]
        PG[("PostgreSQL 17 (optional)<br/>Encrypted Sensitive Columns<br/>+ Coverage Ledger + Overrides")]
    end

    subgraph External["Target Networks & Integrations"]
        NET["AGH Campus Subnets (/16+)<br/>or Deterministic Test Lab (172.28.0.0/24)"]
        DD_SRV["DefectDojo API v2<br/>(Production or Offline Mock Receiver)"]
        AGENT["aegis agent<br/>(remote segment, outbound HTTPS only)"]
    end

    UI -->|HTTPS / REST + SSE| API
    CLI -->|REST| API
    API --> ING
    API --> ENG
    API --> SIG
    API --> DD
    ENG --> FP
    ENG -->|Normalized Observations| ING
    ING --> SIG
    ING --> INT
    ING --> VAULT
    VAULT --> FS
    VAULT --> PG
    SCH --> ENG
    ING --> NTF
    AGENT -->|enroll, heartbeat, jobs, chunk results| HUB
    HUB --> ING
    API --> VAULT
    ENG -->|nmap + Safe GET/HEAD| NET
    DD -->|POST /import-scan & /findings| DD_SRV
```

### Core Architectural Principles

1. **Unified Pipeline (Single Source of Truth):** Active network scans (`ACTIVE`), manual analyst forms (`MANUAL`), CSV/JSON imports (`IMPORT_CSV`, `IMPORT_JSON`), and passive feeds (`PASSIVE`) all normalize into identical `ObservedHost` / `ObservedService` records and execute the exact same signature matching, confidence fusion, lifecycle FSM, change detection, override preservation, and encryption pipeline.
2. **Strict Separation of Scanner Truth vs. Analyst Curation:** Scanner observations are stored as evidence receipts (`service_observations`), while analyst edits live in `asset_overrides`. Merging at read time guarantees manual edits work regardless of scan status and are **never overwritten** by subsequent scans, while surfacing *"Scanner observed: X"* diffs when reality drifts.
3. **Read-Only Discovery Safety:** All HTTP probes strictly use `GET`/`HEAD`, enforce bounded body/redirect limits (256 KB, max 5 redirects), carry an identifiable `User-Agent`, and never attempt authentication, brute-force, or mutating requests. Custom signatures pass through the **Safety Validator** before saving or executing.

---

## 2. Large-Scale Scanning (>10,000 IP), Coverage Ledger & Time Windows

```mermaid
flowchart LR
    IN["Inputs: IPs, CIDRs (/16+),<br/>Ranges, Domains"] --> NORM["Normalize, Deduplicate<br/>& Scope/Deny Gate"]
    NORM --> CAL["Calibration Micro-Probe<br/>(Measure RTT & throughput)"]
    CAL --> CHUNK["Adaptive Chunker<br/>(32..512 IPs / chunk)"]
    CHUNK --> LEDGER[("Coverage Ledger<br/>PENDING / RUNNING / DONE / PAUSED")]
    LEDGER --> WG{"WindowGuard<br/>IsOpen(now)?"}
    WG -->|Yes| POOL["Bounded Worker Pool +<br/>Target Noise Governor"]
    WG -->|No| PAUSE["Checkpoint PAUSED_WINDOW<br/>Wait for NextOpen(now)"]
    PAUSE -.->|Next Window| WG
    POOL --> S1["Stage 1: Host Discovery<br/>(nmap -Pn port sweep + ICMP when privileged<br/>/ pure-Go TCP connect fallback)"]
    S1 --> S4["Stage 4: Unstable Re-Probe<br/>(previously seen hosts missed in Stage 1)"]
    S4 --> S2["Stage 2: Service Detection<br/>(nmap -sV on live hosts)"]
    S2 --> S3["Stage 3: HTTP/TLS Fingerprinting<br/>(GET/HEAD, Certs, Favicon MMH3, JARM)"]
    S3 --> LEDGER
```

- **Target Estimation (`POST /api/v1/targets/estimate`):** Expands CIDRs (e.g., `/18` = 16,384 IPs, `/16` = 65,536 IPs) with O(1) prefix arithmetic, subtracts `TargetExclusion` rules, calculates chunk counts and realistic ETA, and indicates whether the scan fits inside the configured maintenance window.
- **Hard Time Windows (`WindowGuard`):** Supports overnight windows (e.g., `22:00–06:00` in `Europe/Warsaw`). When a window expires, the engine finishes in-flight work cleanly, marks remaining chunks `PENDING`, sets the scan status to `PAUSED_WINDOW`, and resumes from the exact next `PENDING` chunk when the next window opens.
- **One rate budget, pipelined stages:** chunks flow through the stages concurrently; the profile's `max_rate_pps` is split across the concurrent nmap processes (`--max-rate`), so the sum never exceeds it. Above a size threshold chunks are built from a permuted address order, so no subnet is hit in a burst.
- **Target Noise Governor:** Tracks per-host and global token buckets. Bursts of timeouts, `429 Too Many Requests`, or TCP RST spikes automatically trigger exponential backoff and emit `governor.throttle` SSE events so university infrastructure is never overloaded.

---

## 3. Envelope Encryption At Rest (AES-256-GCM) & Blind Indexing

Every sensitive field (in PostgreSQL columns and in the file store alike: host IPs, hostnames, domains, OS guesses, banners, HTTP headers, cookies, body snippets, TLS certificates, raw Nmap XML, analyst overrides, user emails, and DefectDojo API tokens) is encrypted at the application layer before leaving Go memory.

```mermaid
flowchart LR
    KEK["ASI_MASTER_KEY<br/>(256-bit KEK in env / KMS)"] -->|Wrap/Unwrap AES-256-GCM<br/>AAD: dek:kid| DEK["Versioned 256-bit DEK<br/>(dek-v1, dek-v2, ...)"]
    KEK -->|HMAC-SHA256 label:<br/>aegis-asi:blind-index:v1| HKEY["Blind Index Subkey"]
    KEK -->|HMAC-SHA256 label:<br/>aegis-asi:jwt-signing:v1| JKEY["JWT Subkey (fallback)"]

    PT["Sensitive Field Plaintext"] --> AEAD["AES-256-GCM Encrypt<br/>12-byte random CSPRNG nonce<br/>AAD = table:record_id:column"]
    DEK --> AEAD
    AEAD --> CT["Stored Ciphertext:<br/>enc:v1:dek-v1:&lt;base64(nonce|ct|tag)&gt;"]

    IP["Normalized IP / Hostname"] --> BI["HMAC-SHA256(HKEY, lower(val))"]
    HKEY --> BI
    BI --> IDX["64-char hex Blind Index<br/>(Exact lookup & deduplication)"]
```

### Cryptographic Properties

| Property | Implementation | Security Guarantee |
| :--- | :--- | :--- |
| **Algorithm** | AES-256-GCM (AEAD) | Confidentiality + 128-bit integrity tag per field |
| **Envelope Format** | `enc:v1:<kid>:<base64(nonce\|ct\|tag)>` | Self-describing key version for seamless online rotation |
| **Context Binding (AAD)** | `table:record_id:column` | Prevents ciphertext transplantation / row-swapping attacks inside DB |
| **DEK Storage** | `wrap:v1:<kid>:<base64(...)>` with AAD `dek:<kid>` | Database dump alone cannot unwrap DEKs without `ASI_MASTER_KEY` |
| **Exact Lookups** | HMAC-SHA256 blind index (`hosts.ip_hmac`) | Fast indexed deduplication without storing plaintext IPs |
| **Key Rotation** | `POST /api/v1/admin/crypto/rotate` | Generates `dek-v(N+1)`, re-encrypts sensitive rows under new DEK while preserving old DEKs for zero-downtime decryption |
| **Verification** | `scripts/verify_encryption.sh` + `/api/v1/admin/crypto/status` | Direct `psql` inspection proving ciphertext storage with zero plaintext leakage (PostgreSQL mode) |

---

## 4. Intelligence Engine

### 4.1 Host Lifecycle State Machine (Hysteresis + Re-Probe)

To avoid alert fatigue from transient campus devices (laptops, lab workstations, scheduled nightly shutdowns), hosts transition through a hysteresis state machine:

```mermaid
stateDiagram-v2
    [*] --> NEW: First discovery
    NEW --> ACTIVE: Seen in subsequent scan
    NEW --> MISSING: Not seen + failed re-probe

    ACTIVE --> ACTIVE: Seen again
    ACTIVE --> MISSING: Missed scan & failed re-probe
    ACTIVE --> INTERMITTENT: High transition ratio / flapping

    MISSING --> ACTIVE: Seen before grace expiry
    MISSING --> INTERMITTENT: Repeatedly flips up/down
    MISSING --> INACTIVE: consecutive_misses >= K<br/>AND elapsed >= T_grace

    INTERMITTENT --> ACTIVE: Stabilized across window
    INTERMITTENT --> INACTIVE: consecutive_misses >= K<br/>AND elapsed >= T_grace

    INACTIVE --> REACTIVATED: Reappears in later scan
    REACTIVATED --> ACTIVE: Confirmed in next scan
```

- **Automatic Re-Probe:** Before transitioning a previously active host to `MISSING`, Stage 4 executes `retry_unstable_count` targeted verification probes to filter transient packet loss.
- **Bayesian liveness:** each host keeps a Beta-Bernoulli availability estimate per time-of-day slot with exponential forgetting (`internal/intelligence/liveness.go`); it explains *why* a host is considered gone or merely off-hours (see `docs/RESEARCH.md`).
- **Dual-Condition Deactivation:** A host moves to `INACTIVE` only when **both** `consecutive_misses >= missing_threshold` ($K$) **and** time since `last_seen` exceeds `grace_period_hours` ($T_{\text{grace}}$).

### 4.2 Time-of-Day Availability Matrix (Heatmap)

Each host tracks availability ratios across 4 daily UTC/local slots:
- `00-06` (Night)
- `06-12` (Morning)
- `12-18` (Afternoon)
- `18-24` (Evening)

When a host is absent in a slot where its historical availability ratio is low (e.g., an instructional lab PC offline during `00-06`), the event is classified as `EXPECTED_OFF_HOURS` (`is_expected_schedule = true`), suppressing false alarms. Conversely, a disappearance during a normally 95%+ available slot—or an unexpected appearance at 03:00 on a normally dormant host—is flagged as `TIME_ANOMALY` (`is_time_anomaly = true`).

### 4.3 Noisy-OR Confidence Fusion & Interestingness Scoring

Multiple independent fingerprinting signals (HTTP headers, cookies, HTML generator/footer, safe-path hits, TLS SANs, Favicon MurmurHash3) are fused using the **Noisy-OR** probabilistic model:

$$C(\text{tech}) = \text{round}\left(100 \times \left(1 - \prod_{i=1}^{n} (1 - w_i)\right)\right)$$

where each matched evidence receipt $i$ contributes a calibrated weight $w_i \in [0.10, 0.98]$. Every technology badge stores the exact list of `TechEvidence` receipts (`signal_type`, `detail`, `weight`) so analysts can audit *why* a technology was reported.

**Interestingness Score (0–100)** prioritizes SOC triage by summing explainable `InterestingnessFactor` points:
- Exposed admin panels (`/admin`, Grafana, phpMyAdmin, Jenkins, Keycloak)
- Non-production environments (`staging`, `dev`, `test`, debug headers such as `X-Debug-Token` / `X-Staging-Debug`)
- Missing HTTP security headers and insecure cookies (`missing_httponly`, `missing_secure`)
- Self-signed, expired, or expiring-soon (<30 days) TLS certificates
- Unexpected time-of-day anomalies or newly opened services
- Networked IoT devices (printers, cameras, BMCs) on campus VLANs

---

## 5. Attack Surface Graph, Service Clustering & DefectDojo v2

- **Interactive Attack Surface Graph (`GET /api/v1/graph`):** Models directed topology `Scope → Host (lifecycle state) → Service (port/proto) → Technology / Matched Signature`, enabling analysts to filter by risk score, lifecycle state, or exposure category.
- **Similar Service Clustering (`GET /api/v1/clusters`):** Groups services sharing identical `favicon_mmh3` (Shodan-compatible base64-with-newlines MurmurHash3), technology stack, HTTP `<title>`, or TLS certificate issuer to spot shadow IT clones or unpatched fleets at a glance.
- **DefectDojo API v2 Integration:**
  - `POST /api/v2/import-scan/` uploads aggregated raw Nmap XML (`scan_type="Nmap Scan"`) linked to a target `engagement`.
  - `POST /api/v2/findings/` selectively pushes curated services or change events with full evidence receipts, severity mapping, and deterministic `unique_id_from_tool` deduplication keys.
  - For offline demos or staging verification, `lab-defectdojo-mock` implements the exact DefectDojo v2 contract plus a live HTML viewer at `http://localhost:18000/ui`.

---

## 6. Remote Scanning Agents & Scheduler

- **`aegis agent`** runs the same `scanner.Engine` inside a network segment the server cannot reach. It only opens outbound HTTPS to the server: one-time enrollment token, heartbeat, long-polled job leases, per-chunk results ingested through the same `ingest.Pipeline` (disappearance detection scoped to the chunk's IPs), and checkpoint resume after restarts. Protocol and security model: [DEPLOYMENT.md, section 0a](./DEPLOYMENT.md).
- **Scheduler** (`internal/scheduler`) fires profiles with `schedule_cron`; a slot that falls outside the profile's time window is deferred to the next window opening, and a profile never has two active runs.
