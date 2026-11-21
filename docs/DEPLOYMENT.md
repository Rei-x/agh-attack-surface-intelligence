# AegisASI — Deployment, Lab & Production Hardening Guide

This guide covers quick-start deployment with Docker Compose, running the deterministic university test lab, verifying encryption and RBAC end-to-end, key rotation, and production hardening for **CBI AGH**.

---

## 1. Prerequisites

- **Docker Engine** 24+ and **Docker Compose v2** (`docker compose version`)
- Optional for local verification scripts: `bash`, `curl`, `jq`
- Minimum resources: 1 vCPU, 512 MB RAM (production with 65k IP scans: 2 vCPU, 2 GB RAM, SSD for PostgreSQL)

---

## 2. Quick Start (Application + PostgreSQL)

```bash
# 1. Start PostgreSQL 17 and AegisASI (multi-stage build: React UI + Go binary + nmap)
docker compose up -d --build

# 2. Verify health & active AES-256-GCM encryption
curl -s http://localhost:8080/api/v1/health | jq .
```

Open the SOC Dashboard at **http://localhost:8080**.

### Seeded Demo Accounts (`ASI_SEED_DEMO=true`)

| Username | Password | Role (Polish) | Key Capabilities |
| :--- | :--- | :--- | :--- |
| `admin` | `Admin123!` | Administracja | Full access (`*`), RBAC roles/users, crypto rotation, DefectDojo config, audit log |
| `operator` | `Operator123!` | Dodawanie, usuwanie, modyfikacja | Targets, profiles, run/stop scans, CSV/JSON/manual ingest, signatures, DefectDojo push |
| `analyst` | `Analyst123!` | Modyfikacja i odczyt | Curate hosts/services (preserved overrides), edit scan notes, test signatures, export |
| `viewer` | `Viewer123!` | Odczyt | Read-only dashboard, graph, assets, diff, signatures, export (`403` on all writes) |

> **Production Note:** Set `ASI_SEED_DEMO=false` before exposing AegisASI on a production network and provision real operator accounts via the Admin panel.

---

## 3. Running the Deterministic University Test Lab

The test lab (`docker-compose.lab.yml`) spins up 6 ultra-lightweight Python stdlib containers (<100 MB RAM total, <5 s startup, zero external pip installs) on subnet `172.28.0.0/24` sharing `aegis-asi-net`:

```bash
# Start AegisASI + PostgreSQL + full deterministic test lab + DefectDojo v2 mock
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
```

### Lab Topology (`172.28.0.0/24`)

| Service | Static IP & Port | Host Exposure | Simulated Asset & Key Signals |
| :--- | :--- | :--- | :--- |
| `lab-cms` | `172.28.0.10:80` | internal | WordPress 6.4.2 (`<meta generator>`, `wp-settings-1` cookie, `/wp-login.php`, Apache/2.4.58, distinctive favicon) |
| `lab-admin` | `172.28.0.11:80` | internal | CBI AGH Internal Admin Console / Grafana (`/admin`, `/login`, `X-Powered-By: Express`, insecure `admin_session` cookie) |
| `lab-staging` | `172.28.0.12:443` | internal | HTTPS Staging USOS Portal with runtime-generated self-signed TLS cert (21-day expiry), `X-Debug-Token`, Werkzeug/3.0.1, `/version` |
| `lab-iot` | `172.28.0.13:8080` | internal | HP LaserJet Pro MFP M428fdw (`Virata-EmWeb/R6_2_1`, `/info_deviceStatus.html`, distinctive favicon) |
| `lab-flapping` | `172.28.0.14:80` | `:19999` (control) | Dynamic mutating & flapping Moodle host (`normal` / `changed` / `down`) |
| `lab-defectdojo-mock` | `172.28.0.20:8000` | `:18000` (UI & API) | Offline DefectDojo API v2 receiver + live viewer at **http://localhost:18000/ui** |

### Live Mutation Control (`lab-flapping`)

Between Scan 1 and Scan 2, toggle `lab-flapping` behavior live without restarting containers:

```bash
# Normal state (Moodle 4.3.2 on nginx/1.24.0, /admin -> 403)
curl -X POST "http://localhost:19999/control?mode=normal"

# Changed state (banner -> Apache, title -> Maintenance - Admin Exposed, /admin -> 200, X-Staging-Debug: true)
curl -X POST "http://localhost:19999/control?mode=changed"

# Down state (closes TCP :80 listener to simulate disappearing/flapping host)
curl -X POST "http://localhost:19999/control?mode=down"
```

---

## 4. Automated Verification Scripts

### 4.1 Prove Encryption At Rest Directly in PostgreSQL

```bash
./scripts/verify_encryption.sh
```

Connects directly to PostgreSQL via `docker compose exec -T postgres psql` and verifies:
- All encrypted columns store `enc:v1:<kid>:...` AES-256-GCM ciphertext and `wrap:v1:<kid>:...` wrapped DEKs.
- Lookup columns use 64-character hex HMAC-SHA256 blind indexes.
- Zero plaintext lab IPs, cookies, or debug headers appear in encrypted tables.

### 4.2 Full End-to-End Verification Suite

```bash
./scripts/demo_e2e.sh
```

Automates a 10-stage verification covering: health & crypto status, 4-role RBAC `200`/`403` enforcement, 16,384-IP target estimation (`10.0.0.0/18`), manual + CSV (`scripts/sample_import.csv`) + JSON (`scripts/sample_import.json`) unified ingestion, Scan 1 on `172.28.0.10-14`, analyst override curation, live mutation of `lab-flapping`, Scan 2, Scan Diff & override preservation proof, Signature Studio safety validation & retroactive playground (`scripts/sample_signatures.json`), and DefectDojo API v2 export verification.

---

## 5. Environment Variables

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | Yes (prod) | *(in-memory fallback if empty)* | PostgreSQL connection URI (`postgres://user:pass@host:5432/db?sslmode=require`) |
| `ASI_MASTER_KEY` | **Yes (prod)** | Dev default in compose | 256-bit Key Encryption Key (64 hex chars or 32-byte base64). Generate via `openssl rand -hex 32`. |
| `ASI_JWT_SECRET` | Recommended | Derived from `ASI_MASTER_KEY` | Secret for HS256 JWT signing. Rotate independently of data encryption keys. |
| `ASI_SEED_DEMO` | No | `true` in compose | Seeds 4 demo accounts (`admin`, `operator`, `analyst`, `viewer`). **Set `false` in production.** |
| `ASI_STATIC_DIR` | No | `/app/static` | Directory containing built React SPA static assets. |
| `ASI_LISTEN_ADDR` | No | `:8080` | HTTP bind address inside container. |
| `ASI_PORT` | No | `8080` | Host port mapped to container `:8080`. |
| `TZ` | No | `Europe/Warsaw` | Default timezone for scan windows and logs. |

---

## 6. Key Management & Online DEK Rotation

### Generating a Production Master Key

```bash
openssl rand -hex 32
```

Store `ASI_MASTER_KEY` in a dedicated secret manager (HashiCorp Vault, Kubernetes SealedSecrets, or systemd `LoadCredential=`) — **never commit it to Git** or bake it into container images.

### Rotating the Data Encryption Key (DEK)

AegisASI supports zero-downtime DEK rotation via the Admin UI (**Admin → Encryption At Rest → Rotate DEK**) or REST API:

```bash
curl -X POST http://localhost:8080/api/v1/admin/crypto/rotate \
  -H "Authorization: Bearer ${ADMIN_JWT}"
```

1. Generates a fresh 256-bit DEK (`dek-v(N+1)`) and wraps it under `ASI_MASTER_KEY` (`wrap:v1:dek-v(N+1):...`).
2. Activates the new DEK for all new writes while retaining previous wrapped DEKs for decryption.
3. Re-encrypts existing sensitive rows in PostgreSQL under `dek-v(N+1)` verifying every `table:record_id:column` AAD tag.

---

## 7. Production Hardening Checklist for CBI AGH

1. **TLS Termination:** Place AegisASI behind CBI AGH's reverse proxy (Nginx / Traefik / HAProxy) with TLS 1.3, HSTS, and SSE proxy buffering disabled (`proxy_buffering off;` on `/api/v1/events/stream`).
2. **Database TLS & Least Privilege:** Enable `sslmode=verify-full` in `DATABASE_URL`, bind PostgreSQL to internal VLAN/loopback only, and use a dedicated non-superuser PostgreSQL role.
3. **Disable Demo Accounts:** Set `ASI_SEED_DEMO=false` and enforce strong unique passwords for all SOC personnel.
4. **Network Capabilities:** The container requests only `NET_RAW` and `NET_ADMIN` so `nmap` can perform fast SYN/ICMP host discovery; drop all other Linux capabilities (`cap_drop: [ALL]`, `cap_add: [NET_RAW, NET_ADMIN]`, `security_opt: [no-new-privileges:true]`) in production.
5. **Scope/Deny Gate Governance:** Immediately configure permanent `TargetExclusion` rules for sensitive medical/SCADA/safety-critical subnets and core routing infrastructure before scheduling recurring scans.
6. **Maintenance Windows & Rate Limits:** Configure `window_enabled: true` (e.g., `22:00–06:00` `Europe/Warsaw`) and conservative `max_rate_pps` / `http_rps` values for production campus `/16` sweeps.
7. **Automated Backups:** Back up both PostgreSQL (`pg_dump`) and `ASI_MASTER_KEY` separately; without `ASI_MASTER_KEY`, database backups remain cryptographically unreadable.
