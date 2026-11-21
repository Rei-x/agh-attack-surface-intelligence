# AegisASI — Deployment, Lab & Production Hardening Guide

This guide covers the single-binary install (no Docker), quick-start deployment with Docker Compose, running the deterministic university test lab, verifying encryption and RBAC end-to-end, key rotation, and production hardening for **CBI AGH**.

---

## 0. Single Binary (no Docker, no database)

The `aegis` binary contains the web UI (embedded with `go:embed`), the REST API, the scanner
and the CLI. It is a static `CGO_ENABLED=0` build for darwin/arm64, darwin/amd64,
linux/amd64, linux/arm64 and windows/amd64.

```bash
curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
aegis serve                                   # UI + API on :8080, prints demo logins on first run
aegis scan 10.0.0.0/24 -p 22,80,443,8080      # headless scan, live progress, summary table
aegis scan -f targets.txt --json -o report.json
aegis import results.xml                      # nmap -oX, CSV or JSON
aegis export --format csv -o inventory.csv
aegis runs && aegis diff                      # list runs, compare the last two
```

### Storage without PostgreSQL

When `DATABASE_URL` is empty, data lives in the data directory (`~/.aegis`, override with
`--data-dir` or `ASI_DATA_DIR`):

| File | Purpose |
| :--- | :--- |
| `aegis-store.enc` | `AEGISDB1` magic + AES-256-GCM(gzip(JSON state)), key = HMAC-SHA256(KEK, `aegis-asi:file-blob:v1`), magic bound as AAD |
| `master.key` | 256-bit KEK as 64 hex chars, created on first run with mode `0600` unless `ASI_MASTER_KEY` is set. Never logged. |
| `aegis.lock` | OS-level exclusive lock (`flock` / `LockFileEx`) + JSON holder info (pid, command, URL) |

The state inside the envelope is the same row model as the in-memory/PostgreSQL stores:
IPs, hostnames, domains, OS guesses, banners, HTTP fingerprints, notes, e-mails, overrides,
change payloads, raw nmap XML and scan snapshots are each envelope-encrypted with versioned
DEKs (`enc:v1:<kid>:...`, AAD-bound to table/row/column); the wrapped DEKs are stored in the
snapshot. So data is encrypted twice at rest, and online DEK rotation (Admin > Crypto) works
the same as with PostgreSQL.

Persistence: writes are debounced (1.5 s quiet period, at most 10 s under continuous writes),
plus a 30 s safety tick and a final flush on shutdown (SIGINT/SIGTERM). Every save is atomic
(temp file in the same directory, `fsync`, `rename`, directory `fsync`), so a crash leaves
either the previous or the new snapshot, never a torn file. If `master.key` is missing while
`aegis-store.enc` exists, `aegis` refuses to start instead of generating a new key.

**Why a snapshot file, not embedded SQLite:** the `MemoryStore` already implements the full
`db.Store` interface with field-level encryption and is what the API test-suite (including the
10k-host scale test) runs against. Persisting it is ~300 lines and keeps the release a
dependency-free static binary. A pure-Go SQLite (modernc.org) would add several MB to the
binary and require a third 1,800-line `Store` implementation plus migrations. The trade-off is
that the whole state is rewritten on save. Measured on an M-series Mac with 10,000 hosts and
20,000 services: 7.6 MB on disk, 0.10 s per save, 0.11 s to load.
For bigger multi-user deployments use PostgreSQL (`DATABASE_URL`).

**Single writer:** `aegis serve`, `aegis scan` and `aegis import` take the lock. If a server
is running, `scan` and `import` fail with a message naming the server's pid and URL. In that
case start scans from the UI or with `POST /api/v1/scans`. `export`, `diff` and `runs` are
read-only and work while the server runs (they read its last autosave). With `DATABASE_URL`
set, every command uses PostgreSQL and no lock is taken.

**Exclusions:** stored target exclusions apply to CLI scans too. The default `127.0.0.0/8`
safety exclusion means a local test needs `--ignore-exclusions`.

### Scanner prerequisites

nmap is optional. Without it, the pure-Go TCP connect scanner with banner grabbing is used, and
`aegis scan` prints install hints (`brew install nmap`, `sudo apt install nmap`,
`winget install Insecure.Nmap`). Root is never required: nmap runs as `-sT` (TCP connect).
Unprivileged nmap on macOS cannot send ICMP echo, so host discovery uses TCP probes.

### Building and releasing

```bash
make ui         # pnpm build + copy frontend/dist into backend/internal/webui/ui (go:embed)
make build      # ui + bin/aegis (version ldflags from git describe)
make release    # ui + dist/aegis-<os>-<arch>[.exe] for 5 targets + dist/checksums.txt
```

`backend/internal/webui/ui/` is git-ignored except for `.gitkeep`, so a plain `go build ./...`
works without a frontend build and serves a placeholder page. `ASI_STATIC_DIR` (or
`--static-dir`) overrides the embedded UI. Pushing a `v*` tag runs
`.github/workflows/release.yml`, which tests, cross-compiles, smoke-tests the linux binary and
publishes the binaries, `checksums.txt` and `install.sh` as a GitHub Release.

---

## 0a. Zdalni agenci skanujący (`aegis agent`)

Agent to ten sam plik binarny uruchomiony jako lekki demon wewnątrz innego segmentu sieci
(VLAN innego wydziału, inna uczelnia, sieć za NAT-em). Łączy się **wyłącznie wychodząco** do
centralnego serwera AegisASI, pobiera zadania skanowania, skanuje lokalnie tym samym silnikiem
(chunki, limity PPS, okna czasowe, wykluczenia) i odsyła wyniki. Serwer nigdy nie łączy się z
agentem, agent nie otwiera żadnego portu.

### Architektura

```
   Segment B (VLAN 120, za NAT)                     Sieć CBI AGH
  +-------------------------------+               +--------------------------------+
  |  aegis agent  (systemd,       |  HTTPS 443    |  aegis serve (UI + API)         |
  |  DynamicUser, bez uprawnień)  | ------------> |  /api/v1/agent/*                |
  |   - enroll (token 1x)         |  tylko        |   - rejestr agentów, tokeny     |
  |   - heartbeat co 15 s         |  wychodząco   |   - kolejka zadań (long-poll)   |
  |   - jobs/next (long-poll 25s) |               |   - ingest.Pipeline (ten sam    |
  |   - Engine.Execute lokalnie   |               |     co dla skanów lokalnych)    |
  |   - outbox na dysku (fsync)   |               |   - SSE -> UI (postęp na żywo)  |
  |   - --allow-cidr (lokalnie)   |               |                                 |
  +-------------------------------+               +--------------------------------+
        | nmap -sT / TCP connect
        v
   hosty segmentu B
```

Sekwencja wywołań (JSON, `Authorization: Bearer <poświadczenie agenta>`):

1. `POST /api/v1/agent/enroll` – jednorazowy token -> `agent_id` + poświadczenie (zapisane 0600 w `agent.json`).
2. `POST /api/v1/agent/heartbeat` co 15 s – wersja, możliwości (nmap, root, allowlista); odpowiedź niesie polecenia `pause`/`stop` dla bieżącego skanu.
3. `POST /api/v1/agent/jobs/next?wait=25` – long-poll; zwraca profil, wykluczenia i księgę chunków (pusta = nowy skan, inaczej wznowienie od punktu kontrolnego).
4. `POST /jobs/{id}/start` – agent planuje chunki własnym DNS-em i wysyła księgę.
5. `POST /jobs/{id}/chunks` – wynik każdego zakończonego chunku (obserwacje); serwer wpuszcza je przez `Pipeline.ProcessObservations` z wykrywaniem zniknięć ograniczonym do IP tego chunku. Idempotentne po `chunk.id`.
6. `POST /jobs/{id}/progress` co 2 s – liczniki, księga, zdarzenia na żywo (przekazywane do SSE, więc UI działa bez zmian).
7. `POST /jobs/{id}/finish` – koniec segmentu: `completed` / `paused_window` / `paused_user` / `stopped` / `interrupted` / `failed` / `refused` + scalony surowy XML nmap. Idempotentne po `segment_id`.

### Instalacja

1. W UI: **Skany -> Agenci -> Dodaj agenta** (wymaga `admin:settings`). Token jest pokazany raz, ważny 1–720 h, jednorazowy, przechowywany tylko jako SHA-256.
2. Na maszynie w segmencie (Linux + systemd, root):

```bash
curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh \
  | sudo sh -s -- --agent --server https://aegis.cbi.agh.edu.pl --token aet_... \
      --name wydzial-eaiib --allow-cidr 10.20.0.0/16
```

`install.sh --agent` instaluje binarkę do `/usr/local/bin`, zapisuje ustawienia do
`/etc/aegis-agent.env` (0600) i włącza `aegis-agent.service` (plik: `deploy/aegis-agent.service`).
To samo bez skryptu: `sudo aegis agent install --server ... --token ...`. Ręcznie (dowolny system):
`aegis agent --server https://... --token aet_... [--data-dir DIR] [--ca-file ca.pem] [--allow-cidr ...]`.
Kolejne uruchomienia nie potrzebują tokenu. Logi: `journalctl -u aegis-agent -f`.

3. W profilu skanowania wybierz pole **Skanuje: Agent: ...**. Harmonogram, „Uruchom teraz”,
pauza/wznowienie/stop działają jak dla skanów lokalnych; profil nadal nie może mieć dwóch
aktywnych przebiegów.

### Wymagania sieciowe

- Agent -> serwer: **tylko wychodzący TCP 443** (HTTPS; obsługiwany `HTTPS_PROXY`). Żadnych portów przychodzących.
- Agent -> skanowane hosty: jak dla zwykłego skanu (nmap `-sT`, bez roota).
- Serwer: wystawiony pod HTTPS (reverse proxy / tunel). `ASI_PUBLIC_URL` ustala adres podawany w komendzie instalacji.

### Model bezpieczeństwa

- **Token rejestracyjny**: losowe 256 bitów, jednorazowy, z datą ważności, w bazie tylko SHA-256; można go unieważnić.
- **Poświadczenie agenta** (`agt.<id>.<sekret>`): losowe 256 bitów, w bazie tylko SHA-256 (porównanie w stałym czasie). Otwiera **wyłącznie** `/api/v1/agent/*`; tokeny użytkowników (JWT) są tam odrzucane (401), a poświadczenie agenta na endpointach użytkowników też daje 401 (test `TestAgentAuthIsolation`). Agent widzi i raportuje tylko swoje zadania; wyłączenie/usunięcie agenta w UI natychmiast blokuje poświadczenie.
- **TLS**: certyfikat serwera weryfikowany domyślnie; `--ca-file` dla wewnętrznego CA; `--insecure` tylko w laboratorium. Zwykły HTTP jest odrzucany poza adresem lokalnym.
- **Lokalna allowlista** (`--allow-cidr`): agent odmawia (`refused`, z notatką w skanie) każdego zadania, którego cel lub chunk wychodzi poza dozwolone sieci – przejęty serwer nie zmusi agenta do skanowania dowolnych sieci.
- **Unit systemd**: `DynamicUser`, `NoNewPrivileges`, `ProtectSystem=strict`, puste `CapabilityBoundingSet` – agent działa bez uprawnień.
- Stan agentów (rejestr, tokeny, zadania) leży w zaszyfrowanych dokumentach `app_settings` (plik `aegis-store.enc` lub PostgreSQL), jak reszta danych.

### Odporność

- Wyniki każdego chunku trafiają najpierw do `outbox/` (fsync), dopiero potem są wysyłane – utrata sieci lub restart agenta niczego nie gubi; wysyłka z wykładniczym backoffem.
- Agent milczący dłużej niż `ASI_AGENT_OFFLINE_AFTER` (domyślnie 90 s) jest oznaczany offline, a jego skan przechodzi w `PAUSED_WINDOW` z notatką; po powrocie agent dostaje ten sam skan i wznawia od punktu kontrolnego (chunki DONE są pomijane).
- Restart serwera nie przerywa skanów agentów (lokalny mechanizm odzyskiwania je pomija).

### Porównanie

- **runZero Explorer / Rapid7 Scan Engine (engine-to-console)**: ten sam wzorzec – lekki skaner w segmencie, tylko połączenie wychodzące do konsoli, rejestracja tokenem.
- **Tenable Nessus linked scanner / agent**: jak „linking key” – jednorazowy klucz zamieniany na tożsamość skanera, zadania pobierane z centrali.
- Różnica: jeden plik binarny dla serwera i agenta, wyniki przechodzą przez ten sam potok co skany lokalne i import, plus lokalna allowlista po stronie agenta.

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
| `DATABASE_URL` | Yes (prod) | *(encrypted file store in `ASI_DATA_DIR` if empty)* | PostgreSQL connection URI (`postgres://user:pass@host:5432/db?sslmode=require`) |
| `ASI_MASTER_KEY` | **Yes (prod)** | Dev default in compose; otherwise `$ASI_DATA_DIR/master.key` (auto-generated, `0600`) | 256-bit Key Encryption Key (64 hex chars or 32-byte base64). Generate via `openssl rand -hex 32`. |
| `ASI_DATA_DIR` | No | `~/.aegis` (`/data` in the Docker image) | Data directory for the encrypted file store, `master.key` and the lock. Same as `--data-dir`. |
| `ASI_JWT_SECRET` | Recommended | Derived from `ASI_MASTER_KEY` | Secret for HS256 JWT signing. Rotate independently of data encryption keys. |
| `ASI_SEED_DEMO` | No | `true` in compose | Seeds 4 demo accounts (`admin`, `operator`, `analyst`, `viewer`). **Set `false` in production.** |
| `ASI_STATIC_DIR` | No | *(embedded UI)*; compose sets `/app/static` | Serve the React SPA from this directory instead of the UI embedded in the binary. |
| `ASI_LISTEN_ADDR` | No | `:8080` | HTTP bind address (same as `aegis serve --listen`; `PORT` is honoured when unset). |
| `ASI_PORT` | No | `8080` | Host port mapped to container `:8080`. |
| `ASI_PUBLIC_URL` | No | *(scheme/host of the admin's request)* | Server URL put into the agent install command (e.g. `https://aegis.cbi.agh.edu.pl`). |
| `ASI_AGENT_OFFLINE_AFTER` | No | `90s` | Silence after which a remote agent is marked offline and its running scan is parked (resumed when it returns). |
| `TZ` | No | `Europe/Warsaw` | Default timezone for scan windows and logs. |
| `ASI_DEFECTDOJO_PRODUCT_TYPE_NAME` / `_PRODUCT_NAME` / `_ENGAGEMENT_NAME` | No | `AegisASI` / `AGH Attack Surface` / `AegisASI continuous discovery` | DefectDojo context names used when no product/engagement is pinned by ID (same levels as the secureCodeBox DefectDojo hook annotations, see `docs/SECURECODEBOX.md`). |
| `ASI_DEFECTDOJO_DEDUPLICATE_ON_ENGAGEMENT` | No | `false` | Sends `deduplication_on_engagement=true` when DefectDojo auto-creates the engagement. |
| `ASI_DEFECTDOJO_MINIMUM_SEVERITY` | No | `Info` | `minimum_severity` for reimports (`Info`, `Low`, `Medium`, `High`, `Critical`). |

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
