# Dzięcioł: kontrakt API i RBAC (v1)

Wszystkie endpointy poza `/api/v1/health`, `/api/v1/auth/login` i `/api/v1/auth/demo-accounts` wymagają nagłówka `Authorization: Bearer <jwt>` (lub tokenu `?token=` dla strumienia SSE `/api/v1/events/stream`).

## 1. Role i uprawnienia RBAC

### Predefiniowane role (seedowane przy starcie)
1. `admin` („Administration”): wszystkie uprawnienia (`*`).
2. `operator` („Add, delete, modify”): `dashboard:read`, `assets:read`, `assets:write`, `assets:delete`, `scans:read`, `scans:write`, `scans:delete`, `scans:run`, `signatures:read`, `signatures:write`, `signatures:delete`, `import:write`, `export:read`, `defectdojo:push`.
3. `analyst` („Modify and read”): `dashboard:read`, `assets:read`, `assets:write`, `scans:read`, `scans:write`, `signatures:read`, `signatures:write`, `export:read`.
4. `viewer` („Read only”): `dashboard:read`, `assets:read`, `scans:read`, `signatures:read`, `export:read`.

### Konta demo (seedowane gdy `DZIECIOL_SEED_DEMO=true`)
- `admin` / `Admin123!` (Administration)
- `operator` / `Operator123!` (Add, delete, modify)
- `analyst` / `Analyst123!` (Modify and read)
- `viewer` / `Viewer123!` (Read only)

## 2. Endpointy REST

### Auth & Health
- `GET /api/v1/health` → `{status, version, db, nmap_available, encryption_active, key_version}`
- `GET /api/v1/auth/demo-accounts` → lista kont demo (gdy włączone)
- `POST /api/v1/auth/login` → `{username, password}` → `{token, user: {id, username, email, role, permissions[]}}`
- `GET /api/v1/auth/me` → bieżący użytkownik + uprawnienia

### Dashboard & Graph & Clusters
- `GET /api/v1/dashboard/summary` → KPIs, active scan status, timeline points, top interesting findings, lifecycle breakdown, recent changes
- `GET /api/v1/graph` → `{nodes: GraphNode[], edges: GraphEdge[]}` (topologia Scope → Host → Service → Technology/Signature)
- `GET /api/v1/clusters` → lista grup podobnych usług (po `favicon_mmh3`, `tech_stack`, `http_title`, `tls_issuer`)
- `GET /api/v1/events/stream` → SSE (`scan.progress`, `scan.chunk`, `scan.paused_window`, `scan.completed`, `change.detected`, `governor.throttle`, `scan.workers`, `scan.rechunk`, `schedule.fired`, `schedule.skipped`)

### Targets & Scan Profiles & Scan Runs
- `GET /api/v1/targets` | `POST /api/v1/targets` | `DELETE /api/v1/targets/:id`
- `POST /api/v1/targets/estimate` → `{targets[], exclusions[], ports, max_rate_pps, concurrency}` → `{total_ips, excluded_ips, effective_ips, recommended_chunk_size, chunk_count, estimated_seconds, fits_in_window}`
- `GET /api/v1/exclusions` | `POST /api/v1/exclusions` | `DELETE /api/v1/exclusions/:id`
- `GET /api/v1/profiles` | `POST /api/v1/profiles` | `PUT /api/v1/profiles/:id` | `DELETE /api/v1/profiles/:id`
- `GET /api/v1/profiles/:id` (`scans:read`) → profil + `schedule`
- `POST /api/v1/profiles/:id/run` (`scans:run`) → „Uruchom teraz”: `202` + `ScanRun` (`triggered_by` = użytkownik); `409 {error, active_run}` gdy profil ma aktywny przebieg (QUEUED/CALIBRATING/RUNNING/PAUSED_WINDOW/PAUSED_USER); `404` dla nieznanego profilu. Jeśli okno czasowe jest zamknięte, przebieg od razu przechodzi w `PAUSED_WINDOW` i startuje po otwarciu okna.
- **Harmonogram (cykliczne skany):** `schedule_cron` = 5-polowy cron (`min godz dzień-mies mies dzień-tyg`, także `@daily`/`@hourly`/…), liczony w strefie `timezone` profilu (DST-aware). Puste = tylko ręcznie. `POST`/`PUT /profiles` walidują cron, okno i strefę → `400 {"error": "invalid schedule_cron \"…\": …"}`.
  - Każdy profil w odpowiedziach `GET/POST/PUT /profiles*` ma dodatkowe pole (wsteczna kompatybilność: pola profilu bez zmian, `schedule` jest addytywne):
    `schedule: {scheduled, cron, timezone, cron_error?, next_slot_at?, next_run_at?, deferred_by_window, pending_catch_up, will_skip, last_fire_at?, last_skip_at?, last_skip_reason?, last_run?: RunRef, active_run?: RunRef}`, gdzie `RunRef = {id, name, status, triggered_by, started_at, finished_at?}`.
  - `next_slot_at` = najbliższy slot cron; `next_run_at` = faktyczny start (slot poza oknem → przesunięty na otwarcie okna, `deferred_by_window=true`). `pending_catch_up=true` gdy slot już minął (np. przestój serwera) i czeka na okno.
  - Reguły: jeden profil nigdy nie ma dwóch równoległych przebiegów, więc slot przy aktywnym przebiegu jest pomijany, a powód trafia do `last_skip_reason`. Przekroczenie okna → `PAUSED_WINDOW` z checkpointem chunków i wznowienie w kolejnym oknie. Po restarcie wszystkie przegapione sloty zwijają się do maks. jednego uruchomienia „catch-up” (z poszanowaniem okna). Przerwane restartem przebiegi `RUNNING` są parkowane jako `PAUSED_WINDOW` i wznawiane z checkpointu. Przebiegi z harmonogramu mają `triggered_by="scheduler"`.
- `GET /api/v1/scans` → lista przebiegów skanów (z metrykami i progress)
- `POST /api/v1/scans` → uruchomienie nowego skanu dla `profile_id` (lub konfiguracji ad-hoc)
- `GET /api/v1/scans/:id` → szczegóły skanu + lista `chunks[]` (Coverage Ledger). Każdy chunk ma dodatkowo `nmap_commands[]` (dokładne linie poleceń nmap: discovery, ewentualne re-probe, service scan; albo opis fallbacku pure-Go), `max_rate_pps` (udział chunka w globalnym `--max-rate`) i `worker` (slot równoległego workera). Chunk przerwany zamknięciem okna wraca do `PENDING` z `error="interrupted: scan window closed; …"`.
- `PUT /api/v1/scans/:id` → edycja metadanych/notatek skanu (działa niezależnie od statusu)
- `POST /api/v1/scans/:id/pause` | `POST /api/v1/scans/:id/resume` | `POST /api/v1/scans/:id/stop`
- `DELETE /api/v1/scans/:id`

### Hosts, Services & Preserved Overrides
- `GET /api/v1/hosts` → filtrowanie: `?q=&state=&tag=&min_score=&env=&has_admin=&page=&limit=`
- `GET /api/v1/hosts/:id` → pełny widok hosta (merged observed + overrides), usługi, historia obserwacji, Time-of-Day heatmap, `locked_fields`, ostatnie zmiany
- `PATCH /api/v1/hosts/:id/overrides` → zapis nadpisań pól hosta (`hostname`, `environment`, `owner`, `notes`, `tags`, `lifecycle_state`, `unlock_fields[]`). Nadpisania są zachowywane przy kolejnych skanach.
- `DELETE /api/v1/hosts/:id`
- `GET /api/v1/services` → lista usług z filtrami
- `PATCH /api/v1/services/:id/overrides` → nadpisania pól usługi (`service_name`, `product`, `version`, `http_title`, `notes`, `tags`, `triage_status`, `unlock_fields[]`)
- `GET /api/v1/services/:id/observations` → historia surowych dowodów (Evidence Receipts)

### Diff & Changes
- `GET /api/v1/changes` → lista zmian (`?scan_id=&severity=&type=&anomaly_only=`)
- `GET /api/v1/scans/diff?from=<scanA>&to=<scanB>` → pełne porównanie dwóch skanów: `{new_hosts, missing_hosts, new_services, closed_services, changed_services, time_anomalies, summary}`
- `POST /api/v1/changes/:id/acknowledge`

### Unified Manual Entry, Import & Export
- `POST /api/v1/ingest/manual` → formularz ręczny (host + usługi + HTTP/TLS/nagłówki/ciasteczka/notatki) → tworzy `scan_run(MANUAL)` i przepuszcza dane przez pełny pipeline
- `POST /api/v1/ingest/import` → upload `multipart/form-data` lub JSON body (`format: csv|json|nmap|scb|passive`, opcjonalne `scan_name`; findings.json z OWASP secureCodeBox jest wykrywany automatycznie także przy `json`) → tworzy `scan_run(IMPORT_*)` i przepuszcza dane przez pełny pipeline
- `GET /api/v1/export?format=json|csv|nmap|urls|ecs|scb&scan_id=&state=&tag=` → pobranie pliku (JSON, CSV, nmap XML, lista URL, ECS NDJSON, `scb` = findings.json OWASP secureCodeBox, zob. `docs/SECURECODEBOX.md`)

### Signatures Studio
- `GET /api/v1/signatures` | `POST /api/v1/signatures` | `PUT /api/v1/signatures/:id` | `DELETE /api/v1/signatures/:id`
- `POST /api/v1/signatures/validate` → walidacja bezpieczeństwa sygnatury (blokuje metody mutujące / próby logowania)
- `POST /api/v1/signatures/test` → retroaktywny playground: testuje definicję sygnatury na zapisanych obserwacjach z DB i zwraca dopasowania
- `POST /api/v1/signatures/import` | `GET /api/v1/signatures/export`

### DefectDojo v2 Integration
- `GET /api/v1/integrations/defectdojo` | `PUT /api/v1/integrations/defectdojo`
- `POST /api/v1/integrations/defectdojo/test` → weryfikacja połączenia z API v2
- `POST /api/v1/integrations/defectdojo/push-findings` → `{service_ids[], change_ids[], engagement_id, severity}`
- `POST /api/v1/integrations/defectdojo/push-nmap` → `{scan_run_id, engagement_id}`
- `GET /api/v1/integrations/defectdojo/history`
- `GET /api/v1/integrations/defectdojo/status` (`assets:read`) → header chip: `{configured, url, auto_push_nmap, auto_push_findings, sync, last_export?, login?}`. `login` is `{username, password}` of the DefectDojo account set in Admin, returned to every user who can read the chip; it is absent when none is set.
- `PUT /api/v1/integrations/defectdojo/login` (`admin:settings`) → `{username, password}` stores the login shown in the header chip (encrypted at rest); both fields are required, both empty clears it. Answers `{login}`.
- `DELETE /api/v1/integrations/defectdojo/login` (`admin:settings`) → clears the login, answers `{login: null}`.

### Admin: Users, Dynamic Roles, Crypto Proof & Audit
- `GET /api/v1/admin/users` | `POST /api/v1/admin/users` | `PUT /api/v1/admin/users/:id` | `DELETE /api/v1/admin/users/:id`
- `GET /api/v1/admin/roles` | `POST /api/v1/admin/roles` | `PUT /api/v1/admin/roles/:id` | `DELETE /api/v1/admin/roles/:id`
- `GET /api/v1/admin/permissions` → lista wszystkich dostępnych slugów uprawnień
- `GET /api/v1/admin/crypto/status` → status szyfrowania, wersja DEK, próbka dowodowa surowego ciphertextu z DB vs zdekryptowanego widoku (bez ujawniania klucza)
- `POST /api/v1/admin/crypto/rotate` → rotacja DEK (re-wrapping + re-szyfrowanie)
- `GET /api/v1/admin/audit` → dziennik audytowy

## 3. Konfiguracja silnika skanowania (zmienne środowiskowe)

Równoległość: chunki Coverage Ledger przetwarza N workerów (każdy = osobny proces nmap). N = min(`DZIECIOL_CHUNK_WORKERS` (domyślnie 4), `concurrency` profilu, `max_rate_pps`/20, liczba oczekujących chunków). Każdy proces dostaje `--max-rate = max_rate_pps / N`, więc suma nigdy nie przekracza limitu profilu. Rozmiar chunków jest korygowany w trakcie skanu na podstawie zmierzonej przepustowości (cel: `chunk_target_sec` na chunk).

Flagi nmap. Polityka bezpieczeństwa skanera nie pozwala dodać `--script`/`-sC`/`-A`/`-O`.

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `DZIECIOL_NMAP_PING_ICMP` | `true` | `-PE` w discovery |
| `DZIECIOL_NMAP_PING_SYN_PORTS` | `21,22,23,25,80,443,445,3389,8080,8443` | `-PS…` (+ porty z profilu); pusty = wyłączone |
| `DZIECIOL_NMAP_PING_ACK_PORTS` | `80,443` | `-PA…`; pusty = wyłączone |
| `DZIECIOL_NMAP_DISCOVERY_MAX_RETRIES` / `DZIECIOL_NMAP_DISCOVERY_HOST_TIMEOUT` | `1` / `20s` | `--max-retries` / `--host-timeout` dla `-sn` |
| `DZIECIOL_NMAP_MAX_RETRIES` / `DZIECIOL_NMAP_HOST_TIMEOUT` | `2` / `3m` | `--max-retries` / `--host-timeout` dla `-sT -sV` |
| `DZIECIOL_NMAP_VERSION_INTENSITY` | `5` | `--version-intensity` (0-9) |
| `DZIECIOL_NMAP_TIMING` | auto | `-T0…5`; auto = `-T4` gdy udział workera ≥ 200 pps, inaczej `-T3` |

Bez roota nmap automatycznie zamienia sondy `-PS/-PA` na `connect()`; gdy nmap jest niedostępny lub zawiedzie, używany jest fallback pure-Go (TCP connect + pasywny banner), opisany w `nmap_commands` chunka.
