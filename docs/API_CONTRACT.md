# AegisASI — Kontrakt API & RBAC (v1)

Wszystkie endpointy poza `/api/v1/health`, `/api/v1/auth/login` i `/api/v1/auth/demo-accounts` wymagają nagłówka `Authorization: Bearer <jwt>` (lub tokenu `?token=` dla strumienia SSE `/api/v1/events/stream`).

## 1. Role i Uprawnienia RBAC

### Predefiniowane role (seedowane przy starcie)
1. **`admin` („Administracja”):** wszystkie uprawnienia (`*`).
2. **`operator` („Dodawanie, usuwanie, modyfikacja”):** `dashboard:read`, `assets:read`, `assets:write`, `assets:delete`, `scans:read`, `scans:write`, `scans:delete`, `scans:run`, `signatures:read`, `signatures:write`, `signatures:delete`, `import:write`, `export:read`, `defectdojo:push`.
3. **`analyst` („Modyfikacja i odczyt”):** `dashboard:read`, `assets:read`, `assets:write`, `scans:read`, `scans:write`, `signatures:read`, `signatures:write`, `export:read`.
4. **`viewer` („Odczyt”):** `dashboard:read`, `assets:read`, `scans:read`, `signatures:read`, `export:read`.

### Konta demo (seedowane gdy `ASI_SEED_DEMO=true`)
- `admin` / `Admin123!` (Administracja)
- `operator` / `Operator123!` (Dodawanie, usuwanie, modyfikacja)
- `analyst` / `Analyst123!` (Modyfikacja i odczyt)
- `viewer` / `Viewer123!` (Odczyt)

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
- `GET /api/v1/events/stream` → SSE (`scan.progress`, `scan.chunk`, `scan.paused_window`, `scan.completed`, `change.detected`, `governor.throttle`)

### Targets & Scan Profiles & Scan Runs
- `GET /api/v1/targets` | `POST /api/v1/targets` | `DELETE /api/v1/targets/:id`
- `POST /api/v1/targets/estimate` → `{targets[], exclusions[], ports, max_rate_pps, concurrency}` → `{total_ips, excluded_ips, effective_ips, recommended_chunk_size, chunk_count, estimated_seconds, fits_in_window}`
- `GET /api/v1/exclusions` | `POST /api/v1/exclusions` | `DELETE /api/v1/exclusions/:id`
- `GET /api/v1/profiles` | `POST /api/v1/profiles` | `PUT /api/v1/profiles/:id` | `DELETE /api/v1/profiles/:id`
- `GET /api/v1/scans` → lista przebiegów skanów (z metrykami i progress)
- `POST /api/v1/scans` → uruchomienie nowego skanu dla `profile_id` (lub konfiguracji ad-hoc)
- `GET /api/v1/scans/:id` → szczegóły skanu + lista `chunks[]` (Coverage Ledger)
- `PUT /api/v1/scans/:id` → edycja metadanych/notatek skanu (działa niezależnie od statusu!)
- `POST /api/v1/scans/:id/pause` | `POST /api/v1/scans/:id/resume` | `POST /api/v1/scans/:id/stop`
- `DELETE /api/v1/scans/:id`

### Hosts, Services & Preserved Overrides
- `GET /api/v1/hosts` → filtrowanie: `?q=&state=&tag=&min_score=&env=&has_admin=&page=&limit=`
- `GET /api/v1/hosts/:id` → pełny widok hosta (merged observed + overrides), usługi, historia obserwacji, Time-of-Day heatmap, `locked_fields`, ostatnie zmiany
- `PATCH /api/v1/hosts/:id/overrides` → zapis nadpisań pól hosta (`hostname`, `environment`, `owner`, `notes`, `tags`, `lifecycle_state`, `unlock_fields[]`) — **zachowywane przy kolejnych skanach!**
- `DELETE /api/v1/hosts/:id`
- `GET /api/v1/services` → lista usług z filtrami
- `PATCH /api/v1/services/:id/overrides` → nadpisania pól usługi (`service_name`, `product`, `version`, `http_title`, `notes`, `tags`, `triage_status`, `unlock_fields[]`)
- `GET /api/v1/services/:id/observations` → historia surowych dowodów (Evidence Receipts)

### Diff & Changes
- `GET /api/v1/changes` → lista zmian (`?scan_id=&severity=&type=&anomaly_only=`)
- `GET /api/v1/scans/diff?from=<scanA>&to=<scanB>` → pełne porównanie dwóch skanów: `{new_hosts, missing_hosts, new_services, closed_services, changed_services, time_anomalies, summary}`
- `POST /api/v1/changes/:id/acknowledge`

### Unified Manual Entry, Import & Export
- `POST /api/v1/ingest/manual` → formularz ręczny (host + usługi + HTTP/TLS/nagłówki/ciasteczka/notatki) → tworzy `scan_run(MANUAL)` i przepuszcza przez pełny pipeline!
- `POST /api/v1/ingest/import` → upload `multipart/form-data` lub JSON body (`format: csv|json|passive`, opcjonalne `scan_name`) → tworzy `scan_run(IMPORT_*)` i przepuszcza przez pełny pipeline!
- `GET /api/v1/export?format=json|csv&scan_id=&state=&tag=` → pobranie pliku JSON lub CSV

### Signatures Studio
- `GET /api/v1/signatures` | `POST /api/v1/signatures` | `PUT /api/v1/signatures/:id` | `DELETE /api/v1/signatures/:id`
- `POST /api/v1/signatures/validate` → walidacja bezpieczeństwa sygnatury (blokuje metody mutujące / próby logowania)
- `POST /api/v1/signatures/test` → **Playground Retroaktywny** (testuje definicję sygnatury na zapisanych obserwacjach z DB i zwraca dopasowania!)
- `POST /api/v1/signatures/import` | `GET /api/v1/signatures/export`

### DefectDojo v2 Integration
- `GET /api/v1/integrations/defectdojo` | `PUT /api/v1/integrations/defectdojo`
- `POST /api/v1/integrations/defectdojo/test` → weryfikacja połączenia z API v2
- `POST /api/v1/integrations/defectdojo/push-findings` → `{service_ids[], change_ids[], engagement_id, severity}`
- `POST /api/v1/integrations/defectdojo/push-nmap` → `{scan_run_id, engagement_id}`
- `GET /api/v1/integrations/defectdojo/history`

### Admin: Users, Dynamic Roles, Crypto Proof & Audit
- `GET /api/v1/admin/users` | `POST /api/v1/admin/users` | `PUT /api/v1/admin/users/:id` | `DELETE /api/v1/admin/users/:id`
- `GET /api/v1/admin/roles` | `POST /api/v1/admin/roles` | `PUT /api/v1/admin/roles/:id` | `DELETE /api/v1/admin/roles/:id`
- `GET /api/v1/admin/permissions` → lista wszystkich dostępnych slugów uprawnień
- `GET /api/v1/admin/crypto/status` → status szyfrowania, wersja DEK, próbka dowodowa surowego ciphertextu z DB vs zdekryptowanego widoku (bez ujawniania klucza!)
- `POST /api/v1/admin/crypto/rotate` → rotacja DEK (re-wrapping + re-szyfrowanie)
- `GET /api/v1/admin/audit` → dziennik audytowy
