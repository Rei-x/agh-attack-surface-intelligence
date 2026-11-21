# Specyfikacja Techniczna i Strategia Wygranej: **AegisASI** (Attack Surface Intelligence dla CBI AGH)

> **Zadanie:** HackNation 2026 — `[Akademia Górniczo-Hutnicza] Attack Surface Intelligence`
> **Zamawiający:** Centrum Bezpieczeństwa Informacji AGH (CBI AGH)
> **Cel:** Zbudowanie produkcyjnego, lekkiego (Go + PostgreSQL + React/TS), bezpiecznego systemu ciągłego discovery i analizy zmian powierzchni ataku dla dużych sieci (10 000–65 536+ IP) z natywną integracją DefectDojo, dynamicznym RBAC i szyfrowaniem w spoczynku — gotowego do realnego wdrożenia w CBI AGH po hackathonie.

---

## 1. Strategia: Jak zdeklasować konkurencję?

### Analiza kryteriów oceny jury (100%)

| Kryterium | Waga | Co zrobi typowy zespół | Jak my wygrywamy 10/10 |
| :--- | :---: | :--- | :--- |
| **Discovery & identyfikacja usług w dużej sieci** | **30%** | Pythonowy wrapper na `nmap` dla małego zakresu, blokujący się przy >1000 IP, brak checkpointów. | **Silnik w Go** (rekomendowany w briefie!), 2-fazowe skanowanie, **kalibracja szybkości + adaptacyjny podział na chunki** (obsługa `/16` = 65 536 IP), **twarde okna czasowe z automatycznym Pause/Resume od dokładnego chunka**, estymacja ETA i liczby okien. |
| **Jakość techniczna, dokumentacja, prezentacja, import/eksport, DefectDojo** | **20%** | Mock DefectDojo, brak spójności między importem a skanem, trudne odpalenie. | `docker compose up -d` odpala cały stack w 15s; **prawdziwa integracja DefectDojo API v2** (zarówno `Nmap Scan` XML jak i selektywny eksport obserwacji/evidence jako Findings z deduplikacją); **zunifikowany pipeline** (dane ręczne/CSV/JSON przechodzą ten sam enrichment, diffing, scoring i szyfrowanie); pełne OpenAPI + README + 10-slajdowa prezentacja z live demo. |
| **Zmiany w czasie, hosty niestabilne, raportowanie** | **15%** | Prosty `diff(scan_n, scan_n-1)`, zalew fałszywych alarmów gdy host na chwilę zniknie. | **Odpowiadamy matematycznie na 3 kluczowe pytania z sekcji 1 zadania**: (1) Maszyna stanów hosta z histerezą i automatycznym re-probe dla hostów niestabilnych, (2) **Macierz dostępności wg pory dnia (Time-of-Day Heatmap)** odróżniająca normalny harmonogram od anomalii, (3) **Bayesowski Confidence Score (0–100%)** dla detekcji technologii + **Interestingness Score (0–100)** dla priorytetyzacji SOC. |
| **Bezpieczeństwo działania, kontrola intensywności, dashboard** | **15%** | Brak limitów ruchu, niejasne tabele. | **Safe-by-Design**: twarda whitelista portów, blacklista wykluczonych CIDR, globalny i per-host Token Bucket rate limiter, `--max-rate` Nmapa, wyłącznie bezpieczne żądania GET/HEAD bez prób logowania, Emergency Stop z zapisem stanu, pełny Audit Log + **czytelny SOC Dashboard** z grupowaniem podobnych usług i timeline zmian. |
| **Fingerprinting HTTP/HTTPS, technologie, CMS, nagłówki, ciasteczka, sygnatury** | **10%** | Tylko `Server` header i `<title>`. | Czysty, ultraszybki **fingerprinter w Go**: tytuł, pełny łańcuch przekierowań, nagłówki + analiza security headers, ciasteczka + flagi (`HttpOnly`/`Secure`/`SameSite`), pełny certyfikat TLS (SAN, Issuer, wygasanie, self-signed), **Favicon MurmurHash3 (kompatybilny z Shodan)**, stopka/wersja, CMS/framework/serwer/IoT/staging/admin panel + **kreator customowych sygnatur z walidatorem bezpieczeństwa i testowaniem retroaktywnym na zapisanych danych**. |
| **RBAC i szyfrowanie danych (Encryption At Rest)** | **10%** | Zahardkodowane `if is_admin`, plaintext w SQLite/Postgres. | **Dynamiczny RBAC** (4 wymagane role predefiniowane + tworzenie własnych ról i uprawnień w UI, wymuszane na poziomie API i UI) + **prawdziwe szyfrowanie pól wrażliwych AES-256-GCM (Envelope Encryption z AAD + rotacją kluczy)** w PostgreSQL z **widokiem/skryptem dowodowym `psql` dla jury** + **dwuwarstwowy model danych gwarantujący zachowanie ręcznych edycji przy kolejnych skanach**. |

---

## 2. Architektura Systemu

### Stack technologiczny (lekki, produkcyjny, w pełni Open Source)

* **Core Engine + API + Scheduler:** **Go 1.24+** (niskie zużycie RAM/CPU zgodnie z sekcją 5 zadania; natywna współbieżność na gorutynach; jedna statyczna binarka).
  * HTTP API: `chi` lub `net/http` (stdlib Go 1.22+ router) + OpenAPI/Swagger.
  * Skanowanie sieciowe: orkiestracja `nmap` (`-oX -` parsowane natywnie w Go) + natywny moduł Go dla HTTP/HTTPS/TLS/Favicon/DNS.
  * Rate limiting: `golang.org/x/time/rate` (token bucket globalny + per-host).
  * Szyfrowanie: `crypto/aes`, `crypto/cipher` (AES-256-GCM), `crypto/hmac` (blind indexes), `golang.org/x/crypto/argon2` (Argon2id dla haseł).
* **Baza danych:** **PostgreSQL 17** (Docker) — transakcyjność przy wielowątkowych zapisach, JSONB, pełne indeksowanie metadanych przy zaszyfrowanych kolumnach wrażliwych.
* **Frontend (SOC Dashboard):** **React 19 + TypeScript + Vite + Tailwind CSS + Recharts** (budowany statycznie i serwowany bezpośrednio z binarki Go przez `embed.FS` lub w osobnym lekkim kontenerze Nginx — zero zbędnych zależności w runtime!).
* **Deployment & Lab:**
  * `docker-compose.yml` — produkcyjny start (`aegis-asi` + `postgres` — 1 komenda).
  * `docker-compose.lab.yml` — deterministyczne środowisko laboratoryjne do testów i demo (symuluje WordPressa, panel admina, staging/dev, drukarkę IoT, host niestabilny/flapping, host zmieniający odpowiedź między skanem 1 a 2, oraz opcjonalny mock/instancję DefectDojo).

### Diagram architektury

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         SOC Web UI (React + TS)                              │
│  Dashboard │ Assets & Groups │ Scan Runs & Live Progress │ Diff & Timeline   │
│  Heatmap   │ Signatures      │ Manual Form & Import/Exp  │ RBAC & Audit      │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │ REST API + SSE (Live Progress)
┌───────────────────────────────────────▼──────────────────────────────────────┐
│                       AegisASI Core Server (Go)                              │
│                                                                              │
│  ┌─────────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐  │
│  │ Auth & Dynamic RBAC │  │  Crypto Vault Layer  │  │ DefectDojo v2 Sync  │  │
│  │ (JWT/Session, 4+    │  │  AES-256-GCM (AEAD)  │  │ • Nmap XML import   │  │
│  │  roles, Audit Log)  │  │  + Envelope KEK/DEK  │  │ • Curated Findings  │  │
│  └─────────────────────┘  └──────────────────────┘  └─────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                 Unified Ingestion & Processing Pipeline                 │ │
│  │  [Active Scanner] ─┐                                                    │ │
│  │  [Manual Form]    ─┼─► Normalize ─► Fingerprinter & Signatures ─► Diff  │ │
│  │  [CSV/JSON Import]─┤   & Validate    & Confidence Engine        & State │ │
│  │  [Passive Feeds]  ─┘                                            Machine │ │
│  │                         └─► Merge with Preserved Analyst Overrides ──┐  │ │
│  └──────────────────────────────────────────────────────────────────────┼──┘ │
│                                                                         │    │
│  ┌──────────────────────────────────────────────────────────────────────┼──┐ │
│  │                Scan Orchestrator & Window Scheduler                  │  │ │
│  │  Target Expander (IP/CIDR/Domain) ► Calibration & Adaptive Chunking  │  │ │
│  │  ► Time-Window Guard (Pause/Resume Checkpoint) ► Bounded Workers     │  │ │
│  │    • Stage 1: Safe Host Discovery (nmap -sn / TCP ping, rate-limited)│  │ │
│  │    • Stage 2: Service & Version Detection (nmap -sV -oX, allowed pts)│  │ │
│  │    • Stage 3: Go HTTP/HTTPS/TLS/Favicon/Path Fingerprinter (GET/HEAD)│  │ │
│  │    • Stage 4: Unstable Host Verification Re-Probe                    │  │ │
│  └──────────────────────────────────────────────────────────────────────┼──┘ │
└─────────────────────────────────────────────────────────────────────────┼────┘
                                                                          ▼
                                                     ┌─────────────────────────┐
                                                     │     PostgreSQL 17       │
                                                     │ (Encrypted At Rest cols │
                                                     │  + Blind Indexes + JSON)│
                                                     └─────────────────────────┘
```

---

## 3. Rozwiązanie 5 najtrudniejszych problemów z briefu (Nasze "Killer Features")

### 3.1. Skala 10 000–65 536+ IP: Adaptacyjny podział na podgrupy, estymacja czasu i okna czasowe (Pause/Resume)

Brief wymaga tego wprost dwukrotnie (sekcja 2 i 3). Zamiast wrzucać cały `/16` do jednego procesu `nmap`:

1. **Target Normalization & Safety Filter:**
   * Akceptuje pojedyncze IP, zakresy (`10.0.1.1-10.0.1.50`), CIDR (`10.0.0.0/16`), domeny (z bezpieczną rezolucją DNS A/AAAA i zapamiętaniem mapowania `domain -> IP` dla nagłówka `Host` i TLS SNI!).
   * Deduplikuje nakładające się zakresy i **twardo wycina adresy z globalnej listy wykluczeń (Exclusions)** przed utworzeniem choćby jednego zadania.
2. **Kalibracja i Adaptacyjny Chunking:**
   * Przed uruchomieniem właściwego skanu (lub na pierwszym chunku próbkowym, np. 64 IP) system mierzy realny throughput `R` (hosty/s i usługi/s) w danym środowisku sieciowym i dla zadanego limitu `--max-rate`.
   * Wylicza **optymalny rozmiar podgrupy (chunk size)** wg wzoru:
     $$\text{chunk\_size} = \text{clamp}\left(\lfloor R \times T_{\text{target}} \rfloor,\; 32,\; 512\right)$$
     gdzie $T_{\text{target}} \approx 45\text{–}90\text{s}$ na chunk. Dzięki temu:
     * UI pokazuje płynny, dokładny pasek postępu i **realistyczne ETA** (`Pozostało: 14m 20s | Prędkość: 185 IP/s | Chunk 42/256`),
     * zatrzymanie na granicy okna czasowego marnuje maksymalnie kilkanaście sekund pracy.
   * Każdy chunk ma własny rekord w bazie (`scan_chunks`: `PENDING`, `RUNNING`, `DONE`, `PAUSED`, `FAILED`) — odporność na restart procesu/kontenera!
3. **Harmonogram i Okna Czasowe (Time Window Enforcement):**
   * Każdy profil skanu definiuje:
     * **Częstotliwość (Cron / interwał)**, np. co 6 godzin lub codziennie o 22:00,
     * **Dozwolone okno czasowe**, np. `22:00–06:00` (obsługa okien przechodzących przez północ!) oraz strefę czasową (`Europe/Warsaw`).
   * Scheduler w trakcie skanu stale monitoruje zegar okna:
     * Jeśli zbliża się koniec okna (`now >= window_end`), worker **nie pobiera nowych chunków**, bezpiecznie kończy/anuluje aktywne przez `context.Context`, ustawia stan skanu na **`PAUSED_WINDOW`** i zapisuje dokładny kursor.
     * Gdy otwiera się kolejne okno czasowe, scheduler **automatycznie wznawia ten sam `scan_run`** od pierwszego nieukończonego chunka (stan `RUNNING` -> po zakończeniu `COMPLETED`), zamiast zaczynać od zera!
   * W UI można to zaprezentować na żywo (np. ustawiając okno 30-sekundowe na demo, obserwując automatyczne zatrzymanie w połowie chunków i automatyczne wznowienie w kolejnym oknie!).

---

### 3.2. Odpowiedź na 3 pytania merytoryczne CBI AGH (Intelligence Engine)

W sekcji 1 mentorzy zadali 3 konkretne pytania badawcze. Nasz system odpowiada na każde z nich wprost, konfigurowalnie i transparentnie:

#### Pytanie A: *"Po jakim czasie braku odpowiedzi w sukcesywnych skanach raportować host jako nieaktywny?"*
Zamiast binarnego `UP/DOWN` wdrażamy **Maszynę Stanów Hosta z Histerezą i Re-probingiem**:
* `NEW` — wykryty po raz pierwszy.
* `ACTIVE` — odpowiada stabilnie.
* `INTERMITTENT` (Niestabilny / Okresowy) — w oknie ostatnich $W$ skanów (domyślnie $W=10$) współczynnik obecności wynosi $0.15 < p < 0.85$ lub wystąpiły $\ge 2$ przejścia UP↔DOWN.
* `MISSING` (Okres karencji / Grace Period) — host nie odpowiedział w $1 \dots (K-1)$ kolejnych skanach (domyślnie $K=3$). **Automatycznie uruchamiany jest Stage 4 (Verification Re-Probe)** — ponowienie sondy z lekkim opóźnieniem i alternatywną metodą detekcji, zanim raportujemy problem!
* `INACTIVE` — host nie odpowiedział w **$K$ kolejnych skanach ORAZ minął minimalny czas karencji $T_{\text{grace}}$** (domyślnie: `missed_scans >= 3 AND elapsed >= 24h`, w pełni konfigurowalne per profil skanu — np. dla labu testowego `K=2, T=0m`). Dopiero wtedy emitowane jest zdarzenie `HOST_INACTIVE`.
* `REACTIVATED` — host oznaczony jako `INACTIVE` ponownie się odezwał (wysoki priorytet analityczny!).

#### Pytanie B: *"W jaki sposób raportować zmianę (szczególnie przy różnicach zależnych od pory dnia)?"*
* **Strukturalny Silnik Diff (Scan A vs Scan B oraz Scan vs Baseline):**
  * Każda zmiana to osobny, filtrowalny `ChangeEvent` z `severity`, `category`, `before`, `after`, `timestamp`:
    * Hosty: `HOST_NEW`, `HOST_INACTIVE`, `HOST_REACTIVATED`, `HOST_FLAPPING`
    * Porty/Usługi: `PORT_OPENED`, `PORT_CLOSED`, `SERVICE_CHANGED`, `BANNER_CHANGED`
    * HTTP/TLS: `HTTP_STATUS_CHANGED`, `HTTP_TITLE_CHANGED`, `HEADER_ADDED/CHANGED`, `COOKIE_ADDED/CHANGED`, `TLS_CERT_CHANGED`, `TLS_EXPIRING_SOON`
    * Technologie/Sygnatury: `TECH_DETECTED`, `TECH_VERSION_CHANGED`, `SIGNATURE_MATCHED`, `SIGNATURE_LOST`
* **Wykrywanie wzorców pory dnia (Time-of-Day Availability Matrix):**
  * Każda obserwacja zapisuje `time_slot` (4 sloty: `00-06 Noc`, `06-12 Rano`, `12-18 Popołudnie`, `18-24 Wieczór` + dokładna godzina `0-23`).
  * System buduje dla każdego hosta/usługi profil dostępności per slot (wizualizowany w UI jako **Heatmap 24h / 4-slotowa**).
  * Jeśli host historycznie żyje w godzinach `08:00–16:00` (>80% obecności) i jest wyłączony w nocy (<10%), brak odpowiedzi o `02:00` jest klasyfikowany jako **`EXPECTED_OFF_HOURS` (tłumienie szumu!)**, natomiast pojawienie się usługi o `02:00` lub zmiana odpowiedzi HTTP względem tego samego slotu czasowego jest oznaczana jako **`TIME_ANOMALY` (wysoki priorytet!)**.

#### Pytanie C: *"Jak określić pewność wyniku identyfikacji technologii?"*
* **Wielosygnałowy Model Pewności (Noisy-OR Confidence Fusion, 0–100%):**
  Każda reguła/sygnatura ma wagę wiarygodności $w_i \in (0, 1]$, np.:
  * Favicon MurmurHash3 exact match: `0.85`
  * Charakterystyczny fragment HTML / meta generator / endpoint wersji: `0.70`
  * Specyficzne ciasteczko (np. `wordpress_logged_in`, `JSESSIONID`, `grafana_session`): `0.55`
  * Nagłówek HTTP (`X-Powered-By`, `Server`, `X-Generator`): `0.45`
  * Baner Nmap / CPE / certyfikat TLS: `0.50`
  Łączna pewność dla technologii $T$ ze zbioru dopasowanych sygnałów $E$:
  $$C_{\text{base}}(T) = 1 - \prod_{i \in E} (1 - w_i)$$
  Do tego **czynnik stabilności czasowej**: jeśli technologia potwierdza się w kolejnych skanach, pewność rośnie (maks. +10 pp, cap 99%); jeśli sygnały są sprzeczne (np. nagłówek mówi Apache, a struktura wskazuje Nginx/proxy), pewność jest korygowana i oznaczana flagą `behind_proxy / conflicting_signals`.
  * W UI analityk widzi nie tylko `WordPress 6.4 (94%)`, ale po najechaniu/kliknięciu **dokładny rozkład dowodów (evidence breakdown)** dlaczego system dał 94%!

#### Bonus: Ocena „ciekawości” / Priorytetu Analitycznego (`Interestingness Score`, 0–100)
Deterministyczny, przejrzysty scoring pomagający SOC od razu trafić w najważniejsze znaleziska:
* `+30` — wykryty panel administracyjny (`/admin`, `/wp-admin`, phpMyAdmin, Grafana, Jenkins, IPMI/iDRAC)
* `+25` — wykryte środowisko `dev` / `staging` / `test` lub tryb debug (Werkzeug/Django/Symfony debug, `X-Debug-Token`)
* `+20` — nowa, niezweryfikowana usługa lub host `REACTIVATED` / `TIME_ANOMALY`
* `+15` — dopasowanie customowej sygnatury o wysokim priorytecie
* `+15` — nieaktualna / przestarzała wersja CMS/serwera lub brak podstawowych security headers / ciasteczko sesyjne bez `HttpOnly`/`Secure`
* `+10` — certyfikat TLS wygasły, wygasający (<14 dni) lub self-signed na porcie publicznym
* `+10` — urządzenie IoT / nietypowy baner / usługa HTTP na niestandardowym porcie

---

### 3.3. Bezpieczny Fingerprinter HTTP/HTTPS + Silnik Customowych Sygnatur

#### Zbierane artefakty HTTP/HTTPS (dla każdej usługi HTTP/HTTPS wykrytej na dowolnym porcie):
* Kod statusu HTTP + pełny łańcuch przekierowań (`hops: [{url, status}]`, limit max 5 przekierowań),
* Tytuł strony (`<title>`), `meta[name=generator]`, wykrywanie wersji w stopce (`<footer>` / regexy wersji),
* Wszystkie nagłówki odpowiedzi + automatyczne flagowanie ciekawych nagłówków (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-*`, `WWW-Authenticate`, `Via`, brak `HSTS`/`CSP`/`X-Frame-Options`),
* Wszystkie ciasteczka (`Set-Cookie`: nazwa, flagi `HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain` — **bez przechowywania wrażliwych wartości w plaintekście w DB — szyfrowane AES-256-GCM!**),
* Certyfikat TLS: Subject CN, Issuer, SANs (dodatkowe domeny!), NotBefore, NotAfter, `days_to_expiry`, `is_self_signed`, wersja TLS (flagowanie TLS 1.0/1.1!), SHA-256 fingerprint,
* **Favicon Hash:** pobranie `/favicon.ico` (lub z `<link rel="icon">`), wyliczenie **MurmurHash3 (Shodan format)** oraz SHA-256,
* Bezpieczne sondowanie ścieżek z sygnatur (np. `/login`, `/admin`, `/version`, `/robots.txt`, `/wp-login.php`) — **wyłącznie GET/HEAD**, nigdy POST, nigdy próby logowania, limit rozmiaru body (np. 256 KB), konfigurowalny identyfikowalny `User-Agent` (np. `CBI-AGH-ASI/1.0`).

#### Silnik Customowych Sygnatur (YAML/JSON + UI Builder):
* **Walidator bezpieczeństwa (Safety Guard):** odrzuca przy zapisie każdą sygnaturę próbującą użyć metod innych niż `GET`/`HEAD`, parametrów autoryzacyjnych, path traversalu czy niebezpiecznych payloadów — gwarancja zgodności z wymogiem *"służyć wyłącznie bezpiecznej detekcji, a nie eksploatacji"*.
* Obsługiwane typy dopasowań (łączone przez `match_mode: any | all`):
  * `header` (nazwa + regex/contains)
  * `cookie` (nazwa + regex/flagi)
  * `favicon_mmh3` / `favicon_sha256`
  * `html_body` / `footer_version` (substring / regex z grupą przechwytującą wersję `version_group`)
  * `safe_path` (ścieżka `/admin`, `/login`, `/version` + oczekiwany status/body)
  * `tls_cert` (subject / issuer / SAN regex)
  * `nmap_service` / `banner` / `port`
* **Retroactive Signature Playground:** przycisk *"Przetestuj na istniejących danych"* w UI natychmiast uruchamia nową sygnaturę na zapisanych obserwacjach z bazy i pokazuje trafienia bez konieczności ponownego skanowania sieci!
* **Import/Export paczek sygnatur (YAML/JSON)** — natychmiastowa kompatybilność z zestawem przykładowych sygnatur od AGH z Discorda!
* **Wbudowany zestaw startowy (~40–60 wysokiej jakości sygnatur):** WordPress, Drupal, Joomla, Moodle (kluczowe na uczelni!), MediaWiki, Next.js, React, Angular, Django, Flask, Laravel, Spring Boot, ASP.NET, Nginx, Apache, IIS, Tomcat, Grafana, Jenkins, GitLab, Keycloak, phpMyAdmin, Adminer, Zabbix, Portainer, Roundcube, Prometheus, urządzenia IoT (HP/Canon/Brother printers, Hikvision, MikroTik, Synology, iDRAC/iLO), detektory Staging/Dev/Debug oraz detektory Paneli Admina.

---

### 3.4. Dwuwarstwowy Model Danych (Zachowanie Edycji) + Dynamiczny RBAC + Szyfrowanie At Rest

#### Zachowanie edycji użytkownika przy kolejnych skanach (Wymóg #14 — KRYTYCZNY!)
Rozdzielamy ściśle dwie warstwy danych:
1. **Warstwa Obserwacji (`scan_observations` / `host_latest_observed`):** zapisywana przez skaner i importer przy każdym skanie. Stanowi niezmienny dowód historyczny.
2. **Warstwa Kuratorska / Nadpisań (`asset_overrides`):** edytowana przez uprawnionych użytkowników **niezależnie od stanu skanu** (`RUNNING`, `PAUSED`, `COMPLETED`, `IMPORTED`). Przechowuje mapę nadpisanych pól (np. `hostname`, `os_guess`, `environment`, `owner`, `notes`, `tags`, `service_name`, `product`, `version`, `http_title`, `status`, `custom_technologies`) wraz z `locked_fields`, `updated_by`, `updated_at`.
3. **Widok Efektywny (Merged View):** API i UI zawsze łączą `observed` + `overrides` (override wygrywa dla zablokowanych pól). Gdy kolejny skan wykryje inną wartość na nadpisanym polu, **nie nadpisuje edycji użytkownika**, ale zapisuje surową obserwację i wyświetla subtelną plakietkę *"Zablokowane przez analityka (skaner widzi: X)"* z opcją odblokowania jednym kliknięciem.

#### Zunifikowany Import Ręczny / CSV / JSON (Wymóg #11 — KRYTYCZNY!)
* Formularz ręczny w UI (dodanie hosta + usług + opcjonalnych danych HTTP/nagłówków/ciasteczek/notatek) ORAZ upload pliku **CSV / JSON** (z podglądem mapowania kolumn — łatwo dopasujemy się 1:1 do przykładowego formatu z Discorda AGH!).
* **Kluczowe:** zaimportowane / wprowadzone ręcznie rekordy tworzą normalny `scan_run` typu `MANUAL` lub `IMPORT_CSV` / `IMPORT_JSON` i **przechodzą przez ten sam pipeline**:
  * dopasowanie sygnatur i detekcja technologii + scoring,
  * porównanie (diff) z poprzednimi skanami i aktualizacja maszyny stanów hosta,
  * szyfrowanie pól wrażliwych w bazie,
  * pełna edytowalność z zachowaniem zmian przy kolejnych skanach,
  * eksport do CSV/JSON i wysyłka do DefectDojo!

#### Dynamiczny RBAC (Wymogi #12, #13, #15)
Model `users` ↔ `roles` ↔ `permissions` (możliwość tworzenia nowych ról i edycji macierzy uprawnień przez Admina!).

Predefiniowane 4 role z briefu:

| Rola (PL) | Slug | Odczyt & Dashboard | Edycja wyników/notatek/tagów | Dodawanie / Usuwanie / Skanowanie / Import / Sygnatury / DefectDojo | Administracja (Użytkownicy, Role, Ustawienia, Szyfrowanie, Audit) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Administracja** | `admin` | ✅ | ✅ | ✅ | ✅ |
| **Dodawanie, usuwanie, modyfikacja** | `operator` | ✅ | ✅ | ✅ | ❌ |
| **Modyfikacja i odczyt** | `analyst` | ✅ | ✅ | ❌ (tylko edycja istniejących wyników/konfiguracji, bez usuwania i dodawania nowych zasobów) | ❌ |
| **Odczyt** | `viewer` | ✅ | ❌ | ❌ | ❌ |

* **Egzekwowanie:** middleware na KAŻDYM endpoincie REST (zwraca `403 Forbidden` + zapis w Audit Logu) ORAZ adaptacyjny UI (przyciski/formularze ukryte lub w trybie read-only zgodnie z uprawnieniami roli).
* **Ułatwienie dla jury:** 4 gotowe konta testowe + czytelny panel informacyjny na ekranie logowania (w trybie demo), pozwalający w 5 sekund przelogować się między wszystkimi 4 rolami i sprawdzić ograniczenia!

#### Szyfrowanie danych w spoczynku — Encryption At Rest (Wymóg #16)
* **Envelope Encryption (AES-256-GCM AEAD):**
  * Master Key (KEK) ładowany ze zmiennej środowiskowej / pliku klucza poza bazą (`ASI_MASTER_KEY`).
  * Data Encryption Key (DEK) wersjonowany (`key_version`), szyfrowany przez KEK — gotowość na rotację kluczy (`POST /api/v1/admin/crypto/rotate`).
  * Każda szyfrowana wartość zapisywana w formacie `enc:v1:<kid>:<base64(nonce|ciphertext|tag)>` z **AAD = `table:record_id:column_name`** (uniemożliwia podmianę zaszyfrowanej wartości między wierszami w bazie!).
  * **Wszystkie pola wrażliwe szyfrowane at-rest:**
    * Adresy IP i domeny docelowe (z towarzyszącym **HMAC-SHA256 blind index** do szybkiego wyszukiwania/deduplikacji bez ujawniania plaintekstu w indeksie!),
    * Nagłówki HTTP, ciasteczka (`Set-Cookie`), tytuły stron, fragmenty HTML, łańcuchy przekierowań,
    * Certyfikaty TLS (CN, SAN, Issuer), banery usług Nmap, surowy XML Nmapa,
    * Notatki analityków, ręczne nadpisania (`asset_overrides`),
    * Token API DefectDojo, dane konfiguracji zewnętrznych integracji, e-maile użytkowników.
  * Hasła użytkowników: **Argon2id** (salted).
  * **Dowód dla jury:** dedykowany skrypt `./scripts/verify_encryption.sh` (oraz zakładka w panelu Admina *"Encryption Status & Proof"*) pokazujący surowy odczyt kolumn z PostgreSQL (`enc:v1:...`) obok zdekryptowanego widoku w aplikacji!

---

### 3.5. Prawdziwa Integracja z DefectDojo API v2

Zgodnie z dokumentacją `https://demo.defectdojo.org/api/v2/oa3/swagger-ui/`:
1. **Konfiguracja w UI (Admin):** URL instancji DefectDojo, Token API (`Token <key>`, szyfrowany at-rest), wybór/wyszukanie `Product` i `Engagement` + przycisk *"Test Connection"* (`GET /api/v2/users/` lub `/api/v2/engagements/`).
2. **Tryb 1 — Import surowego skanu Nmap:** wysyłka `multipart/form-data` do `POST /api/v2/import-scan/` z `scan_type="Nmap Scan"` i wygenerowanym XML-em z naszego skanu.
3. **Tryb 2 — Selektywny eksport obserwacji / znalezisk jako Info/Low/Medium Findings z Evidence:**
   * Analityk zaznacza wybrane usługi, dopasowania sygnatur lub zmiany (Diff Events) w UI i klika **"Wyślij do DefectDojo"**.
   * System wysyła finding przez `POST /api/v2/findings/` (lub `Generic Findings Import` przez `/api/v2/import-scan/`) z:
     * tytułem, opisem, pełnymi dowodami (nagłówki, ciasteczka, certyfikat TLS, dopasowana sygnatura, Confidence Score, Interestingness Score, historia zmian),
     * przypisanym endpointem (`host:port`), tagami (`aegis-asi`, `staging`, `admin-panel`, itd.),
     * deterministycznym `unique_id_from_tool` zapobiegającym duplikatom w DefectDojo!
   * Zapisujemy `defectdojo_finding_id` i `pushed_at` w bazie — w UI widać link bezpośredni do utworzonego findingu w DefectDojo!

---

## 4. Model Danych (PostgreSQL — główne encje)

* `users`, `roles`, `role_permissions`, `audit_logs` — autentykacja, dynamiczny RBAC, ślad audytowy.
* `targets` — zaimportowane cele (IP/CIDR/domena), wykluczenia (`target_exclusions`), tagi.
* `scan_profiles` — konfiguracja skanu: dozwolone porty, rate limits (`max_rate_pps`, `http_rps`, `concurrency`), harmonogram cron, **okno czasowe (`window_start`, `window_end`, `timezone`)**, progi niestabilności (`missing_threshold_scans`, `grace_period_hours`, `retry_count`), User-Agent.
* `scan_runs` — konkretne przebiegi skanów (typ: `ACTIVE`, `MANUAL`, `IMPORT_CSV`, `IMPORT_JSON`, `PASSIVE`), status (`QUEUED`, `CALIBRATING`, `RUNNING`, `PAUSED_WINDOW`, `PAUSED_USER`, `COMPLETED`, `FAILED`), statystyki szybkości, ETA, czas trwania, zaszyfrowany surowy Nmap XML.
* `scan_chunks` — podgrupy IP dla danego `scan_run` (zakres, liczba IP, status, czas trwania, checkpoint wznowienia).
* `hosts` — unikalne hosty (`ip_blind_idx`, zaszyfrowany `ip_enc`, `hostname_enc`, `lifecycle_state`, `first_seen`, `last_seen`, `consecutive_misses`, `stability_score`, `interestingness_score`, `time_of_day_stats` JSONB, `tags`).
* `services` — aktualny stan usług na hoście (`host_id`, `port`, `protocol`, `state`, zaszyfrowane `service_enc`, `product_enc`, `version_enc`, `banner_enc`, `http_fingerprint_enc`, `tls_cert_enc`, `favicon_mmh3`, `technologies_json_enc` z confidence, `cluster_key`, `interestingness_score`, `tags`).
* `scan_observations` — niezmienna historia obserwacji `(scan_run_id, host_id, service_id, observed_at, time_slot, raw_payload_enc)` — napędza porównywanie dowolnych dwóch skanów, timeline i macierz pory dnia!
* `asset_overrides` — warstwa ręcznych edycji analityka (`entity_type: host|service|scan_run`, `entity_id`, `overrides_enc`, `locked_fields`, `updated_by`, `updated_at`) — **nigdy nie nadpisywana przez skaner!**
* `change_events` — wykryte zmiany między skanami (`scan_run_id`, `prev_scan_run_id`, `host_id`, `service_id`, `event_type`, `severity`, `is_expected_schedule`, `before_enc`, `after_enc`, `acknowledged_by`).
* `signatures` — wbudowane i własne sygnatury detekcyjne (reguły JSONB, `weight`, `category`, `is_builtin`, `enabled`, walidowane pod kątem bezpieczeństwa).
* `defectdojo_exports` — historia wysyłek do DefectDojo (ID findingu, typ, status, timestamp).

---

## 5. Kluczowe Widoki UI (Dashboard SOC)

Projektujemy interfejs czysty, responsywny (dark/light mode, styl nowoczesnego narzędzia SecOps typu Wiz / Shodan / Nuclei Cloud), z naciskiem na **czytelność w trakcie 5-minutowego demo**:

1. **Główny Dashboard (Executive + SOC Overview):**
   * Karty KPI: Całkowity zakres IP, Aktywne hosty, Hosty niestabilne / okresowe, Wykryte usługi, Zmiany od ostatniego skanu, Krytyczne / Ciekawe znaleziska.
   * **Baner aktywnego skanu na żywo (SSE):** pasek postępu po chunkach, aktualna prędkość (IP/s), ETA, status okna czasowego (`W oknie: pozostało 02:14:00`), przyciski Pause / Resume / Emergency Stop.
   * **Wykres zmian w czasie (Timeline):** aktywne hosty, usługi i wykryte delty w kolejnych skanach.
   * **Top „Ciekawe znaleziska” (Interestingness Leaderboard):** np. wystawiony `/admin`, środowisko `staging`, wygasający certyfikat TLS, nieoczekiwana anomalia nocna — z szybkim przyciskiem *"Wyślij do DefectDojo"*.
2. **Zasoby (Hosts & Services) + Grupowanie Podobnych Usług:**
   * Tabela z wyszukiwaniem, filtrami po stanie (`NEW`, `ACTIVE`, `INTERMITTENT`, `MISSING`, `INACTIVE`), technologii, tagach, `interestingness_score`, środowisku (`staging`/`admin`).
   * Przełącznik widoku **"Grupuj podobne usługi"** (klastry wg Favicon MMH3, stosu technologicznego, tytułu HTTP lub wystawcy TLS — od razu widać np. *"12 identycznych instancji WordPress"*).
   * **Panel szczegółów hosta/usługi (Drawer):**
     * Pełny fingerprint HTTP (tytuł, status, przekierowania, nagłówki, analiza flag ciasteczek, certyfikat TLS, favicon),
     * Technologie z paskiem **Confidence %** i rozbiciem na dowody,
     * **Time-of-Day Availability Heatmap** (kiedy host odpowiada w ciągu doby),
     * **Edycja inline (Override Editor):** edycja dowolnych pól, tagów i notatek (dostępna również podczas trwania skanu!), z wizualnym znacznikiem kłódki *"Zachowane przed nadpisaniem"*.
3. **Porównanie Skanów (Diff Viewer):**
   * Wybór dowolnych dwóch skanów (`Scan A` vs `Scan B`) — czytelny podział na: **Nowe**, **Znikające / Nieaktywne**, **Zmienione** (z widokiem before → after) oraz **Anomalie pory dnia vs oczekiwany harmonogram**.
4. **Skaner, Profile i Import/Eksport:**
   * Formularz konfiguracji celu (IP/CIDR/domena) z kalkulatorem liczby IP i **symulacją podziału na podgrupy i czasu skanu**,
   * Konfiguracja harmonogramu, okna czasowego, dozwolonych portów, limitów ruchu i progów niestabilności,
   * **Formularz ręcznego dodawania danych** + **Import CSV/JSON** (przechodzący przez ten sam silnik analizy!) + **Eksport CSV/JSON** z aktywnymi filtrami.
5. **Sygnatury Detekcyjne (Signature Studio):**
   * Lista wbudowanych + własnych sygnatur, prosty kreator wizualny + edytor YAML/JSON,
   * **Walidator bezpieczeństwa** (na żywo sprawdza brak prób logowania / metod mutujących),
   * **Przycisk "Testuj na obecnych danych"** — natychmiastowe wyniki dopasowań!
6. **Integracja DefectDojo & Administracja (RBAC, Szyfrowanie, Audit Log):**
   * Zarządzanie użytkownikami i **dynamicznymi rolami** (tworzenie nowych ról z macierzą uprawnień),
   * Panel konfiguracji DefectDojo + historia eksportów,
   * Panel **Encryption At Rest** (status klucza, wersja, przycisk rotacji klucza, podgląd dowodowy zaszyfrowanych kolumn),
   * Dziennik audytowy (kto, kiedy, co zmienił lub zeskanował).

---

## 6. Plan Realizacji Hackathonowej (Fazy)

| Faza | Zakres | Cel / Kamień milowy |
| :--- | :--- | :--- |
| **Faza 0: Sync z AGH (teraz)** | Pobranie zasobów z Discorda AGH (środowisko Docker, dozwolone porty, format JSON/CSV, przykładowe sygnatury, testowe DefectDojo). | Dopasowanie schematu importu/eksportu, portów i sygnatur 1:1 do środowiska walidacyjnego jury! |
| **Faza 1: Fundamenty (Backend + DB + Crypto + RBAC)** | Szkielet Go, PostgreSQL + migracje, warstwa szyfrowania AES-256-GCM + blind index, dynamiczny RBAC (4 role + custom), Audit Log, `docker-compose.yml`. | Działające API z autoryzacją, rolami i udowodnionym szyfrowaniem w DB. |
| **Faza 2: Silnik Skanowania + Fingerprinting + Sygnatury** | Target expander (10k+ IP), kalibracja + adaptacyjny chunking, Time-Window scheduler z Pause/Resume, 2-fazowy Nmap + Go HTTP/HTTPS/TLS/Favicon fingerprinter, silnik sygnatur z walidatorem bezpieczeństwa i wbudowaną bazą reguł. | Bezpieczny, wielowątkowy skan przechodzący na labie Dockerowym z realnym wykrywaniem CMS/admin/staging/IoT. |
| **Faza 3: Intelligence Engine (Diff, Stabilność, Overrides, Import/Export, DefectDojo)** | Maszyna stanów hosta + Re-probe, Time-of-Day Heatmap, Confidence & Interestingness scoring, warstwa `asset_overrides` (zachowywana między skanami!), zunifikowany import ręczny/CSV/JSON, eksport CSV/JSON, pełna integracja DefectDojo API v2. | Przejście pełnego scenariusza 2+ skanów na labie ze zmianami, flappingiem, edycją w locie i wysyłką do DefectDojo. |
| **Faza 4: SOC Dashboard UI (React + TS)** | Wszystkie 6 widoków z Live SSE progress, Diff Viewer, Heatmap, Grouping, Signature Studio z playgroundem, RBAC UI, Demo Role Switcher. | Kompletny, piękny i intuicyjny interfejs. |
| **Faza 5: Testy, Lab Demo, Dokumentacja & Slajdy** | Testy automatyczne (w tym test skalowalności na 16 384 IP, test pause/resume okna, test preservation of edits, test RBAC 403, test szyfrowania), `README.md` + docs techniczne, prezentacja <=10 slajdów + próba generalna live demo. | 100% pewności na prezentacji przed jury. |

---

## 7. Checklist: O co zapytać mentorów / co pobrać z Discorda AGH (Sekcja 7 briefu)

Zgodnie z sekcją 7 briefu, na Discordzie lub stanowisku AGH powinny być (lub pojawią się) kluczowe zasoby. **Zanim zakodujemy dokładne parsery i domyślne profile, sprawdźmy i pobierzmy:**
1. **Konfiguracja kontenerów środowiska testowego** (Docker Compose / sieć labowa).
2. **Lista dozwolonych portów** oraz **opis limitów ruchu / zasad bezpiecznego skanowania** (np. max PPS / RPS).
3. **Przykładowy format eksportu/importu JSON i CSV** — zrobimy nasz format domyślnie w 100% kompatybilny z ich wzorcem!
4. **Zestaw przykładowych sygnatur** — nasz parser sygnatur będzie w stanie załadować ich plik bez przeróbek!
5. **Przykładowy zbiór wyników referencyjnych** i opcjonalna lista „ciekawych artefaktów”.
6. **Czy jest wystawiona testowa instancja DefectDojo** (URL + klucz API) — jeśli nie, postawimy lokalny kontener / mock zgodny 1:1 z OpenAPI DefectDojo v2 lub przetestujemy przeciwko `demo.defectdojo.org`!
7. **Szybkie pytanie do mentorów (buduje świetne wrażenie na starcie!):**
   * *"Czy planujecie docelowo uruchamiać to jako Docker Compose na serwerze w CBI AGH z PostgreSQL, czy też w klastrze Kubernetes (jak SecureCodeBox)?"*
   * *"Czy przy szyfrowaniu At Rest preferujecie szyfrowanie kolumn wrażliwych w aplikacji (AEAD AES-256-GCM z kluczem poza bazą) tak, aby nawet zrzut bazy `pg_dump` był nieczytelny?"* (Odpowiedź prawie na pewno: TAK — a to dokładnie nasza architektura!)

---

## 8. Plan 10-slajdowej prezentacji dla Jury

1. **Tytuł & Problem:** Dlaczego jednorazowy skan zawodzi w sieci >10 000 IP (dynamika, pory dnia, brak kontekstu aplikacji, brak mostu do DefectDojo).
2. **Architektura AegisASI:** Lekki silnik Go + PostgreSQL (AEAD) + React UI + DefectDojo v2 — `docker compose up` i działa.
3. **Skala >10 000 IP & Bezpieczeństwo:** Adaptacyjny chunking, estymacja ETA, twarde okna czasowe z Pause/Resume, token-bucket rate limiting, zero eksploatacji.
4. **Intelligence Engine (3 odpowiedzi na pytania CBI AGH):** Maszyna stanów z re-probe, Time-of-Day Heatmap, Bayesowski Confidence Score + Interestingness Score.
5. **Fingerprinting HTTP/HTTPS & Signature Studio:** Co wyciągamy (favicon MMH3, TLS, ciasteczka, nagłówki, CMS/admin/staging) + bezpieczne własne sygnatury z testem retroaktywnym.
6. **Warstwa Kuratorska & Zunifikowany Import:** Edycje analityka zachowane między skanami + dane ręczne/CSV/JSON przetwarzane identycznie jak skan.
7. **Bezpieczeństwo Danych & RBAC:** Dynamiczny RBAC (4 wymagane role + własne) + dowód szyfrowania AES-256-GCM At Rest (`psql` proof).
8. **Integracja DefectDojo v2:** Nmap XML + selektywne Findings z evidence i deduplikacją.
9. **LIVE DEMO (główna część prezentacji!):** Skan 1 -> Okno czasowe Pause/Resume -> Edycja wyniku -> Skan 2 (zmiany + flapping + zachowana edycja) -> Custom sygnatura -> Przełączenie roli -> Push do DefectDojo.
10. **Gotowość Wdrożeniowa w CBI AGH:** Minimalne zasoby (Go benchmark), dokumentacja, roadmapa dalszego rozwoju na uczelniach.
