# Specyfikacja Techniczna i Strategia Wygranej: **AegisASI** (Attack Surface Intelligence dla CBI AGH)

> **Zadanie:** HackNation 2026 — `[Akademia Górniczo-Hutnicza] Attack Surface Intelligence`
> **Zamawiający:** Centrum Bezpieczeństwa Informacji AGH (CBI AGH)
> **Cel:** Produkcyjny, lekki (jedna binarka Go + PostgreSQL + wbudowany React/TS UI), bezpieczny system ciągłego discovery i analizy zmian powierzchni ataku dla dużych sieci (10 000–65 536+ IP) z interaktywnym grafem powierzchni ataku, natywną integracją DefectDojo, dynamicznym RBAC i szyfrowaniem w spoczynku — gotowy do wdrożenia w CBI AGH.

---

## 1. Architektura i Wyróżniki Systemu

### 1.1. Stack technologiczny (niskie zasoby, pełny Open Source)
- **Backend + Silnik Skanowania + Scheduler:** **Go 1.24+** — kompilowany do pojedynczej, lekkiej binarki z osadzonym frontendem (`embed.FS`), z minimalnym zużyciem RAM i natywną współbieżnością na gorutynach.
- **Baza danych:** **PostgreSQL 17** — pełna transakcyjność przy wielowątkowym zapisie, JSONB, szyfrowanie pól wrażliwych w spoczynku (**Envelope Encryption AES-256-GCM + AAD + HMAC-SHA256 blind indexes**).
- **Frontend (SOC Dashboard):** **React 19 + TypeScript + Vite + Tailwind CSS + Recharts** — nowoczesny interfejs SecOps (dark/light) z live SSE telemetry, interaktywnym grafem zasobów i pełnym wsparciem dla wszystkich ról RBAC.
- **Wdrożenie:** `docker compose up -d` (15 sekund do pełnego startu) + osobny `docker-compose.lab.yml` z deterministycznym środowiskiem testowym.

### 1.2. Kluczowe filary przewagi (pod kryteria oceny 30/20/15/15/10/10)

1. **Skala >10 000 IP, Coverage Ledger i Okna Czasowe (30%)**
   - Normalizacja i deduplikacja dowolnych wejść (IP, zakresy `a-b`, CIDR `/16`+, domeny z rezolucją DNS) + twarda lista wykluczeń (**Scope/Deny Gate**).
   - **Kalibracja i Adaptacyjny Chunking:** dynamiczny dobór rozmiaru podgrupy (32–512 IP) na podstawie zmierzonej prędkości skanowania; **Coverage Ledger** śledzący stan każdego chunka (`PENDING`, `RUNNING`, `DONE`, `PAUSED`, `FAILED`) oraz realistyczne **ETA**.
   - **Twarde Okna Czasowe (Pause/Resume):** przekroczenie okna czasowego (np. `22:00–06:00`) natychmiast zatrzymuje pobieranie nowych chunków, zapisuje checkpoint (`PAUSED_WINDOW`) i automatycznie wznawia ten sam skan w kolejnym oknie od dokładnego miejsca zatrzymania.
   - **Target Noise Governor:** adaptacyjne wyhamowywanie tempa przy wykryciu timeoutów, `429 Too Many Requests` lub masowych RST — skaner nigdy nie przeciąży infrastruktury uczelni.

2. **Intelligence Engine — 3 odpowiedzi na kluczowe wyzwania CBI AGH (15%)**
   - **Maszyna stanów hosta z histerezą + automatyczny Re-Probe:** `NEW` → `ACTIVE` → `INTERMITTENT` → `MISSING` (automatyczne ponowienie sondy!) → `INACTIVE` (po $K$ opuszczonych skanach ORAZ czasie karencji $T_{\text{grace}}$) → `REACTIVATED`.
   - **Macierz dostępności wg pory dnia (Time-of-Day Heatmap):** śledzenie zachowania hostów i usług w 4 slotach dobowych (`00–06`, `06–12`, `12–18`, `18–24`). Odróżnianie przewidywanego harmonogramu (`EXPECTED_OFF_HOURS`, redukcja szumu) od anomalii (`TIME_ANOMALY`).
   - **Noisy-OR Confidence Score (0–100%)** dla detekcji technologii z pełnym rozbiciem dowodów (evidence receipts) oraz **Interestingness Score (0–100)** priorytetyzujący znaleziska dla analityka SOC.

3. **Evidence-First Fingerprinting + Interaktywny Graf Powierzchni Ataku (10% + 15%)**
   - **HTTP/HTTPS/TLS Fingerprinter (pure Go, wyłącznie GET/HEAD):** `<title>`, kod odpowiedzi, pełny łańcuch przekierowań, nagłówki + analiza security headers, ciasteczka + flagi (`HttpOnly`/`Secure`/`SameSite`), certyfikat TLS (Subject, SANs, Issuer, wygasanie, self-signed), **Favicon MurmurHash3 (Shodan-compatible)**, wersje ze stopek, detekcja CMS, frameworków, serwerów aplikacyjnych, urządzeń IoT, środowisk `staging/dev/test` oraz paneli administracyjnych.
   - **Evidence Receipts:** każda technologia, zmiana i finding jest trwale powiązany z konkretną, zaszyfrowaną obserwacją surową (dowodem).
   - **Interaktywny Graf Powierzchni Ataku:** wizualizacja topologii `Zakres/Domena → Host (stan) → Usługa (port) → Technologia/Sygnatura/Finding` + widok **Grupowania Podobnych Usług** (klastry po faviconie, stosie technologicznym, tytule HTTP, TLS).
   - **Signature Studio:** 45+ wbudowanych bezpiecznych sygnatur + kreator własnych sygnatur (YAML/JSON/UI) z **Walidatorem Bezpieczeństwa** (blokuje metody mutujące i próby logowania) oraz **Playgroundem Retroaktywnym** (test na zapisanych danych bez ponownego skanowania).

4. **Zunifikowany Import, Warstwa Kuratorska (Overrides), RBAC, Szyfrowanie At Rest i DefectDojo v2 (20% + 10%)**
   - **Zunifikowany pipeline:** ręczny formularz oraz import **CSV / JSON** tworzą normalne `scan_runs` i przechodzą identyczne przetwarzanie (sygnatury, diff, stan hosta, scoring, szyfrowanie, eksport).
   - **Zachowanie edycji przy kolejnych skanach:** ścisły podział na niezmienne obserwacje skanera (`scan_observations`) oraz warstwę edycji analityka (`asset_overrides`). Edycje działają niezależnie od stanu skanu i są chronione przed nadpisaniem przez kolejne skany.
   - **Dynamiczny RBAC:** 4 predefiniowane role (`Administracja`, `Dodawanie, usuwanie, modyfikacja`, `Modyfikacja i odczyt`, `Odczyt`) + tworzenie własnych ról i macierzy uprawnień w UI; twarde `403 Forbidden` w API + Audit Log.
   - **Encryption At Rest (AEAD AES-256-GCM):** wszystkie pola wrażliwe (IP/hosty, nagłówki, ciasteczka, banery, certyfikaty, notatki, nadpisania, surowy Nmap XML, tokeny API) szyfrowane z AAD i wersjonowaniem kluczy (`enc:v1:<kid>:...`) + blind indeksy HMAC-SHA256 + skrypt i widok dowodowy `psql`.
   - **DefectDojo API v2:** zarówno upload surowego `Nmap Scan` XML (`/api/v2/import-scan/`), jak i selektywny eksport wybranych obserwacji jako Findings z dowodami i deduplikacją (`unique_id_from_tool`).
