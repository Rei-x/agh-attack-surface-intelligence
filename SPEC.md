# Specyfikacja techniczna i strategia wygranej: Dzięcioł (Attack Surface Intelligence dla CBI AGH)

> **Zadanie:** HackNation 2026, `[Akademia Górniczo-Hutnicza] Attack Surface Intelligence`
> **Zamawiający:** Centrum Bezpieczeństwa Informacji AGH (CBI AGH)
> **Cel:** produkcyjny, lekki i bezpieczny system ciągłego discovery i analizy zmian powierzchni ataku dla dużych sieci (10 000-65 536+ IP), gotowy do wdrożenia w CBI AGH. Składa się z jednej binarki Go, PostgreSQL i wbudowanego UI w React/TS. Ma interaktywny graf powierzchni ataku, natywną integrację z DefectDojo, dynamiczny RBAC i szyfrowanie w spoczynku.

---

## 1. Architektura i wyróżniki systemu

### 1.1. Stack technologiczny (niskie zasoby, pełny Open Source)
- Backend, silnik skanowania i scheduler: Go 1.24+. Kompiluje się do jednej lekkiej binarki z osadzonym frontendem (`embed.FS`), zużywa mało RAM i korzysta z natywnej współbieżności gorutyn.
- Baza danych: PostgreSQL 17. Daje pełną transakcyjność przy wielowątkowym zapisie i JSONB. Pola wrażliwe są szyfrowane w spoczynku (Envelope Encryption AES-256-GCM + AAD + HMAC-SHA256 blind indexes).
- Frontend (SOC Dashboard): React 19 + TypeScript + Vite + Tailwind CSS + Recharts. Interfejs SecOps (dark/light) z telemetrią na żywo przez SSE, interaktywnym grafem zasobów i obsługą wszystkich ról RBAC.
- Wdrożenie: `docker compose up -d` (15 sekund do pełnego startu) oraz osobny `docker-compose.lab.yml` z deterministycznym środowiskiem testowym.

### 1.2. Wyróżniki pod kryteria oceny (30/20/15/15/10/10)

1. **Skala >10 000 IP, Coverage Ledger i okna czasowe (30%)**
   - Normalizacja i deduplikacja dowolnych wejść (IP, zakresy `a-b`, CIDR `/16`+, domeny z rezolucją DNS) plus twarda lista wykluczeń (Scope/Deny Gate).
   - Kalibracja i adaptacyjny chunking: rozmiar podgrupy (32-512 IP) zależy od zmierzonej prędkości skanowania. Coverage Ledger śledzi stan każdego chunka (`PENDING`, `RUNNING`, `DONE`, `PAUSED`, `FAILED`) i liczy realistyczne ETA.
   - Twarde okna czasowe (pause/resume): gdy skan przekroczy okno (np. `22:00-06:00`), skaner od razu przestaje pobierać nowe chunki, zapisuje checkpoint (`PAUSED_WINDOW`) i w kolejnym oknie sam wznawia ten sam skan dokładnie od miejsca zatrzymania.
   - Target Noise Governor: przy timeoutach, `429 Too Many Requests` lub masowych RST skaner adaptacyjnie zwalnia, żeby nie przeciążyć infrastruktury uczelni.

2. **Intelligence Engine: odpowiedzi na 3 główne wyzwania CBI AGH (15%)**
   - Maszyna stanów hosta z histerezą i automatycznym re-probe: `NEW` → `ACTIVE` → `INTERMITTENT` → `MISSING` (tu sonda jest automatycznie ponawiana) → `INACTIVE` (po $K$ opuszczonych skanach ORAZ po czasie karencji $T_{\text{grace}}$) → `REACTIVATED`.
   - Macierz dostępności wg pory dnia (Time-of-Day Heatmap): zachowanie hostów i usług jest śledzone w 4 slotach dobowych (`00-06`, `06-12`, `12-18`, `18-24`). System odróżnia przewidywalny harmonogram (`EXPECTED_OFF_HOURS`, mniej szumu) od anomalii (`TIME_ANOMALY`).
   - Noisy-OR Confidence Score (0-100%) dla detekcji technologii, z pełnym rozbiciem dowodów (evidence receipts), oraz Interestingness Score (0-100), który ustala kolejność znalezisk dla analityka SOC.

3. **Evidence-first fingerprinting i interaktywny graf powierzchni ataku (10% + 15%)**
   - Fingerprinter HTTP/HTTPS/TLS (pure Go, wyłącznie GET/HEAD) zbiera `<title>`, kod odpowiedzi, pełny łańcuch przekierowań, nagłówki z analizą security headers, ciasteczka z flagami (`HttpOnly`/`Secure`/`SameSite`), certyfikat TLS (Subject, SANs, Issuer, wygasanie, self-signed), hash faviconu MurmurHash3 (zgodny z Shodanem) i wersje ze stopek. Wykrywa CMS-y, frameworki, serwery aplikacyjne, urządzenia IoT, środowiska `staging/dev/test` i panele administracyjne.
   - Evidence receipts: każda technologia, zmiana i finding jest trwale powiązany z konkretną zaszyfrowaną obserwacją surową, która jest jego dowodem.
   - Interaktywny graf powierzchni ataku pokazuje topologię `Zakres/Domena → Host (stan) → Usługa (port) → Technologia/Sygnatura/Finding`. Osobny widok grupuje podobne usługi w klastry po faviconie, stosie technologicznym, tytule HTTP i TLS.
   - Signature Studio: 66 wbudowanych bezpiecznych sygnatur i kreator własnych (YAML/JSON/UI). Walidator bezpieczeństwa blokuje metody mutujące i próby logowania, a retroaktywny playground testuje sygnaturę na zapisanych danych bez ponownego skanowania.

4. **Zunifikowany import, warstwa kuratorska (overrides), RBAC, szyfrowanie at rest i DefectDojo v2 (20% + 10%)**
   - Zunifikowany pipeline: ręczny formularz i import CSV / JSON tworzą zwykłe `scan_runs` i przechodzą to samo przetwarzanie (sygnatury, diff, stan hosta, scoring, szyfrowanie, eksport).
   - Edycje przetrwają kolejne skany: niezmienne obserwacje skanera (`scan_observations`) są ściśle oddzielone od warstwy edycji analityka (`asset_overrides`). Edycje działają niezależnie od stanu skanu i kolejne skany ich nie nadpisują.
   - Dynamiczny RBAC: 4 predefiniowane role (`Administracja`, `Dodawanie, usuwanie, modyfikacja`, `Modyfikacja i odczyt`, `Odczyt`), a do tego własne role i macierz uprawnień w UI. API odpowiada twardym `403 Forbidden`, wszystko trafia do Audit Log.
   - Encryption at rest (AEAD AES-256-GCM): wszystkie pola wrażliwe (IP/hosty, nagłówki, ciasteczka, banery, certyfikaty, notatki, nadpisania, surowy Nmap XML, tokeny API) są szyfrowane z AAD i wersjonowaniem kluczy (`enc:v1:<kid>:...`). Do tego blind indeksy HMAC-SHA256 oraz skrypt i widok dowodowy `psql`.
   - DefectDojo API v2: upload surowego XML `Nmap Scan` (`/api/v2/import-scan/`) oraz selektywny eksport wybranych obserwacji jako Findings z dowodami i deduplikacją (`unique_id_from_tool`).
