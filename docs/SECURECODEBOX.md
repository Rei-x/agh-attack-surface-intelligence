# AegisASI a OWASP secureCodeBox

Treść zadania wskazuje [OWASP secureCodeBox](https://www.securecodebox.io) (SCB,
Apache-2.0, <https://github.com/secureCodeBox/secureCodeBox>) jako najbliższe istniejące
narzędzie, które „nie spełnia w pełni wymagań”. Nie próbujemy go zastąpić ani skopiować.
Przejęliśmy z niego słownictwo, format wyników i dane testowe, żeby zespół, który zna SCB,
od razu rozpoznał koncepcje. Oba narzędzia mogą też wymieniać dane w obie strony.

Dziękujemy autorom secureCodeBox. Wszystkie pliki skopiowane z SCB mają zachowane nagłówki
SPDX i plik `NOTICE` z licencją Apache-2.0.

## 1. Słownik: pojęcie SCB i odpowiednik w AegisASI

| secureCodeBox | AegisASI | Gdzie |
|---|---|---|
| **ScanType** (`nmap`, `sslyze`, `ssh-audit`; definicja skanera z parametrami) | **Preset profilu skanowania**: „Szybki discovery”, „Standard”, „Pełny web”. Preset wypełnia formularz profilu, a limity zostają zachowawcze. | UI: Skany → Profile → „Typ skanu (preset)”; `frontend/src/pages/ScansPage.tsx` (`PROFILE_PRESETS`) |
| **Scan** (jednorazowe uruchomienie) | **Scan run** (przebieg skanowania) z Coverage Ledger (lista chunków) | `POST /api/v1/scans`, `aegis scan` |
| **ScheduledScan** (`spec.interval`, cykliczny Scan) | **Profil z `schedule_cron` + okno czasowe** (`window_start`/`window_end`, strefa czasowa) | `internal/scheduler`, `internal/scanner/window.go` |
| **Hook** (ReadOnly / ReadAndWrite, np. `persistence-defectdojo`, `notification`) | **Integracja DefectDojo** (automatyczny reimport po skanie) i **webhook alertów** (Slack/Teams/Discord/n8n) | `internal/defectdojo`, `internal/notify` |
| **findings.json** (zunifikowany format wyników) | **Eksport `format=scb`** (i import tego samego formatu) | `internal/ingest/scb_export.go`, `scb_import.go` |
| **Parser** (raw → findings) | Parsery importu: nmap XML, CSV, JSON, SCB findings | `internal/scanner/nmap.go`, `internal/ingest/parsers.go` |
| **CascadingRule** (np. `Open Port` 22 → `ssh-audit`, 443 → `sslyze`) | **Etapy follow-up wbudowane w silnik**: HTTP/TLS fingerprint, JARM, pasywne kontrole TLS/SSH (pkt 4) | `internal/scanner/engine.go`, `internal/ingest/passive_checks.go` |
| Etykiety `securecodebox.io/invasive: non-invasive`, `intensive: light` | Polityka bezpieczeństwa skanera: wszystkie nasze etapy są „non-invasive / light”, NSE (`--script`, `-sC`, `-A`, `-O`) jest zablokowane w kodzie | `internal/scanner/nmap_args.go` (`ValidateSafeNmapArgs`) |
| Adnotacje `defectdojo.securecodebox.io/*` | Te same poziomy nazw w DefectDojo (pkt 3) | `internal/defectdojo/naming.go` |

## 2. Wymiana danych: findings.json

### Eksport do SCB

```bash
aegis export --format scb -o aegis-findings.json
# lub API (uprawnienie export:read):
curl -H "Authorization: Bearer $TOKEN" "https://aegis/api/v1/export?format=scb&state=ACTIVE" -o findings.json
```

W UI: Skany → Import/Eksport → przycisk **secureCodeBox**.

Każdy host daje finding `Host`, a każda otwarta usługa finding `Open Port`, w dokładnie takim
kształcie jak parser nmap w SCB (`scanners/nmap/parser/parser.js`): `name: "Open Port: 22 (ssh)"`,
`location: "tcp://host:22"`, `osi_layer: NETWORK`, `severity: INFORMATIONAL`, atrybuty
`port`, `state`, `ip_addresses`, `hostname`, `service`, `serviceProduct`, `serviceVersion`,
`tunnel`, `operating_system`. Reguły kaskadowe SCB, które dopasowują np.
`category: "Open Port", attributes.port: 22`, zadziałają więc na naszym eksporcie bez zmian.
Nasze dodatkowe dane (stan cyklu życia, scoring, technologie, URL, tagi) trafiają do
`attributes.aegis`. Identyfikatory to deterministyczne UUID, więc ponowny eksport tego samego
hosta lub portu daje to samo `id`, a deduplikacja po stronie SCB lub DefectDojo działa.

### Import z SCB

Zespół, który już ma SCB, może przekazać nam jego wyniki:

```bash
aegis import findings.json            # wykrywane automatycznie
aegis import wyniki.json --format scb
```

W UI: Import → Format „secureCodeBox findings.json” (albo zwykły JSON, bo format jest
rozpoznawany automatycznie). Plik przechodzi przez ten sam pipeline co skan: diff,
cykl życia hostów, sygnatury, szyfrowanie w spoczynku.

| Kategoria SCB | Co z nią robimy |
|---|---|
| `Host` (nmap) | host żywy, hostname, system operacyjny |
| `Open Port` (nmap) | usługa: port, protokół, nazwa, produkt, wersja (porty `filtered` pomijamy, bo u nas usługa oznacza port otwarty) |
| `SSH Service` (ssh-audit) | usługa ssh z banerem |
| inne, z `host:port` w `location` (np. `TLS Service Info`, `Outdated TLS Version`, `FTP`, `SMB`) | tag `scb:<kategoria>` na tej usłudze |
| inne, bez portu (np. `SSH Policy Violation`) | tag `scb:<kategoria>` na hoście |
| bez adresu IP (np. `Subdomain`) | pomijamy. Inwentarz jest indeksowany po IP, a podczas importu nie rozwiązujemy nazw DNS. |

Limity: 32 MiB i 500 000 findingów na plik. Porty spoza 1–65535 i niepoprawne adresy IP
są odrzucane.

### Dane testowe z SCB

- `backend/internal/scanner/testdata/scb/*.xml`: 9 plików nmap XML z testów parsera SCB
  (host bez nazwy, brak portów, port `filtered`, IPv6, skrypty NSE `ftp-anon`/`banner`/
  `smb-protocols`, sieć /24 z 246 hostami `down`, dwa bloki `<host>` dla tego samego IP).
  Test `scb_fixtures_test.go` sprawdza nasz `ParseNmapXML` na każdym z nich. Wykryte i
  poprawione luki: adres MAC nie może zostać adresem hosta, zduplikowane bloki hosta są
  scalane, a wyniki NSE z importowanego XML są wykorzystywane (`banner` uzupełnia baner,
  `ftp-anon` daje tag `ftp-anonymous`, `smb-protocols` z SMBv1 daje tag `smbv1`, tak jak
  w parserze SCB). Sami skryptów NSE nie uruchamiamy.
- `backend/internal/ingest/testdata/scb/nmap-basic-findings.json`: prawdziwy findings.json
  ze skanera nmap SCB (`scanners/nmap/examples/basic-example`), test importu.

## 3. DefectDojo: te same poziomy co hook SCB

Hook `persistence-defectdojo` z SCB i nasz klient DefectDojo robią to samo: wysyłają
`reimport-scan` z `auto_create_context`, więc DefectDojo sam zakłada Product Type, Product,
Engagement i Test. Nazwy odpowiadają sobie tak:

| Adnotacja SCB (`defectdojo.securecodebox.io/…`) | Domyślnie w SCB | AegisASI (zmienna środowiskowa) | Domyślnie w AegisASI |
|---|---|---|---|
| `product-type-name` | Product Type o id 1 | `ASI_DEFECTDOJO_PRODUCT_TYPE_NAME` | `AegisASI` |
| `product-name` | nazwa ScheduledScan | `ASI_DEFECTDOJO_PRODUCT_NAME` | `AGH Attack Surface` |
| `engagement-name` | nazwa Scan | `ASI_DEFECTDOJO_ENGAGEMENT_NAME` | `AegisASI continuous discovery` |
| `engagement-deduplicate-on-engagement` | `false` | `ASI_DEFECTDOJO_DEDUPLICATE_ON_ENGAGEMENT` | `false` |
| `test-title` | nazwa Scan | (automatycznie) | `AegisASI Nmap: <nazwa profilu>` |
| `minimum_severity` | brak | `ASI_DEFECTDOJO_MINIMUM_SEVERITY` | `Info` |

Produkt lub engagement przypięty po ID w ustawieniach (Admin → DefectDojo) ma pierwszeństwo
przed nazwami. Jeden profil skanowania odpowiada jednemu testowi w DefectDojo, tak jak
ScheduledScan w SCB. Każdy kolejny przebieg robi reimport do tego samego testu z
`close_old_findings=true`, więc usługi, które zniknęły, są zamykane jako mitigated.

## 4. „Cascading scans” w AegisASI

W SCB reguła kaskadowa uruchamia nowy Scan (osobny pod) dla findingu, np. `Open Port` 22
uruchamia `ssh-audit`, a 443 uruchamia `sslyze`. U nas ten sam pomysł działa w jednym
przebiegu, dla każdego chunku:

```
Stage 1  discovery (nmap -sn / TCP connect)          ~ SCB: nmap -sn
Stage 2  usługi (nmap -sT -sV, bez NSE)               ~ SCB: nmap -sV
Stage 3  follow-up dla usług HTTP/TLS:                ~ SCB CascadingRule "https-tls-scan"
           nagłówki, tytuł, favicon mmh3, certyfikat,
           JARM, bezpieczne ścieżki z sygnatur
Stage 4  ponowna weryfikacja niestabilnych hostów     (brak odpowiednika w SCB)
Pasywnie pochodne findingi TLS/SSH z danych etapów 2-3 ~ SCB: sslyze / ssh-audit (część pasywna)
```

Pasywne kontrole (`internal/ingest/passive_checks.go`) nie wysyłają żadnego dodatkowego
pakietu. Korzystają z handshake'u TLS zebranego przy fingerprincie HTTP i z banera SSH:

| Finding (nazwa i kategoria jak w parserach SCB) | Skąd dane |
|---|---|
| `TLS Service` / `TLS Service Info` | wersja i szyfr wynegocjowane przy fingerprincie, CN, wystawca, JARM |
| `TLS Version TLS 1.0 is considered insecure` / `Outdated TLS Version` (MEDIUM) | wynegocjowana wersja to najwyższa obsługiwana przez serwer; 1.0 lub 1.1 oznacza brak TLS 1.2+ |
| `Self-Signed Certificate`, `Expired Certificate` / `Invalid Certificate` (MEDIUM) | certyfikat z tego samego handshake'u |
| `SSH Service` / `SSH Service` | baner `SSH-2.0-OpenSSH_…` lub pola `-sV` nmapa |
| `Insecure SSH Protocol Version 1.99` / `SSH Policy Violation` (HIGH) | baner ogłaszający SSH-1 |

Na razie pojawiają się one w eksporcie `scb`. Świadomie nie robimy pełnego `sslyze`
(enumeracja wszystkich wersji i szyfrów) ani pełnego `ssh-audit` (lista algorytmów z
KEXINIT), bo to oznaczałoby dodatkowe połączenia do każdej usługi. Jeśli zespół chce takiej
głębi, może zrobić eksport `scb` z AegisASI, przekazać go do SCB, który uruchomi swoje
reguły kaskadowe, a jego wyniki zaimportować z powrotem do AegisASI.

## 5. Co AegisASI dodaje ponad SCB (wymagania zadania)

| Wymaganie zadania | SCB | AegisASI |
|---|---|---|
| Okna czasowe skanowania z pauzą i wznowieniem | ScheduledScan uruchamia skan, ale nie pauzuje go w trakcie | okno HH:MM–HH:MM ze strefą czasową. Przebieg pauzuje się na końcu okna (`PAUSED_WINDOW`) i wznawia od niedokończonego chunku |
| >10 000 IP bez obciążania sieci | jeden pod nmap na cały zakres (lub ręczne dzielenie) | adaptacyjny podział na chunki (`chunk_target_sec`), Target Noise Governor (wycofanie przy timeoutach i RST), limity pps i rps na profil |
| Wykrywanie zmian między skanami | brak (każdy skan to osobny zbiór findingów) | diff nowe/zniknięte/zmienione usługi, cykl życia hosta NEW→ACTIVE→MISSING z histerezą, wykrywanie hostów migających (flapping) i działających tylko o pewnych porach (model bayesowski) |
| Kontrola dostępu | RBAC Kubernetesa | 4 role aplikacyjne (admin, operator, analyst, viewer), uprawnienia per endpoint, dziennik audytu |
| Ochrona zebranych danych | sekrety K8s, dane w S3/MinIO | szyfrowanie w spoczynku AES-256-GCM (envelope, rotacja kluczy, blind index) |
| Interfejs dla analityka | brak własnego UI (wyniki ogląda się w DefectDojo lub Kibanie) | UI po polsku: inwentarz, oś czasu hosta, graf, triage, akceptacja ryzyka, studio sygnatur |
| Wdrożenie | wymaga klastra Kubernetes, operatora, Helm | jedna binarka lub `docker compose`, opcjonalnie PostgreSQL |

## 6. Jak używać obu narzędzi razem

1. **AegisASI jako źródło inwentarza dla SCB.** Cykliczne, bezpieczne discovery w oknach
   czasowych robi AegisASI. Eksport `scb` (np. z cron: `aegis export --format scb --state ACTIVE`)
   trafia do SCB, gdzie reguły kaskadowe na `Open Port` uruchamiają głębsze skany (sslyze,
   ssh-audit, nuclei) tam, gdzie zespół ma na nie zgodę.
2. **SCB jako dodatkowe źródło dla AegisASI.** Wyniki nmap, ssh-audit i sslyze z istniejących
   ScheduledScanów importuje się przez `aegis import findings.json`. Trafiają do tego samego
   inwentarza, diffu i alertów, a kategorie SCB widać jako tagi `scb:*`.
3. **Wspólny DefectDojo.** Jeśli oba narzędzia mają te same nazwy Product Type, Product i
   Engagement (pkt 3), wyniki lądują w jednym produkcie w DefectDojo, jako osobne testy.

## 7. Czego świadomie nie przejęliśmy

- **Kubernetes, operatora i CRD.** Zadanie dotyczy jednej uczelnianej sieci. Jedna binarka
  jest prostsza w utrzymaniu i audycie.
- **Kolejnych skanerów** (ZAP, nikto, ffuf, nuclei, sqlmap, …). Zadanie wymaga bezpiecznego
  discovery bez eksploatacji. Fuzzing katalogów i aktywne skany podatności są poza zakresem.
- **Pełnego sslyze i ssh-audit.** Opisane w pkt 4: robimy tylko część pasywną.
- **Parsera wyników NSE na żywo.** Nasz skaner nie uruchamia skryptów NSE (zablokowane
  w `ValidateSafeNmapArgs`). Wyniki skryptów odczytujemy tylko z importowanego XML.
- **Modelu „każdy skan to osobny zbiór findingów”.** U nas podstawą jest inwentarz ze
  stanem i historią, a findingi SCB są tylko formatem wymiany.
