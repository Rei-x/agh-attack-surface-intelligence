# Dzięcioł (AegisASI) — Attack Surface Intelligence dla CBI AGH

Cykliczne discovery i analiza zmian powierzchni ataku w sieciach powyżej 10 000 adresów IP. Projekt na **HackNation 2026** dla **Centrum Bezpieczeństwa Informacji AGH**.

Jeden plik binarny `aegis` (Go) zawiera skaner, potok analizy, REST API z SSE, panel React i narzędzia CLI. Domyślnie dane trzyma w zaszyfrowanym pliku, opcjonalnie w PostgreSQL. Skan jest dzielony na chunki z punktami kontrolnymi, mieści się w oknach czasowych i ma jeden budżet pakietów na cały skan. Zmiany między skanami (nowe/zniknięte hosty, usługi, wersje) trafiają do panelu, webhooka i DefectDojo.

## Szybki start

```bash
# 1) jeden plik binarny (bez Dockera i bazy): instalacja z GitHub Releases + weryfikacja SHA-256
curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
aegis serve                                 # http://localhost:8080
aegis scan 192.168.1.0/24 -p 22,80,443      # skan z terminala, wyniki w tym samym magazynie

# 2) Docker Compose: aplikacja + PostgreSQL 17 (+ opcjonalne laboratorium testowe)
docker compose up -d --build                                              # http://localhost:8080
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
```

Konta demo (wyłączenie: `--seed-demo=false` / `ASI_SEED_DEMO=false`):

| Login | Hasło | Rola |
| :--- | :--- | :--- |
| `admin` | `Admin123!` | Administracja |
| `operator` | `Operator123!` | Dodawanie, usuwanie, modyfikacja |
| `analyst` | `Analyst123!` | Modyfikacja i odczyt |
| `viewer` | `Viewer123!` | Odczyt |

## Architektura

```
  cele (IP / CIDR / zakresy / domeny) - wykluczenia
          │
          ▼
  scanner.Engine  (chunki 32-512 IP, permutacja kolejności, okna czasowe, checkpoint/resume,
          │        jeden budżet pakietów/s, Target Noise Governor: backoff na timeout/429/RST)
          │   Stage 1  nmap sweep (-Pn na dozwolonych portach, ICMP gdy root)  | fallback: TCP connect w Go
          │   Stage 4  ponowna próba hostów widzianych wcześniej, a teraz brakujących
          │   Stage 2  nmap -sV na żywych hostach
          │   Stage 3  HTTP/TLS fingerprint (tylko GET/HEAD: nagłówki, tytuł, favicon mmh3, cert, JARM)
          ▼                               ▲
  ingest.Pipeline  ◄── import: nmap XML, CSV, JSON, secureCodeBox findings.json, formularz ręczny
          │   signatures + intelligence: produkt/wersja, Noisy-OR confidence, interestingness,
          │   cykl życia hosta (NEW/ACTIVE/MISSING/INTERMITTENT/INACTIVE/REACTIVATED), liveness,
          │   zdarzenia zmian (diff skanów, anomalie pory dnia)
          ▼
  db.Store ── zaszyfrowany plik ~/.aegis/aegis-store.enc (domyślnie)  |  PostgreSQL (DATABASE_URL)
          │   pola wrażliwe: AES-256-GCM per pole (DEK wersjonowane, KEK = master key), AAD tabela:id:kolumna
          ▼
  api.Server ── REST /api/v1 + SSE + wbudowany panel React (JWT, RBAC, audit log)
          │
          ├── defectdojo   import nmap XML + findings (nazewnictwo jak hook secureCodeBox)
          ├── notify       webhook alertów po ingeście ze zmianami
          ├── scheduler    cykliczne skany z ScanProfile.ScheduleCron (z oknem czasowym)
          └── agenthub ◄── HTTPS, tylko wychodząco ── aegis agent (zdalny segment sieci:
                            enroll tokenem, heartbeat, long-poll zadań, Engine.Execute lokalnie,
                            wyniki per chunk przez ten sam ingest.Pipeline)
```

## Mapa kodu

`backend/` (moduł Go, binarka z `backend/cmd/server`):

| Pakiet | Rola |
| :--- | :--- |
| `cmd/server` | binarka `aegis`: `serve`, `scan`, `import`, `export`, `diff`, `runs`, `agent`; spina skaner, analizator i magazyn |
| `cmd/calibrate`, `cmd/jarm`, `cmd/scanbench` | narzędzia deweloperskie: kalibracja confidence na labie, JARM jednego hosta, benchmark silnika |
| `internal/scanner` | silnik skanowania: chunki, sweep/-sV/fingerprint, budżet pakietów, governor, okna czasowe |
| `internal/fingerprint` | sondy HTTP/HTTPS, metadane TLS, JARM, cechy strony |
| `internal/ingest` | wspólny potok obserwacji → hosty/usługi/zmiany; parsery importu i eksportery (CSV/JSON/SCB) |
| `internal/intelligence` | identyfikacja produktu/wersji, fuzja confidence, scoring, cykl życia i liveness hostów |
| `internal/signatures` | sygnatury wbudowane i własne, walidacja, test wsteczny na zapisanych usługach |
| `internal/db` | interfejs `Store`: pamięć, zaszyfrowany plik, PostgreSQL; język zapytań o zasoby |
| `internal/crypto` | szyfrowanie kopertowe (KEK/DEK, AES-256-GCM), blob magazynu, Argon2id |
| `internal/api` | REST API, SSE, hardening, handlery skanów/agentów/DefectDojo |
| `internal/auth` | JWT, middleware, role RBAC, konta demo |
| `internal/agent` | zdalny agent skanujący (`aegis agent`) |
| `internal/agenthub` | serwerowa strona agentów: rejestr, tokeny, kolejka zadań, ingest wyników |
| `internal/scheduler` | cykliczne uruchamianie profili skanów |
| `internal/defectdojo` | klient DefectDojo API v2 |
| `internal/notify` | webhook alertów (Slack/Teams/Discord/n8n) |
| `internal/localdata` | katalog danych `~/.aegis`, master key, blokada jednego pisarza |
| `internal/domain` | wspólny model danych |
| `internal/webui` | panel React wbudowany w binarkę (`go:embed`) |

`frontend/` to panel React 19 + TypeScript (Vite), `lab/` to deterministyczne laboratorium testowe i laboratorium skali.

## Dokumentacja

- [docs/OPERATIONS.md](./docs/OPERATIONS.md): instrukcja operacyjna (instalacja, master key, zmienne, rozwiązywanie problemów)
- [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md): wdrożenie, zdalni agenci, Docker + PostgreSQL, laboratorium, rotacja kluczy
- [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md): architektura szczegółowo (szyfrowanie, cykl życia hosta, confidence)
- [docs/RESEARCH.md](./docs/RESEARCH.md): metody badawcze (JARM, bayesowski model dostępności, Noisy-OR, permutacja adresów)
- [docs/SECURECODEBOX.md](./docs/SECURECODEBOX.md): mapowanie pojęć OWASP secureCodeBox i współpraca narzędzi
- [lab/scale/README.md](./lab/scale/README.md): laboratorium skali (/18, emulowane usługi, scorer)
- [docs/API_CONTRACT.md](./docs/API_CONTRACT.md), [SPEC.md](./SPEC.md): kontrakt API i pierwotna specyfikacja

## Szczegóły użycia (jeden plik binarny)

Bez Dockera, bez bazy danych, bez uprawnień roota.

### 1. Instalacja

```bash
curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
```

Skrypt wykrywa system i architekturę (macOS arm64/amd64, Linux amd64/arm64, Windows amd64 w Git Bash), pobiera plik z [GitHub Releases](https://github.com/Rei-x/agh-attack-surface-intelligence/releases), **weryfikuje sumę SHA-256** i instaluje do `~/.local/bin` (albo `/usr/local/bin`, gdy uruchomiony jako root). Konkretna wersja: `AEGIS_VERSION=v1.2.0`, inny katalog: `AEGIS_INSTALL_DIR=...`.

Ręcznie: pobierz `aegis-<os>-<arch>` oraz `checksums.txt` z Releases, sprawdź `grep aegis-darwin-arm64 checksums.txt | shasum -a 256 -c`, nadaj `chmod +x`. (macOS, plik pobrany przeglądarką: `xattr -d com.apple.quarantine aegis-darwin-arm64`.)

**Opcjonalnie nmap** — bez niego działa wbudowany skaner pure-Go (TCP connect + banner grabbing); z nmapem dostajesz detekcję wersji `-sV`:
`brew install nmap` / `sudo apt install nmap` / `winget install Insecure.Nmap`. Root nie jest potrzebny (skan TCP connect `-sT`; na macOS bez roota nmap nie wysyła ICMP — wykrywanie hostów idzie przez TCP).

### 2. Panel webowy

```bash
aegis serve                      # http://localhost:8080
aegis serve --listen 127.0.0.1:9000 --data-dir ./dane
```

Przy pierwszym uruchomieniu w terminalu pojawi się adres i konta demo (tabela wyżej). Domyślnie `:8080` nasłuchuje na wszystkich interfejsach — na współdzielonej sieci użyj `--listen 127.0.0.1:8080`.

### 3. Skan z terminala

```bash
aegis scan 192.168.1.0/24 -p 22,80,443,8080
aegis scan 10.0.0.1-10.0.0.50 scanme.example.org --rate 300 --concurrency 64
aegis scan -f cele.txt --json -o raport.json          # cele: jeden na linię, komentarze #
aegis scan --profile "Szybki Skan Demo"                # zapisany profil z UI
aegis scan 127.0.0.1 -p 22,8080 --ignore-exclusions    # lokalny test (127.0.0.0/8 jest domyślnie wykluczone)
```

W trakcie skanu widać pasek postępu (hosty zrobione/wszystkie, hosts/s, ETA, liczba żywych hostów i usług), a na końcu tabelę: żywe hosty, najciekawsze znaleziska (panele admina, środowiska staging, IoT, wykryte technologie) oraz **zmiany względem poprzedniego skanu** (nowe / zniknięte hosty, nowe / zamknięte / zmienione usługi). Wyniki trafiają do tej samej bazy, więc `aegis serve` od razu je pokazuje.

Magazyn danych ma jednego pisarza: jeśli działa `aegis serve` na tym samym katalogu, `aegis scan` odmówi z czytelnym komunikatem — wtedy uruchom skan z panelu (zakładka *Skaner*) albo zatrzymaj serwer.

### 4. Pozostałe polecenia

```bash
aegis runs                                  # lista skanów
aegis diff                                  # porównanie dwóch ostatnich skanów
aegis diff <runA> <runB>                    # konkretne skany (wystarczy unikalny prefiks ID)
aegis import wyniki.xml                     # nmap -oX, a także .csv / .json
aegis export --format csv -o inwentarz.csv  # albo --format json (na stdout bez -o)
aegis export --format scb -o findings.json  # findings.json OWASP secureCodeBox (import też działa)
aegis version
```

### Gdzie są dane i jak są chronione

Domyślnie `~/.aegis` (zmiana: `--data-dir` lub `ASI_DATA_DIR`):

| Plik | Zawartość |
| :--- | :--- |
| `aegis-store.enc` | cała baza, zaszyfrowana AES-256-GCM (klucz pochodny od klucza głównego); w środku pola wrażliwe (IP, hostname, bannery, nagłówki HTTP, notatki, e-maile) są **dodatkowo** szyfrowane per rekord wersjonowanymi kluczami DEK — tak samo jak w trybie PostgreSQL |
| `master.key` | klucz główny (256 bit, generowany przy pierwszym uruchomieniu, prawa `0600`) — **zrób kopię**, bez niego danych nie da się odczytać. Można go zastąpić zmienną `ASI_MASTER_KEY` |
| `aegis.lock` | blokada: tylko jeden proces zapisuje do magazynu |

Zapis jest atomowy (plik tymczasowy + fsync + rename): po ~1,5 s bez zmian, najpóźniej co 10 s przy ciągłych zapisach oraz przy zamknięciu (Ctrl+C).

Tryb z Dockerem i PostgreSQL: szczegóły w [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md).

Znasz OWASP secureCodeBox? Mapowanie pojęć (ScanType, ScheduledScan, Hook, findings.json) i współpraca obu narzędzi: [docs/SECURECODEBOX.md](./docs/SECURECODEBOX.md).

### Budowanie ze źródeł

```bash
make build      # frontend (pnpm) + bin/aegis z wbudowanym UI
make release    # dist/aegis-{darwin,linux}-{amd64,arm64}, aegis-windows-amd64.exe + checksums.txt
make test
```

Wymagania: Go 1.24+, Node 22+ z pnpm. Sam `cd backend && go build -o aegis ./cmd/server` też działa (bez frontendu serwer pokaże stronę zastępczą; UI można wskazać przez `ASI_STATIC_DIR`). Wydanie na GitHubie buduje workflow `.github/workflows/release.yml` po wypchnięciu taga `v*`.
