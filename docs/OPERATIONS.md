# AegisASI - instrukcja operacyjna

Krótko: jak zainstalować, uruchomić, zabezpieczyć klucz i co znaczą komunikaty, które można zobaczyć.

## 1. Instalacja

**Pojedynczy plik binarny** (Linux, macOS, Windows; bez zależności, nmap opcjonalny):

```bash
curl -fsSL https://raw.githubusercontent.com/Rei-x/agh-attack-surface-intelligence/main/install.sh | sh
aegis version
```

Z kodu źródłowego: `make build` (wymaga Go i pnpm), wynik w `bin/aegis`.

**Docker Compose** (aplikacja + PostgreSQL):

```bash
docker compose up -d --build      # UI: http://localhost:8080
docker compose logs -f aegis-asi  # baner startowy, ostrzeżenia
```

Port zmienisz przez `ASI_PORT=9090 docker compose up -d`. PostgreSQL nie jest wystawiony na host.

## 2. Pierwsze uruchomienie

```bash
aegis serve                       # http://localhost:8080, dane w ~/.aegis
aegis serve --listen 127.0.0.1:9090 --data-dir /srv/aegis
```

Przy pierwszym starcie AegisASI sam tworzy katalog danych, losowy 256-bitowy klucz główny
(`master.key`, prawa 0600) i zaszyfrowany magazyn (`aegis-store.enc`, AES-256-GCM).

**Tryb demo (domyślny)** - zakłada 4 konta z jawnymi hasłami, po jednym na rolę:
`admin / Admin123!`, `operator / Operator123!`, `analyst / Analyst123!`, `viewer / Viewer123!`.
Baner i log pokazują wtedy ostrzeżenie `DEMO MODE`. Tylko do laboratorium.

**Tryb produkcyjny** - `ASI_SEED_DEMO=false` (lub `aegis serve --seed-demo=false`):

- konta demo, które wciąż mają jawne hasło, zostają wyłączone,
- jeśli nie ma aktywnego administratora, powstaje konto `admin` z hasłem z `ASI_ADMIN_PASSWORD`
  albo z losowym hasłem wypisanym **jeden raz** na terminal (w Dockerze: `docker compose logs aegis-asi`).
  Po zalogowaniu zmień je w Administracja > Użytkownicy.

Skan z terminala (gdy `aegis serve` nie działa na tym samym katalogu danych):

```bash
aegis scan 192.168.1.0/24 -p 22,80,443
aegis import wyniki.csv      # CSV (',' ';' lub TAB, także eksport z Excela), JSON, nmap XML
aegis export --format csv -o inwentarz.csv
```

## 3. Klucz główny - kopia zapasowa (ważne)

Bez klucza danych **nie da się odszyfrować**. Zrób kopię od razu po pierwszym starcie:

| Tryb | Gdzie jest klucz | Kopia |
|---|---|---|
| binarka | `~/.aegis/master.key` (lub `--data-dir`) | `cp ~/.aegis/master.key /bezpieczne/miejsce/` |
| Docker | wolumen `aegis-data`, plik `/data/master.key` | `docker compose cp aegis-asi:/data/master.key ./master.key.bak` |
| własny klucz | zmienna `ASI_MASTER_KEY` (64 znaki hex) | przechowuj w menedżerze sekretów |

Kopia danych: binarka - cały katalog `~/.aegis` (najlepiej przy zatrzymanym `aegis serve`);
Docker - `docker compose exec postgres pg_dump -U aegis aegis_asi > backup.sql` plus klucz.
`docker compose down -v` **usuwa wolumeny** (dane i klucz) - używaj `down` bez `-v`.

Klucz można też podać z zewnątrz: `ASI_MASTER_KEY=$(openssl rand -hex 32)`; podpis tokenów JWT
jest z niego wyprowadzany (albo `ASI_JWT_SECRET`).

## 4. Zmienne środowiskowe

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `ASI_LISTEN_ADDR` / `PORT` | `:8080` | adres nasłuchu |
| `ASI_DATA_DIR` | `~/.aegis` | katalog danych (klucz, magazyn, blokada) |
| `DATABASE_URL` | brak | PostgreSQL zamiast pliku |
| `ASI_MASTER_KEY` | generowany | klucz główny (hex/base64, 32 bajty) |
| `ASI_SEED_DEMO` | `true` | konta demo |
| `ASI_ADMIN_PASSWORD` | losowe | hasło konta `admin` w trybie produkcyjnym (min. 10 znaków) |
| `ASI_CORS_ORIGINS` | brak | dodatkowe originy z dostępem do API (lista po przecinku) |
| `ASI_CHUNK_WORKERS` | 4 | równoległe procesy nmap |

## 5. Zabezpieczenia aplikacji (dla audytu)

- Każdy endpoint poza `/api/v1/health`, `/api/v1/auth/login` i `/api/v1/auth/demo-accounts`
  wymaga tokenu JWT (HS256, ważny 24 h); uprawnienia sprawdzane per trasa (4 role, RBAC).
- Hasła: Argon2id. Po 10 nieudanych logowaniach na konto (30 na adres IP) w 5 min - blokada (HTTP 429).
- Nagłówki: CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`; CORS tylko dla `ASI_CORS_ORIGINS`.
- Limity: 8 MB na żądanie JSON, 64 MB na import; timeouty HTTP (ochrona przed slowloris).
- Eksport CSV neutralizuje formuły arkusza (`=`, `+`, `-`, `@`) pochodzące ze skanowanych hostów.
- Nie da się usunąć/zdegradować ostatniego administratora.

## 6. Rozwiązywanie problemów

| Komunikat | Przyczyna | Co zrobić |
|---|---|---|
| `listen on :8080: ... address already in use` | port zajęty | `aegis serve --listen :8081` lub `ASI_PORT=8081 docker compose up -d` |
| `data directory is in use by 'aegis serve' (pid ...)` | inny proces używa katalogu danych (magazyn jest jednopiszący) | zatrzymaj `aegis serve` albo uruchom skan/import z UI; `aegis export`/`runs`/`diff` działają równolegle (tylko odczyt) |
| `data directory ... is not writable` / `create data dir ...: permission denied` | brak praw zapisu | popraw uprawnienia lub wskaż inny `--data-dir` |
| `decrypt blob (wrong ASI_MASTER_KEY / master.key?)` | zły klucz do istniejącego magazynu | przywróć właściwy `master.key` / `ASI_MASTER_KEY` |
| `encrypted store ... exists but master.key is missing` | usunięty klucz, dane zostały | przywróć kopię klucza; AegisASI celowo nie generuje nowego |
| `unwrap crypto keys: the master key does not match the data in this database` | PostgreSQL zaszyfrowany innym kluczem (np. utracony wolumen `aegis-data`, wcześniejsza wersja z wbudowanym kluczem) | przywróć klucz; dla instalacji sprzed tej wersji: `ASI_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| `connect PostgreSQL: ping postgres: ...` | baza niedostępna przy starcie | sprawdź `docker compose ps`, `DATABASE_URL` |
| UI: „Problem z magazynem danych”, `/health` = 503 `degraded` | baza padła lub zapis na dysk nie działa (pełny dysk, tylko do odczytu) | zwolnij miejsce / uruchom bazę; zmiany od tej chwili mogą nie zostać zapisane |
| `baza danych jest niedostępna` (HTTP 503) | chwilowa awaria PostgreSQL | odczekaj; sesja nie jest wylogowywana |
| `zbyt wiele nieudanych prób logowania` (HTTP 429) | blokada po błędnych hasłach | odczekaj czas z komunikatu (maks. 5 min) |
| `niepoprawne cele` / `obejmuje N adresów, limit to 262144` | literówka w celu lub zakres większy niż /14 | popraw wpis; podziel duży zakres |
| `niepoprawna lista portów` | port spoza 1-65535 | np. `22,80,443,8000-8100` |
| `brak poprawnych hostów: kolumna 'ip' ...` | import bez poprawnych adresów IP | plik musi mieć kolumnę `ip` (lub `host`, `address`) z adresami IPv4/IPv6 |
| `plik importu jest za duży (limit 64 MB)` | zbyt duży plik | podziel plik |
| odpowiedź importu `skipped_records > 0` | część wierszy miała zły IP/port/protokół | pozostałe wiersze zostały zaimportowane |
| `można wznowić tylko wstrzymany skan` / `skan jest już zakończony` (409) | akcja niepasująca do stanu skanu | odśwież listę skanów |
| skan `FAILED` z notatką „Przerwany przez restart/awarię serwera” | serwer zatrzymano w trakcie szybkiego skanu | uruchom ponownie; wyniki zebrane wcześniej są zapisane. Skany z profilu wznawiają się same od punktu kontrolnego |
| `operacja odebrałaby dostęp ostatniemu administratorowi` (409) | próba usunięcia/wyłączenia ostatniego admina | najpierw nadaj rolę admina innemu kontu |
| Scanner: `TCP fallback` zamiast nmap | brak nmap w PATH | zainstaluj nmap (`apt install nmap`, `brew install nmap`); fallback działa, ale bez detekcji wersji nmap |
| `Pool overlaps with other one on this address space` (docker compose) | sieć 172.28.0.0/24 z `docker-compose.yml` koliduje z istniejącą | zmień podsieć w sekcji `networks` |
