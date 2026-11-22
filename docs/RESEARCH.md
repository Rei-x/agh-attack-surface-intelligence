# Dzięcioł: metody badawcze (materiał na slajdy)

Trzy pytania z treści zadania i nasze odpowiedzi oparte na publikacjach:

| Pytanie z zadania | Metoda | Kod |
|---|---|---|
| Jak rozpoznać stos TLS i grupować podobne usługi? | **JARM** (Salesforce, 2020) | `backend/internal/fingerprint/jarm.go` |
| Po jakim czasie bez odpowiedzi uznać host za nieaktywny? Jak traktować hosty działające tylko o pewnych porach? | **Bayesowski model dostępności** (Beta-Bernoulli, 4 okna doby, zapominanie wykładnicze) | `backend/internal/intelligence/liveness.go` |
| Jak wyznaczyć pewność identyfikacji technologii? | **Noisy-OR z kanałami dowodów**, wagi skalibrowane na ground truth laboratorium | `backend/internal/intelligence/confidence.go`, `backend/cmd/calibrate` |
| Jak skanować >10 000 IP bezpiecznie dla sieci? | **Permutacja adresów w stylu ZMap** (grupa cykliczna) | `backend/internal/scanner` (osobny zespół) |

---

## 1. JARM: odcisk palca serwera TLS

**Idea.** Wysyłamy 10 celowo różnych komunikatów TLS ClientHello: różne wersje (1.1, 1.2, 1.3), kolejność szyfrów (rosnąco, malejąco, połowy, „od środka”), GREASE, rzadkie ALPN, różne listy wersji. Każda biblioteka TLS z konkretną konfiguracją odpowiada na nie inaczej. Z każdej odpowiedzi ServerHello bierzemy wybrany szyfr, wersję, ALPN i listę rozszerzeń.

```
JARM (62 znaki) = 10 × [indeks szyfru (2 hex) + wersja (1 znak)]   ← 30 znaków
                + SHA-256(wszystkie ALPN + listy rozszerzeń)[0:32]  ← 32 znaki
```

**Do czego go używamy.**
- **Klastrowanie:** ten sam JARM oznacza ten sam stos TLS (bibliotekę, wersję, konfigurację). Wymiar `tls_jarm` w `ComputeClusters` pokazuje np. „40 hostów z tym samym urządzeniem”.
- **Sygnatury:** nowy typ warunku `jarm` porównuje cały odcisk (62 hex). Z `regex=true` można dopasować prefiks, czyli sam wzorzec szyfrów i wersji.
- **Odporność na podszywanie:** nagłówek `Server:` łatwo zmienić, odpowiedzi stosu TLS już nie. W laboratorium skalowym usługi „IIS”, „Apache” i „Keycloak” mają ten sam JARM `40d1db40d00040d1dc43d1db1db43d539b9d77deca9292bdcadbfed36e46f1`, bo wszystkie obsługuje ten sam emulator w Go. JARM to widzi, nagłówki HTTP nie.

**Bezpieczeństwo.** Każda próba to jedno ClientHello na nowym połączeniu TCP. Czytamy pierwszą odpowiedź (≤1484 B), nie kończymy handshake'u, nie wysyłamy danych aplikacji i od razu zamykamy połączenie. Każda z 10 prób przechodzi przez ten sam `RateLimiter` co reszta skanera. Limity czasu: 4 s na próbę i 15 s na całość. Timeout przerywa serię, tak jak w referencyjnym `jarm.py`. JARM można wyłączyć opcją `DisableJARM`.

**Dlaczego bez wbudowanej bazy „JARM → produkt”.** Odcisk zależy od wersji biblioteki i konfiguracji serwera, a znane są kolizje (np. domyślny Cobalt Strike i zwykłe serwery Java). Taka baza dawałaby fałszywą pewność. Udostępniamy więc JARM do klastrowania i sygnatur pisanych przez analityka. Kanał `tls` ma w modelu pewności niską wagę 0,60.

**Weryfikacja (known-answer test).**
1. Bajty wszystkich 10 ClientHello są identyczne z `packet_building()` z `jarm.py` przy tym samym, deterministycznym źródle losowości (`TestJARMClientHelloMatchesReference`).
2. Odpowiedzi nagrane z trzech serwerów (OpenSSL 3.0.13 `s_server`, Go 1.27 `crypto/tls`, nginx 1.27 z h2) dają te same wyniki cząstkowe i ten sam hash co `read_packet()`/`jarm_hash()` z `jarm.py` (`TestJARMParseAndHashKnownAnswers`).
3. Test na żywo, `python3 jarm.py` kontra `go run ./cmd/jarm`:

| Serwer | JARM (obie implementacje identyczne) |
|---|---|
| OpenSSL 3.0.13 s_server | `07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d` |
| Go 1.27 crypto/tls | `3fd3fd0003fd3fd00043d43d00043d3bef2bf79cd6719851e8198c1e8f9a14` |
| nginx 1.27 (TLS + h2) | `21d19d00021d21d00042d43d00000091f9827a8676a9d9f27d421962a09b5d` |

Wektory odtworzysz skryptem `backend/internal/fingerprint/testdata/jarm/katgen.py`. Skrypt korzysta z oddzielnie sklonowanego `jarm.py`; kodu `jarm.py` nie dołączamy do repozytorium.

---

## 2. Kiedy host jest nieaktywny? Bayesowski model dostępności

**Problem stałego progu.** Reguła „N pustych skanów z rzędu” daje albo fałszywe alarmy dla hostów niestabilnych, albo zbyt późną reakcję dla hostów stabilnych. Komputer w laboratorium wyłączany na noc nie powinien nigdy dostać statusu INACTIVE tylko dlatego, że skanujemy o 2:00.

**Model.** Rozdzielamy dwie rzeczy:

1. **Dostępność hosta, który istnieje**, osobno dla 4 okien doby (00-06, 06-12, 12-18, 18-24):
   `p_s ~ Beta(α_s, β_s)`. Odpowiedź dodaje 1 do `α_s`. Brak odpowiedzi, po którym host wrócił, dodaje 1 do `β_s`: to był przestój, a host nadal istnieje. Stare obserwacje tracą wagę wykładniczo z okresem połowicznym **H = 14 dni**, więc model uczy się zmian zachowania. Prior to `Beta(2; 0,5)`, czyli średnio 80% dostępności przy wadze 2,5 obserwacji.
2. **Trwająca seria braków** `k_s` w każdym oknie. Gdy host istnieje, prawdopodobieństwo takiej serii daje rozkład beta-dwumianowy. Gdy hosta już nie ma, braki są pewne:

```
L = Π_s Π_{i<k_s} (β_s + i) / (α_s + β_s + i)

P(host istnieje | historia, seria braków) = π·L / (π·L + (1 − π)),   π = 0,9
```

**Reguła (jeden akapit na slajd).** Host przechodzi w stan **INACTIVE**, gdy prawdopodobieństwo, że nadal istnieje, spada poniżej **5%** i jednocześnie spełnione są minima z profilu skanu: `missing_threshold` kolejnych braków (domyślnie 3) oraz `grace_period_hours` od ostatniej odpowiedzi (domyślnie 72 h). Braki w oknie, w którym host zwykle nie działa, prawie nie obniżają tego prawdopodobieństwa, bo `β_s` jest tam duże. Dlatego host aktywny w godzinach 07-19 nie zostanie uznany za nieaktywny w nocy. Stanie się INACTIVE dopiero wtedy, gdy przestanie odpowiadać także w dzień. Każda decyzja ma czytelne uzasadnienie, np.:

> *INACTIVE: prawdopodobieństwo, że host nadal działa: 1% po 4 nieudanych próbach (okno nocne 00-06: 1× (hist. dostępność 16%); okno poranne 06-12: 1× (hist. dostępność 96%); okno popołudniowe 12-18: 1× (hist. dostępność 96%); okno wieczorne 18-24: 1× (hist. dostępność 16%)) < próg 5%*

**Zachowanie na syntetycznych historiach** (`liveness_test.go`, skan co 6 h, 14 dni historii, minima wyłączone):

| Historia hosta | Ile braków do INACTIVE | Dlaczego |
|---|---|---|
| Stabilny (zawsze odpowiadał) | **2** (z domyślnymi minimami decyduje okres 72 h: INACTIVE w pierwszym skanie po jego upływie) | brak u takiego hosta jest bardzo mało prawdopodobny |
| Niestabilny (~50% odpowiedzi) | **7** | braki są u niego normalne, więc potrzeba więcej dowodów |
| Działa tylko 07-19 | **nigdy w nocy**; po zniknięciu INACTIVE po 2 brakach w oknach dziennych | nocne braki są zgodne z harmonogramem |
| Wraca po przestoju | seria braków trafia do `β` jako przestój | dzięki temu model uczy się realnej dostępności hosta |

**Zgodność wsteczna.** Stany (NEW/ACTIVE/INTERMITTENT/MISSING/INACTIVE/REACTIVATED), pola API i zdarzenia (`HOST_MISSING`, `HOST_INACTIVE`, `EXPECTED_OFF_HOURS`, `TIME_ANOMALY`) zostają bez zmian. Dochodzą:
- `host.liveness`: `p_alive`, `p_up_slot`, `reason`, `threshold`, `model`;
- pola `alpha`, `beta`, `p_up`, `streak_misses` w `time_of_day_stats` (JSONB, bez migracji);
- `p_alive` i `liveness_reason` w `after` zdarzeń zmiany.

Hosty zapisane przed tą zmianą dostają model zainicjalizowany z liczników `seen/total`.

---

## 3. Pewność identyfikacji technologii: skalibrowany noisy-OR

**Model.** Każdy dowód działa jak niezależna „przyczyna”, która ujawnia technologię z prawdopodobieństwem `w`:
`P(tech | dowody) = 1 − Π (1 − w_kanał)`.

Dwie poprawki sprawiają, że ten model nie przecenia pewności:
1. **Dowody z tego samego kanału nie są niezależne.** Trzy wyrażenia regularne na tym samym HTML to jeden świadek, nie trzy. W obrębie kanału łączymy dowody, ale wynik nie przekracza limitu kanału. Mnożymy tylko między **różnymi** kanałami.
2. **Limit kanału to jego zmierzona wiarygodność:** precyzja wykryć opartych wyłącznie na tym kanale, zmierzona na ground truth laboratorium (`cmd/calibrate`). Na to nakładamy **sufit 80% dla pojedynczego kanału**, bo jedną odpowiedź HTTP łatwo podrobić. Pewność powyżej 80% wymaga potwierdzenia z niezależnego kanału albo bannera protokołu.

| Kanał | Waga (limit) | Uzasadnienie / pomiar (lab, n) |
|---|---|---|
| banner (nmap -sV, banner protokołu) | 0,90 | usługa sama się przedstawia we własnym protokole |
| favicon (MMH3/SHA-256) | 0,80 | dokładny hash, ale favikony bywają kopiowane |
| header (`Server`, `X-Powered-By`, nagłówki producenta) | 0,80 | precyzja 100% (1420); sufit, bo proxy/WAF podmieniają nagłówki |
| html (generator, tytuł, znaczniki) | 0,80 | precyzja 88% (252) |
| cookie (nazwa ciasteczka sesyjnego) | 0,75 | precyzja 100% (44); nazwy generyczne kolidują |
| tls (CN/wystawca certyfikatu, JARM) | 0,60 | identyfikuje stos TLS lub urządzenie, nie aplikację |
| path (trafienie w safe-path, np. `/metrics`) | 0,25 | precyzja **0%** (23): Grafana też wystawia `/metrics` |

Każda technologia w API ma pole `explanation` z rachunkiem, np. `html 0.80 ⊕ cookie 0.75 → 1-(0.20·0.25) = 95%`. Interfejs pokazuje go pod listą dowodów.

**Kalibracja (diagram niezawodności).** Laboratorium skalowe: 1441 usług HTTP, 2388 technologii w ground truth, 2316 predykcji, recall 94,8%.

| Przewidywana pewność | Przed: n | Przed: precyzja | Po: n | Po: precyzja |
|---|---|---|---|---|
| 0-49% | 0 | - | 23 | 0% (śr. przew. 25%) |
| 60-69% | 382 | 100% | 14 | 100% |
| 70-79% | 25 | 100% | 426 | 100% |
| 80-89% | 161 | **67%** (śr. przew. 85%) | 1513 | 98% |
| 90-94% | 92 | 100% | 16 | 100% |
| 95-100% | 1656 | 100% | 324 | 100% |
| **Nadmierna pewność (OCE)** | | **1,3 pp** | | **0,2 pp** |
| ECE (dwustronny) | | 8,8 pp | | 16,6 pp |

**Jak to czytać.** Stary model dawał 85-90% pojedynczemu trafieniu w ścieżkę (np. „Prometheus”, bo odpowiada `/metrics`), a w tym przedziale tylko 67% predykcji było trafnych. Nowy model nie przecenia pewności w żadnym przedziale powyżej 50%. Ceną jest zamierzona ostrożność: laboratorium jest „czyste” (nikt nie podmienia nagłówków), więc wykrycia z jednego nagłówka są w nim zawsze trafne, a my i tak pokazujemy dla nich 78-80%. W prawdziwej sieci proxy, WAF-y i load balancery zmieniają nagłówki. Dlatego wolimy zaniżać pewność niż ją zawyżać. Pomiar powtórzysz poleceniem `calibrate -replay obs.jsonl` (bez sieci) albo zbierzesz nowe dane w kontenerze w `dzieciol-net`.

---

## 4. Permutowane skanowanie w stylu ZMap (osobny zespół)

Zamiast skanować adresy po kolei (10.0.0.1, .2, .3…, co przeciąża pojedyncze podsieci i routery) przechodzimy przestrzeń w pseudolosowej kolejności. Iterujemy po grupie multiplikatywnej modulo liczba pierwsza `p` większa od rozmiaru zakresu: `x_{i+1} = g · x_i mod p`, gdzie `g` to losowy generator. Każdy adres pojawia się dokładnie raz, kolejność jest pseudolosowa, a stan iteratora to jedna liczba. Pozwala to wznowić skan i podzielić go na fragmenty (sharding) bez listy adresów w pamięci. Obciążenie rozkłada się równomiernie na wszystkie podsieci, co wspiera wymóg bezpieczeństwa skanera.

---

## Bibliografia

1. J. Althouse, A. Smart, RJ Nunnally, M. Brady, *Easily Identify Malicious Servers on the Internet with JARM*, Salesforce Engineering, listopad 2020; implementacja referencyjna: github.com/salesforce/jarm (BSD-3-Clause).
2. A. Gelman i in., *Bayesian Data Analysis*, wyd. 3, CRC Press 2013, rozdz. 2 (model Beta-Bernoulli / beta-dwumianowy).
3. L. Quan, J. Heidemann, Y. Pradkin, *Trinocular: Understanding Internet Reliability Through Adaptive Probing*, ACM SIGCOMM 2013 (bayesowskie wnioskowanie o awarii z pustych sond przy znanej dostępności bloku; nasz model to wersja per host i per okno doby).
4. L. Quan, J. Heidemann, Y. Pradkin, *When the Internet Sleeps: Correlating Diurnal Networks With External Factors*, ACM IMC 2014 (dobowe wzorce dostępności hostów).
5. R. Kulhavý, M. B. Zarrop, *On a general concept of forgetting*, International Journal of Control 58(4), 1993 (zapominanie wykładnicze w estymacji bayesowskiej).
6. R. P. Adams, D. J. C. MacKay, *Bayesian Online Changepoint Detection*, arXiv:0710.3742, 2007 (pokrewna idea: test „host istnieje” kontra „host zniknął” jako wykrywanie punktu zmiany).
7. J. Pearl, *Probabilistic Reasoning in Intelligent Systems*, Morgan Kaufmann 1988 (model noisy-OR); M. Henrion, *Some Practical Issues in Constructing Belief Networks*, UAI 1987.
8. M. H. DeGroot, S. E. Fienberg, *The Comparison and Evaluation of Forecasters*, The Statistician 32, 1983 (diagram niezawodności); C. Guo i in., *On Calibration of Modern Neural Networks*, ICML 2017 (ECE).
9. Z. Durumeric, E. Wustrow, J. A. Halderman, *ZMap: Fast Internet-wide Scanning and Its Security Applications*, USENIX Security 2013; D. Adrian i in., *Zippier ZMap: Internet-Wide Scanning at 10 Gbps*, USENIX WOOT 2014.
