# Dzięcioł scale lab

A local test range that gives Dzięcioł a realistic large network: a whole
`10.66.0.0/18` (16,384 IPs) with ~1,500 live hosts, served by one Go binary on
one Linux box or container, plus a ground-truth API and an accuracy scorer.
It exists so we can prove the scanner at 10k+ IPs, with two scan runs and
change detection, before the jury tests us in their lab.

Nothing here touches real networks: the address space lives on a dummy
interface and dead addresses are blackholed.

```
 scanner (nmap / Dzięcioł)                      scale lab (Linux netns or host)
 ───────────────────────────    route 10.66/18  ─────────────────────────────────────────
  nmap -sn / -sT -sV  ───────────────────────▶  uplink (eth0 / enp7s0)  [tc netem: delay, jitter, loss]
  HTTP fingerprinting                           iptables SCALELAB: ICMP-blocking + firewalled (DROP) hosts
                                                 dummy iface scl0: one /32 per *live* host
                                                 blackhole 10.66.0.0/18: dead IPs never answer
                                                 scalelab: ~4,000 ip:port listeners, ~30 product personalities
                                                 control API :9900  (/truth, /scenario, /mark, /stats)
```

## Layout

| Path | What |
|---|---|
| `cmd/scalelab` | emulator + control API (single static binary) |
| `cmd/scorer` | compares Dzięcioł JSON exports to ground truth, prints markdown |
| `internal/plan` | deterministic population generator (seeded) and scenario B mutations |
| `internal/emu` | HTTP personalities (`apps.go`), wire protocols (`protocols.go`), TLS certs, runtime, truth builder |
| `internal/netcfg` | `ip` / `tc` / `iptables` plumbing, degrades gracefully |
| `deploy/` | systemd unit + env for a native Linux host, compose file for a scanner host |
| `../../docker-compose.scale.yml` | local Docker lab on `dzieciol-net` (172.28.0.66) + optional `scale-runner` |
| `../../scripts/scale_test.sh` | end-to-end driver: 2 scans via the API, scenario switch, exports, score |

Separate Go module, standard library only; it does not touch `backend/go.mod`.

## What the lab contains

Defaults: `SCALE_HOSTS=1500`, `SCALE_SEED=1337`, 28 distinct TCP ports, ~4,000 listeners.

**Personalities** (modelled on what the real products put on the wire: headers,
cookies, titles, redirects, version leaks; *not* tuned to our fingerprinter):

- CMS: WordPress (meta generator, `wp-content`, `wp-json` Link header, `/wp-login.php`
  with `wordpress_test_cookie`, `/wp-admin` → login redirect, `/readme.html`, `/feed/` generator),
  Joomla (generator, random-hex session cookie, `/administrator/`, `joomla.xml` manifest),
  Drupal 7/9/10 (`X-Generator`, `X-Drupal-Cache`, 1978 `Expires`), Moodle (`MoodleSession`).
- Dev/ops: Jenkins (`X-Jenkins`, `X-Hudson`, Jetty, 403 + login redirect), Grafana (`/` → `/login`,
  `grafanaBootData` version, `/api/health`, `/metrics`), phpMyAdmin (cookies + `?v=` asset versions + 3306),
  Tomcat (default page, `/manager/html` 401 Basic), GitLab (`/users/sign_in`, `_gitlab_session`,
  `X-Gitlab-Meta`), Keycloak (welcome page, admin console), Kibana (`kbn-name`, injected version) +
  Elasticsearch 7 (open, version JSON) / 8 (401), Prometheus, Zabbix, Roundcube + Postfix/Dovecot.
- Windows: IIS default page, IIS + ASP.NET MVC app (`X-AspNet-Version`, `X-AspNetMvc-Version`,
  `ASP.NET_SessionId`, `/admin` → login), RDP (X.224 confirm), 135/139/445.
- Appliances / IoT: Synology DSM 6/7, MikroTik RouterOS (webfig with version, ROSSSH, MikroTik FTP,
  telnet, winbox 8291), HP LaserJet EWS (long `Server` header, 9100/631), Brother (`debut/1.30`),
  Hikvision camera (`webserver`, JS redirect to `/doc/page/login.asp`, RTSP 554 with Digest realm, 8000),
  CUPS, Dell iDRAC.
- Staging / misconfig: Express staging apps (`X-Powered-By: Express`, staging banners, version
  endpoints, `connect.sid`), Spring Boot (Whitelabel, `/actuator/info`), Django `runserver` with
  `DEBUG=True` 404 pages and `/admin/`, "TEST -" Apache/PHP apps with `PHPSESSID` (no
  HttpOnly/Secure), custom PHP admin panels with footer versions.
- Plain servers: nginx and Apache default pages with/without versions (incl. `ServerTokens Prod`),
  http → https redirects.
- Banners: OpenSSH (Ubuntu/Debian/RHEL builds), vsftpd/ProFTPD, Postfix/Exim, Dovecot POP3/IMAP,
  MySQL/MariaDB handshakes, PostgreSQL error packets, Redis (open `INFO` or `NOAUTH`).
- TLS on 443/5001/8443: certs minted at handshake time, `valid` (internal CA), `self_signed`, `expired`.

**Network behaviour**

- dead IPs: blackhole route, no RST, no ICMP (scanners time out)
- `tc netem` on the uplink: 3 ms ± 2 ms delay, 0.1 % loss (`SCALE_NETEM`, `off` disables)
- ~12 % of hosts (40 % of Windows) drop all ICMP: only TCP-discoverable
- ~15 % are firewalled: closed ports are DROPped (filtered) instead of RST
- ~2 % are both, so a default `nmap -sn` (ICMP echo/timestamp, SYN 443, ACK 80) misses them unless 80/443 is open
- 15 flapping hosts (up for half of a 120-240 s period) and 12 time-of-day hosts (up `07-19` Europe/Warsaw)

**Scenario B** ("a week later") relative to A: +75 new hosts, −45 gone hosts, +45 new ports
(MySQL, Redis, Jenkins, vsftpd, Django dev, Prometheus), −45 closed ports, ~60 hosts with version
upgrades (OpenSSH, nginx, Apache, WordPress, Jenkins, Grafana, Tomcat) and ~20 default pages that became
real apps (title + tech change).

## Control API

| Call | Purpose |
|---|---|
| `GET /health`, `GET /stats` | status, listeners, hosts up now, hosts toggled since mark, warnings |
| `GET /scenario`, `POST /scenario {"name":"B"}` | read / switch scenario (listeners, filters, addresses) |
| `POST /mark` | start an observation window; hosts whose state changes after this get `toggled: true` |
| `GET /truth[?scenario=A]` | ground truth (see `internal/truth/truth.go`) |

Truth is also written at startup to `$SCALE_TRUTH_DIR/truth-{A,B}.json` (nominal, flapping state at that moment).

Per IP: `alive`, `archetype`, `hostname`, `icmp_blocked`, `firewalled`, `flapping`, `time_of_day`,
`toggled`, and per port: nmap-style `service`/`product`/`version`, `banner`, `technologies`
(canonical ids), `flags` (`admin_panel`, `staging`, `iot`), and for HTTP what a browser-like
`GET /` sees after redirects: title, server, meta generator, disclosed tech version,
interesting headers, missing security headers, cookies + insecure cookies, cert kind.
Truth HTTP data is produced by running the real handlers in-process, so it can't drift from what's on the wire.

## Running locally (Docker)

Needs the app stack (`docker-compose.yml`) running so `dzieciol-net` exists.

```bash
docker compose -f docker-compose.scale.yml up -d --build
docker exec dzieciol-app ip route replace 10.66.0.0/18 via 172.28.0.66   # app has NET_ADMIN
curl -s localhost:19900/stats | jq
# ad-hoc checks from the runner container (route preinstalled)
docker compose -f docker-compose.scale.yml --profile runner run --rm scale-runner \
  nmap -n -sn -PS22,80,443 --max-rate 1500 10.66.0.0/22
docker compose -f docker-compose.scale.yml --profile runner run --rm scale-runner \
  nmap -n -Pn -sV -p22,80,443,3306 10.66.0.136
```

The lab container needs `NET_ADMIN`; the compose file also sets `ip_nonlocal_bind`, a high
`nofile` limit and `mem_limit: 512m` (it uses ~100 MB).

## Running natively on a Linux host

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o scalelab ./cmd/scalelab
scp scalelab root@lab:/usr/local/bin/
scp deploy/scalelab.service root@lab:/etc/systemd/system/
scp deploy/scalelab.env.example root@lab:/etc/default/scalelab     # set SCALE_UPLINK, SCALE_CONTROL
ssh root@lab 'systemctl daemon-reload && systemctl enable --now scalelab'
```

On the scanner, route the CIDR to the lab (`ip route add 10.66.0.0/18 via <lab-ip>`), or use a
cloud network route. If a host daemon already owns a lab port on `0.0.0.0` (typically `sshd` on 22),
scalelab binds `ip:20022` and adds `iptables -t nat ... --dport 22 -j DNAT --to-destination :20022`.
The destination IP is preserved, so scanners still see `ip:22`. On SIGTERM it removes the dummy
interface, blackhole route, iptables chains and the netem qdisc.

## End-to-end scale test

```bash
scripts/scale_test.sh                                   # local docker: lab up, route, 2 scans, report
MODE=remote API=http://localhost:8080 LAB=http://10.0.0.3:9900 scripts/scale_test.sh   # e.g. on the scanner host
```

The driver logs in as `admin`, then for scenario A and B in turn: switches the scenario, `POST /mark`,
starts an ad-hoc scan of the whole CIDR (`allowed_ports` = every lab port, `max_rate_pps=1500`), polls
until `COMPLETED`, waits for ingest (`changes_detected`), dumps truth, and exports JSON/CSV by `scan_id`.
At the end it fetches `GET /api/v1/scans/diff` and runs the scorer. Output goes to `lab/scale/out/<ts>/`:
`report.md`, `summary.json`, `meta.json` (durations), truth, exports, `driver.log`.

## Scorer

```bash
go run ./cmd/scorer -truth1 out/x/truth-run1.json -export1 out/x/export-run1.json \
   -truth2 out/x/truth-run2.json -export2 out/x/export-run2.json -app-diff out/x/app-diff.json \
   -ports 22,80,443 -meta out/x/meta.json -out report.md
```

What it scores, per run:

- **Live hosts**: predicted alive = exported host in the lab CIDR with lifecycle ≠ MISSING/INACTIVE.
  It also reports a variant that counts only hosts with ≥1 open port, plus recall split by network class
  (normal / ICMP-blocked / firewalled / both) and by archetype.
- **Open ports** (`ip:port`, only ports that were scanned).
- **Service name** (equivalence classes: `http≡https≡ssl/http≡http-alt…`, `microsoft-ds≡netbios-ssn`),
  **product** and **version**, scored on correctly found ports where the wire discloses them.
- **Web technologies / CMS**: host-level sets of canonical ids. App names are normalised (`Apache HTTP Server`→`apache`).
  Generic findings (admin panel, staging, header/cookie/TLS findings) are excluded, and banner products
  (OpenSSH, MySQL…) are left to product accuracy. There is a per-technology table.
- **Flags** `admin_panel` / `staging` / `iot` (host level; staging also accepts host `environment`).
- **HTTP details**: title and `Server` exact match, interesting headers (names, excluding `Server`),
  insecure cookies, missing HSTS/CSP/XFO/XCTO, self-signed / expired certificates.
- **Unstable hosts**: flapping hosts, plus any host that toggled during the scan, are excluded from every
  metric above and listed separately with the app's lifecycle state.
- **Change detection**: the expected diff comes from truth A vs B (flapping, toggled and time-of-day
  hosts excluded). It is scored twice: against the diff derived from the two exports (scanner
  observation quality) and against the app's own `/scans/diff` (new/gone hosts, new/closed ports, changed services).

Judgement calls in the truth: "admin panel" means an unauthenticated management/login console of an admin
tool (WordPress `wp-admin`, Joomla administrator, Jenkins, Grafana, phpMyAdmin, Tomcat manager, Keycloak,
Kibana, Zabbix, router/NAS/BMC UIs, custom `/admin`). Generic user logins (GitLab, Roundcube,
Moodle, ASP.NET app logins) don't count. "IoT" means printers, cameras, NAS, routers and BMCs.

## Knobs

`SCALE_CIDR`, `SCALE_HOSTS`, `SCALE_SEED`, `SCALE_UPLINK`, `SCALE_NETEM`, `SCALE_CONTROL`,
`SCALE_FLAP_HOSTS`, `SCALE_FLAP_PERIOD`, `SCALE_TOD_HOSTS`, `SCALE_TOD_HOURS`, `SCALE_TZ`,
`SCALE_TRUTH_DIR`, `SCALE_IFACE`, `SCALE_SCENARIO` (all also available as flags, see `scalelab -h`).
`scalelab -plan-only -truth-dir /tmp/t` writes the truth files without touching the network.
