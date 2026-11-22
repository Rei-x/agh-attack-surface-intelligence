# Testing Dziecioł with the jury lab template

This page shows how to point Dziecioł at the lab template published for the final
evaluation (`docker-compose-modern.yml`, `-modern-proxy.yml`, `-vulnerable.yml`,
`-custom-network.yml`, `quickstart.sh`) and what it reports for each stack. Everything
below was rehearsed on a clean Ubuntu 24.04 VM with Docker 29, nmap 7.94 and Google Chrome
(for screenshots); the table at the end is the output of `scripts/jury_lab_test.sh` there.

## 1. Get the binary

```bash
make build                 # or use a release binary: bin/dzieciol
sudo apt install nmap      # recommended: service versions come from nmap -sV
```

Without nmap Dziecioł falls back to its own TCP scanner and protocol probes (all ports
are still found; fewer versions are named). Google Chrome or Chromium on the PATH enables
page screenshots; nothing else is needed.

## 2. Scan from the terminal (one line)

Start one lab stack as its README says, then on the same machine:

```bash
dzieciol scan localhost          # or: dzieciol scan 127.0.0.1, or the host's LAN IP
```

Defaults that matter for the lab:

- **Ports are automatic.** 1 to 4 target IPs: all 65535 TCP ports (rate raised to 4000
  probes/s so one host takes about 20 to 60 s). Up to 1024 IPs: nmap's top 1000 plus common
  alternative web, admin, database and queue ports (3001, 5673, 8474, 8787, 15432, 15672, ...).
  Larger ranges keep the compact campus list. Override with `-p 1-65535` or `-p 22,80,8080`.
- **Localhost is scanned.** There is no hidden loopback exclusion any more. Exclusions you add
  yourself (Scans, Scope tab) still apply and the CLI says how many IPs they removed.
- **The host's own LAN IP works too**, also as root: for this machine's addresses Dziecioł
  uses connect scans, because raw SYN probes to a local IP do not see Docker-published ports.
- **Container IPs**: scan the containers' subnet as a /24 (`dzieciol scan 172.18.0.0/24`),
  not Docker's default /16 (65536 addresses would take a long time). Containers listen on
  their internal ports (80, 3000, 5432, 5672, 8080, ...), not on the published ones.
- Each run is stored in `~/.dzieciol` (encrypted). Running the same command again prints
  the changes against the previous run: new, closed and reopened services, version changes
  and response time jumps. `-o report.json` also writes the full JSON report.

The report lists every open port with its identification, the top findings (admin panels,
exposed databases, cleartext FTP, CVE hints), a table of HTTP response times (median over
about a dozen requests per web service) and the change summary.

## 3. Web UI (serve mode)

```bash
dzieciol serve --listen :9080    # http://localhost:9080, log in as admin / Admin123!
```

Use a port that is not in the lab: the default `:8080` is WordPress in the modern stack
(when 8080 is busy, `serve` picks 9080 by itself and prints the address). `dzieciol scan`
and `dzieciol serve` share one data store, so stop `serve` before a CLI scan, or start
scans in the UI:

- **Quick scan** (top bar) > preset **This machine (127.0.0.1)** or type the host IP > Start.
  Ports and rate are `auto` (shown under the estimate).
- For the quickstart scenario, create a profile (Scans > Profiles > New profile,
  targets `127.0.0.1`, ports `auto`) and press **Run** after each `./quickstart.sh` step. The
  **Diff** page compares the last two runs of the profile.
- Asset inspector (click a service): identification with evidence, admin panel flag,
  screenshot, CVE hints and the HTTP response time.

## 4. What to expect per stack

| Stack | Port | Reported as |
|---|---|---|
| modern | 80 | http, OpenResty (Nginx Proxy Manager default site) |
| | 81 | Nginx Proxy Manager 2.x, **admin panel** |
| | 443 | https (no certificate configured, TLS handshake fails) |
| | 6379 | Redis 7.4, exposed database, **no authentication** (PING answered) |
| | 8080 | WordPress (current version) on Apache, **unfinished installer (admin panel)** |
| | 8081 | phpMyAdmin 5.2, **admin panel** |
| modern-proxy | 8085 | WordPress behind Traefik and Toxiproxy (installer) |
| | 8086 | Traefik Dashboard / API 3.1, **admin panel** |
| | 8474 | Toxiproxy API 2.12, **admin panel** (can inject faults) |
| vulnerable | 21 | FTP vsftpd 3.0.2, cleartext login, CVE-2015-1419 hint; anonymous login is tested and reported if allowed |
| | 8088 | WordPress 4.7.x on Apache 2.4.10 / PHP 5.6 (PHP end of life), CVE-2017-16510 hint, installer exposed |
| | 8089 | Adminer, **admin panel** |
| | 8090 | DVWA 1.10 (intentionally vulnerable app, marked development) |
| | 21000-21010 | open, `tcpwrapped` (published FTP passive ports, no listener until a transfer) |
| custom-network | 2223 | ssh, OpenSSH (Gitea) |
| | 3001 | Gitea, **unfinished installer (admin panel)** |
| | 5673 | AMQP, RabbitMQ 3.13 |
| | 8787 | http, nginx default page |
| | 8888 | httpbin (gunicorn) |
| | 15432 | PostgreSQL, exposed database |
| | 15673 | RabbitMQ Management, **admin panel** |

Ports of the Docker host itself also appear: its SSH server (22), `dzieciol serve` if it runs
(9080) and any other local listener. They are not part of the lab.

### Quickstart (8787 disappears and comes back)

```bash
chmod +x quickstart.sh                            # the template ships it without the x bit
./quickstart.sh up;     dzieciol scan localhost   # baseline: 2223 3001 5673 8787 15673
./quickstart.sh change; dzieciol scan localhost   # - SERVICE_CLOSED 8787, nothing else
./quickstart.sh up;     dzieciol scan localhost   # + SERVICE_REOPENED 8787, nothing else
```

### Toxiproxy latency

With `ENABLE_LATENCY=true` and `LATENCY_MS=500` in `.env` (stack restarted), the WordPress
port 8085 answers about 500 ms slower. The scan still finds and identifies it (nothing
times out), the response time table shows the new median, and the second scan reports
`RESPONSE_TIME_CHANGED  Response time on 127.0.0.1:8085 N ms -> M ms (slower; median of K
requests)`. A change is reported when the median grows or shrinks at least 3 times and by
at least 200 ms.

### Switching stacks

Scanning a different stack with the same store reports the old stack's ports as
`SERVICE_CLOSED` and the new ones as `NEW_SERVICE` / `ADMIN_PANEL_EXPOSED`, so the diff reads
as "these services went away, these appeared".

## 5. Automated rehearsal

```bash
scripts/jury_lab_test.sh --lab /path/to/lab-template      # needs docker compose and jq
```

It starts each stack alone, scans it, checks every port above, repeats the scan (must report
no changes), runs the quickstart and latency scenarios and prints a PASS/FAIL table.
Options: `--only "vulnerable"`, `--skip-latency`, `--target <host IP>`, `--bin ./bin/dzieciol`.

## Rehearsal result

RESULT_TABLE_PLACEHOLDER
