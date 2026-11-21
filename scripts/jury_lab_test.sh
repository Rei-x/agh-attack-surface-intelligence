#!/usr/bin/env bash
# Rehearsal of the jury lab template (docker-compose-modern.yml, -modern-proxy.yml,
# -vulnerable.yml, -custom-network.yml, quickstart.sh) against Dziecioł.
#
# Starts one stack at a time (as the lab README asks), scans it with `dzieciol scan`, checks
# that every published port is found and identified, then runs the quickstart scenario
# (8787 disappears and comes back), the Toxiproxy latency scenario, a repeat scan that must
# report no changes, and prints a PASS/FAIL table.
#
# Usage:
#   scripts/jury_lab_test.sh --lab /path/to/lab-template [--bin dzieciol] [--target 127.0.0.1]
#                            [--only "modern vulnerable"] [--skip-quickstart] [--skip-latency]
#
# Needs: docker compose, jq, the dzieciol binary (nmap recommended). Run it on the docker
# host. Every scan uses its own data directory under $WORK (default /tmp/dzieciol-jury).
# It stops the lab stacks it starts; it never scans anything but --target.
set -uo pipefail

LAB=""
BIN="${DZIECIOL_BIN:-dzieciol}"
TARGET="127.0.0.1"
ONLY="modern modern-proxy vulnerable custom-network"
DO_QS=1
DO_LAT=1
WORK="${WORK:-/tmp/dzieciol-jury}"
WAIT_SEC="${WAIT_SEC:-240}"

while [ $# -gt 0 ]; do
  case "$1" in
    --lab) LAB="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --skip-quickstart) DO_QS=0; shift ;;
    --skip-latency) DO_LAT=0; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$LAB" ] && [ -f "$LAB/docker-compose-modern.yml" ] || { echo "--lab must point to the lab template directory" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
command -v "$BIN" >/dev/null || [ -x "$BIN" ] || { echo "dzieciol binary not found ($BIN)" >&2; exit 2; }
LAB="$(cd "$LAB" && pwd)"
mkdir -p "$WORK"

RESULTS=()
FAILS=0
record() { # record STATUS AREA CHECK DETAIL
  RESULTS+=("$1|$2|$3|$4")
  [ "$1" = PASS ] || FAILS=$((FAILS + 1))
  printf '  %-4s %-15s %-42s %s\n' "$1" "$2" "$3" "$4"
}

compose() { (cd "$LAB" && docker compose --env-file .env -f "docker-compose-$1.yml" "${@:2}"); }
all_down() { for s in modern modern-proxy vulnerable custom-network; do compose "$s" down >/dev/null 2>&1; done; }

wait_ports() { # wait_ports PORT... : until every port accepts TCP or WAIT_SEC passes
  local deadline=$(( $(date +%s) + WAIT_SEC )) p
  for p in "$@"; do
    until (exec 3<>"/dev/tcp/$TARGET/$p") 2>/dev/null; do
      [ "$(date +%s)" -ge "$deadline" ] && return 1
      sleep 2
    done
    exec 3>&- 2>/dev/null || true
  done
}

wait_http() { # wait_http PORT : until the port answers HTTP with a status < 500
  local deadline=$(( $(date +%s) + WAIT_SEC )) code
  while :; do
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "http://$TARGET:$1/" || true)
    case "$code" in 2*|3*|4*) return 0 ;; esac
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep 3
  done
}

scan() { # scan DATADIR OUT : one CLI scan with default (auto) settings
  "$BIN" scan --data-dir "$1" "$TARGET" -o "$2" >"$2.log" 2>&1
}

svc() { # svc JSON PORT : the service object of PORT
  jq -c --argjson p "$2" --arg ip "$TARGET" '[.hosts[] | select(.ip == $ip) | .services[] | select(.port == $p and .state == "open")][0] // empty' "$1"
}

# check_svc AREA JSON PORT REGEX [admin]
# REGEX is matched (case-insensitive) against "service product version techs tags banner".
check_svc() {
  local area="$1" json="$2" port="$3" re="$4" admin="${5:-}" s text
  s=$(svc "$json" "$port")
  if [ -z "$s" ]; then record FAIL "$area" "port $port open" "not found"; return; fi
  text=$(jq -r '[.service_name, .product, .version, (.technologies // [] | map(.name + " " + (.version // "")) | join(", ")), (.tags // [] | join(",")), .banner] | map(select(. != null and . != "")) | join(" | ")' <<<"$s")
  if grep -Eiq -- "$re" <<<"$text"; then
    record PASS "$area" "port $port: /$re/" "$(cut -c1-110 <<<"$text")"
  else
    record FAIL "$area" "port $port: /$re/" "$(cut -c1-110 <<<"$text")"
  fi
  if [ "$admin" = admin ]; then
    if [ "$(jq -r '.is_admin_panel' <<<"$s")" = true ]; then
      record PASS "$area" "port $port flagged as admin panel" ""
    else
      record FAIL "$area" "port $port flagged as admin panel" "is_admin_panel=false"
    fi
  fi
}

changes_of() { # changes_of JSON TYPE PORT : number of change events
  jq --arg t "$2" --argjson p "$3" '[.changes[] | select(.event_type == $t and .port == $p)] | length' "$1"
}

echo "Dziecioł jury lab rehearsal: lab=$LAB target=$TARGET binary=$(command -v "$BIN" || echo "$BIN")"
"$BIN" version 2>/dev/null | tail -1
[ -f "$LAB/.env" ] || cp "$LAB/.env.example" "$LAB/.env"

for stack in $ONLY; do
  echo
  echo "== stack $stack"
  all_down
  compose "$stack" up -d >/dev/null 2>&1 || { record FAIL "$stack" "docker compose up" "failed"; continue; }
  case "$stack" in
    modern) wait_ports 80 81 6379 8080 8081 && wait_http 8080 && wait_http 8081 && wait_http 81 ;;
    modern-proxy) wait_ports 8085 8086 8474 && wait_http 8085 ;;
    vulnerable) wait_ports 21 8088 8089 8090 && wait_http 8088 && wait_http 8090 ;;
    custom-network) wait_ports 2223 3001 5673 8787 8888 15432 15673 && wait_http 3001 && wait_http 15673 ;;
  esac || record FAIL "$stack" "services ready in ${WAIT_SEC}s" "continuing anyway"
  sleep 10
  dd="$WORK/data-$stack"; rm -rf "$dd"
  out="$WORK/$stack-1.json"
  t0=$(date +%s)
  if ! scan "$dd" "$out"; then record FAIL "$stack" "dzieciol scan $TARGET" "see $out.log"; continue; fi
  record PASS "$stack" "dzieciol scan $TARGET" "$(( $(date +%s) - t0 )) s, $(jq '[.hosts[].services[] | select(.state=="open")] | length' "$out") open services"
  case "$stack" in
    modern)
      check_svc "$stack" "$out" 80 'http.*(openresty|nginx)'
      check_svc "$stack" "$out" 81 'Nginx Proxy Manager' admin
      check_svc "$stack" "$out" 443 'https|ssl|http'
      check_svc "$stack" "$out" 6379 'redis.*[0-9]+\.[0-9]+.*redis-no-auth|redis-no-auth'
      check_svc "$stack" "$out" 8080 'WordPress [0-9]+\.[0-9]+'
      check_svc "$stack" "$out" 8081 'phpMyAdmin [0-9]+\.[0-9]+' admin
      ;;
    modern-proxy)
      check_svc "$stack" "$out" 8085 'WordPress'
      check_svc "$stack" "$out" 8086 'Traefik.*[0-9]+\.[0-9]+' admin
      check_svc "$stack" "$out" 8474 'Toxiproxy API [0-9]+\.[0-9]+' admin
      ;;
    vulnerable)
      check_svc "$stack" "$out" 21 'ftp.*vsftpd.*[0-9]+\.[0-9]+'
      check_svc "$stack" "$out" 8088 'WordPress 4\.7'
      check_svc "$stack" "$out" 8089 'Adminer [0-9]+\.[0-9]+' admin
      check_svc "$stack" "$out" 8090 'DVWA'
      s=$(svc "$out" 8088)
      if jq -e '(.known_vulns // [] | length > 0) or ((.outdated // []) | length > 0)' <<<"$s" >/dev/null 2>&1; then
        record PASS "$stack" "WordPress 4.7: CVE / EOL hint" "$(jq -r '[(.known_vulns // [])[].id] + [(.outdated // [])[] | (.product + " " + .version)] | join(", ")' <<<"$s")"
      else
        record FAIL "$stack" "WordPress 4.7: CVE / EOL hint" "none"
      fi
      ;;
    custom-network)
      check_svc "$stack" "$out" 2223 'ssh.*OpenSSH'
      check_svc "$stack" "$out" 3001 'Gitea' admin
      check_svc "$stack" "$out" 5673 'amqp.*RabbitMQ [0-9]+\.[0-9]+'
      check_svc "$stack" "$out" 8787 'http.*nginx'
      check_svc "$stack" "$out" 8888 'httpbin'
      check_svc "$stack" "$out" 15432 'postgres'
      check_svc "$stack" "$out" 15673 'RabbitMQ Management' admin
      ;;
  esac
  # A second scan of the unchanged stack must not report service changes. (The host itself
  # moves from NEW to ACTIVE on its second sighting: a HOST_STATE_CHANGED event, port 0.)
  out2="$WORK/$stack-2.json"
  if scan "$dd" "$out2"; then
    svcq='[.changes[] | select((.port // 0) > 0 and .event_type != "OUTDATED_VERSION")]'
    n=$(jq "$svcq | length" "$out2")
    if [ "$n" -eq 0 ]; then record PASS "$stack" "repeat scan: no service changes" "$(jq -r '[.changes[] | .event_type] | join(", ")' "$out2")"; else
      record FAIL "$stack" "repeat scan: no service changes" "$(jq -r "$svcq | map(.event_type + \" \" + (.port|tostring) + \": \" + .summary) | join(\"; \")" "$out2" | cut -c1-160)"; fi
  fi
done

if [ "$DO_QS" = 1 ]; then
  echo
  echo "== quickstart: 8787 disappears and comes back"
  all_down
  dd="$WORK/data-quickstart"; rm -rf "$dd"
  (cd "$LAB" && bash ./quickstart.sh up >/dev/null 2>&1) || record FAIL quickstart "quickstart.sh up" "failed"
  wait_http 3001; wait_http 15673; sleep 10
  scan "$dd" "$WORK/qs-1.json"
  for p in 2223 3001 5673 8787 15673; do
    [ -n "$(svc "$WORK/qs-1.json" $p)" ] && record PASS quickstart "scan 1: port $p open" "" || record FAIL quickstart "scan 1: port $p open" ""
  done
  (cd "$LAB" && bash ./quickstart.sh change >/dev/null 2>&1)
  scan "$dd" "$WORK/qs-2.json"
  [ "$(changes_of "$WORK/qs-2.json" SERVICE_CLOSED 8787)" -ge 1 ] && record PASS quickstart "scan 2: 8787 reported closed" "" || record FAIL quickstart "scan 2: 8787 reported closed" ""
  other=$(jq '[.changes[] | select((.port // 0) > 0 and .port != 8787 and .event_type != "OUTDATED_VERSION")] | length' "$WORK/qs-2.json")
  [ "$other" -eq 0 ] && record PASS quickstart "scan 2: other services unchanged" "" || record FAIL quickstart "scan 2: other services unchanged" "$(jq -r '[.changes[] | select((.port // 0) > 0 and .port != 8787) | .event_type + " " + (.port|tostring)] | join("; ")' "$WORK/qs-2.json")"
  (cd "$LAB" && bash ./quickstart.sh up >/dev/null 2>&1)
  sleep 5
  scan "$dd" "$WORK/qs-3.json"
  back=$(( $(changes_of "$WORK/qs-3.json" SERVICE_REOPENED 8787) + $(changes_of "$WORK/qs-3.json" NEW_SERVICE 8787) ))
  [ "$back" -ge 1 ] && record PASS quickstart "scan 3: 8787 reported back" "" || record FAIL quickstart "scan 3: 8787 reported back" ""
  other=$(jq '[.changes[] | select((.port // 0) > 0 and .port != 8787 and .event_type != "OUTDATED_VERSION")] | length' "$WORK/qs-3.json")
  [ "$other" -eq 0 ] && record PASS quickstart "scan 3: other services unchanged" "" || record FAIL quickstart "scan 3: other services unchanged" "$(jq -r '[.changes[] | select((.port // 0) > 0 and .port != 8787) | .event_type + " " + (.port|tostring)] | join("; ")' "$WORK/qs-3.json")"
  (cd "$LAB" && bash ./quickstart.sh down >/dev/null 2>&1)
fi

if [ "$DO_LAT" = 1 ]; then
  echo
  echo "== Toxiproxy latency (modern-proxy, LATENCY_MS=500)"
  all_down
  dd="$WORK/data-latency"; rm -rf "$dd"
  envf="$LAB/.env"
  cp "$envf" "$WORK/env.backup"
  sed -i.bak -e 's/^ENABLE_LATENCY=.*/ENABLE_LATENCY=false/' "$envf"
  compose modern-proxy up -d >/dev/null 2>&1; wait_http 8085; sleep 10
  scan "$dd" "$WORK/lat-1.json"
  before=$(svc "$WORK/lat-1.json" 8085 | jq -r '.http.median_response_ms // .http.response_time_ms // 0')
  sed -i.bak -e 's/^ENABLE_LATENCY=.*/ENABLE_LATENCY=true/' -e 's/^LATENCY_MS=.*/LATENCY_MS=500/' "$envf"
  compose modern-proxy down >/dev/null 2>&1
  compose modern-proxy up -d >/dev/null 2>&1; wait_http 8085; sleep 10
  scan "$dd" "$WORK/lat-2.json"
  after=$(svc "$WORK/lat-2.json" 8085 | jq -r '.http.median_response_ms // .http.response_time_ms // 0')
  [ -n "$(svc "$WORK/lat-2.json" 8085)" ] && record PASS latency "8085 still found with 500 ms latency" "" || record FAIL latency "8085 still found with 500 ms latency" ""
  [ "${after:-0}" -ge 400 ] && record PASS latency "response time recorded" "$before ms -> $after ms" || record FAIL latency "response time recorded" "$before ms -> $after ms"
  [ "$(changes_of "$WORK/lat-2.json" RESPONSE_TIME_CHANGED 8085)" -ge 1 ] && record PASS latency "RESPONSE_TIME_CHANGED event" "$(jq -r '[.changes[] | select(.event_type=="RESPONSE_TIME_CHANGED") | .summary][0]' "$WORK/lat-2.json")" || record FAIL latency "RESPONSE_TIME_CHANGED event" ""
  cp "$WORK/env.backup" "$envf"; rm -f "$envf.bak"
  compose modern-proxy down >/dev/null 2>&1
fi

all_down
echo
echo "RESULT TABLE"
printf '%-5s %-15s %-42s %s\n' STATUS AREA CHECK DETAIL
for r in "${RESULTS[@]}"; do IFS='|' read -r st ar ch de <<<"$r"; printf '%-5s %-15s %-42s %s\n' "$st" "$ar" "$ch" "$de"; done
echo
echo "$(( ${#RESULTS[@]} - FAILS )) passed, $FAILS failed. JSON reports and logs: $WORK"
[ "$FAILS" -eq 0 ]
