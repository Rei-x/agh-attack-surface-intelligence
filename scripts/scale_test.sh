#!/usr/bin/env bash
# =============================================================================
# Dzięcioł scale test: two full scans of the scale lab (/18 by default) through
# the Dzięcioł API, a scenario switch in between, exports, and an accuracy report.
#
# Local Docker (lab container + running app stack from docker-compose.yml):
#   scripts/scale_test.sh
#
# Remote (lab and app already running elsewhere, e.g. Hetzner):
#   MODE=remote API=http://49.12.19.130:8080 LAB=http://10.0.0.3:9900 scripts/scale_test.sh
#
# Environment knobs (defaults in brackets):
#   MODE        docker | remote                                   [docker]
#   API         Dzięcioł base URL                                 [http://localhost:8080]
#   LAB         scale-lab control API                             [http://localhost:19900]
#   LAB_CURL    command prefix used to reach LAB (e.g. "ssh root@host curl") [curl]
#   SCALE_CIDR  scope to scan                                     [10.66.0.0/18]
#   PORTS       comma list of ports to scan                       [all lab ports from /stats]
#   RATE        max_rate_pps for the scan profile                 [1500]
#   CONCURRENCY profile concurrency                               [64]
#   DZIECIOL_USER / DZIECIOL_PASS                                           [admin / Admin123!]
#   RUNS        1 or 2 (2 = switch to scenario B and rescan)      [2]
#   SCAN_TIMEOUT seconds per scan before giving up                [10800]
#   OUT         output directory                                  [lab/scale/out/<timestamp>]
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${MODE:-docker}"
API="${API:-http://localhost:8080}"
LAB="${LAB:-http://localhost:19900}"
LAB_CURL="${LAB_CURL:-curl}"
SCALE_CIDR="${SCALE_CIDR:-10.66.0.0/18}"
RATE="${RATE:-1500}"
CONCURRENCY="${CONCURRENCY:-64}"
DZIECIOL_USER="${DZIECIOL_USER:-admin}"
DZIECIOL_PASS="${DZIECIOL_PASS:-Admin123!}"
RUNS="${RUNS:-2}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-10800}"
POLL="${POLL:-10}"
OUT="${OUT:-$ROOT/lab/scale/out/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/driver.log" >&2; }
die() { log "FATAL: $*"; exit 1; }
need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }
need curl
need jq

lab() { # lab METHOD PATH [JSON]
  local m="$1" p="$2" d="${3:-}"
  if [[ -n "$d" ]]; then
    $LAB_CURL -fsS -X "$m" -H 'Content-Type: application/json' -d "$d" "$LAB$p"
  else
    $LAB_CURL -fsS -X "$m" "$LAB$p"
  fi
}

TOKEN=""
api() { # api METHOD PATH [JSON]
  local m="$1" p="$2" d="${3:-}"
  local args=(-fsS -X "$m" -H "Authorization: Bearer $TOKEN" --max-time 600)
  [[ -n "$d" ]] && args+=(-H 'Content-Type: application/json' -d "$d")
  curl "${args[@]}" "$API$p"
}

# ---------------------------------------------------------------- 1. lab up
if [[ "$MODE" == "docker" ]]; then
  need docker
  log "building + starting scale lab container"
  docker compose -f "$ROOT/docker-compose.scale.yml" up -d --build >>"$OUT/driver.log" 2>&1 || die "compose up failed"
  for i in $(seq 1 60); do lab GET /health >/dev/null 2>&1 && break; sleep 2; done
  APP_CT="${APP_CT:-dzieciol-app}"
  if docker inspect "$APP_CT" >/dev/null 2>&1; then
    log "adding route $SCALE_CIDR via 172.28.0.66 inside $APP_CT"
    docker exec "$APP_CT" ip route replace "$SCALE_CIDR" via 172.28.0.66 || die "could not add route in $APP_CT (needs NET_ADMIN)"
  else
    log "WARNING: container $APP_CT not found; make sure the scanner can route $SCALE_CIDR to 172.28.0.66"
  fi
fi
lab GET /health >/dev/null || die "lab control API $LAB not reachable"
lab GET /stats >"$OUT/lab-stats-start.json"
if [[ -z "${PORTS:-}" ]]; then
  PORTS="$(jq -r '.ports | map(tostring) | join(",")' "$OUT/lab-stats-start.json")"
fi
log "lab: $(jq -c '{scenario,scenario_hosts,up_now,listeners,warnings}' "$OUT/lab-stats-start.json")"
log "ports: $PORTS"

# ---------------------------------------------------------------- 2. login
curl -fsS "$API/api/v1/health" >"$OUT/app-health.json" || die "API $API not reachable"
TOKEN="$(curl -fsS -X POST -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$DZIECIOL_USER" --arg p "$DZIECIOL_PASS" '{username:$u,password:$p}')" \
  "$API/api/v1/auth/login" | jq -r .token)"
[[ -n "$TOKEN" && "$TOKEN" != null ]] || die "login failed"
log "logged in as $DZIECIOL_USER; app: $(jq -c . "$OUT/app-health.json")"

META="$OUT/meta.json"
echo '{}' >"$META"
meta() { local t; t="$(mktemp)"; jq --arg k "$1" --argjson v "$2" '.[$k]=$v' "$META" >"$t" && mv "$t" "$META"; }
meta lab_cidr "\"$SCALE_CIDR\""
meta max_rate_pps "$RATE"
meta concurrency "$CONCURRENCY"
meta ports_scanned "$(awk -F, '{print NF}' <<<"$PORTS")"

# ---------------------------------------------------------------- 3. scan helper
run_scan() { # run_scan N SCENARIO
  local n="$1" sc="$2"
  log "=== run $n: scenario $sc ==="
  lab POST /scenario "{\"name\":\"$sc\"}" >/dev/null || die "scenario switch failed"
  sleep 3
  lab POST /mark >/dev/null
  local body id t0 t1 t2 st
  body="$(jq -nc --arg n "scale-run$n-$sc" --arg c "$SCALE_CIDR" --arg p "$PORTS" \
    --argjson r "$RATE" --argjson cc "$CONCURRENCY" \
    '{name:$n,targets:[$c],allowed_ports:$p,max_rate_pps:$r,concurrency:$cc,notes:"scale lab automated run"}')"
  t0=$(date +%s)
  id="$(api POST /api/v1/scans "$body" | jq -r .id)"
  [[ -n "$id" && "$id" != null ]] || die "scan start failed"
  log "scan $id started"
  echo "$id" >"$OUT/scan-run$n.id"
  while :; do
    sleep "$POLL"
    if ! api GET "/api/v1/scans/$id" >"$OUT/scan-run$n.json" 2>/dev/null; then
      log "  (poll failed, retrying)"; continue
    fi
    st="$(jq -r .status "$OUT/scan-run$n.json")"
    log "  status=$st chunks=$(jq -r '"\(.completed_chunks)/\(.total_chunks)"' "$OUT/scan-run$n.json") active=$(jq -r .active_hosts "$OUT/scan-run$n.json") services=$(jq -r .services_found "$OUT/scan-run$n.json") eta=$(jq -r .eta_seconds "$OUT/scan-run$n.json")s"
    case "$st" in
      COMPLETED) break ;;
      FAILED|STOPPED) die "scan $id ended with $st" ;;
    esac
    (( $(date +%s) - t0 > SCAN_TIMEOUT )) && die "scan $id timed out after ${SCAN_TIMEOUT}s"
  done
  t1=$(date +%s)
  # Ingest (diff, lifecycle, snapshot) runs after the engine reports COMPLETED.
  log "scan engine finished in $((t1 - t0))s; waiting for ingest/snapshot"
  local base_changes; base_changes=0
  for i in $(seq 1 120); do
    api GET "/api/v1/scans/$id" >"$OUT/scan-run$n.json" 2>/dev/null || true
    [[ "$(jq -r '.changes_detected // 0' "$OUT/scan-run$n.json")" -gt "$base_changes" ]] && break
    sleep 5
  done
  t2=$(date +%s)
  lab GET /truth >"$OUT/truth-run$n.json"
  lab GET /stats >"$OUT/lab-stats-run$n.json"
  api GET "/api/v1/export?format=json&scan_id=$id" >"$OUT/export-run$n.json" || die "export failed"
  api GET "/api/v1/export?format=csv&scan_id=$id" >"$OUT/export-run$n.csv" || true
  log "run $n: engine $((t1 - t0))s, ingest $((t2 - t1))s, export hosts=$(jq .count "$OUT/export-run$n.json"), toggled during scan=$(jq .toggled_since_mark "$OUT/lab-stats-run$n.json")"
  meta "run${n}_scenario" "\"$sc\""
  meta "run${n}_engine_seconds" "$((t1 - t0))"
  meta "run${n}_ingest_wait_seconds" "$((t2 - t1))"
  meta "run${n}_app_duration_ms" "$(jq '.duration_ms // 0' "$OUT/scan-run$n.json")"
  meta "run${n}_app_total_ips" "$(jq '.total_ips // 0' "$OUT/scan-run$n.json")"
  meta "run${n}_app_chunks" "$(jq '.total_chunks // 0' "$OUT/scan-run$n.json")"
  meta "run${n}_app_active_hosts" "$(jq '.active_hosts // 0' "$OUT/scan-run$n.json")"
  meta "run${n}_app_hosts_per_sec" "$(jq '.hosts_per_sec // 0' "$OUT/scan-run$n.json")"
}

run_scan 1 A
ARGS=(-truth1 "$OUT/truth-run1.json" -export1 "$OUT/export-run1.json")
if [[ "$RUNS" == "2" ]]; then
  run_scan 2 B
  api GET "/api/v1/scans/diff?from=$(cat "$OUT/scan-run1.id")&to=$(cat "$OUT/scan-run2.id")" >"$OUT/app-diff.json" || log "WARNING: app diff fetch failed"
  ARGS+=(-truth2 "$OUT/truth-run2.json" -export2 "$OUT/export-run2.json")
  [[ -s "$OUT/app-diff.json" ]] && ARGS+=(-app-diff "$OUT/app-diff.json")
  log "app diff summary: $(jq -c .summary "$OUT/app-diff.json" 2>/dev/null)"
fi

# ---------------------------------------------------------------- 4. score
ARGS+=(-ports "$PORTS" -meta "$META" -out "$OUT/report.md" -json "$OUT/summary.json")
if command -v go >/dev/null; then
  (cd "$ROOT/lab/scale" && go run ./cmd/scorer "${ARGS[@]}")
elif command -v scorer >/dev/null; then
  scorer "${ARGS[@]}"
elif command -v docker >/dev/null; then
  docker run --rm -v "$OUT:$OUT" --entrypoint scorer dzieciol-scalelab:local "${ARGS[@]}"
else
  die "no way to run the scorer (need go, scorer binary or docker)"
fi
log "report: $OUT/report.md"
jq -c '{run1: .run1 | {hosts: .hosts.f1, ports: .ports.f1, tech: .tech.f1}, run2: (.run2 // {} | {hosts: .hosts.f1?, ports: .ports.f1?, tech: .tech.f1?})}' "$OUT/summary.json" | tee -a "$OUT/driver.log"
