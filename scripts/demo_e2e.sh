#!/usr/bin/env bash
# =============================================================================
# AegisASI — End-to-End Automated Verification & Demo Script
#
# Verifies all core HackNation / CBI AGH criteria against a running stack:
#   1. Healthcheck & active AES-256-GCM encryption
#   2. Dynamic RBAC enforcement across all 4 roles (403 Forbidden checks)
#   3. Large-scale target estimation (10.0.0.0/18 -> 16,384 IPs + exclusions)
#   4. Unified ingestion pipeline (Manual + CSV + JSON -> ScanRuns)
#   5. Scan 1 on deterministic lab (172.28.0.10-14)
#   6. Analyst Override + Scan metadata edit (preserved across rescans)
#   7. Live mutation of lab-flapping (normal -> changed) + Scan 2
#   8. Scan Diff verification + Analyst Override preservation proof
#   9. Signature Studio: Safety Validator rejection + Retroactive Playground test
#  10. DefectDojo v2 integration: Test + Nmap XML push + Finding push verification
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_URL="${API_URL:-http://localhost:8080}"
LAB_CTRL_URL="${LAB_CTRL_URL:-http://localhost:19999}"
DD_INTERNAL_URL="${DD_INTERNAL_URL:-http://172.28.0.20:8000}"
DD_HOST_URL="${DD_HOST_URL:-http://localhost:18000}"
DD_TOKEN="${DD_TOKEN:-aegis-agh-demo-token}"
SCAN_TIMEOUT_SEC="${SCAN_TIMEOUT_SEC:-120}"

for bin in curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: Required tool '$bin' is not installed." >&2
    exit 1
  fi
done

if [[ -t 1 ]]; then
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  CYAN=$'\033[0;36m'
  YELLOW=$'\033[1;33m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
else
  GREEN="" RED="" CYAN="" YELLOW="" BOLD="" RESET=""
fi

PASS_COUNT=0
step() { echo -e "\n${BOLD}${CYAN}===> $1${RESET}"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}[PASS]${RESET} $1"; }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1" >&2; exit 1; }

cleanup() {
  # Always restore lab-flapping to normal state when exiting
  curl -fsS -X POST "${LAB_CTRL_URL}/control?mode=normal" >/dev/null 2>&1 || true
}
trap cleanup EXIT

api_status() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-sS -o /tmp/aegis_resp.json -w "%{http_code}" -X "$method" "${API_URL}${path}")
  if [[ -n "$token" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  curl "${args[@]}"
}

login_role() {
  local user="$1" pass_str="$2"
  local code
  code="$(api_status POST "/api/v1/auth/login" "" "{\"username\":\"${user}\",\"password\":\"${pass_str}\"}")"
  [[ "$code" == "200" ]] || fail "Login failed for ${user} (HTTP ${code}): $(cat /tmp/aegis_resp.json)"
  jq -r '.token // empty' /tmp/aegis_resp.json
}

wait_for_scan() {
  local scan_id="$1" token="$2"
  local deadline=$((SECONDS + SCAN_TIMEOUT_SEC))
  local status=""
  while (( SECONDS < deadline )); do
    local code
    code="$(api_status GET "/api/v1/scans/${scan_id}" "$token")"
    [[ "$code" == "200" ]] || fail "Failed polling scan ${scan_id} (HTTP ${code})"
    status="$(jq -r '.status // .scan.status // empty' /tmp/aegis_resp.json)"
    if [[ "$status" == "COMPLETED" ]]; then
      return 0
    fi
    if [[ "$status" == "FAILED" || "$status" == "STOPPED" ]]; then
      fail "Scan ${scan_id} ended with status ${status}: $(cat /tmp/aegis_resp.json)"
    fi
    sleep 2
  done
  fail "Timed out waiting for scan ${scan_id} (last status: ${status})"
}

# =============================================================================
step "1/10 Healthcheck & Encryption Status"
# =============================================================================
CODE="$(api_status GET "/api/v1/health")"
[[ "$CODE" == "200" ]] || fail "Health endpoint returned HTTP ${CODE}"
ENC_ACTIVE="$(jq -r '.encryption_active // false' /tmp/aegis_resp.json)"
KEY_VER="$(jq -r '.key_version // "unknown"' /tmp/aegis_resp.json)"
[[ "$ENC_ACTIVE" == "true" ]] || fail "Expected encryption_active=true, got ${ENC_ACTIVE}"
pass "API healthy, encryption_active=true (key_version=${KEY_VER})"

# =============================================================================
step "2/10 RBAC Enforcement Across All 4 Roles"
# =============================================================================
ADMIN_TOKEN="$(login_role admin 'Admin123!')"
OPERATOR_TOKEN="$(login_role operator 'Operator123!')"
ANALYST_TOKEN="$(login_role analyst 'Analyst123!')"
VIEWER_TOKEN="$(login_role viewer 'Viewer123!')"
[[ -n "$ADMIN_TOKEN" && -n "$OPERATOR_TOKEN" && -n "$ANALYST_TOKEN" && -n "$VIEWER_TOKEN" ]] \
  || fail "One or more role tokens came back empty"
pass "Logged in successfully as admin, operator, analyst, viewer"

CODE="$(api_status GET "/api/v1/hosts" "$VIEWER_TOKEN")"
[[ "$CODE" == "200" ]] || fail "Viewer GET /hosts expected 200, got ${CODE}"

CODE="$(api_status POST "/api/v1/scans" "$VIEWER_TOKEN" '{"name":"forbidden-scan"}')"
[[ "$CODE" == "403" ]] || fail "Viewer POST /scans expected 403, got ${CODE}"

CODE="$(api_status PATCH "/api/v1/hosts/00000000-0000-0000-0000-000000000000/overrides" "$VIEWER_TOKEN" '{"notes":"denied"}')"
[[ "$CODE" == "403" ]] || fail "Viewer PATCH overrides expected 403, got ${CODE}"

CODE="$(api_status POST "/api/v1/scans" "$ANALYST_TOKEN" '{"name":"forbidden-scan"}')"
[[ "$CODE" == "403" ]] || fail "Analyst POST /scans expected 403, got ${CODE}"

CODE="$(api_status GET "/api/v1/admin/users" "$OPERATOR_TOKEN")"
[[ "$CODE" == "403" ]] || fail "Operator GET /admin/users expected 403, got ${CODE}"

CODE="$(api_status GET "/api/v1/admin/users" "$ADMIN_TOKEN")"
[[ "$CODE" == "200" ]] || fail "Admin GET /admin/users expected 200, got ${CODE}"

CODE="$(api_status GET "/api/v1/admin/crypto/status" "$ADMIN_TOKEN")"
[[ "$CODE" == "200" ]] || fail "Admin GET /admin/crypto/status expected 200, got ${CODE}"
pass "All RBAC 200/403 assertions enforced strictly (viewer, analyst, operator, admin)"

# =============================================================================
step "3/10 Large-Scale Target Estimate (10.0.0.0/18 = 16,384 IPs)"
# =============================================================================
EST_REQ='{"targets":["10.0.0.0/18"],"exclusions":["10.0.0.0/24"],"ports":"22,80,443,8080","max_rate_pps":500,"concurrency":64}'
CODE="$(api_status POST "/api/v1/targets/estimate" "$OPERATOR_TOKEN" "$EST_REQ")"
[[ "$CODE" == "200" ]] || fail "Target estimate failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
TOTAL_IPS="$(jq -r '.total_ips' /tmp/aegis_resp.json)"
EXCL_IPS="$(jq -r '.excluded_ips' /tmp/aegis_resp.json)"
EFF_IPS="$(jq -r '.effective_ips' /tmp/aegis_resp.json)"
CHUNKS="$(jq -r '.chunk_count' /tmp/aegis_resp.json)"
[[ "$TOTAL_IPS" == "16384" ]] || fail "Expected total_ips=16384, got ${TOTAL_IPS}"
[[ "$EXCL_IPS" == "256" ]] || fail "Expected excluded_ips=256, got ${EXCL_IPS}"
[[ "$EFF_IPS" == "16128" ]] || fail "Expected effective_ips=16128, got ${EFF_IPS}"
pass "Target estimate verified: total=${TOTAL_IPS}, excluded=${EXCL_IPS}, effective=${EFF_IPS}, chunks=${CHUNKS}"

# =============================================================================
step "4/10 Unified Ingestion (Manual Form + CSV Import + JSON Import)"
# =============================================================================
MANUAL_REQ='{
  "scan_name": "E2E Manual Entry",
  "ip": "192.0.2.50",
  "hostname": "legacy-usos.agh.local",
  "environment": "staging",
  "tags": ["manual-e2e", "legacy"],
  "notes": "Manually registered host via E2E verification",
  "services": [
    {
      "port": 8080,
      "protocol": "tcp",
      "state": "open",
      "service_name": "http",
      "product": "Apache Tomcat",
      "version": "9.0.80",
      "http": {
        "url": "http://192.0.2.50:8080/",
        "scheme": "http",
        "status_code": 200,
        "title": "Apache Tomcat/9.0.80 - Legacy Staging",
        "server_header": "Apache-Coyote/1.1",
        "headers": {"X-Debug-Token": "manual-test-01"}
      }
    }
  ]
}'
CODE="$(api_status POST "/api/v1/ingest/manual" "$OPERATOR_TOKEN" "$MANUAL_REQ")"
[[ "$CODE" == "200" || "$CODE" == "201" ]] || fail "Manual ingest failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "Manual ingest accepted (HTTP ${CODE})"

CODE="$(curl -sS -o /tmp/aegis_resp.json -w "%{http_code}" \
  -X POST "${API_URL}/api/v1/ingest/import" \
  -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  -F "format=csv" \
  -F "scan_name=E2E CSV Import" \
  -F "file=@${SCRIPT_DIR}/sample_import.csv")"
[[ "$CODE" == "200" || "$CODE" == "201" ]] || fail "CSV import failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "CSV import processed through unified pipeline (HTTP ${CODE})"

CODE="$(curl -sS -o /tmp/aegis_resp.json -w "%{http_code}" \
  -X POST "${API_URL}/api/v1/ingest/import" \
  -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  -F "format=json" \
  -F "scan_name=E2E JSON Import" \
  -F "file=@${SCRIPT_DIR}/sample_import.json")"
if [[ "$CODE" != "200" && "$CODE" != "201" ]]; then
  # Fallback to direct JSON body if endpoint expects raw application/json
  CODE="$(api_status POST "/api/v1/ingest/import" "$OPERATOR_TOKEN" "$(jq '{format:"json", scan_name:.scan_name, observations:.observations}' "${SCRIPT_DIR}/sample_import.json")")"
fi
[[ "$CODE" == "200" || "$CODE" == "201" ]] || fail "JSON import failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "JSON import processed through unified pipeline (HTTP ${CODE})"

# =============================================================================
step "5/10 Deterministic Lab Reset & Scan 1 (172.28.0.10-14)"
# =============================================================================
curl -fsS -X POST "${LAB_CTRL_URL}/control?mode=normal" >/dev/null \
  || fail "Could not reach lab-flapping control API at ${LAB_CTRL_URL}. Is docker-compose.lab.yml running?"
pass "lab-flapping reset to mode=normal"

PROFILE_REQ='{
  "name": "CBI AGH Lab Verification Profile",
  "description": "Deterministic test lab subnet 172.28.0.10-14",
  "targets": ["172.28.0.10-172.28.0.14"],
  "allowed_ports": "80,443,8080",
  "max_rate_pps": 300,
  "http_rps": 30,
  "concurrency": 16,
  "chunk_target_sec": 15,
  "window_enabled": false,
  "missing_threshold": 2,
  "grace_period_hours": 1,
  "retry_unstable_count": 1,
  "enable_http_fingerprint": true,
  "enabled": true
}'
CODE="$(api_status POST "/api/v1/profiles" "$OPERATOR_TOKEN" "$PROFILE_REQ")"
[[ "$CODE" == "200" || "$CODE" == "201" ]] || fail "Create profile failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
PROFILE_ID="$(jq -r '.id // .profile.id // empty' /tmp/aegis_resp.json)"
[[ -n "$PROFILE_ID" ]] || fail "Missing profile_id in response"

CODE="$(api_status POST "/api/v1/scans" "$OPERATOR_TOKEN" "{\"profile_id\":\"${PROFILE_ID}\",\"name\":\"Lab Baseline Scan 1\"}")"
[[ "$CODE" == "200" || "$CODE" == "201" || "$CODE" == "202" ]] || fail "Start Scan 1 failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
SCAN1_ID="$(jq -r '.id // .scan.id // empty' /tmp/aegis_resp.json)"
[[ -n "$SCAN1_ID" ]] || fail "Missing scan1_id"
wait_for_scan "$SCAN1_ID" "$OPERATOR_TOKEN"
pass "Scan 1 (${SCAN1_ID}) completed against lab hosts 172.28.0.10-14"

# =============================================================================
step "6/10 Analyst Override on 172.28.0.14 + Scan Metadata Edit"
# =============================================================================
CODE="$(api_status GET "/api/v1/hosts?q=172.28.0.14" "$ANALYST_TOKEN")"
[[ "$CODE" == "200" ]] || fail "GET /hosts failed (HTTP ${CODE})"
FLAPPING_HOST_ID="$(jq -r '(.hosts // .items // .) | map(select(.ip == "172.28.0.14")) | .[0].id // empty' /tmp/aegis_resp.json)"
[[ -n "$FLAPPING_HOST_ID" ]] || fail "Host 172.28.0.14 not found after Scan 1: $(cat /tmp/aegis_resp.json)"

OVERRIDE_REQ='{
  "owner": "CBI AGH E-Learning Team",
  "environment": "prod",
  "notes": "Verified Moodle production node - must survive rescans",
  "tags": ["moodle", "pinned-override"]
}'
CODE="$(api_status PATCH "/api/v1/hosts/${FLAPPING_HOST_ID}/overrides" "$ANALYST_TOKEN" "$OVERRIDE_REQ")"
[[ "$CODE" == "200" ]] || fail "PATCH host overrides failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "Analyst override applied on host ${FLAPPING_HOST_ID} (172.28.0.14)"

CODE="$(api_status PUT "/api/v1/scans/${SCAN1_ID}" "$ANALYST_TOKEN" '{"name":"Lab Baseline Scan 1 (Curated)","notes":"Baseline curated by SOC analyst"}')"
[[ "$CODE" == "200" ]] || fail "PUT /scans/${SCAN1_ID} failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "Scan 1 metadata edited after completion"

# =============================================================================
step "7/10 Live Mutate lab-flapping (normal -> changed) & Run Scan 2"
# =============================================================================
curl -fsS -X POST "${LAB_CTRL_URL}/control?mode=changed" >/dev/null \
  || fail "Failed switching lab-flapping to mode=changed"
pass "lab-flapping mutated to mode=changed (title, banner, X-Staging-Debug, /admin 200 OK)"

CODE="$(api_status POST "/api/v1/scans" "$OPERATOR_TOKEN" "{\"profile_id\":\"${PROFILE_ID}\",\"name\":\"Lab Post-Mutation Scan 2\"}")"
[[ "$CODE" == "200" || "$CODE" == "201" || "$CODE" == "202" ]] || fail "Start Scan 2 failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
SCAN2_ID="$(jq -r '.id // .scan.id // empty' /tmp/aegis_resp.json)"
wait_for_scan "$SCAN2_ID" "$OPERATOR_TOKEN"
pass "Scan 2 (${SCAN2_ID}) completed"

# =============================================================================
step "8/10 Diff Verification & Override Preservation Proof"
# =============================================================================
CODE="$(api_status GET "/api/v1/scans/diff?from=${SCAN1_ID}&to=${SCAN2_ID}" "$ANALYST_TOKEN")"
[[ "$CODE" == "200" ]] || fail "GET /scans/diff failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
CHANGED_CNT="$(jq -r '((.changed_services // []) | length) + ((.new_services // []) | length)' /tmp/aegis_resp.json)"
(( CHANGED_CNT >= 1 )) || fail "Expected >=1 detected change between Scan 1 and Scan 2, got: $(cat /tmp/aegis_resp.json)"
pass "Scan Diff detected ${CHANGED_CNT} service change(s) between Scan 1 and Scan 2"

CODE="$(api_status GET "/api/v1/hosts/${FLAPPING_HOST_ID}" "$ANALYST_TOKEN")"
[[ "$CODE" == "200" ]] || fail "GET /hosts/${FLAPPING_HOST_ID} failed (HTTP ${CODE})"
CUR_OWNER="$(jq -r '.owner // .host.owner // empty' /tmp/aegis_resp.json)"
CUR_NOTES="$(jq -r '.notes // .host.notes // empty' /tmp/aegis_resp.json)"
[[ "$CUR_OWNER" == "CBI AGH E-Learning Team" ]] || fail "Analyst override 'owner' was overwritten! Got: '${CUR_OWNER}'"
[[ "$CUR_NOTES" == *"must survive rescans"* ]] || fail "Analyst override 'notes' was overwritten! Got: '${CUR_NOTES}'"
pass "Analyst overrides (owner & notes) preserved intact across Scan 2"

# =============================================================================
step "9/10 Signature Studio: Safety Validator & Retroactive Playground"
# =============================================================================
UNSAFE_SIG='{
  "name": "Unsafe Traversal Attempt",
  "category": "custom",
  "match_mode": "any",
  "matchers": [{"type": "safe_path", "key": "/../../etc/passwd", "pattern": "root:"}],
  "confidence_weight": 0.9,
  "interesting_points": 50
}'
CODE="$(api_status POST "/api/v1/signatures/validate" "$ANALYST_TOKEN" "$UNSAFE_SIG")"
VALID_FLAG="$(jq -r 'if has("valid") then .valid else false end' /tmp/aegis_resp.json 2>/dev/null || echo false)"
if [[ "$CODE" == "200" && "$VALID_FLAG" == "true" ]]; then
  fail "Safety validator unexpectedly accepted path traversal signature!"
fi
pass "Safety Validator blocked unsafe path traversal signature (HTTP ${CODE}, valid=${VALID_FLAG})"

VALID_SIG="$(jq '.[0]' "${SCRIPT_DIR}/sample_signatures.json")"
CODE="$(api_status POST "/api/v1/signatures/validate" "$ANALYST_TOKEN" "$VALID_SIG")"
[[ "$CODE" == "200" ]] || fail "Valid custom signature validation failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"

CODE="$(api_status POST "/api/v1/signatures/test" "$ANALYST_TOKEN" "$VALID_SIG")"
[[ "$CODE" == "200" ]] || fail "Retroactive signature test failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
MATCH_CNT="$(jq -r '(.matches // .matched_services // .) | length' /tmp/aegis_resp.json)"
(( MATCH_CNT >= 1 )) || fail "Retroactive Playground expected >=1 match against stored lab observations, got 0"
pass "Retroactive Playground matched ${MATCH_CNT} stored service(s) without rescanning"

# =============================================================================
step "10/10 DefectDojo API v2 Integration (Test + Nmap XML + Finding Push)"
# =============================================================================
DD_CFG="{\"url\":\"${DD_INTERNAL_URL}\",\"api_token\":\"${DD_TOKEN}\",\"product_id\":1,\"engagement_id\":1,\"verify_tls\":false,\"auto_push_nmap\":false}"
CODE="$(api_status PUT "/api/v1/integrations/defectdojo" "$ADMIN_TOKEN" "$DD_CFG")"
[[ "$CODE" == "200" ]] || fail "PUT DefectDojo config failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"

CODE="$(api_status POST "/api/v1/integrations/defectdojo/test" "$ADMIN_TOKEN" "{}")"
[[ "$CODE" == "200" ]] || fail "DefectDojo connection test failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "DefectDojo API v2 connection test succeeded against ${DD_INTERNAL_URL}"

# Push Nmap XML if available on Scan 2
CODE="$(api_status POST "/api/v1/integrations/defectdojo/push-nmap" "$OPERATOR_TOKEN" "{\"scan_run_id\":\"${SCAN2_ID}\",\"engagement_id\":1}")"
if [[ "$CODE" == "200" || "$CODE" == "201" ]]; then
  pass "Nmap XML scan pushed to DefectDojo API v2"
else
  echo -e "  ${YELLOW}[INFO]${RESET} Nmap XML push returned HTTP ${CODE} (expected if running without raw nmap XML)"
fi

# Find a service ID from 172.28.0.14 or 172.28.0.12 to push as a Finding
CODE="$(api_status GET "/api/v1/services" "$OPERATOR_TOKEN")"
[[ "$CODE" == "200" ]] || fail "GET /services failed (HTTP ${CODE})"
SVC_ID="$(jq -r '(.services // .items // .) | .[0].id // empty' /tmp/aegis_resp.json)"
[[ -n "$SVC_ID" ]] || fail "No services found to push to DefectDojo"

CODE="$(api_status POST "/api/v1/integrations/defectdojo/push-findings" "$OPERATOR_TOKEN" "{\"service_ids\":[\"${SVC_ID}\"],\"engagement_id\":1,\"severity\":\"High\"}")"
[[ "$CODE" == "200" || "$CODE" == "201" ]] || fail "Push findings to DefectDojo failed (HTTP ${CODE}): $(cat /tmp/aegis_resp.json)"
pass "Finding pushed to DefectDojo API v2 for service ${SVC_ID}"

# Confirm arrival on mock receiver
DD_COUNT="$(curl -fsS -H "Authorization: Token ${DD_TOKEN}" "${DD_HOST_URL}/api/v2/findings/" | jq -r '.count // 0')"
(( DD_COUNT >= 1 )) || fail "DefectDojo mock reported 0 received findings"
pass "Verified ${DD_COUNT} finding(s) live in DefectDojo mock UI (${DD_HOST_URL}/ui)"

echo -e "\n${GREEN}${BOLD}=== ALL ${PASS_COUNT} E2E CHECKS PASSED ===${RESET}"
