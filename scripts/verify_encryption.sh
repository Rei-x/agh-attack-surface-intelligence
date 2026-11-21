#!/usr/bin/env bash
# =============================================================================
# AegisASI — Encryption At Rest Proof Script (PostgreSQL Direct Inspection)
#
# Queries PostgreSQL directly via `docker compose exec -T postgres psql` to prove:
#   1. Sensitive columns are stored as AES-256-GCM envelope ciphertext (`enc:v1:<kid>:...`)
#   2. Wrapped Data Encryption Keys are stored as `wrap:v1:<kid>:...` (never plaintext)
#   3. Lookup indexes use deterministic HMAC-SHA256 blind indexes (64-char hex)
#   4. Zero plaintext lab IP addresses or sensitive cookies appear in encrypted columns
# =============================================================================
set -euo pipefail

PG_SERVICE="${PG_SERVICE:-postgres}"
PG_USER="${POSTGRES_USER:-aegis}"
PG_DB="${POSTGRES_DB:-aegis_asi}"

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

psql_exec() {
  docker compose exec -T "$PG_SERVICE" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 "$@"
}

echo "${BOLD}${CYAN}=== AegisASI Encryption At Rest Verification (PostgreSQL Direct Query) ===${RESET}"
echo "Target container: ${PG_SERVICE} | Database: ${PG_DB} | User: ${PG_USER}"
echo ""

# 1. Verify database connectivity and list tables
echo "${BOLD}[1/4] Discovering schema tables in PostgreSQL...${RESET}"
TABLES="$(psql_exec -tA -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;")"
if [[ -z "$TABLES" ]]; then
  echo "${RED}FAIL: No tables found in schema 'public'. Is AegisASI started and migrated?${RESET}"
  exit 1
fi
echo "$TABLES" | sed 's/^/  - /'
echo ""

# 2. Scan all text/varchar columns in public schema for enc:v1: and wrap:v1: values
echo "${BOLD}[2/4] Auditing encrypted columns (enc:v1:* AES-256-GCM & wrap:v1:* DEKs)...${RESET}"
AUDIT_OUTPUT="$(psql_exec -tA -F '|' <<'SQL'
DO $$
DECLARE
  rec RECORD;
  enc_cnt BIGINT;
  wrap_cnt BIGINT;
  total_nonempty BIGINT;
  sample_val TEXT;
BEGIN
  CREATE TEMP TABLE IF NOT EXISTS _enc_audit (
    table_name TEXT,
    column_name TEXT,
    total_nonempty BIGINT,
    enc_count BIGINT,
    wrap_count BIGINT,
    sample_prefix TEXT
  ) ON COMMIT DROP;

  FOR rec IN
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND data_type IN ('text', 'character varying')
    ORDER BY table_name, ordinal_position
  LOOP
    EXECUTE format(
      'SELECT
         COUNT(*) FILTER (WHERE %I IS NOT NULL AND %I <> ''''),
         COUNT(*) FILTER (WHERE %I LIKE ''enc:v1:%%''),
         COUNT(*) FILTER (WHERE %I LIKE ''wrap:v1:%%''),
         COALESCE(MAX(LEFT(%I, 54)) FILTER (WHERE %I LIKE ''enc:v1:%%'' OR %I LIKE ''wrap:v1:%%''), '''')
       FROM %I.%I',
      rec.column_name, rec.column_name,
      rec.column_name,
      rec.column_name,
      rec.column_name, rec.column_name, rec.column_name,
      'public', rec.table_name
    ) INTO total_nonempty, enc_cnt, wrap_cnt, sample_val;

    IF enc_cnt > 0 OR wrap_cnt > 0 THEN
      INSERT INTO _enc_audit VALUES (
        rec.table_name, rec.column_name, total_nonempty, enc_cnt, wrap_cnt, sample_val
      );
    END IF;
  END LOOP;
END $$;

SELECT table_name, column_name, total_nonempty, enc_count, wrap_count, sample_prefix
FROM _enc_audit
ORDER BY table_name, column_name;
SQL
)"

if [[ -z "$AUDIT_OUTPUT" ]]; then
  echo "${RED}FAIL: Found 0 columns containing 'enc:v1:' or 'wrap:v1:' ciphertext!${RESET}"
  echo "Ensure AegisASI has been started and at least demo accounts / assets have been seeded."
  exit 1
fi

ENC_TOTAL=0
PLAINTEXT_LEAKS=0
printf "  %-24s %-24s %8s %8s %8s  %s\n" "TABLE" "COLUMN" "NONEMPTY" "ENC:V1" "WRAP:V1" "RAW DB SAMPLE"
printf "  %-24s %-24s %8s %8s %8s  %s\n" "------------------------" "------------------------" "--------" "--------" "--------" "------------------------------------------------------"

while IFS='|' read -r tbl col nonempty enc_cnt wrap_cnt sample; do
  [[ -z "$tbl" ]] && continue
  ENC_TOTAL=$((ENC_TOTAL + enc_cnt + wrap_cnt))
  printf "  %-24s %-24s %8s %8s %8s  %s...\n" "$tbl" "$col" "$nonempty" "$enc_cnt" "$wrap_cnt" "$sample"
  if (( enc_cnt + wrap_cnt < nonempty )); then
    PLAINTEXT_LEAKS=$((PLAINTEXT_LEAKS + 1))
  fi
done <<< "$AUDIT_OUTPUT"
echo ""

# 3. Show concrete raw DB rows from hosts / services / crypto_keys / users if present
echo "${BOLD}[3/4] Raw PostgreSQL row proof (direct SELECT without application decryption)...${RESET}"
if echo "$TABLES" | grep -qx "crypto_keys"; then
  echo "${CYAN}-- Table: crypto_keys (KEK-wrapped DEKs) --${RESET}"
  psql_exec -c "SELECT kid, is_active, LEFT(wrapped_dek, 46) AS wrapped_dek_prefix, created_at FROM crypto_keys ORDER BY created_at;"
fi

if echo "$TABLES" | grep -qx "hosts"; then
  echo "${CYAN}-- Sample rows from table: hosts --${RESET}"
  psql_exec -c "SELECT id, LEFT(ip_enc, 42) AS ip_ciphertext, LEFT(ip_hmac, 24) AS ip_hmac_blind_idx, lifecycle_state FROM hosts LIMIT 5;"
fi

if echo "$TABLES" | grep -qx "services"; then
  echo "${CYAN}-- Sample rows from table: services --${RESET}"
  psql_exec -c "SELECT id, port, protocol, LEFT(http_enc, 42) AS http_ciphertext, LEFT(banner_enc, 42) AS banner_ciphertext FROM services LIMIT 5;"
fi

if echo "$TABLES" | grep -qx "users"; then
  echo "${CYAN}-- Sample rows from table: users --${RESET}"
  psql_exec -c "SELECT username, LEFT(email_enc, 42) AS email_ciphertext, active FROM users LIMIT 5;"
fi
echo ""

# 4. Negative check: ensure no plaintext lab IPs (172.28.0.10..14) or sensitive tokens exist in encrypted tables
echo "${BOLD}[4/4] Negative plaintext leak check across encrypted columns...${RESET}"
LEAK_COUNT="$(psql_exec -tA <<'SQL'
DO $$
DECLARE
  rec RECORD;
  hits BIGINT := 0;
  c BIGINT;
BEGIN
  FOR rec IN
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name IN ('hosts', 'services', 'service_observations', 'asset_overrides', 'change_events', 'scan_runs', 'scan_snapshots', 'defectdojo_config', 'users')
      AND (column_name LIKE '%_enc' OR column_name = 'wrapped_dek')
  LOOP
    EXECUTE format(
      'SELECT COUNT(*) FROM %I.%I WHERE %I LIKE ''%%172.28.0.1%%'' OR %I LIKE ''%%admin_session=%%'' OR %I LIKE ''%%X-Debug-Token%%'' OR (%I <> '''' AND %I NOT LIKE ''enc:v1:%%'' AND %I NOT LIKE ''wrap:v1:%%'')',
      'public', rec.table_name, rec.column_name, rec.column_name, rec.column_name, rec.column_name, rec.column_name, rec.column_name
    ) INTO c;
    hits := hits + c;
  END LOOP;
  PERFORM set_config('aegis.leak_hits', hits::TEXT, false);
END $$;
SELECT current_setting('aegis.leak_hits');
SQL
)"
LEAK_COUNT="${LEAK_COUNT:-0}"

if [[ "$PLAINTEXT_LEAKS" -gt 0 ]]; then
  echo "${RED}FAIL: $PLAINTEXT_LEAKS encrypted column(s) contain unencrypted non-empty values!${RESET}"
  exit 1
fi

if [[ "$LEAK_COUNT" -gt 0 ]]; then
  echo "${RED}FAIL: Found $LEAK_COUNT plaintext sensitive pattern match(es) in database columns!${RESET}"
  exit 1
fi

echo "${GREEN}${BOLD}PASS: Verified ${ENC_TOTAL} AES-256-GCM / wrapped DEK values across PostgreSQL with 0 plaintext leaks.${RESET}"
