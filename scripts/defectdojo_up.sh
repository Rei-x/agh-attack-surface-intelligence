#!/usr/bin/env bash
# Starts a real OWASP DefectDojo locally (official docker compose) and prints an API token
# for Dzięcioł's DefectDojo settings.
#
#   scripts/defectdojo_up.sh            # clone (once) + start on http://localhost:8081
#   DD_DIR=~/dd DD_PORT=9000 scripts/defectdojo_up.sh
#
# Dzięcioł imports into DefectDojo via /api/v2/reimport-scan/ with auto_create_context, so no
# manual product/engagement setup is needed: product type "Dzięcioł", product
# "AGH Attack Surface" and engagement "Dzięcioł continuous discovery" are created on first push.
set -euo pipefail

DD_VERSION="${DD_VERSION:-3.5.202}"
DD_DIR="${DD_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/defectdojo}"
DD_PORT="${DD_PORT:-8081}"
DD_TLS_PORT="${DD_TLS_PORT:-8444}"

if [ ! -d "$DD_DIR/.git" ]; then
  git clone -q --depth 1 --branch "$DD_VERSION" https://github.com/DefectDojo/django-DefectDojo.git "$DD_DIR"
fi
cd "$DD_DIR"
DD_PORT="$DD_PORT" DD_TLS_PORT="$DD_TLS_PORT" docker compose up -d

echo "Waiting for DefectDojo initializer to print the admin password..."
pw=""
for _ in $(seq 1 120); do
  pw="$(docker compose logs initializer 2>/dev/null | sed -n 's/.*Admin password: //p' | tail -1 | tr -d '\r')"
  [ -n "$pw" ] && curl -sf -o /dev/null "http://localhost:$DD_PORT/login" && break
  sleep 5
done
if [ -z "$pw" ]; then
  echo "Admin password not found yet; check: (cd $DD_DIR && docker compose logs initializer)" >&2
  exit 1
fi

token="$(curl -s -X POST "http://localhost:$DD_PORT/api/v2/api-token-auth/" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$pw\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"

cat <<EOF

DefectDojo $DD_VERSION is up: http://localhost:$DD_PORT  (login: admin / $pw)
Dzięcioł -> Ustawienia -> DefectDojo:
  URL:       http://localhost:$DD_PORT   (from the dzieciol container: http://host.docker.internal:$DD_PORT)
  API token: $token
EOF
