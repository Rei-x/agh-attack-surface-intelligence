# Dzięcioł production image. The frontend build is embedded into the Go binary
# via go:embed (the same single binary as the releases); the runtime is Alpine
# with only nmap, ca-certificates and tzdata.

FROM node:24-alpine AS frontend-builder

WORKDIR /src/frontend

# npm instead of corepack: corepack prepare fails to reach the registry inside some BuildKit setups
RUN npm install -g pnpm@10.12.1

COPY frontend/package.json frontend/pnpm-lock.yaml* ./
RUN if [ -f pnpm-lock.yaml ]; then pnpm install --frozen-lockfile; else pnpm install; fi

COPY frontend/ ./
RUN pnpm run build

FROM golang:1.24-alpine AS backend-builder

WORKDIR /src/backend

COPY backend/go.mod backend/go.sum* ./
RUN go mod download

COPY backend/ ./
# backend/internal/webui/ui is go:embed'ed into the binary.
COPY --from=frontend-builder /src/frontend/dist/ ./internal/webui/ui/
ARG VERSION=docker
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=docker" \
      -o /app/dzieciol ./cmd/server
# The same binary for the other platforms, handed out to new agents by GET /install.sh and
# /download/. The server serves itself for its own platform, so that one is not stored twice.
RUN set -e; self="linux/$(go env GOARCH)"; mkdir -p /app/dist; \
    for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
      [ "$p" = "$self" ] && continue; \
      CGO_ENABLED=0 GOOS="${p%/*}" GOARCH="${p#*/}" go build -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=docker" \
        -o "/app/dist/dzieciol-${p%/*}-${p#*/}" ./cmd/server; \
    done; ls -l /app/dist

FROM alpine:3.21 AS runtime

# nmap-scripts is required by -sV: version detection always loads NSE (nse_main.lua and the
# "version" category scripts). Without it Alpine's nmap aborts every -sV run ("could not
# locate nse_main.lua") and the scanner falls back to plain TCP connect + banners.
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata

WORKDIR /app

COPY --from=backend-builder /app/dzieciol /app/dzieciol
COPY --from=backend-builder /app/dist /app/dist
# Kept for compatibility with deployments that set DZIECIOL_STATIC_DIR=/app/static;
# without it the UI embedded in the binary is served.
COPY --from=frontend-builder /src/frontend/dist /app/static
RUN mkdir -p /data && chmod 700 /data

# DATABASE_URL set   -> PostgreSQL store (docker-compose.yml)
# DATABASE_URL unset -> AES-256-GCM encrypted file store in $DZIECIOL_DATA_DIR (mount a volume on /data)
ENV DZIECIOL_LISTEN_ADDR=:8080 \
    DZIECIOL_DATA_DIR=/data \
    TZ=Europe/Warsaw
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/dzieciol"]
CMD ["serve"]
