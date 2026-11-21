# =============================================================================
# Dzięcioł — Multi-Stage Production Dockerfile
# Stage 1: Frontend build (Node 22 + pnpm -> frontend/dist)
# Stage 2: Backend build (Go 1.24 -> /app/dzieciol, same single binary as releases,
#          with the UI embedded via go:embed)
# Stage 3: Minimal Alpine runtime (ONLY nmap, ca-certificates, tzdata)
# =============================================================================

# --- Stage 1: Frontend Builder -----------------------------------------------
FROM node:24-alpine AS frontend-builder

WORKDIR /src/frontend

# npm instead of corepack: corepack prepare fails to reach the registry inside some BuildKit setups
RUN npm install -g pnpm@10.12.1

COPY frontend/package.json frontend/pnpm-lock.yaml* ./
RUN if [ -f pnpm-lock.yaml ]; then pnpm install --frozen-lockfile; else pnpm install; fi

COPY frontend/ ./
RUN pnpm run build


# --- Stage 2: Backend Builder ------------------------------------------------
FROM golang:1.24-alpine AS backend-builder

WORKDIR /src/backend

COPY backend/go.mod backend/go.sum* ./
RUN go mod download

COPY backend/ ./
# Embed the freshly built UI into the binary (backend/internal/webui/ui is go:embed'ed).
COPY --from=frontend-builder /src/frontend/dist/ ./internal/webui/ui/
ARG VERSION=docker
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=docker" \
      -o /app/dzieciol ./cmd/server


# --- Stage 3: Minimal Production Runtime -------------------------------------
FROM alpine:3.21 AS runtime

# nmap-scripts is required by -sV: version detection always loads NSE (nse_main.lua and the
# "version" category scripts). Without it Alpine's nmap aborts every -sV run ("could not
# locate nse_main.lua") and the scanner silently fell back to plain TCP connect + banners.
RUN apk add --no-cache nmap nmap-scripts ca-certificates tzdata

WORKDIR /app

COPY --from=backend-builder /app/dzieciol /app/dzieciol
# Kept for compatibility with deployments that set ASI_STATIC_DIR=/app/static;
# without it the UI embedded in the binary is served.
COPY --from=frontend-builder /src/frontend/dist /app/static
# Old names kept as symlinks so existing `docker exec ... /app/aegis ...` scripts keep working.
RUN ln -s /app/dzieciol /app/aegis && ln -s /app/dzieciol /app/aegis-asi && mkdir -p /data && chmod 700 /data

# DATABASE_URL set   -> PostgreSQL store (docker-compose.yml)
# DATABASE_URL unset -> AES-256-GCM encrypted file store in $ASI_DATA_DIR (mount a volume on /data)
ENV ASI_LISTEN_ADDR=:8080 \
    ASI_DATA_DIR=/data \
    TZ=Europe/Warsaw
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/dzieciol"]
CMD ["serve"]
