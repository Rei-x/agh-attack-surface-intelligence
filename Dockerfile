# =============================================================================
# AegisASI — Multi-Stage Production Dockerfile
# Stage 1: Frontend build (Node 22 + pnpm -> frontend/dist)
# Stage 2: Backend build (Go 1.24 -> /app/aegis, same single binary as releases,
#          with the UI embedded via go:embed)
# Stage 3: Minimal Alpine runtime (ONLY nmap, ca-certificates, tzdata)
# =============================================================================

# --- Stage 1: Frontend Builder -----------------------------------------------
FROM node:24-alpine AS frontend-builder

WORKDIR /src/frontend

RUN corepack enable && corepack prepare pnpm@10 --activate

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
      -o /app/aegis ./cmd/server


# --- Stage 3: Minimal Production Runtime -------------------------------------
FROM alpine:3.21 AS runtime

RUN apk add --no-cache nmap ca-certificates tzdata

WORKDIR /app

COPY --from=backend-builder /app/aegis /app/aegis
# Kept for compatibility with deployments that set ASI_STATIC_DIR=/app/static;
# without it the UI embedded in the binary is served.
COPY --from=frontend-builder /src/frontend/dist /app/static
RUN ln -s /app/aegis /app/aegis-asi && mkdir -p /data && chmod 700 /data

# DATABASE_URL set   -> PostgreSQL store (docker-compose.yml)
# DATABASE_URL unset -> AES-256-GCM encrypted file store in $ASI_DATA_DIR (mount a volume on /data)
ENV ASI_LISTEN_ADDR=:8080 \
    ASI_DATA_DIR=/data \
    TZ=Europe/Warsaw
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/aegis"]
CMD ["serve"]
