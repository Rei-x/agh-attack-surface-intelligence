# =============================================================================
# AegisASI — Multi-Stage Production Dockerfile
# Stage 1: Frontend build (Node 22 + pnpm -> frontend/dist)
# Stage 2: Backend build (Go 1.24 -> /app/aegis-asi)
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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/aegis-asi ./cmd/server


# --- Stage 3: Minimal Production Runtime -------------------------------------
FROM alpine:3.21 AS runtime

RUN apk add --no-cache nmap ca-certificates tzdata

WORKDIR /app

COPY --from=backend-builder /app/aegis-asi /app/aegis-asi
COPY --from=frontend-builder /src/frontend/dist /app/static

ENV ASI_STATIC_DIR=/app/static \
    ASI_LISTEN_ADDR=:8080 \
    TZ=Europe/Warsaw

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/aegis-asi"]
