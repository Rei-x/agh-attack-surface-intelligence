# Dzięcioł scale lab: emulator + scorer + nmap (for the optional scanner-runner).
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/scalelab ./cmd/scalelab \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/scorer ./cmd/scorer

FROM alpine:3.21
RUN apk add --no-cache iproute2 iproute2-tc iptables nmap nmap-scripts curl jq tzdata ca-certificates
COPY --from=build /out/scalelab /out/scorer /usr/local/bin/
ENV SCALE_TRUTH_DIR=/var/lib/scalelab
ENTRYPOINT ["/usr/local/bin/scalelab"]
