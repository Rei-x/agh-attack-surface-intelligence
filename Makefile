# AegisASI - single binary build
#
#   make ui        build the React UI and copy it into backend/internal/webui/ui (go:embed)
#   make build     ui + bin/aegis for this machine
#   make build-go  bin/aegis without rebuilding the UI (uses whatever is embedded)
#   make release   ui + cross-compiled binaries for all platforms + checksums in dist/
#   make test      go build + go test

SHELL := /bin/bash

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BACKEND   := backend
MAIN_PKG  := ./cmd/server
UI_EMBED  := $(BACKEND)/internal/webui/ui
BIN_DIR   := bin
DIST_DIR  := dist
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

export CGO_ENABLED := 0

.PHONY: all ui ui-clean build build-go release checksums test clean

all: build

ui:
	cd frontend && pnpm install --frozen-lockfile && pnpm build
	$(MAKE) ui-clean
	cp -R frontend/dist/. $(UI_EMBED)/
	@echo "UI embedded into $(UI_EMBED)"

# Remove previously embedded UI files but keep the committed .gitkeep.
ui-clean:
	find $(UI_EMBED) -mindepth 1 ! -name .gitkeep -delete

build: ui build-go

build-go:
	@mkdir -p $(BIN_DIR)
	cd $(BACKEND) && go build -trimpath -ldflags "$(LDFLAGS)" -o ../$(BIN_DIR)/aegis $(MAIN_PKG)
	@ls -lh $(BIN_DIR)/aegis
	@./$(BIN_DIR)/aegis version

release: ui
	@rm -rf $(DIST_DIR) && mkdir -p $(DIST_DIR)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="$(DIST_DIR)/aegis-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		(cd $(BACKEND) && GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o ../$$out $(MAIN_PKG)); \
	done
	$(MAKE) checksums
	@ls -lh $(DIST_DIR)

checksums:
	@cd $(DIST_DIR) && rm -f checksums.txt && \
		if command -v sha256sum >/dev/null 2>&1; then sha256sum aegis-* > checksums.txt; \
		else shasum -a 256 aegis-* > checksums.txt; fi && cat checksums.txt

test:
	cd $(BACKEND) && go build ./... && go test ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
	$(MAKE) ui-clean
