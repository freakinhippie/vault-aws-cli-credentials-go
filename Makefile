SHELL := /bin/bash

BINARY := vaultcreds
CMD := ./cmd/$(BINARY)
BIN_DIR := ./bin
GOCACHE ?= $(CURDIR)/.cache/go-build
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
LATEST_TAG ?= $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)
SNAPSHOT_VERSION ?= $(patsubst v%,%,$(LATEST_TAG))
CHOCO_DOCKER_IMAGE ?= ghcr.io/freakinhippie/goreleaser-choco:latest

.PHONY: help build run test test-integration fmt vet tidy clean release-check release-snapshot

help:
	@echo "Available targets:"
	@echo "  build             Build OS/arch-specific binaries into $(BIN_DIR)/"
	@echo "  run               Run vaultcreds (set ARGS='...')"
	@echo "  test              Run unit tests"
	@echo "  test-integration  Run integration tests (requires vault binary)"
	@echo "  fmt               Format Go files"
	@echo "  vet               Run go vet"
	@echo "  tidy              Run go mod tidy"
	@echo "  clean             Remove build and cache artifacts"
	@echo "  release-check     Run goreleaser check"
	@echo "  release-snapshot  Build goreleaser snapshot artifacts"

build:
	@mkdir -p $(BIN_DIR)
	@rm -f $(BIN_DIR)/$(BINARY)
	@set -euo pipefail; \
	host_os="$$(uname -s | tr '[:upper:]' '[:lower:]')"; \
	for platform in $(PLATFORMS); do \
		os="$${platform%/*}"; \
		arch="$${platform#*/}"; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(BIN_DIR)/$${os}_$${arch}/$(BINARY)_$${os}_$${arch}$$ext"; \
		mkdir -p "$$(dirname "$$out")"; \
		if [ "$$os" = "darwin" ] && [ "$$host_os" != "darwin" ]; then \
			echo "Skipping $$out (macOS keychain support requires a native darwin build with cgo enabled)"; \
			continue; \
		fi; \
		echo "Building $$out"; \
		cgo=0; \
		if [ "$$os" = "darwin" ]; then cgo=1; fi; \
		GOOS="$$os" GOARCH="$$arch" CGO_ENABLED="$$cgo" GOCACHE=$(GOCACHE) go build -o "$$out" $(CMD); \
	done

run:
	GOCACHE=$(GOCACHE) go run $(CMD) $(ARGS)

test:
	GOCACHE=$(GOCACHE) go test ./...

test-integration:
	GOCACHE=$(GOCACHE) go test -tags=integration ./internal/e2e -v

fmt:
	GOCACHE=$(GOCACHE) gofmt -w $$(find . -name '*.go' -not -path './.git/*')

vet:
	GOCACHE=$(GOCACHE) go vet ./...

tidy:
	GOCACHE=$(GOCACHE) go mod tidy

clean:
	rm -rf $(BIN_DIR) .cache dist

release-check:
	GOCACHE=$(GOCACHE) goreleaser check

release-snapshot:
	@set -euo pipefail; \
	if command -v choco >/dev/null 2>&1; then \
		echo "Using local choco for Chocolatey packaging"; \
		VERSION=$(SNAPSHOT_VERSION) GOCACHE=$(GOCACHE) goreleaser release --clean --snapshot; \
	elif command -v docker >/dev/null 2>&1; then \
		echo "Local choco not found; attempting Docker Chocolatey runner: $(CHOCO_DOCKER_IMAGE)"; \
		if docker run --rm \
			-e VERSION=$(SNAPSHOT_VERSION) \
			-e GOCACHE=/tmp/go-build \
			-v "$(CURDIR):/workspace" \
			-w /workspace \
			$(CHOCO_DOCKER_IMAGE) \
			goreleaser release --clean --snapshot; then \
			true; \
		else \
			echo "Docker Chocolatey runner unavailable; falling back to --skip=chocolatey"; \
			VERSION=$(SNAPSHOT_VERSION) GOCACHE=$(GOCACHE) goreleaser release --clean --snapshot --skip=chocolatey; \
		fi; \
	else \
		echo "Neither choco nor docker found; skipping Chocolatey packaging"; \
		VERSION=$(SNAPSHOT_VERSION) GOCACHE=$(GOCACHE) goreleaser release --clean --snapshot --skip=chocolatey; \
	fi
