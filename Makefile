# Kanea: developer tasks. See AGENTS.md for conventions and binding constraints.

GO      ?= go
BINARY  ?= kanea
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the kanea binary into ./bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/kanea

.PHONY: test
test: ## Run all tests with the race detector
	$(GO) test ./... -race -count=1 -timeout 20m

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## golangci-lint (config: .golangci.yml)
	golangci-lint run ./...

.PHONY: security
security: ## Security gates: gosec + govulncheck + gitleaks (AGENTS.md constraint #7)
	gosec -quiet ./...
	govulncheck $(if $(GOVULNDB),-db "$(GOVULNDB)",) ./...
	gitleaks detect --source . --verbose

# govulncheck needs a vulnerability DB (default https://vuln.go.dev). On networks
# where vuln.go.dev is unreachable, generate a local mirror and override:
#   git clone https://github.com/golang/vulndb /tmp/vulndb && cd /tmp/vulndb \
#     && go run ./cmd/gendb -out $(CURDIR)/.cache/vulndb
#   GOVULNDB=file://$(CURDIR)/.cache/vulndb make security

# The BPF toolchain: cilium/ebpf's own builder image (Go + clang/LLVM, the
# same one its CI uses), pinned BY DIGEST so `make bpf` output is a function
# of the committed sources: tag 1777990914, the toolchain cilium/ebpf
# v0.22.0 builds with. The generated artifacts are committed; `bpf-verify`
# regenerates and diffs, so a hand-edited artifact or a drifted toolchain is
# a CI failure, not a code path (AGENTS.md, PRD v1.36).
BPF_IMAGE      := ghcr.io/cilium/ebpf-builder@sha256:22ce6d5aad2f15df921db21770e759554cbda52f6d4e291b1ff58b4b9a5d6fcb
BPF2GO_VERSION := v0.22.0

.PHONY: bpf
bpf: ## Regenerate the committed BPF artifacts (requires docker)
	docker run --rm -v $(CURDIR):/src -w /src/internal/datapath/bpf \
		--env HOME=/tmp $(BPF_IMAGE) \
		go run github.com/cilium/ebpf/cmd/bpf2go@$(BPF2GO_VERSION) \
			-go-package bpf -cc clang-22 -target bpfel,bpfeb \
			-cflags '-O2 -g -Wall -Werror' kanea kanea.c

.PHONY: bpf-verify
bpf-verify: ## Regenerate BPF artifacts and diff; CI gate (requires docker)
	$(MAKE) bpf
	git diff --exit-code internal/datapath/bpf/

.PHONY: dashboard-dev
dashboard-dev: ## Run the dashboard dev server against the built-in mock API (no daemon needed)
	cd dashboard && npm install && npm run dev:mock

.PHONY: dashboard-dev-live
dashboard-dev-live: ## Run the dashboard dev server against a real kanead (proxies /v1 to 127.0.0.1:8600)
	cd dashboard && npm install && npm run dev

.PHONY: dashboard
dashboard: ## Dashboard gates: lint, typecheck, test, build, audit
	@if [ -f dashboard/package.json ]; then \
		cd dashboard && npm ci && npm run lint && npm run typecheck && npm run test:coverage && npm run build && npm audit --audit-level=high; \
	else \
		echo "dashboard/ not scaffolded yet (milestone M4); skipping"; \
	fi

.PHONY: tools
# Pinned, never @latest (K-42): a gate tool fetched at its newest tag is code
# running in the trust root nobody reviewed. Bump these deliberately.
tools: ## Install dev tools (gitleaks via package manager: brew install gitleaks)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
	$(GO) install golang.org/x/vuln/cmd/govulncheck@v1.7.0

.PHONY: check
check: vet test lint security dashboard bpf-verify ## Run all gates (CI parity); must pass before merge

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/
