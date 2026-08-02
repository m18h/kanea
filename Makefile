# Kanea — developer tasks. See AGENTS.md for conventions and binding constraints.

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
	$(GO) test ./... -race -count=1

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

.PHONY: dashboard
dashboard: ## Dashboard gates: lint, typecheck, test, build, audit
	@if [ -f dashboard/package.json ]; then \
		cd dashboard && npm ci && npm run lint && npm run typecheck && npm test && npm run build && npm audit --audit-level=high; \
	else \
		echo "dashboard/ not scaffolded yet (milestone M4) — skipping"; \
	fi

.PHONY: tools
tools: ## Install dev tools (gitleaks via package manager: brew install gitleaks)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: check
check: vet test lint security dashboard ## Run all gates (CI parity) — must pass before merge

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/
