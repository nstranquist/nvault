VERSION ?= 0.2.0-alpha.1
PNPM ?= corepack pnpm@11.15.1
GOLANGCI_LINT_VERSION ?= v2.13.1
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1

.PHONY: build test lint security secrets test-client schema-check verify publish-ready

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o nvault ./cmd/nvault

test:
	go test -race ./...
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

security:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

secrets:
	go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir --no-banner --redact .

test-client:
	$(PNPM) --dir client test
	$(PNPM) --dir client audit --prod

schema-check:
	go run ./cmd/nvault-schemagen --check client/src/types.generated.ts

verify: test lint security secrets schema-check test-client

publish-ready: verify
	$(PNPM) --dir client pack --dry-run
	go run ./cmd/nvault-release --check-source .
