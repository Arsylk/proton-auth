# Development targets. CI runs the same steps; see .github/workflows/ci.yml.
GOLANGCI_LINT_VERSION ?= v2.15.0
GOLANGCI_LINT = go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: all build test race lint fmt vuln tidy-check check

all: check build

build:
	go build -o proton-auth ./cmd/proton-auth

test:
	go test -count=1 ./...

race:
	go test -race -shuffle=on -count=1 ./...

lint:
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GOLANGCI_LINT) fmt ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy-check:
	go mod tidy -diff
	go mod verify

check: tidy-check lint race vuln
