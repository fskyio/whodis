GO ?= go
GOFMT ?= gofmt
BINARY ?= whodis
CONTAINER_ENGINE ?= docker
IMAGE ?= whodis:dev

.DEFAULT_GOAL := build

.PHONY: build run test test-race lint fmt fmt-check check generate refresh-data refresh-whois refresh-rdap container clean help

build: ## Build the whodis executable (default)
	$(GO) build -trimpath -o ./$(BINARY) ./cmd/whodis

run: ## Run the web application from source
	$(GO) run ./cmd/whodis

test: ## Run all unit and integration tests
	$(GO) test ./...

test-race: ## Run all tests with the race detector
	$(GO) test -race ./...

lint: ## Run the standard Go static analyzer
	$(GO) vet ./...

fmt: ## Format all Go packages in place
	$(GO) fmt ./...

fmt-check: ## Report unformatted Go source without modifying it
	@files="$$(find . -type f -name '*.go' -not -path './vendor/*' -exec $(GOFMT) -l {} +)"; \
	if [ -n "$$files" ]; then \
		printf '%s\n' "$$files"; \
		exit 1; \
	fi

check: fmt-check lint test ## Run offline formatting, lint, and test checks

generate: refresh-data ## Refresh all checked-in protocol data

refresh-data: refresh-whois refresh-rdap ## Refresh all checked-in protocol data

refresh-whois: ## Refresh the checked-in WHOIS routing snapshot (networked)
	$(GO) generate ./whois

refresh-rdap: ## Refresh the checked-in RDAP bootstrap snapshot (networked)
	$(GO) generate ./rdap

container: ## Build a development container image
	$(CONTAINER_ENGINE) build -t $(IMAGE) .

clean: ## Remove only the local build artifact
	rm -f -- ./$(BINARY)

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make [target]\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
