# Podplane <https://podplane.dev>
# Copyright The Podplane Authors
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

BINDIR := bin
BINARY_NAME := podplane-operator
MAIN_PKG := ./cmd/podplane-operator
IMAGE_REPOSITORY ?= ghcr.io/podplane/operator
IMAGE_TAG ?= latest
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.18.0

.PHONY: help setup fmt lint precommit test generate generate-crds generate-deepcopy build image clean

help: ## Show available targets
	@echo "Usage: make <target>"
	@awk 'BEGIN {FS = ":.*?## "} /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Verify required tools
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required but not installed"; exit 1; }
	@echo "All required tools are installed."
	@cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@cp scripts/git-hooks/commit-msg .git/hooks/commit-msg
	@chmod +x .git/hooks/commit-msg
	@echo "Git hooks installed."

fmt: ## Format Go source files
	@go fmt ./...

lint: ## Run linters
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is required but not installed"; exit 1; }
	@golangci-lint run --timeout=5m

precommit: ## Check formatting and run vet
	@echo "Checking formatting..."
	@UNFORMATTED=$$(gofmt -l . 2>&1); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "The following files need formatting (run 'make fmt'):"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@go vet ./...

test: ## Run tests
	go test ./...

generate: generate-crds generate-deepcopy ## Generate CRDs and generated Go code

generate-crds: ## Generate Kubernetes CRDs
	$(CONTROLLER_GEN) crd:headerFile=config/boilerplate/crd.yaml.txt paths=./api/... output:crd:dir=config/crd/bases

generate-deepcopy: ## Generate Kubernetes deepcopy code
	$(CONTROLLER_GEN) object:headerFile=config/boilerplate/go.txt paths=./api/...

build: ## Build the podplane-operator binary
	mkdir -p $(BINDIR)
	go build -trimpath -o $(BINDIR)/$(BINARY_NAME) $(MAIN_PKG)

image: ## Build container image
	docker build -f images/podplane-operator/Containerfile -t $(IMAGE_REPOSITORY):$(IMAGE_TAG) .

clean: ## Remove build artifacts
	rm -rf $(BINDIR)
