# hashvault: developer and CI entry points. `make` alone prints the help.

.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

C_SECTION := \033[1;33m
C_TARGET  := \033[36m
C_OK      := \033[32m
C_WARN    := \033[33m
C_ERR     := \033[31m
C_RESET   := \033[0m

GO ?= go
# Pinned analyzer versions. Bump deliberately, never to "latest".
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOSEC       := github.com/securego/gosec/v2/cmd/gosec@v2.29.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
GITLEAKS    := github.com/zricethezav/gitleaks/v8@v8.30.1
# staticcheck v0.8.1 and gosec v2.29.0 cannot read Go 1.27 export data yet
# ("export data version 5 is greater than maximum supported version 4"), so
# they analyse the sources with the latest Go 1.26 toolchain. Tests and
# govulncheck keep the toolchain pinned in go.mod. Drop this once both tools
# support Go 1.27.
LINT_TOOLCHAIN ?= go1.26.9

FUZZTIME ?= 30s
FUZZ_TARGETS := \
	./internal/envelope:FuzzParseRecord \
	./internal/iam:FuzzParse \
	./internal/iam:FuzzMatchGlob

# ─── Help ────────────────────────────────────────────────────────────────────
help: ## Show the targets, grouped by section
	@awk 'BEGIN {FS = ":.*?## "} \
		/^# ─── / { s = $$0; sub(/^# ─── /, "", s); sub(/ ─+$$/, "", s); printf "\n$(C_SECTION)%s$(C_RESET)\n", s; next } \
		/^[a-zA-Z0-9_-]+:.*?## / { printf "  $(C_TARGET)%-20s$(C_RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo

# ─── Setup ───────────────────────────────────────────────────────────────────
deps: ## Download and verify module dependencies
	@$(GO) mod download && $(GO) mod verify
	@printf '$(C_OK)[make] modules verified$(C_RESET)\n'

tidy: ## Tidy go.mod and go.sum (fails in CI if they change)
	@$(GO) mod tidy

# ─── Check ───────────────────────────────────────────────────────────────────
fmt: ## Rewrite Go sources with gofmt
	@gofmt -w .

fmt-check: ## Fail if a Go file is not gofmt-formatted
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then printf '$(C_ERR)[make] not formatted:$(C_RESET)\n%s\n' "$$out"; exit 1; fi
	@printf '$(C_OK)[make] gofmt clean$(C_RESET)\n'

vet: ## Run go vet
	@$(GO) vet ./...

staticcheck: ## Run staticcheck (pinned)
	@GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run $(STATICCHECK) ./...
	@printf '$(C_OK)[make] staticcheck clean$(C_RESET)\n'

gosec: ## Run gosec (pinned)
	@GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run $(GOSEC) -quiet ./...
	@printf '$(C_OK)[make] gosec clean$(C_RESET)\n'

vuln: ## Run govulncheck against the code and its dependencies
	@$(GO) run $(GOVULNCHECK) ./...

secrets-scan: ## Scan the working tree for committed secrets (gitleaks)
	@$(GO) run $(GITLEAKS) dir --no-banner --redact .

lint: fmt-check vet staticcheck gosec ## All static checks

# ─── Test ────────────────────────────────────────────────────────────────────
test: ## Unit and property tests, with the race detector
	@$(GO) test -race -shuffle=on -count=1 ./...

cover: ## Tests with coverage, then enforce the per-package thresholds
	@$(GO) test -race -count=1 -covermode=atomic -coverprofile=coverage.out ./...
	@./scripts/coverage-check.sh coverage.out

fuzz: ## Run every fuzz target for FUZZTIME each (default 30s)
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		printf '$(C_TARGET)[make] fuzz %s %s$(C_RESET)\n' "$$pkg" "$$name"; \
		$(GO) test -run='^$$' -fuzz="^$$name\$$" -fuzztime=$(FUZZTIME) "$$pkg"; \
	done
	@printf '$(C_OK)[make] fuzzing done$(C_RESET)\n'

# ─── CI ──────────────────────────────────────────────────────────────────────
ci: deps lint cover vuln ## Everything the CI workflow runs, locally
	@printf '$(C_OK)[make] ci passed$(C_RESET)\n'

clean: ## Remove generated reports
	@rm -f coverage.out
	@printf '$(C_WARN)[make] reports removed$(C_RESET)\n'

.PHONY: help deps tidy fmt fmt-check vet staticcheck gosec vuln secrets-scan lint test cover fuzz ci clean
