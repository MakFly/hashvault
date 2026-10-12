# hashvault : commandes de développement et de CI. `make` affiche l'aide.

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
BUN ?= bun
DEV_PORT := 4322
DEV_BRIDGE_PORT := 8822
DEV_BIN := .tools/hashvault-dev
DEV_VAULT_BIN := .tools/hashvault-local
# Versions des analyseurs fixées. Les mettre à jour explicitement, jamais vers "latest".
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOSEC       := github.com/securego/gosec/v2/cmd/gosec@v2.29.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
GITLEAKS    := github.com/zricethezav/gitleaks/v8@v8.30.1
# staticcheck v0.8.1 et gosec v2.29.0 ne lisent pas encore les exports Go 1.27
# ("export data version 5 is greater than maximum supported version 4").
# Ils analysent donc les sources avec Go 1.26. Les tests et govulncheck
# conservent la version fixée dans go.mod. Retirer cette adaptation lorsque
# les deux outils prendront en charge Go 1.27.
LINT_TOOLCHAIN ?= go1.26.9

# OpenBao pour le coffre local et les tests : version fixée, empreinte vérifiée
# avec la valeur de checksums.txt ci-dessous, jamais "latest".
OPENBAO_VERSION := 2.7.1
OPENBAO_SHA256  := 0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243
OPENBAO_BIN     := .tools/bao-$(OPENBAO_VERSION)

FUZZTIME ?= 30s
FUZZ_TARGETS := \
	./internal/envelope:FuzzParseRecord \
	./internal/iam:FuzzParse \
	./internal/iam:FuzzMatchGlob \
	./internal/batch:FuzzOpen \
	./internal/audit:FuzzVerifyChain \
	./internal/dotenv:FuzzParse

# ─── Aide ─────────────────────────────────────────────────────────────────────
help: ## Afficher les commandes regroupées par section
	@awk 'BEGIN {FS = ":.*?## "} \
		/^# ─── / { s = $$0; sub(/^# ─── /, "", s); sub(/ ─+$$/, "", s); printf "\n$(C_SECTION)%s$(C_RESET)\n", s; next } \
		/^[a-zA-Z0-9_-]+:.*?## / { printf "  $(C_TARGET)%-20s$(C_RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo

# ─── Installation ─────────────────────────────────────────────────────────────
deps: ## Télécharger et vérifier les dépendances Go
	@$(GO) mod download && $(GO) mod verify
	@printf '$(C_OK)[make] dépendances Go vérifiées$(C_RESET)\n'

ui-deps: ## Installer les dépendances UI depuis le verrou Bun
	@$(BUN) install --frozen-lockfile

tidy: ## Mettre à jour go.mod et go.sum (modifications refusées en CI)
	@$(GO) mod tidy

openbao: $(OPENBAO_BIN) ## Télécharger OpenBao pour le coffre local et les tests, vérifier son empreinte

$(OPENBAO_BIN):
	@mkdir -p .tools/dl
	@curl -fsSL -o .tools/dl/openbao.tar.gz \
		https://github.com/openbao/openbao/releases/download/v$(OPENBAO_VERSION)/openbao_$(OPENBAO_VERSION)_linux_amd64.tar.gz
	@echo "$(OPENBAO_SHA256)  .tools/dl/openbao.tar.gz" | sha256sum -c --quiet - \
		|| { printf '$(C_ERR)[make] empreinte OpenBao incorrecte$(C_RESET)\n'; rm -f .tools/dl/openbao.tar.gz; exit 1; }
	@tar -xzf .tools/dl/openbao.tar.gz -C .tools/dl bao && mv .tools/dl/bao $@ && chmod 0755 $@
	@printf '$(C_OK)[make] OpenBao $(OPENBAO_VERSION) disponible dans $@$(C_RESET)\n'

# ─── Développement ────────────────────────────────────────────────────────────
dev: ui-deps openbao ## Démarrer le coffre local persistant et l'interface sur http://127.0.0.1:4322
	@mkdir -p .tools
	@$(GO) build -o $(DEV_BIN) ./cmd/hashvault
	@$(GO) build -o $(DEV_VAULT_BIN) ./cmd/hashvault-local
	@C_OK='$(C_OK)' C_WARN='$(C_WARN)' C_ERR='$(C_ERR)' C_RESET='$(C_RESET)' BUN='$(BUN)' HASHVAULT_BAO_BIN='$(abspath $(OPENBAO_BIN))' HASHVAULT_UI_BRIDGE='http://127.0.0.1:$(DEV_BRIDGE_PORT)' bash scripts/ui-dev.sh start $(DEV_PORT) $(DEV_BRIDGE_PORT)

stop: ## Arrêter les processus de make dev en conservant les secrets locaux
	@C_OK='$(C_OK)' C_WARN='$(C_WARN)' C_ERR='$(C_ERR)' C_RESET='$(C_RESET)' bash scripts/ui-dev.sh stop $(DEV_PORT) $(DEV_BRIDGE_PORT)

# ─── Vérification ─────────────────────────────────────────────────────────────
fmt: ## Formater les sources Go avec gofmt
	@gofmt -w .

fmt-check: ## Vérifier le formatage des fichiers Go
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then printf '$(C_ERR)[make] fichiers à formater :$(C_RESET)\n%s\n' "$$out"; exit 1; fi
	@printf '$(C_OK)[make] formatage Go validé$(C_RESET)\n'

vet: ## Analyser les sources avec go vet
	@$(GO) vet ./...

staticcheck: ## Analyser les sources avec staticcheck (version fixée)
	@GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run $(STATICCHECK) ./...
	@printf '$(C_OK)[make] staticcheck validé$(C_RESET)\n'

gosec: ## Analyser la sécurité avec gosec (version fixée)
	@GOTOOLCHAIN=$(LINT_TOOLCHAIN) $(GO) run $(GOSEC) -quiet ./...
	@printf '$(C_OK)[make] gosec validé$(C_RESET)\n'

vuln: ## Rechercher les vulnérabilités du code et de ses dépendances
	@$(GO) run $(GOVULNCHECK) ./...

secrets-scan: ## Rechercher les secrets dans le dépôt avec gitleaks
	@$(GO) run $(GITLEAKS) dir --no-banner --redact .

tidy-check: ## Vérifier que go.mod et go.sum sont à jour
	@$(GO) mod tidy && git diff --exit-code go.mod go.sum >/dev/null \
		|| { printf '$(C_ERR)[make] go.mod/go.sum modifiés : enregistrer le résultat de go mod tidy$(C_RESET)\n'; exit 1; }
	@printf '$(C_OK)[make] modules Go à jour$(C_RESET)\n'

lint: fmt-check tidy-check vet staticcheck gosec ## Exécuter toutes les analyses statiques

ui-check: ui-deps ## Vérifier les types, le lint UI et les définitions API générées
	@$(BUN) run typecheck
	@$(BUN) run lint:ui
	@before=$$(cksum ui/src/api/schema.d.ts); $(BUN) run api:types; after=$$(cksum ui/src/api/schema.d.ts); \
		if [ "$$before" != "$$after" ]; then printf '$(C_ERR)[make] régénérer et enregistrer les définitions API$(C_RESET)\n'; exit 1; fi
	@printf '$(C_OK)[make] types et lint UI validés$(C_RESET)\n'

# ─── Tests ────────────────────────────────────────────────────────────────────
test: ## Exécuter les tests unitaires et de propriétés ; intégration si OpenBao disponible
	@$(GO) test -race -shuffle=on -count=1 ./...

cover: openbao ## Exécuter tous les tests et vérifier les seuils de couverture
	@HASHVAULT_REQUIRE_INTEGRATION=1 $(GO) test -race -count=1 -covermode=atomic -coverpkg=./internal/... -coverprofile=coverage.out ./...
	@./scripts/coverage-check.sh coverage.out

fuzz: ## Exécuter le fuzzing pendant FUZZTIME par cible (30s par défaut)
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		printf '$(C_TARGET)[make] fuzzing %s %s$(C_RESET)\n' "$$pkg" "$$name"; \
		$(GO) test -run='^$$' -fuzz="^$$name\$$" -fuzztime=$(FUZZTIME) "$$pkg"; \
	done
	@printf '$(C_OK)[make] fuzzing terminé$(C_RESET)\n'

# ─── CI ───────────────────────────────────────────────────────────────────────
ci: deps lint cover vuln ui-check ## Exécuter les contrôles du backend et de la console en local
	@printf '$(C_OK)[make] CI validée$(C_RESET)\n'

clean: ## Supprimer les rapports générés
	@rm -f coverage.out
	@printf '$(C_WARN)[make] rapports supprimés$(C_RESET)\n'

.PHONY: help dev stop deps ui-deps ui-check tidy tidy-check openbao fmt fmt-check vet staticcheck gosec vuln secrets-scan lint test cover fuzz ci clean
