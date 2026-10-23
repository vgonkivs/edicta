export GOWORK := off

# Binaries go to bin/. The nested modules, in dependency order; each has a
# Makefile on make/go.mk, and they never run in parallel.
BIN := bin
MODS := plugins/celestia services/gate services/signer services/cli examples

.PHONY: build demo test test-clipin test-q vet vectors clean contracts contracts-check dev-up dev-down dev-smoke test-dev check-mods

# edicta-principal is the root module's light standalone; the modules build
# edicta, edicta-signer, edicta-demo and edicta-live.
build:
	go build -o $(BIN)/edicta-principal ./cmd/edicta-principal
	@for m in $(MODS); do $(MAKE) -C $$m build || exit 1; done

# The demo is an example binary: make demo ARGS="fast-mode --json" runs bin/edicta-demo fast-mode --json.
demo: build
	$(BIN)/edicta-demo $(ARGS)

vet:
	go vet ./...
	go vet -tags edictadev ./plugins/edenescrow/...
	@for m in $(MODS); do $(MAKE) -C $$m vet || exit 1; done

test:
	go test -race -p 2 ./...
	@for m in $(MODS); do $(MAKE) -C $$m test || exit 1; done
	$(MAKE) test-dev
	$(MAKE) test-clipin

# Command line pin: builds every entry point and replays test/clipin's case
# table against the goldens. Regenerate them with ARGS=-update.
test-clipin:
	go test -count=1 -timeout 30m -tags clipin ./test/clipin $(ARGS)

vectors:
	python3 spec/vectors/check/check_vectors.py
	env -u GOROOT go -C spec/vectors/tools/execresult-gen run . -check
	env -u GOROOT go -C spec/vectors/tools/edenescrow-gen run . -check

# EdictaPublish artifacts with the pinned solc image (needs docker).
contracts:
	contracts/edictapublish/build.sh

contracts-check:
	contracts/edictapublish/build.sh check

clean:
	rm -rf $(BIN)

# Module hygiene: relative in-repo replaces, nothing requires examples, tidy
# go.mod files, and the fork replace block equal across the heavy modules.
check-mods:
	make/check-mods.sh
	go test -count=1 ./test/modparity

# Quiet test run: package summary lines that failed, plus failure output only.
# PKGS defaults to everything; pass PKGS="./engine/policy/... ./engine/gate/..." to narrow.
PKGS ?= ./...
test-q:
	@go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:|ok )' | grep -v '^ok ' ; \
	 echo "root: done"
	@for m in $(MODS); do $(MAKE) --no-print-directory -C $$m test-q PKGS="$(PKGS)"; done

# Local dev stack (docker compose, DEV ONLY keys). dev-smoke needs dev-up.
DEV_COMPOSE := docker compose -f deploy/dev/compose.yaml --project-directory deploy/dev --profile dev

dev-up:
	$(DEV_COMPOSE) up -d --build --wait

dev-down:
	$(DEV_COMPOSE) down -v

dev-smoke:
	EDICTA_DEV_SMOKE=1 go test -tags composesmoke -count=1 ./deploy/dev/smoke

# Unit tests of the code behind the edictadev build tag (no docker, no network).
test-dev:
	go test -race -count=1 -tags edictadev ./plugins/edenescrow/...
	@for m in $(MODS); do $(MAKE) -C $$m test-dev || exit 1; done
