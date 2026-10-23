export GOWORK := off

BIN := celestia/bin
CMDS := edicta edictad edicta-verify edicta-signer

.PHONY: build demo test test-clipin test-q vet vectors clean contracts contracts-check dev-up dev-down dev-smoke test-dev check-mods

build:
	@for c in $(CMDS); do echo "go build $$c"; go -C celestia build -o bin/$$c ./cmd/$$c || exit 1; done
	$(MAKE) -C examples build

# The demo is an example binary: make demo ARGS="fast-mode --json" runs bin/edicta-demo fast-mode --json.
demo: build
	bin/edicta-demo $(ARGS)

vet:
	go vet ./...
	go -C celestia vet ./...
	go -C examples vet ./...
	go vet -tags edictadev ./plugins/edenescrow/...
	go -C celestia vet -tags edictadev ./initcmd ./cmd/edicta-devinit ./edictad/ ./verifycli/

test:
	go test -race -p 2 ./...
	go -C celestia test -race -p 2 ./...
	go -C examples test -race -p 2 ./...
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
	rm -rf $(BIN) bin

# Module hygiene: relative in-repo replaces, nothing requires examples, tidy
# go.mod files, and the fork replace block equal across the heavy modules.
check-mods:
	make/check-mods.sh
	go -C celestia test -count=1 -run '^TestReplaceSetParityAcrossHeavyModules$$' .

# Quiet test run: package summary lines that failed, plus failure output only.
# PKGS defaults to everything; pass PKGS="./engine/policy/... ./engine/gate/..." to narrow.
PKGS ?= ./...
test-q:
	@go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:|ok )' | grep -v '^ok ' ; \
	 echo "root: done"
	@cd celestia && go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:)' ; \
	 echo "celestia: done"
	@cd examples && go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:)' ; \
	 echo "examples: done"

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
	go -C celestia test -race -count=1 -tags edictadev ./initcmd ./cmd/edicta-devinit ./edictad/ ./verifycli/
