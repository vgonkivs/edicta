BIN := celestia/bin
CMDS := edicta edictad edicta-live edicta-verify

.PHONY: build demo test test-q vet vectors clean contracts contracts-check dev-up dev-down dev-smoke test-dev

build:
	@for c in $(CMDS); do echo "go build $$c"; go -C celestia build -o bin/$$c ./cmd/$$c || exit 1; done

demo: build
	$(BIN)/edicta demo $(ARGS)

vet:
	go vet ./...
	go -C celestia vet ./...
	go -C celestia vet -tags edictadev ./initcmd ./cmd/edicta-devinit

test:
	go test -race -p 2 ./...
	go -C celestia test -race -p 2 ./...
	$(MAKE) test-dev

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

# Quiet test run: package summary lines that failed, plus failure output only.
# PKGS defaults to everything; pass PKGS="./policy/... ./gate/..." to narrow.
PKGS ?= ./...
test-q:
	@go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:|ok )' | grep -v '^ok ' ; \
	 echo "root: done"
	@cd celestia && go test -race -count=1 -p 2 $(PKGS) 2>&1 | grep -E '^(--- FAIL|FAIL|panic:)' ; \
	 echo "celestia: done"

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
	go -C celestia test -race -count=1 -tags edictadev ./initcmd ./cmd/edicta-devinit
