BIN := celestia/bin
CMDS := edicta edictad edicta-live edicta-verify

.PHONY: build demo test test-q vet vectors clean

build:
	@for c in $(CMDS); do echo "go build $$c"; go -C celestia build -o bin/$$c ./cmd/$$c || exit 1; done

demo: build
	$(BIN)/edicta demo $(ARGS)

vet:
	go vet ./...
	go -C celestia vet ./...

test:
	go test -race -p 2 ./...
	go -C celestia test -race -p 2 ./...

vectors:
	python3 spec/vectors/check/check_vectors.py

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
