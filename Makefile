BIN := celestia/bin
CMDS := edicta edictad edicta-live edicta-verify

.PHONY: build demo test vet vectors clean

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
