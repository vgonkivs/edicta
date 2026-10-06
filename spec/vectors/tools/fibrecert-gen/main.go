// Command fibrecert-gen writes the Fibre availability-certificate vectors
// (spec/vectors/da/fibre_cert.json): one live PayForFibre from Mocha with the
// validator set and headers it needs, byte-flip mutations of each input,
// synthetic boundary certificates and the integer threshold table.
//
// It lives in its own module, with the replace set of the celestia-node
// release the Edicta celestia module builds against, and computes every
// expected value with upstream code only (celestia-app's PFF parser,
// PaymentPromise sign bytes and owner check, the keeper's signature walk over
// validator.SignatureSet, celestia-core header and validator-set hashes), so
// no Edicta code can leak into the expectations.
//
// Usage (from this directory):
//
//	go run . -fetch    read the live inputs from Mocha (read-only gRPC), then regenerate
//	go run .           regenerate ../../da/fibre_cert.json from the raw inputs already in it
//	go run . -check    exit 1 if the file differs from a fresh generation
//
// Only -fetch touches the network; it never sends a transaction and holds no
// keys. The raw bytes it reads are stored in the vector file, so tests and
// later regenerations are offline.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func run() error {
	fetchFlag := flag.Bool("fetch", false, "read the live inputs from Mocha before generating (read-only network)")
	check := flag.Bool("check", false, "compare with the existing file instead of writing it")
	out := flag.String("out", filepath.Join("..", "..", "da", "fibre_cert.json"), "output file")
	quick := flag.String("quicknode", "public-endpoint.celestia-mocha.quiknode.pro:9090", "consensus gRPC (TLS) for height-in-request reads")
	pops := flag.String("pops", "grpc-mocha.pops.one:9090", "archival consensus gRPC (plaintext) that honours x-cosmos-block-height")
	guru := flag.String("guru", "grpc-1.testnet.celestia.nodes.guru:10790", "second archival consensus gRPC (plaintext) for the cross-check")
	flag.Parse()

	var in liveInput
	if *fetchFlag {
		var err error
		in, err = fetch(endpoints{quick: *quick, pops: *pops, guru: *guru})
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	} else {
		var old struct {
			Live struct {
				Source liveSource `json:"source"`
				Raw    liveRaw    `json:"raw"`
			} `json:"live"`
		}
		b, err := os.ReadFile(*out)
		if err != nil {
			return fmt.Errorf("no raw inputs (run with -fetch first): %w", err)
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return err
		}
		in = liveInput{Source: old.Live.Source, Raw: old.Live.Raw}
	}

	f, err := build(in)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *check {
		old, err := os.ReadFile(*out)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, b) {
			return fmt.Errorf("%s differs from a fresh generation", *out)
		}
		fmt.Printf("OK: %s matches (%d mutations, %d undetected, %d boundary, %d threshold)\n",
			*out, len(f.Mutations), len(f.Undetected), len(f.Boundary.Cases), len(f.Threshold))
		return nil
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d mutations, %d undetected, %d boundary, %d threshold)\n",
		*out, len(f.Mutations), len(f.Undetected), len(f.Boundary.Cases), len(f.Threshold))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fibrecert-gen:", err)
		os.Exit(1)
	}
}
