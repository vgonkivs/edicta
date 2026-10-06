// Command fibreanchor-gen writes the Fibre anchor-lookup vectors
// (spec/vectors/da/fibre_anchor.json): live PayForFibre namespace data from
// Mocha with the data availability header it is proven against, mutations of
// those inputs, synthetic compact-share sequences for the reassembly rule, and
// the archive form of the proof.
//
// It lives in its own module, with the replace set of the celestia-node
// release the Edicta celestia module builds against, and computes every
// expected value with upstream code (celestia-app's DataAvailabilityHeader,
// celestia-node's NamespaceData.Verify, go-square's ParseTxs and compact share
// splitter, celestia-app's TryParseFibreTx), so no Edicta code can leak into
// the expectations.
//
// Usage (from this directory):
//
//	go run . -fetch    read the live inputs from a Mocha bridge (read-only), then regenerate
//	go run .           regenerate ../../da/fibre_anchor.json from the raw inputs already in it
//	go run . -check    exit 1 if the file differs from a fresh generation
//
// Only -fetch touches the network; it never sends a transaction and holds no
// keys.
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
	out := flag.String("out", filepath.Join("..", "..", "da", "fibre_anchor.json"), "output file")
	bridge := flag.String("bridge", "http://da-bootstrapper-1.celestia-mocha.com:26658", "celestia-node bridge JSON-RPC")
	rpc := flag.String("rpc", "https://rpc.celestia-mocha.com", "consensus CometBFT RPC, for the data_hash cross-check")
	flag.Parse()

	var in liveInput
	if *fetchFlag {
		var err error
		in, err = fetch(*bridge, *rpc, liveHeights)
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	} else {
		var old struct {
			Live struct {
				Source liveSource `json:"source"`
				Cases  []liveCase `json:"cases"`
			} `json:"live"`
		}
		b, err := os.ReadFile(*out)
		if err != nil {
			return fmt.Errorf("no raw inputs (run with -fetch first): %w", err)
		}
		if err := json.Unmarshal(b, &old); err != nil {
			return err
		}
		in.Source = old.Live.Source
		for _, c := range old.Live.Cases {
			in.Raw = append(in.Raw, c.Raw)
		}
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
		fmt.Printf("OK: %s matches (%d live, %d mutations, %d reassembly)\n",
			*out, len(f.Live.Cases), len(f.Mutations), len(f.Reassembly))
		return nil
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d live, %d mutations, %d reassembly)\n",
		*out, len(f.Live.Cases), len(f.Mutations), len(f.Reassembly))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fibreanchor-gen:", err)
		os.Exit(1)
	}
}
