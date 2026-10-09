// Command absence-gen captures the live Mocha cases of the absence-proof
// vectors (spec/vectors/da/absence.json, keys live, live_source and
// live_tail_rule) and checks them again offline with upstream code, together
// with the per-height outcomes of the synthetic cases.
//
// Expected values come from upstream code only: celestia-core for the signed
// header, its hash and the block results root; celestia-app for the DAH, the
// PayForFibre parse and the square rebuild (ConstructEDS); celestia-node for
// NamespaceData.Verify; go-square for ParseTxs, ParseBlobs and
// CreateCommitment. No Edicta code is imported.
//
// Usage (from this directory):
//
//	go run . -fetch -live-out FILE   read Mocha (read-only), write the live sections as JSON to FILE
//	go run . -check                  rebuild the live sections from the records in ../../da/absence.json and
//	                                 classify every synthetic case again, exit 1 on any difference
//
// The Python generator (spec/vectors/check/gen_absence.py --live FILE)
// embeds FILE; afterwards it carries the sections over unchanged. Only
// -fetch touches the network; it never sends a transaction and holds no keys.
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
	fetchFlag := flag.Bool("fetch", false, "read the live inputs from Mocha (read-only network)")
	check := flag.Bool("check", false, "rebuild the live sections from the vector file and compare")
	file := flag.String("file", filepath.Join("..", "..", "da", "absence.json"), "absence vector file")
	liveOut := flag.String("live-out", "", "with -fetch: where to write the live sections")
	bridge := flag.String("bridge", "http://da-bootstrapper-1.celestia-mocha.com:26658", "celestia-node bridge JSON-RPC")
	rpc := flag.String("rpc", "https://rpc.celestia-mocha.com", "consensus CometBFT RPC")
	rpc2 := flag.String("rpc2", "https://rpc-mocha.pops.one", "second consensus CometBFT RPC (another operator), for the trusted hashes")
	flag.Parse()

	switch {
	case *fetchFlag:
		if *liveOut == "" {
			return fmt.Errorf("-fetch needs -live-out")
		}
		in, err := fetch(endpoints{bridge: *bridge, rpc: *rpc, rpc2: *rpc2})
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
		doc, err := build(in)
		if err != nil {
			return err
		}
		b, err := marshal(doc)
		if err != nil {
			return err
		}
		return os.WriteFile(*liveOut, b, 0o644)
	case *check:
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var f liveDoc
		if err := json.Unmarshal(b, &f); err != nil {
			return err
		}
		in, err := inputsFromDoc(f)
		if err != nil {
			return err
		}
		again, err := build(in)
		if err != nil {
			return err
		}
		want, err := marshal(f)
		if err != nil {
			return err
		}
		got, err := marshal(again)
		if err != nil {
			return err
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("%s: live sections differ from a rebuild with upstream code", *file)
		}
		ns, err := checkSynthetic(b)
		if err != nil {
			return fmt.Errorf("%s: synthetic: %w", *file, err)
		}
		fmt.Printf("OK (%s): %d live cases, %d tail-rule blocks rebuilt, %d synthetic cases classified with upstream code\n", *file, len(f.Live), len(f.TailRule.Blocks), ns)
		return nil
	default:
		return fmt.Errorf("give -fetch or -check")
	}
}

func marshal(d liveDoc) ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "absence-gen:", err)
		os.Exit(1)
	}
}
