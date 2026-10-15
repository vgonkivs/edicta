// Command execresult-gen builds the synthetic blocks of the archived
// execution result vectors (kind 19, spec/vectors/archive/execution_result_v1.1.json)
// and checks the vector file again with upstream code.
//
// Every block is built the way ProcessProposal builds it at the pins:
// ClassifyTxs, go-square Construct, ExtendShares and the DAH from celestia-app;
// the share proofs from NewShareInclusionProofFromEDS; the headers, their
// hashes, the block results root and the result proofs from celestia-core.
// The ordinary txs are the live bank-send tx of verifier/execution_outcomes.json
// and fixed byte strings; the Fibre tx is the live PFF of da/fibre_anchor.json.
// No Edicta code is imported, and nothing touches the network.
//
// Usage (from this directory):
//
//	go run . -out FILE   write the block section as JSON to FILE
//	go run . -check      rebuild the block section from the inputs and compare it with the vector file,
//	                     then run the XR rules with upstream code on every case, exit 1 on any difference
//
// The Python generator (spec/vectors/check/gen_v1_1.py --exec FILE) embeds
// FILE; afterwards it carries the section over unchanged.
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
	out := flag.String("out", "", "write the block section to this file")
	check := flag.Bool("check", false, "rebuild the block section and run the XR rules on every case of the vector file")
	file := flag.String("file", filepath.Join("..", "..", "archive", "execution_result_v1.1.json"), "vector file")
	flag.Parse()

	in, err := loadInputs(filepath.Join("..", ".."))
	if err != nil {
		return fmt.Errorf("inputs: %w", err)
	}
	sec, err := build(in)
	if err != nil {
		return err
	}
	switch {
	case *out != "":
		b, err := marshal(sec)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, b, 0o644)
	case *check:
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var f vectorFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return err
		}
		want, err := marshal(f.Upstream)
		if err != nil {
			return err
		}
		got, err := marshal(sec)
		if err != nil {
			return err
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("%s: the upstream section differs from a rebuild with upstream code", *file)
		}
		n, err := checkCases(f)
		if err != nil {
			return fmt.Errorf("%s: %w", *file, err)
		}
		fmt.Printf("OK (%s): %d blocks rebuilt, %d cases classified with upstream code\n", *file, len(sec.Blocks), n)
		return nil
	default:
		return fmt.Errorf("give -out or -check")
	}
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL (execresult-gen):", err)
		os.Exit(1)
	}
}
