// SPDX-License-Identifier: Apache-2.0

// Command edenescrow-gen writes the vectors of the eden-escrow profile with
// go-ethereum: the form T transactions, their EIP-1559 signing hashes and
// signatures, the rebuild of served transactions, the receipt encoding and
// the header hash of a recorded Eden block, the x402 escrow-upto flow from
// the requester's fixtures and the multi-source outcome table. It lives in its own module so
// the main module never depends on go-ethereum. Recorded chain data comes
// only from ../../profiles/eden-escrow/live/; nothing is fetched.
//
// Usage (from this directory):
//
//	go run .           regenerate ../../profiles/eden-escrow/*.json
//	go run . -check    exit 1 if any file differs from a fresh generation
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	format    = "edicta-vectors/v0"
	profile   = "eden-escrow"
	revision  = "eden-escrow-v1-draft.8"
	generator = "spec/vectors/tools/edenescrow-gen"
)

var upstream = obj{{"go-ethereum", "github.com/ethereum/go-ethereum v1.17.8"}}

type live struct {
	Block struct {
		RPCResult json.RawMessage `json:"rpc_result"`
		TxsRawHex []string        `json:"txs_raw_hex"`
	} `json:"block_227899844"`
	Deposit struct {
		Hash       string          `json:"hash"`
		RawHex     string          `json:"raw_hex"`
		RPCTx      json.RawMessage `json:"rpc_tx"`
		RPCReceipt json.RawMessage `json:"rpc_receipt"`
		InnerCall  struct {
			To       string `json:"to"`
			ValueWei string `json:"value_wei"`
			DataHex  string `json:"data_hex"`
			Buyer    string `json:"buyer"`
		} `json:"inner_call"`
	} `json:"deposit"`
	Settle struct {
		Hash   string          `json:"hash"`
		RawHex string          `json:"raw_hex"`
		RPCTx  json.RawMessage `json:"rpc_tx"`
	} `json:"settle"`
}

func main() {
	check := flag.Bool("check", false, "compare with the files on disk instead of writing them")
	flag.Parse()
	dir := filepath.Join("..", "..", "profiles", "eden-escrow")
	raw, err := os.ReadFile(filepath.Join(dir, "live", "f14.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var lv live
	if err := json.Unmarshal(raw, &lv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "live", "escrow-code.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var ec escrowCode
	if err := json.Unmarshal(raw, &ec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := loadEscrowCode(&ec)
	files := []struct {
		name string
		body obj
	}{
		{"deposit_call.json", buildDepositCallFile(&lv)},
		{"action.json", buildActionFile(&lv, code)},
		{"signed.json", buildSignedFile(&lv)},
		{"settlement.json", buildSettlementFile(&lv)},
		{"x402.json", buildX402File(loadHouston(dir))},
		{"multi_source.json", buildQuorumFile()},
	}
	failed := false
	for _, f := range files {
		b, err := json.MarshalIndent(f.body, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		b = append(b, '\n')
		p := filepath.Join(dir, f.name)
		if *check {
			old, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(old, b) {
				fmt.Fprintf(os.Stderr, "FAIL %s differs from a fresh generation\n", p)
				failed = true
			}
			continue
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("OK edenescrow-gen")
}
