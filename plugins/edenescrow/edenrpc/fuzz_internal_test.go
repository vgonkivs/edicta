// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
)

// seeds are the recorded answers, so the fuzzer starts from real shapes.
func seeds(f *testing.F) {
	b, err := os.ReadFile(testkit.RepoPath(f, recordedBlock))
	if err != nil {
		f.Fatal(err)
	}
	var rec struct {
		Block struct {
			Result json.RawMessage `json:"result"`
		} `json:"eth_getBlockByNumber"`
		Receipts struct {
			Result []json.RawMessage `json:"result"`
		} `json:"eth_getBlockReceipts"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(rec.Block.Result))
	var block struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(rec.Block.Result, &block); err != nil {
		f.Fatal(err)
	}
	for _, tx := range block.Transactions {
		f.Add([]byte(tx))
	}
	for _, r := range rec.Receipts.Result {
		f.Add([]byte(r))
	}
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":null}`))
	f.Add([]byte(`{"dataDaHeight":"7"}`))
}

func FuzzDecodeTransaction(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		tx, err := DecodeTransaction(b)
		if err != nil {
			return
		}
		if checkStrict(b) != nil {
			t.Fatal("accepted a transaction that is not strict JSON")
		}
		if out, err := edenexec.RebuildSigned(tx); err == nil && len(out) == 0 {
			t.Fatal("empty rebuild")
		}
	})
}

func FuzzDecodeReceipt(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		rc, err := DecodeReceipt(b)
		if err != nil {
			return
		}
		if rc.Status > 1 {
			t.Fatalf("status %d accepted", rc.Status)
		}
		if _, err := edenexec.ReceiptEncoding(rc); err != nil {
			t.Fatalf("accepted receipt does not encode: %v", err)
		}
	})
}

func FuzzDecodeBlock(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, _, err := DecodeBlock(b)
		if err != nil {
			return
		}
		_, _ = edenexec.HeaderRLP(h)
	})
}

func FuzzParseEnvelope(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := parseEnvelope(b, 1)
		if err == nil && res == nil {
			t.Fatal("no error and no result")
		}
	})
}

func FuzzParseDAHeight(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, inc, err := parseDAHeight(b)
		if err == nil && inc != (h > 0) {
			t.Fatal("included disagrees with the height")
		}
	})
}
