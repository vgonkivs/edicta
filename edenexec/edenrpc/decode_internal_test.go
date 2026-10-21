// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenexec"
)

func TestCheckStrict(t *testing.T) {
	ok := []string{
		`{}`, `[]`, `"x"`, `null`, `1`, ` {"a":1,"b":[1,{"a":2}],"c":{"a":{}}} `,
		`{"a":{"b":1},"b":{"b":2}}`,
	}
	for _, s := range ok {
		assert.NoError(t, checkStrict([]byte(s)), s)
	}
	bad := []string{
		``, `{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"x":{"a":1,"a":2}}`, `[{"a":1,"a":1}]`,
		`{"a":1}{}`, `{"a":1} x`, `1 2`, `{"a":}`, `{"ſtatus":1}`, "{\"a\":\"\xff\"}",
		strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1),
	}
	for _, s := range bad {
		assert.ErrorIs(t, checkStrict([]byte(s)), ErrMalformed, s)
	}
	deep := strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth)
	assert.NoError(t, checkStrict([]byte(deep)))
}

func TestHexForms(t *testing.T) {
	q := map[string][]byte{"0x0": {}, "0x1": {1}, "0xff": {0xff}, "0x100": {1, 0}, "0xABC": {0x0a, 0xbc}}
	for s, want := range q {
		got, err := quantity(s, 32)
		require.NoError(t, err, s)
		assert.Equal(t, want, got, s)
	}
	for _, s := range []string{"", "0x", "0x00", "0x01", "1", "0xg", "0X1", "-0x1", "0x" + strings.Repeat("f", 65)} {
		_, err := quantity(s, 32)
		assert.ErrorIs(t, err, ErrMalformed, s)
	}
	_, err := quantity64("0x" + strings.Repeat("f", 17))
	assert.ErrorIs(t, err, ErrMalformed)
	v, err := quantity64("0xffffffffffffffff")
	require.NoError(t, err)
	assert.Equal(t, uint64(1<<64-1), v)

	for _, s := range []string{"0x", "0x00ff", "0xABcd"} {
		_, err := data(s)
		assert.NoError(t, err, s)
	}
	for _, s := range []string{"", "00", "0x0", "0xzz"} {
		_, err := data(s)
		assert.ErrorIs(t, err, ErrMalformed, s)
	}
	var a [20]byte
	assert.Error(t, fixed("0x"+strings.Repeat("00", 19), a[:]))
	assert.NoError(t, fixed("0x"+strings.Repeat("00", 20), a[:]))
}

// mutate returns the recorded deposit transaction object with one change.
func mutate(t testing.TB, raw json.RawMessage, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	f(m)
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestDecodeTransactionShapes(t *testing.T) {
	f := loadF14(t)
	_, err := DecodeTransaction(f.Deposit.RPCTx)
	require.NoError(t, err)

	t.Run("missing fields of a known type", func(t *testing.T) {
		for _, k := range []string{"type", "hash", "nonce", "gas", "value", "input", "r", "s", "chainId", "accessList", "maxFeePerGas", "maxPriorityFeePerGas"} {
			_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { delete(m, k) }))
			assert.ErrorIs(t, err, ErrMalformed, k)
		}
		_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { delete(m, "v"); delete(m, "yParity") }))
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("v and yParity disagree", func(t *testing.T) {
		_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { m["v"] = "0x1" }))
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("v alone", func(t *testing.T) {
		tx, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { delete(m, "yParity") }))
		require.NoError(t, err)
		b, err := edenexec.RebuildSigned(tx)
		require.NoError(t, err)
		assert.Equal(t, tx.Hash, keccak(b))
	})
	t.Run("pending", func(t *testing.T) {
		tx, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) {
			m["blockHash"], m["blockNumber"], m["transactionIndex"] = nil, nil, nil
		}))
		require.NoError(t, err)
		assert.False(t, tx.Included)
	})
	t.Run("unknown type keeps its hash", func(t *testing.T) {
		tx, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) {
			m["type"] = "0x7e"
			delete(m, "nonce")
		}))
		require.NoError(t, err)
		_, err = edenexec.RebuildSigned(tx)
		require.ErrorIs(t, err, edenexec.ErrTxType)
	})
	t.Run("type above a byte", func(t *testing.T) {
		_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { m["type"] = "0x100" }))
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("non-canonical quantity", func(t *testing.T) {
		_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { m["nonce"] = "0x0bb958" }))
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("short address", func(t *testing.T) {
		_, err := DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { m["to"] = "0x1234" }))
		assert.ErrorIs(t, err, ErrMalformed)
	})
	t.Run("blob and set-code fields", func(t *testing.T) {
		raw := mutate(t, f.Deposit.RPCTx, func(m map[string]any) {
			m["type"] = "0x4"
			m["authorizationList"] = []any{map[string]any{
				"chainId": "0x2ca", "address": "0x" + strings.Repeat("11", 20), "nonce": "0x0", "yParity": "0x1",
				"r": "0x5", "s": "0x6",
			}}
		})
		tx, err := DecodeTransaction(raw)
		require.NoError(t, err)
		require.Len(t, tx.AuthList, 1)
		_, err = DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) { m["type"] = "0x4" }))
		assert.ErrorIs(t, err, ErrMalformed, "authorizationList missing")
		_, err = DecodeTransaction(mutate(t, f.Deposit.RPCTx, func(m map[string]any) {
			m["type"] = "0x3"
			m["maxFeePerBlobGas"] = "0x1"
		}))
		assert.ErrorIs(t, err, ErrMalformed, "blobVersionedHashes missing")
	})
}

func TestDecodeReceiptShapes(t *testing.T) {
	f := loadF14(t)
	_, err := DecodeReceipt(f.Deposit.RPCReceipt)
	require.NoError(t, err)
	for name, mod := range map[string]func(m map[string]any){
		"status 2":       func(m map[string]any) { m["status"] = "0x2" },
		"no status":      func(m map[string]any) { delete(m, "status") },
		"no logs":        func(m map[string]any) { delete(m, "logs") },
		"short bloom":    func(m map[string]any) { m["logsBloom"] = "0x00" },
		"type above 127": func(m map[string]any) { m["type"] = "0x80" },
		"five topics": func(m map[string]any) {
			l := m["logs"].([]any)[0].(map[string]any)
			l["topics"] = append(l["topics"].([]any), "0x"+strings.Repeat("00", 32))
		},
		"removed missing": func(m map[string]any) { delete(m["logs"].([]any)[0].(map[string]any), "removed") },
		"short topic": func(m map[string]any) {
			l := m["logs"].([]any)[0].(map[string]any)
			l["topics"].([]any)[0] = "0x00"
		},
	} {
		_, err := DecodeReceipt(mutate(t, f.Deposit.RPCReceipt, mod))
		assert.ErrorIs(t, err, ErrMalformed, name)
	}
}

func TestDecodeBlockShapes(t *testing.T) {
	f := loadF14(t)
	h, txs, err := DecodeBlock(f.Block.RPCResult)
	require.NoError(t, err)
	assert.Empty(t, h.Unknown)
	assert.Len(t, txs, 2)

	h, _, err = DecodeBlock(mutate(t, f.Block.RPCResult, func(m map[string]any) { m["slotNumber"] = "0x1" }))
	require.NoError(t, err)
	assert.Equal(t, []string{"slotNumber"}, h.Unknown)
	_, err = edenexec.HeaderRLP(h)
	assert.Error(t, err)

	h, _, err = DecodeBlock(mutate(t, f.Block.RPCResult, func(m map[string]any) {
		delete(m, "requestsHash")
		delete(m, "parentBeaconBlockRoot")
	}))
	require.NoError(t, err)
	assert.Nil(t, h.RequestsHash)
	enc, err := edenexec.HeaderRLP(h)
	require.NoError(t, err)
	assert.NotEqual(t, h.Hash, keccak(enc), "an older fork's header shape hashes elsewhere")

	for _, k := range []string{"hash", "parentHash", "number", "timestamp", "nonce", "mixHash", "logsBloom"} {
		_, _, err := DecodeBlock(mutate(t, f.Block.RPCResult, func(m map[string]any) { delete(m, k) }))
		assert.ErrorIs(t, err, ErrMalformed, k)
	}
}

func TestStore(t *testing.T) {
	var gotPath, gotBody, gotCT, gotProto string
	answer := `{"block":{"header":{}},"headerDaHeight":"15152876","dataDaHeight":"15152868"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotBody, gotCT, gotProto = r.URL.Path, string(b), r.Header.Get("Content-Type"), r.Header.Get("Connect-Protocol-Version")
		_, _ = io.WriteString(w, answer)
	}))
	defer srv.Close()
	cfg := StoreConfig{URL: srv.URL + "/"}
	cfg.ApplyDefaults()
	st, err := NewStore(cfg, srv.Client())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", st.Name())
	h, inc, err := st.DataDAHeight(context.Background(), 227899844)
	require.NoError(t, err)
	assert.True(t, inc)
	assert.Equal(t, uint64(15152868), h)
	assert.Equal(t, GetBlockPath, gotPath)
	assert.JSONEq(t, `{"height":"227899844"}`, gotBody)
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, "1", gotProto)

	_, err = NewStore(StoreConfig{URL: "unix:///x", Timeout: 1}, nil)
	assert.Error(t, err)
}

func TestParseDAHeight(t *testing.T) {
	cases := map[string]struct {
		h   uint64
		inc bool
		bad bool
	}{
		`{"dataDaHeight":"7"}`:                      {h: 7, inc: true},
		`{"data_da_height":7}`:                      {h: 7, inc: true},
		`{"block":{}}`:                              {},
		`{"dataDaHeight":"0"}`:                      {},
		`{"dataDaHeight":"07"}`:                     {bad: true},
		`{"dataDaHeight":"-1"}`:                     {bad: true},
		`{"dataDaHeight":"x"}`:                      {bad: true},
		`{"dataDaHeight":"7","data_da_height":"7"}`: {bad: true},
		`{"dataDaHeight":"7","dataDaHeight":"8"}`:   {bad: true},
		`{"dataDaHeight":"18446744073709551616"}`:   {bad: true},
		`[]`: {bad: true},
	}
	for in, want := range cases {
		h, inc, err := parseDAHeight([]byte(in))
		if want.bad {
			assert.Error(t, err, in)
			continue
		}
		require.NoError(t, err, in)
		assert.Equal(t, want.h, h, in)
		assert.Equal(t, want.inc, inc, in)
	}
}
