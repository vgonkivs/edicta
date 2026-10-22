// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
)

const (
	vectorDir     = "vectors/profiles/eden-escrow"
	recordedBlock = "plugins/edenescrow/edenexec/testdata/eden-714-block-227899844.json"
)

// rpcServer answers JSON-RPC requests on the loopback from a table of
// results by method; answer overrides the whole body.
type rpcServer struct {
	t       testing.TB
	mu      sync.Mutex
	results map[string]string
	errors  map[string]string
	answer  func(id json.RawMessage, method string, params []json.RawMessage) (string, bool)
	calls   []string
}

func (s *rpcServer) set(method, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[method] = result
}

func (s *rpcServer) setAnswer(f func(id json.RawMessage, method string, params []json.RawMessage) (string, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer = f
}

func (s *rpcServer) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func newRPCServer(t testing.TB) (*rpcServer, *Client) {
	t.Helper()
	s := &rpcServer{t: t, results: map[string]string{}, errors: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	cfg := Config{URL: srv.URL, Class: edenexec.ClassPublicRPC}
	cfg.ApplyDefaults()
	c, err := New(cfg, srv.Client())
	require.NoError(t, err)
	return s, c
}

func (s *rpcServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.calls = append(s.calls, req.Method)
	answer := s.answer
	e, isErr := s.errors[req.Method]
	res, ok := s.results[req.Method]
	s.mu.Unlock()
	if answer != nil {
		if out, ok := answer(req.ID, req.Method, req.Params); ok {
			_, _ = io.WriteString(w, out)
			return
		}
	}
	if isErr {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":%s}`, req.ID, e)
		return
	}
	if !ok {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"the method %s does not exist"}}`, req.ID, req.Method)
		return
	}
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, res)
}

type recorded struct {
	Block struct {
		Result json.RawMessage `json:"result"`
	} `json:"eth_getBlockByNumber"`
	Receipts struct {
		Result json.RawMessage `json:"result"`
	} `json:"eth_getBlockReceipts"`
}

func loadRecorded(t testing.TB) recorded {
	t.Helper()
	b, err := os.ReadFile(testkit.RepoPath(t, recordedBlock))
	require.NoError(t, err)
	var r recorded
	require.NoError(t, json.Unmarshal(b, &r))
	return r
}

type f14 struct {
	Block struct {
		RPCResult json.RawMessage `json:"rpc_result"`
	} `json:"block_227899844"`
	Deposit struct {
		Hash       string          `json:"hash"`
		RPCTx      json.RawMessage `json:"rpc_tx"`
		RPCReceipt json.RawMessage `json:"rpc_receipt"`
	} `json:"deposit"`
}

func loadF14(t testing.TB) f14 {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, vectorDir, "live/f14.json"))
	require.NoError(t, err)
	var f f14
	require.NoError(t, json.Unmarshal(b, &f))
	return f
}

func h32(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	require.NoError(t, err)
	require.Len(t, b, 32)
	var h [32]byte
	copy(h[:], b)
	return h
}

func TestClientReadsRecordedAnswers(t *testing.T) {
	f := loadF14(t)
	rec := loadRecorded(t)
	s, c := newRPCServer(t)
	s.set("eth_chainId", `"0x2ca"`)
	s.set("eth_blockNumber", `"0xd9579d8"`)
	s.set("eth_getTransactionByHash", string(f.Deposit.RPCTx))
	s.set("eth_getTransactionReceipt", string(f.Deposit.RPCReceipt))
	s.set("eth_getBlockReceipts", string(rec.Receipts.Result))
	s.setAnswer(func(id json.RawMessage, method string, params []json.RawMessage) (string, bool) {
		if method != "eth_getBlockByHash" {
			return "", false
		}
		full := string(params[1]) == "true"
		block := f.Block.RPCResult
		if full {
			block = rec.Block.Result
		}
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, block), true
	})
	ctx := context.Background()
	R := h32(t, f.Deposit.Hash)

	assert.Equal(t, "127.0.0.1", c.Name())
	assert.Equal(t, edenexec.ClassPublicRPC, c.Class())
	id, err := c.ChainID(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(714), id)
	head, err := c.Head(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(0xd9579d8), head)

	tx, err := c.Transaction(ctx, R)
	require.NoError(t, err)
	assert.Equal(t, R, tx.Hash)
	assert.True(t, tx.Included)
	assert.Equal(t, uint64(1), tx.Index)
	b, err := edenexec.RebuildSigned(tx)
	require.NoError(t, err)
	assert.Equal(t, R, keccak(b))

	rc, err := c.Receipt(ctx, R)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), rc.Status)
	assert.Len(t, rc.Logs, 5)

	h, err := c.Header(ctx, tx.BlockHash)
	require.NoError(t, err)
	assert.Equal(t, tx.BlockHash, h.Hash)
	assert.Empty(t, h.Unknown)

	txs, err := c.BlockTransactions(ctx, tx.BlockHash)
	require.NoError(t, err)
	rcpts, err := c.BlockReceipts(ctx, tx.BlockHash)
	require.NoError(t, err)
	require.NoError(t, edenexec.VerifyBlock(h, tx.BlockHash, txs, rcpts, 1, b, rcpts[1]))

	_, err = c.Header(ctx, R)
	require.Error(t, err, "a block served for another hash")
}

func TestClientNotFound(t *testing.T) {
	s, c := newRPCServer(t)
	for _, m := range []string{"eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByHash", "eth_getBlockReceipts"} {
		s.set(m, "null")
	}
	ctx := context.Background()
	_, err := c.Transaction(ctx, [32]byte{1})
	require.ErrorIs(t, err, edenexec.ErrNotFound)
	_, err = c.Receipt(ctx, [32]byte{1})
	require.ErrorIs(t, err, edenexec.ErrNotFound)
	_, err = c.Header(ctx, [32]byte{1})
	require.ErrorIs(t, err, edenexec.ErrNotFound)
	_, err = c.BlockTransactions(ctx, [32]byte{1})
	require.ErrorIs(t, err, edenexec.ErrNotFound)
	_, err = c.BlockReceipts(ctx, [32]byte{1})
	require.ErrorIs(t, err, edenexec.ErrNotFound)
}

func TestClientReceiptsOneByOne(t *testing.T) {
	f := loadF14(t)
	rec := loadRecorded(t)
	var receipts []json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Receipts.Result, &receipts))
	s, c := newRPCServer(t)
	// No eth_getBlockReceipts: the server's default answer is "method not
	// found".
	s.setAnswer(func(id json.RawMessage, method string, params []json.RawMessage) (string, bool) {
		switch method {
		case "eth_getBlockByHash":
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, f.Block.RPCResult), true
		case "eth_getTransactionReceipt":
			for _, r := range receipts {
				var hdr struct {
					TransactionHash string `json:"transactionHash"`
				}
				if json.Unmarshal(r, &hdr) != nil {
					return "", false
				}
				if `"`+hdr.TransactionHash+`"` == string(params[0]) {
					return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, r), true
				}
			}
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":null}`, id), true
		}
		return "", false
	})
	h, _, err := DecodeBlock(f.Block.RPCResult)
	require.NoError(t, err)
	rcpts, err := c.BlockReceipts(context.Background(), h.Hash)
	require.NoError(t, err)
	assert.Equal(t, h.ReceiptRoot, edenexec.DeriveSha(rcpts))
	assert.Contains(t, s.called(), "eth_getBlockReceipts")
}

func TestClientEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body func(id string) string
	}{
		{"wrong id", func(string) string { return `{"jsonrpc":"2.0","id":999,"result":"0x1"}` }},
		{"string id", func(id string) string { return `{"jsonrpc":"2.0","id":"` + id + `","result":"0x1"}` }},
		{"no version", func(id string) string { return `{"id":` + id + `,"result":"0x1"}` }},
		{"version 1", func(id string) string { return `{"jsonrpc":"1.0","id":` + id + `,"result":"0x1"}` }},
		{"no result", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `}` }},
		{"result and error", func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x1","error":{"code":1,"message":"x"}}`
		}},
		{"error", func(id string) string {
			return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32000,"message":"boom"}}`
		}},
		{"duplicate result", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x1","result":"0x2"}` }},
		{"duplicate result in other case", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x1","Result":"0x2"}` }},
		{"trailing data", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x1"} {}` }},
		{"not JSON", func(string) string { return `<html>` }},
		{"leading zero quantity", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x01"}` }},
		{"no 0x", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"1"}` }},
		{"quantity too large", func(id string) string { return `{"jsonrpc":"2.0","id":` + id + `,"result":"0x10000000000000000"}` }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, c := newRPCServer(t)
			s.setAnswer(func(id json.RawMessage, _ string, _ []json.RawMessage) (string, bool) {
				return tc.body(string(id)), true
			})
			_, err := c.ChainID(context.Background())
			require.Error(t, err)
			require.NotErrorIs(t, err, edenexec.ErrNotFound)
		})
	}
}

func TestClientLimitsAndStatus(t *testing.T) {
	t.Run("answer above the limit", func(t *testing.T) {
		s, c := newRPCServer(t)
		big := `"0x` + strings.Repeat("00", DefaultMaxResponse) + `"`
		s.setAnswer(func(id json.RawMessage, _ string, _ []json.RawMessage) (string, bool) {
			return `{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + big + `}`, true
		})
		_, err := c.Transaction(context.Background(), [32]byte{})
		require.ErrorContains(t, err, "larger than")
	})
	t.Run("HTTP error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusTooManyRequests)
		}))
		defer srv.Close()
		cfg := Config{URL: srv.URL}
		cfg.ApplyDefaults()
		c, err := New(cfg, srv.Client())
		require.NoError(t, err)
		_, err = c.ChainID(context.Background())
		require.ErrorContains(t, err, "HTTP 429")
	})
	t.Run("redirect to another host is not followed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://localhost:1/", http.StatusTemporaryRedirect)
		}))
		defer srv.Close()
		cfg := Config{URL: srv.URL}
		cfg.ApplyDefaults()
		c, err := New(cfg, nil)
		require.NoError(t, err)
		_, err = c.ChainID(context.Background())
		require.ErrorContains(t, err, "HTTP 307")
	})
	t.Run("transport errors name the host, not the URL", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		addr := srv.Listener.Addr().String()
		srv.Close() // nothing listens there now
		cfg := Config{URL: "http://" + addr + "/v1/SECRETPATH?apikey=SECRETQUERY"}
		cfg.ApplyDefaults()
		c, err := New(cfg, nil)
		require.NoError(t, err)
		_, err = c.ChainID(context.Background())
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "SECRET")
		assert.Contains(t, err.Error(), "127.0.0.1")

		st, err := NewStore(StoreConfig{URL: "http://" + addr + "/SECRETPATH", Timeout: DefaultTimeout}, nil)
		require.NoError(t, err)
		_, _, err = st.DataDAHeight(context.Background(), 1)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "SECRET")
	})
	t.Run("cancelled", func(t *testing.T) {
		s, c := newRPCServer(t)
		s.set("eth_chainId", `"0x2ca"`)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := c.ChainID(ctx)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestClientExpectChainID(t *testing.T) {
	s := &rpcServer{t: t, results: map[string]string{"eth_chainId": `"0x1"`, "eth_blockNumber": `"0x10"`}, errors: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	defer srv.Close()
	cfg := Config{URL: srv.URL, ExpectChainID: 714}
	cfg.ApplyDefaults()
	c, err := New(cfg, srv.Client())
	require.NoError(t, err)
	_, err = c.Head(context.Background())
	require.ErrorIs(t, err, edenexec.ErrChainConfig)

	s.set("eth_chainId", `"0x2ca"`)
	head, err := c.Head(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(16), head)
	_, err = c.Head(context.Background())
	require.NoError(t, err)
	n := 0
	for _, m := range s.called() {
		if m == "eth_chainId" {
			n++
		}
	}
	assert.Equal(t, 2, n, "checked until it matched, then once")
}

func TestClientBlockTransactionsChecks(t *testing.T) {
	rec := loadRecorded(t)
	var block map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Block.Result, &block))
	var hash string
	require.NoError(t, json.Unmarshal(block["hash"], &hash))

	serve := func(t *testing.T, mutate func(txs []map[string]any)) error {
		var txs []map[string]any
		require.NoError(t, json.Unmarshal(block["transactions"], &txs))
		mutate(txs)
		b := map[string]json.RawMessage{}
		for k, v := range block {
			b[k] = v
		}
		raw, err := json.Marshal(txs)
		require.NoError(t, err)
		b["transactions"] = raw
		out, err := json.Marshal(b)
		require.NoError(t, err)
		s, c := newRPCServer(t)
		s.set("eth_getBlockByHash", string(out))
		_, err = c.BlockTransactions(context.Background(), h32(t, hash))
		return err
	}
	require.NoError(t, serve(t, func([]map[string]any) {}))
	require.Error(t, serve(t, func(txs []map[string]any) { txs[0], txs[1] = txs[1], txs[0] }), "positions")
	require.Error(t, serve(t, func(txs []map[string]any) { txs[1]["nonce"] = "0x1" }), "a lying field")
	require.Error(t, serve(t, func(txs []map[string]any) { txs[1]["type"] = "0x7e" }), "an unknown type")
	require.Error(t, serve(t, func(txs []map[string]any) { txs[1]["blockHash"] = "0x" + strings.Repeat("11", 32) }), "another block")
}

func TestConfigValidate(t *testing.T) {
	good := Config{URL: "https://RPC.Eden.Gateway.FM./", Class: edenexec.ClassOwnNode}
	good.ApplyDefaults()
	require.NoError(t, good.ValidateBasic())
	c, err := New(good, nil)
	require.NoError(t, err)
	assert.Equal(t, "rpc.eden.gateway.fm", c.Name())

	for _, mod := range []func(*Config){
		func(c *Config) { c.URL = "ftp://x" },
		func(c *Config) { c.URL = "http://" },
		func(c *Config) { c.URL = "::" },
		func(c *Config) { c.Class = 9 },
		func(c *Config) { c.Timeout = -1 },
		func(c *Config) { c.MaxResponse = 10 },
		func(c *Config) { c.MaxBlock = c.MaxResponse - 1 },
		func(c *Config) { c.MaxBlock = MaxResponseLimit + 1 },
	} {
		cc := good
		mod(&cc)
		assert.Error(t, cc.ValidateBasic())
		_, err := New(cc, nil)
		assert.Error(t, err)
	}
}

func TestOperatorLabel(t *testing.T) {
	c := Config{URL: "https://RPC.eden.gateway.fm./", Class: edenexec.ClassPublicRPC}
	c.ApplyDefaults()
	cl, err := New(c, nil)
	require.NoError(t, err)
	assert.Empty(t, cl.Operator())
	label, explicit := edenexec.OperatorLabel(cl)
	assert.Equal(t, "rpc.eden.gateway.fm", label, "no label: the host stands in")
	assert.False(t, explicit)

	c.Operator = "gateway"
	cl, err = New(c, nil)
	require.NoError(t, err)
	label, explicit = edenexec.OperatorLabel(cl)
	assert.Equal(t, "gateway", label)
	assert.True(t, explicit)

	for _, bad := range []string{"two words", "tab\t", strings.Repeat("x", maxLabel+1), "caf\xc3\xa9"} {
		c.Operator = bad
		_, err := New(c, nil)
		assert.Error(t, err, "%q", bad)
	}
}

func TestSplitSource(t *testing.T) {
	for in, want := range map[string][2]string{
		"https://rpc.eden.gateway.fm/":         {"", "https://rpc.eden.gateway.fm/"},
		"HTTP://a.example/?x=1":                {"", "HTTP://a.example/?x=1"},
		"gateway=https://rpc.eden.gateway.fm/": {"gateway", "https://rpc.eden.gateway.fm/"},
		"own=http://127.0.0.1:8545/?a=b":       {"own", "http://127.0.0.1:8545/?a=b"},
		"=https://a.example":                   {"", "https://a.example"},
		"a.example":                            {"", "a.example"},
	} {
		op, u := SplitSource(in)
		assert.Equal(t, want, [2]string{op, u}, in)
	}
}
