package cometrpc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/verifier"
)

var bg = context.Background()

var (
	_ headertrust.NamedChain = (*cometrpc.Source)(nil)
	_ railverify.TxSource    = (*cometrpc.Source)(nil)
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

// files answers each path with a fixed body and status, and records the
// request URIs.
type files struct {
	*httptest.Server
	mu   sync.Mutex
	by   map[string]answer
	uris []string
}

type answer struct {
	code int
	body []byte
}

func serveFiles(t testing.TB, by map[string]answer) *files {
	t.Helper()
	f := &files{by: by}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.uris = append(f.uris, r.URL.RequestURI())
		a, ok := f.by[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if a.code != 0 {
			w.WriteHeader(a.code)
		}
		_, _ = w.Write(a.body)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *files) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.uris...)
}

func source(t testing.TB, url string) *cometrpc.Source {
	t.Helper()
	s, err := cometrpc.New(url, nil)
	require.NoError(t, err)
	return s
}

func ok(body []byte) answer { return answer{body: body} }

func TestNewChecksTheURL(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:26657", "https://rpc.example", "https://rpc.example/", "https://rpc.example:8443/prefix"} {
		_, err := cometrpc.New(u, nil)
		assert.NoError(t, err, u)
	}
	for _, u := range []string{"", "rpc.example", "ftp://rpc.example", "ws://rpc.example", "http://u:p@rpc.example", "http://rpc.example?x=1", "http://rpc.example#f", "http:///x", "\x00"} {
		_, err := cometrpc.New(u, nil)
		assert.Error(t, err, "%q", u)
	}
}

func TestNameIsTheNormalizedHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://RPC-Mocha.pops.one":        "rpc-mocha.pops.one",
		"https://rpc-mocha.pops.one:443/":   "rpc-mocha.pops.one",
		"http://rpc-mocha.pops.one.:26657/": "rpc-mocha.pops.one",
		"http://127.0.0.1:1234":             "127.0.0.1",
	} {
		assert.Equal(t, want, source(t, in).Name(), in)
	}
}

func TestStatus(t *testing.T) {
	t.Run("live shape", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/status": ok(fixture(t, "status.json"))})
		s := source(t, f.URL)
		h, err := s.Latest(bg)
		require.NoError(t, err)
		assert.Equal(t, uint64(1459997), h)
		id, err := s.NodeID(bg)
		require.NoError(t, err)
		assert.Equal(t, "ee9f9097a1d9a3f0f5e6a4d2f7b7e1c1a8b3c3c8", id)
		assert.Contains(t, f.requests()[0], "/status")
	})
	bad := map[string]string{
		"not json":           `<html>`,
		"empty object":       `{}`,
		"no result":          `{"jsonrpc":"2.0","id":-1}`,
		"height is a number": `{"result":{"node_info":{"id":"aa"},"sync_info":{"latest_block_height":1459997}}}`,
		"height not decimal": `{"result":{"node_info":{"id":"aa"},"sync_info":{"latest_block_height":"0x10"}}}`,
		"height negative":    `{"result":{"node_info":{"id":"aa"},"sync_info":{"latest_block_height":"-5"}}}`,
		"height zero":        `{"result":{"node_info":{"id":"aa"},"sync_info":{"latest_block_height":"0"}}}`,
		"height overflows":   `{"result":{"node_info":{"id":"aa"},"sync_info":{"latest_block_height":"99999999999999999999999"}}}`,
		"no sync info":       `{"result":{"node_info":{"id":"aa"}}}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			f := serveFiles(t, map[string]answer{"/status": ok([]byte(body))})
			_, err := source(t, f.URL).Latest(bg)
			assert.ErrorIs(t, err, cometrpc.ErrBadResponse)
		})
	}
	t.Run("no node id", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/status": ok([]byte(`{"result":{"node_info":{},"sync_info":{"latest_block_height":"5"}}}`))})
		_, err := source(t, f.URL).NodeID(bg)
		assert.ErrorIs(t, err, cometrpc.ErrBadResponse)
	})
	t.Run("node id is not hex", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/status": ok([]byte(`{"result":{"node_info":{"id":"not-hex"},"sync_info":{"latest_block_height":"5"}}}`))})
		_, err := source(t, f.URL).NodeID(bg)
		assert.ErrorIs(t, err, cometrpc.ErrBadResponse)
	})
}

// independentHash decodes the RPC JSON header with the node's own JSON codec
// and hashes it the way upstream does.
func independentHash(t testing.TB, rpcBody []byte, path ...string) (core.Header, []byte) {
	t.Helper()
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rpcBody, &env))
	cur := env["result"]
	for _, p := range path {
		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(cur, &m))
		cur = m[p]
	}
	var h core.Header
	require.NoError(t, cmtjson.Unmarshal(cur, &h))
	return h, []byte(h.Hash())
}

func decodeHeader(t testing.TB, raw []byte) core.Header {
	t.Helper()
	var ph cmtproto.Header
	require.NoError(t, ph.Unmarshal(raw))
	again, err := ph.Marshal()
	require.NoError(t, err)
	require.Equal(t, raw, again, "the encoding is the canonical protobuf one")
	h, err := core.HeaderFromProto(&ph)
	require.NoError(t, err)
	return h
}

func TestHeaderOfTheLiveShape(t *testing.T) {
	body := fixture(t, "header_1442606.json")
	want, wantHash := independentHash(t, body, "header")
	require.Equal(t, int64(1442606), want.Height)
	require.True(t, strings.HasPrefix(strings.ToUpper(hex.EncodeToString(wantHash)), "BF774780"))
	require.True(t, strings.HasSuffix(strings.ToUpper(hex.EncodeToString(wantHash)), "2771"))

	f := serveFiles(t, map[string]answer{"/header": ok(body)})
	raw, err := source(t, f.URL).Header(bg, 1442606)
	require.NoError(t, err)

	got := decodeHeader(t, raw)
	assert.Equal(t, "mocha-5", got.ChainID)
	assert.Equal(t, want.Height, got.Height)
	assert.True(t, want.Time.Equal(got.Time), "nanosecond time survives")
	assert.Equal(t, wantHash, []byte(got.Hash()), "the hash is recomputed from the fields the RPC served")
	assert.Equal(t, []string{"/header?height=1442606"}, f.requests())
}

func TestHeaderIsABlockReadAtTheRequestedHeight(t *testing.T) {
	f := serveFiles(t, map[string]answer{"/header": ok(fixture(t, "header_1442606.json"))})
	s := source(t, f.URL)
	for _, h := range []uint64{1442605, 1442607, 1, 0} {
		_, err := s.Header(bg, h)
		assert.ErrorIs(t, err, cometrpc.ErrBadResponse, "asked %d, served 1442606", h)
	}
}

func TestHeaderErrors(t *testing.T) {
	good := fixture(t, "header_1442606.json")
	tests := []struct {
		name string
		ans  answer
		want error
	}{
		{"above the head", ok(fixture(t, "header_above_head.json")), nil},
		{"above the head with a 500", answer{http.StatusInternalServerError, fixture(t, "header_above_head.json")}, nil},
		{"rate limited", answer{http.StatusTooManyRequests, []byte("slow down")}, cometrpc.ErrUnavailable},
		{"server error", answer{http.StatusInternalServerError, nil}, nil},
		{"bad gateway", answer{http.StatusBadGateway, []byte("<html>")}, cometrpc.ErrUnavailable},
		{"not found", answer{http.StatusNotFound, nil}, cometrpc.ErrUnavailable},
		{"not json", ok([]byte("<html>")), cometrpc.ErrBadResponse},
		{"empty", ok(nil), cometrpc.ErrBadResponse},
		{"no header", ok([]byte(`{"result":{}}`)), cometrpc.ErrBadResponse},
		{"null header", ok([]byte(`{"result":{"header":null}}`)), cometrpc.ErrBadResponse},
		{"truncated", ok(good[:len(good)/2]), cometrpc.ErrBadResponse},
		{"height is a number", ok([]byte(strings.Replace(string(good), `"height":"1442606"`, `"height":1442606`, 1))), cometrpc.ErrBadResponse},
		{"hash of a field is not hex", ok([]byte(strings.Replace(string(good), "F19D909B", "ZZZZZZZZ", 1))), cometrpc.ErrBadResponse},
		{"time is not a time", ok([]byte(strings.Replace(string(good), "2026-10-06T18:15:14.845417195Z", "yesterday", 1))), cometrpc.ErrBadResponse},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := serveFiles(t, map[string]answer{"/header": tc.ans})
			raw, err := source(t, f.URL).Header(bg, 1442606)
			require.Error(t, err)
			assert.Nil(t, raw)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
		})
	}
	t.Run("above the head names the reason", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/header": ok(fixture(t, "header_above_head.json"))})
		_, err := source(t, f.URL).Header(bg, 1460500)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be less than or equal")
	})
	t.Run("server is down", func(t *testing.T) {
		f := serveFiles(t, nil)
		s := source(t, f.URL)
		f.Close()
		_, err := s.Header(bg, 1)
		assert.ErrorIs(t, err, cometrpc.ErrUnavailable)
	})
	t.Run("cancelled context", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/header": ok(good)})
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_, err := source(t, f.URL).Header(ctx, 1442606)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestHeaderBodyIsBounded(t *testing.T) {
	good := fixture(t, "header_1442606.json")
	padded := append(append([]byte(nil), good...), []byte(strings.Repeat(" ", 64<<20))...)
	f := serveFiles(t, map[string]answer{"/header": ok(good)})
	_, err := source(t, f.URL).Header(bg, 1442606)
	require.NoError(t, err)

	f = serveFiles(t, map[string]answer{"/header": ok(padded)})
	_, err = source(t, f.URL).Header(bg, 1442606)
	require.Error(t, err, "a body far beyond any RPC answer is refused, though it would parse")
}

func TestCommitGivesTheBlockHash(t *testing.T) {
	body := fixture(t, "commit_1460000.json")
	var env struct {
		Result struct {
			SignedHeader struct {
				Header json.RawMessage `json:"header"`
				Commit struct {
					BlockID struct {
						Hash string `json:"hash"`
					} `json:"block_id"`
				} `json:"commit"`
			} `json:"signed_header"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	var hd core.Header
	require.NoError(t, cmtjson.Unmarshal(env.Result.SignedHeader.Header, &hd))
	require.Equal(t, env.Result.SignedHeader.Commit.BlockID.Hash, strings.ToUpper(hex.EncodeToString(hd.Hash())),
		"the fixture is consistent: the header hashes to the commit's block id")

	f := serveFiles(t, map[string]answer{"/commit": ok(body)})
	got, err := source(t, f.URL).BlockHash(bg, 1460000)
	require.NoError(t, err)
	assert.Equal(t, []byte(hd.Hash()), got)
	assert.Equal(t, []string{"/commit?height=1460000"}, f.requests())

	_, err = source(t, f.URL).BlockHash(bg, 1460001)
	assert.ErrorIs(t, err, cometrpc.ErrBadResponse, "the height is echoed and checked")
}

func TestHeadersByRange(t *testing.T) {
	c := cometfake.BuildChain("mocha-5", 100, 400)
	srv := cometfake.New(t, c, 400, "aabbccddeeff00112233445566778899aabbccdd")
	s := source(t, srv.URL)

	t.Run("one call returns up to twenty links in ascending order", func(t *testing.T) {
		got, err := s.Headers(bg, 110, 129)
		require.NoError(t, err)
		require.Len(t, got, 20)
		for i, raw := range got {
			assert.Equal(t, c.Raw(t, 110+uint64(i)), raw)
		}
		hits := srv.Hits()
		q := queryOf(t, hits[len(hits)-1])
		assert.Equal(t, "110", q.Get("minHeight"))
		assert.Equal(t, "129", q.Get("maxHeight"))
		assert.True(t, strings.HasPrefix(hits[len(hits)-1], "/blockchain?"))
	})
	t.Run("a longer span is split by twenty", func(t *testing.T) {
		before := len(srv.Hits())
		got, err := s.Headers(bg, 150, 194)
		require.NoError(t, err)
		require.Len(t, got, 45)
		for i, raw := range got {
			assert.Equal(t, c.Raw(t, 150+uint64(i)), raw)
		}
		assert.Equal(t, 3, len(srv.Hits())-before)
	})
	t.Run("single header", func(t *testing.T) {
		got, err := s.Headers(bg, 200, 200)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, c.Raw(t, 200), got[0])
	})
	t.Run("a header below the pruning point is missing, so the range fails", func(t *testing.T) {
		_, err := s.Headers(bg, 90, 105)
		require.Error(t, err)
	})
	t.Run("above the head", func(t *testing.T) {
		_, err := s.Headers(bg, 390, 410)
		require.Error(t, err)
	})
	t.Run("empty range", func(t *testing.T) {
		_, err := s.Headers(bg, 12, 11)
		require.Error(t, err)
	})
}

func TestHeadersRefusesAnAnswerThatDoesNotMatchTheRange(t *testing.T) {
	c := cometfake.BuildChain("mocha-5", 100, 130)
	meta := func(h uint64) string {
		hj, err := cmtjson.Marshal(c.Hdrs[h])
		require.NoError(t, err)
		return `{"block_id":{"hash":"00","parts":{"total":1,"hash":"00"}},"block_size":"1","header":` + string(hj) + `,"num_txs":"0"}`
	}
	list := func(hs ...uint64) []byte {
		var parts []string
		for _, h := range hs {
			parts = append(parts, meta(h))
		}
		return []byte(`{"result":{"last_height":"130","block_metas":[` + strings.Join(parts, ",") + `]}}`)
	}
	tests := []struct {
		name string
		body []byte
	}{
		{"fewer than asked", list(110, 109)},
		{"a gap", list(110, 108, 107, 106)},
		{"ascending instead of descending", list(107, 108, 109, 110)},
		{"a duplicate", list(110, 109, 109, 107)},
		{"another height inside", list(110, 109, 120, 107)},
		{"more than asked", list(111, 110, 109, 108, 107)},
		{"empty", []byte(`{"result":{"last_height":"130","block_metas":[]}}`)},
		{"no list", []byte(`{"result":{}}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := serveFiles(t, map[string]answer{"/blockchain": ok(tc.body)})
			got, err := source(t, f.URL).Headers(bg, 107, 110)
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestTxOfTheLiveShape(t *testing.T) {
	body := fixture(t, "tx_prove_1442606.json")
	var env struct {
		Result struct {
			Tx    []byte          `json:"tx"`
			Proof json.RawMessage `json:"proof"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	want := sha256.Sum256(env.Result.Tx)
	require.Equal(t, "A9A1550E0BA85FE6F8FACEBF26978B7F7DBFB399987B6D86D78B9B6340245971", strings.ToUpper(hex.EncodeToString(want[:])))

	f := serveFiles(t, map[string]answer{"/tx": ok(body)})
	s := source(t, f.URL)

	got, err := s.Tx(bg, want, true)
	require.NoError(t, err)
	assert.Equal(t, env.Result.Tx, got.Bytes)
	assert.Equal(t, uint64(1442606), got.Height)
	assert.Equal(t, uint32(0), got.Code)
	require.NotEmpty(t, got.Proof)
	assert.JSONEq(t, string(env.Result.Proof), string(got.Proof), "the proof member, as served")
	q := queryOf(t, f.requests()[0])
	assert.Equal(t, "0x"+hex.EncodeToString(want[:]), strings.ToLower(q.Get("hash")))
	assert.Equal(t, "true", q.Get("prove"))

	got, err = s.Tx(bg, want, false)
	require.NoError(t, err)
	assert.Equal(t, env.Result.Tx, got.Bytes)
	assert.Empty(t, got.Proof, "no proof is kept when none was asked for")
	q = queryOf(t, f.requests()[1])
	assert.Equal(t, "0x"+hex.EncodeToString(want[:]), strings.ToLower(q.Get("hash")))
	assert.NotEqual(t, "true", q.Get("prove"))
}

func queryOf(t testing.TB, uri string) url.Values {
	t.Helper()
	u, err := url.Parse(uri)
	require.NoError(t, err)
	return u.Query()
}

func TestTxNotFoundAndFaults(t *testing.T) {
	var h [32]byte
	raw, err := hex.DecodeString("7AD0F3E0B5EBE828924D7C4FF55AF886EBB98341F3E89AD17ADBBCF444B0F543")
	require.NoError(t, err)
	copy(h[:], raw)

	t.Run("not found, as an RPC error", func(t *testing.T) {
		for _, code := range []int{0, http.StatusInternalServerError} {
			f := serveFiles(t, map[string]answer{"/tx": {code, fixture(t, "tx_not_found.json")}})
			_, err := source(t, f.URL).Tx(bg, h, true)
			require.ErrorIs(t, err, railverify.ErrTxNotFound, "status %d", code)
			assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked, "absence on one node proves nothing")
			assert.NotErrorIs(t, err, railverify.ErrTxSourceUnavailable)
		}
	})
	unavailable := map[string]answer{
		"rate limited":      {http.StatusTooManyRequests, []byte("slow")},
		"server error":      {http.StatusInternalServerError, nil},
		"bad gateway":       {http.StatusBadGateway, []byte("<html>")},
		"other rpc error":   {0, []byte(`{"error":{"code":-32603,"message":"Internal error","data":"indexer is disabled"}}`)},
		"other rpc error 2": {http.StatusInternalServerError, []byte(`{"error":{"code":-32602,"message":"Invalid params","data":"bad hash"}}`)},
	}
	for name, a := range unavailable {
		t.Run(name, func(t *testing.T) {
			f := serveFiles(t, map[string]answer{"/tx": a})
			_, err := source(t, f.URL).Tx(bg, h, true)
			require.ErrorIs(t, err, railverify.ErrTxSourceUnavailable)
			assert.ErrorIs(t, err, verifier.ErrExecutionUnchecked)
			assert.NotErrorIs(t, err, railverify.ErrTxNotFound)
		})
	}
	t.Run("server is down", func(t *testing.T) {
		f := serveFiles(t, nil)
		s := source(t, f.URL)
		f.Close()
		_, err := s.Tx(bg, h, true)
		assert.ErrorIs(t, err, railverify.ErrTxSourceUnavailable)
	})
	t.Run("not json", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/tx": ok([]byte("<html>"))})
		_, err := source(t, f.URL).Tx(bg, h, true)
		require.Error(t, err)
		assert.NotErrorIs(t, err, railverify.ErrTxNotFound)
	})
}

func TestTxFieldsAreChecked(t *testing.T) {
	var h [32]byte
	good := func(mod func(m map[string]any)) answer {
		res := map[string]any{
			"hash": strings.Repeat("AB", 32), "height": "100", "index": 0,
			"tx_result": map[string]any{"code": 0}, "tx": "AAEC",
		}
		if mod != nil {
			mod(res)
		}
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": -1, "result": res})
		require.NoError(t, err)
		return ok(b)
	}
	f := serveFiles(t, map[string]answer{"/tx": good(nil)})
	got, err := source(t, f.URL).Tx(bg, h, true)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 1, 2}, got.Bytes)
	assert.Equal(t, uint64(100), got.Height)
	assert.Empty(t, got.Proof)

	t.Run("failed transaction code", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/tx": good(func(m map[string]any) { m["tx_result"] = map[string]any{"code": 11} })})
		got, err := source(t, f.URL).Tx(bg, h, true)
		require.NoError(t, err, "a failed code is a fact for the checker, not an error here")
		assert.Equal(t, uint32(11), got.Code)
	})
	t.Run("null proof", func(t *testing.T) {
		f := serveFiles(t, map[string]answer{"/tx": good(func(m map[string]any) { m["proof"] = nil })})
		got, err := source(t, f.URL).Tx(bg, h, true)
		require.NoError(t, err)
		assert.Empty(t, got.Proof)
	})
	bad := map[string]func(m map[string]any){
		"no tx":           func(m map[string]any) { delete(m, "tx") },
		"tx not base64":   func(m map[string]any) { m["tx"] = "!!!" },
		"empty tx":        func(m map[string]any) { m["tx"] = "" },
		"no height":       func(m map[string]any) { delete(m, "height") },
		"height zero":     func(m map[string]any) { m["height"] = "0" },
		"height negative": func(m map[string]any) { m["height"] = "-1" },
		"height number":   func(m map[string]any) { m["height"] = 100 },
		"no tx_result":    func(m map[string]any) { delete(m, "tx_result") },
		"code is text":    func(m map[string]any) { m["tx_result"] = map[string]any{"code": "x"} },
		"code negative":   func(m map[string]any) { m["tx_result"] = map[string]any{"code": -1} },
		"code too big":    func(m map[string]any) { m["tx_result"] = map[string]any{"code": 1 << 40} },
	}
	for name, mod := range bad {
		t.Run(name, func(t *testing.T) {
			f := serveFiles(t, map[string]answer{"/tx": good(mod)})
			_, err := source(t, f.URL).Tx(bg, h, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, cometrpc.ErrBadResponse)
		})
	}
}

func TestTxOverTheFakeServer(t *testing.T) {
	c := cometfake.BuildChain("mocha-5", 1, 10)
	srv := cometfake.New(t, c, 10, "aabbccddeeff00112233445566778899aabbccdd")
	hash := srv.PutTx(cometfake.Tx{Height: 7, Bytes: []byte("tx-bytes"), Code: 0, Proof: json.RawMessage(`{"data":[]}`)})
	s := source(t, srv.URL)
	got, err := s.Tx(bg, hash, true)
	require.NoError(t, err)
	assert.Equal(t, []byte("tx-bytes"), got.Bytes)
	assert.Equal(t, uint64(7), got.Height)
	assert.JSONEq(t, `{"data":[]}`, string(got.Proof))

	_, err = s.Tx(bg, sha256.Sum256([]byte("other")), true)
	assert.ErrorIs(t, err, railverify.ErrTxNotFound)
}

func FuzzHeaderJSON(f *testing.F) {
	f.Add(fixtureBytes(f, "header_1442606.json"), uint64(1442606))
	f.Add([]byte(`{"result":{"header":{}}}`), uint64(1))
	f.Add([]byte(`{"result":{"header":{"height":"5","chain_id":"x"}}}`), uint64(5))
	f.Add([]byte(`[]`), uint64(1))

	var mu sync.Mutex
	var current []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		b := current
		mu.Unlock()
		_, _ = w.Write(b)
	}))
	f.Cleanup(srv.Close)
	s, err := cometrpc.New(srv.URL, srv.Client())
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, body []byte, height uint64) {
		mu.Lock()
		current = body
		mu.Unlock()
		raw, err := s.Header(bg, height)
		if err != nil {
			assert.Nil(t, raw)
			return
		}
		var ph cmtproto.Header
		require.NoError(t, ph.Unmarshal(raw))
		assert.Equal(t, int64(height), ph.Height, "an accepted header is the one asked for")
		again, err := ph.Marshal()
		require.NoError(t, err)
		assert.Equal(t, raw, again)
	})
}

func fixtureBytes(tb testing.TB, name string) []byte { return fixture(tb, name) }
