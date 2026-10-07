// Package cometfake is a loopback CometBFT RPC server over synthetic
// headers, for tests only.
package cometfake

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func filler(tag string, h uint64) []byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", tag, h)))
	return s[:]
}

// MkHeader builds one header whose last_block_id hash is prev.
func MkHeader(chainID string, h uint64, prev []byte, app string) core.Header {
	return core.Header{
		Version:            cmtversion.Consensus{Block: 11, App: 10},
		ChainID:            chainID,
		Height:             int64(h),
		Time:               time.Unix(1_790_000_000+int64(h%1_000_000)*3, 0).UTC(),
		LastBlockID:        core.BlockID{Hash: prev, PartSetHeader: core.PartSetHeader{Total: 1, Hash: filler("psh", h)}},
		LastCommitHash:     filler("lc", h),
		DataHash:           filler("data", h),
		ValidatorsHash:     filler("vals", 0),
		NextValidatorsHash: filler("vals", 0),
		ConsensusHash:      filler("cons", 0),
		AppHash:            filler(app, h),
		LastResultsHash:    filler("res", h),
		EvidenceHash:       filler("ev", 0),
		ProposerAddress:    filler("prop", 0)[:20],
	}
}

// Chain is a linked run of headers.
type Chain struct {
	ChainID string
	Hdrs    map[uint64]core.Header
}

// BuildChain links headers from..to.
func BuildChain(chainID string, from, to uint64) *Chain {
	c := &Chain{ChainID: chainID, Hdrs: map[uint64]core.Header{}}
	prev := filler("genesis", from)
	for h := from; h <= to; h++ {
		hd := MkHeader(chainID, h, prev, "app")
		c.Hdrs[h] = hd
		prev = hd.Hash()
	}
	return c
}

// Hash is the block hash of the header at h.
func (c *Chain) Hash(h uint64) []byte {
	hd, ok := c.Hdrs[h]
	if !ok {
		return nil
	}
	return hd.Hash()
}

// Raw is the protobuf encoding of the header at h.
func (c *Chain) Raw(tb testing.TB, h uint64) []byte {
	tb.Helper()
	hd, ok := c.Hdrs[h]
	require.Truef(tb, ok, "no header at %d", h)
	return Encode(tb, hd)
}

// Encode is the protobuf encoding of a header.
func Encode(tb testing.TB, h core.Header) []byte {
	tb.Helper()
	p := h.ToProto()
	b, err := p.Marshal()
	require.NoError(tb, err)
	return b
}

// Tx is a transaction the server can serve under /tx.
type Tx struct {
	Height uint64
	Index  uint32
	Code   uint32
	Bytes  []byte
	// Proof is the JSON of the proof member; nil leaves it out.
	Proof json.RawMessage
}

// Result is one transaction result the server can serve under /block_results.
type Result struct {
	Code      uint32
	Data      []byte
	GasWanted int64
	GasUsed   int64
}

// Server answers /status, /header, /blockchain, /commit, /tx and
// /block_results.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	Chain   *Chain
	LatestH uint64
	NodeID  string
	Network string
	Txs     map[string]Tx
	// Results are the block results by height. A height with none is answered
	// like a node that does not persist them.
	Results map[uint64][]Result
	// Status maps a URL path to an HTTP status that replaces the answer.
	Status map[string]int
	// RPCError maps a URL path to a JSON-RPC error data string; the answer
	// is sent with ErrHTTP.
	RPCError map[string]string
	ErrHTTP  int
	// SingleHeader replaces the answer of /header at a height, as a node
	// would that tells one story to /header and another to /blockchain.
	SingleHeader map[uint64]core.Header
	hits         []string
}

// New starts a server over c with latest height latest.
func New(tb testing.TB, c *Chain, latest uint64, nodeID string) *Server {
	tb.Helper()
	s := &Server{
		Chain: c, LatestH: latest, NodeID: nodeID, Network: c.ChainID,
		Txs: map[string]Tx{}, Results: map[uint64][]Result{}, Status: map[string]int{}, RPCError: map[string]string{}, ErrHTTP: http.StatusOK,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	tb.Cleanup(s.Server.Close)
	return s
}

// PutTx registers a transaction under the hash of its bytes.
func (s *Server) PutTx(tx Tx) [32]byte {
	h := sha256.Sum256(tx.Bytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Txs[hex.EncodeToString(h[:])] = tx
	return h
}

// Hits lists the request URIs received so far.
func (s *Server) Hits() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// HostURL is the server URL with the loopback address replaced by host, so
// that one server can stand for sources on different hosts.
func (s *Server) HostURL(host string) string {
	return strings.Replace(s.URL, "127.0.0.1", host, 1)
}

func write(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func result(v any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": -1, "result": v}
}

func (s *Server) rpcErr(w http.ResponseWriter, data string) {
	write(w, s.ErrHTTP, map[string]any{
		"jsonrpc": "2.0", "id": -1,
		"error": map[string]any{"code": -32603, "message": "Internal error", "data": data},
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, r.URL.RequestURI())
	if code, ok := s.Status[r.URL.Path]; ok {
		w.WriteHeader(code)
		return
	}
	if data, ok := s.RPCError[r.URL.Path]; ok {
		s.rpcErr(w, data)
		return
	}
	q := r.URL.Query()
	height := func(name string) (uint64, bool) {
		v, err := strconv.ParseUint(q.Get(name), 10, 64)
		return v, err == nil
	}
	switch r.URL.Path {
	case "/status":
		write(w, http.StatusOK, result(map[string]any{
			"node_info": map[string]any{
				"id": s.NodeID, "network": s.Network, "moniker": "fake",
				"other": map[string]any{"tx_index": "on"},
			},
			"sync_info": map[string]any{
				"latest_block_height":   strconv.FormatUint(s.LatestH, 10),
				"earliest_block_height": "1", "catching_up": false,
			},
		}))
	case "/header":
		h, ok := height("height")
		hd, have := s.Chain.Hdrs[h]
		if alt, replaced := s.SingleHeader[h]; replaced {
			hd, have = alt, true
		}
		switch {
		case !ok:
			s.rpcErr(w, "height is required")
		case h > s.LatestH:
			s.rpcErr(w, fmt.Sprintf("height %d must be less than or equal to the current blockchain height %d", h, s.LatestH))
		case !have:
			s.rpcErr(w, fmt.Sprintf("height %d is not available, lowest height is 1", h))
		default:
			s.header(w, hd)
		}
	case "/commit":
		h, ok := height("height")
		hd, have := s.Chain.Hdrs[h]
		if !ok || !have || h > s.LatestH {
			s.rpcErr(w, "no commit")
			return
		}
		hj, err := cmtjson.Marshal(hd)
		if err != nil {
			s.rpcErr(w, err.Error())
			return
		}
		write(w, http.StatusOK, result(map[string]any{
			"signed_header": map[string]any{
				"header": json.RawMessage(hj),
				"commit": map[string]any{
					"height": strconv.FormatUint(h, 10), "round": 0,
					"block_id": map[string]any{
						"hash":  strings.ToUpper(hex.EncodeToString(hd.Hash())),
						"parts": map[string]any{"total": 1, "hash": strings.ToUpper(hex.EncodeToString(hd.LastBlockID.PartSetHeader.Hash))},
					},
					"signatures": []any{},
				},
			},
			"canonical": true,
		}))
	case "/blockchain":
		lo, ok1 := height("minHeight")
		hi, ok2 := height("maxHeight")
		if !ok1 || !ok2 || lo > hi || hi > s.LatestH {
			s.rpcErr(w, "invalid range")
			return
		}
		if hi-lo >= 20 {
			lo = hi - 19
		}
		var metas []any
		for h := hi; ; h-- {
			hd, have := s.Chain.Hdrs[h]
			if !have {
				break
			}
			hj, err := cmtjson.Marshal(hd)
			if err != nil {
				s.rpcErr(w, err.Error())
				return
			}
			metas = append(metas, map[string]any{
				"block_id":   map[string]any{"hash": strings.ToUpper(hex.EncodeToString(hd.Hash())), "parts": map[string]any{"total": 1, "hash": strings.ToUpper(hex.EncodeToString(hd.LastBlockID.PartSetHeader.Hash))}},
				"block_size": "1000", "header": json.RawMessage(hj), "num_txs": "0",
			})
			if h == lo {
				break
			}
		}
		write(w, http.StatusOK, result(map[string]any{"last_height": strconv.FormatUint(s.LatestH, 10), "block_metas": metas}))
	case "/tx":
		hs := strings.TrimPrefix(strings.ToLower(q.Get("hash")), "0x")
		tx, ok := s.Txs[hs]
		if !ok {
			s.rpcErr(w, fmt.Sprintf("tx (%s) not found", strings.ToUpper(hs)))
			return
		}
		res := map[string]any{
			"hash": strings.ToUpper(hs), "height": strconv.FormatUint(tx.Height, 10), "index": tx.Index,
			"tx_result": map[string]any{"code": tx.Code, "log": ""},
			"tx":        base64.StdEncoding.EncodeToString(tx.Bytes),
		}
		if q.Get("prove") == "true" && len(tx.Proof) > 0 {
			res["proof"] = tx.Proof
		}
		write(w, http.StatusOK, result(res))
	case "/block_results":
		h, ok := height("height")
		rs, have := s.Results[h]
		if !ok || !have {
			s.rpcErr(w, "node is not persisting finalize block responses")
			return
		}
		list := make([]any, len(rs))
		for i, r := range rs {
			list[i] = map[string]any{
				"code": r.Code, "data": base64.StdEncoding.EncodeToString(r.Data), "log": "ignored", "info": "",
				"gas_wanted": strconv.FormatInt(r.GasWanted, 10), "gas_used": strconv.FormatInt(r.GasUsed, 10),
				"events": []any{}, "codespace": "",
			}
		}
		write(w, http.StatusOK, result(map[string]any{"height": strconv.FormatUint(h, 10), "txs_results": list}))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) header(w http.ResponseWriter, hd core.Header) {
	hj, err := cmtjson.Marshal(hd)
	if err != nil {
		s.rpcErr(w, err.Error())
		return
	}
	write(w, http.StatusOK, result(map[string]any{"header": json.RawMessage(hj)}))
}
