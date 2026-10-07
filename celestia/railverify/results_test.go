package railverify_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/verifier"
)

const liveDir = "../../spec/vectors/verifier/live/"

type liveResultVec struct {
	RootHex  string      `json:"root_hex"`
	Results  []vecResult `json:"results"`
	Selected struct {
		Index string `json:"index"`
		Code  string `json:"code"`
		Leaf  string `json:"leaf_hex"`
	} `json:"selected"`
	Uniform  string `json:"uniform_code"`
	HeaderH1 struct {
		LastResultsHash string `json:"last_results_hash"`
	} `json:"header_h1"`
	Mutations []struct {
		ID      string      `json:"id"`
		Results []vecResult `json:"results"`
		Expect  string      `json:"expect"`
	} `json:"mutations"`
	LeavesHex []string `json:"leaves_hex"`
}

type vecResult struct {
	Code      string `json:"code"`
	Data      string `json:"data"`
	GasWanted string `json:"gas_wanted"`
	GasUsed   string `json:"gas_used"`
}

func (v vecResult) toTx(t testing.TB) railverify.TxResult {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(v.Data)
	require.NoError(t, err)
	gw, err := strconv.ParseInt(v.GasWanted, 10, 64)
	require.NoError(t, err)
	gu, err := strconv.ParseInt(v.GasUsed, 10, 64)
	require.NoError(t, err)
	return railverify.TxResult{Code: uint32(u64(t, v.Code)), Data: data, GasWanted: gw, GasUsed: gu}
}

func toTxs(t testing.TB, rs []vecResult) []railverify.TxResult {
	out := make([]railverify.TxResult, len(rs))
	for i, r := range rs {
		out[i] = r.toTx(t)
	}
	return out
}

func loadResultVec(t testing.TB) liveResultVec {
	t.Helper()
	raw, err := os.ReadFile(outcomesPath)
	require.NoError(t, err)
	var doc struct {
		ResultProof liveResultVec `json:"result_proof"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.NotEmpty(t, doc.ResultProof.Results)
	return doc.ResultProof
}

// liveServer serves the two raw captures of the vectors as a node would.
func liveServer(t testing.TB) *httptest.Server {
	t.Helper()
	results, err := os.ReadFile(liveDir + "block_results_1442606.json")
	require.NoError(t, err)
	header, err := os.ReadFile(liveDir + "header_1442607.json")
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block_results":
			if r.URL.Query().Get("height") == "1442606" {
				_, _ = w.Write(results)
				return
			}
		case "/header":
			if r.URL.Query().Get("height") == "1442607" {
				_, _ = w.Write(header)
				return
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":-1,"error":{"code":-32603,"message":"Internal error","data":"node is not persisting finalize block responses"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The deterministic leaf of every result and the root over them are what the
// vectors hold for the live block, as served and under each mutation.
func TestResultsRootMatchesTheLiveVectors(t *testing.T) {
	v := loadResultVec(t)

	t.Run("the leaves are the deterministic ExecTxResult", func(t *testing.T) {
		rs := toTxs(t, v.Results)
		require.Len(t, v.LeavesHex, len(rs))
		for i, r := range rs {
			leaf, err := (&abci.ExecTxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}).Marshal()
			require.NoError(t, err)
			assert.Equal(t, v.LeavesHex[i], hex.EncodeToString(leaf), "result %d", i)
		}
		assert.Equal(t, v.Selected.Leaf, v.LeavesHex[u64(t, v.Selected.Index)])
	})
	t.Run("the root is RFC 6962 over the leaves", func(t *testing.T) {
		var leaves [][]byte
		for _, l := range v.LeavesHex {
			b, err := hex.DecodeString(l)
			require.NoError(t, err)
			leaves = append(leaves, b)
		}
		assert.Equal(t, v.RootHex, hex.EncodeToString(merkle.HashFromByteSlices(leaves)))
		got, err := railverify.ResultsRoot(toTxs(t, v.Results))
		require.NoError(t, err)
		assert.Equal(t, v.RootHex, hex.EncodeToString(got))
	})
	t.Run("the root is last_results_hash of the next live header", func(t *testing.T) {
		assert.Equal(t, v.RootHex, lower(v.HeaderH1.LastResultsHash))
	})
	for _, m := range v.Mutations {
		t.Run("mutation "+m.ID, func(t *testing.T) {
			got, err := railverify.ResultsRoot(toTxs(t, m.Results))
			require.NoError(t, err)
			switch m.Expect {
			case "match":
				assert.Equal(t, v.RootHex, hex.EncodeToString(got))
			case "mismatch":
				assert.NotEqual(t, v.RootHex, hex.EncodeToString(got))
			default:
				require.Failf(t, "unknown expectation", "%q", m.Expect)
			}
		})
	}
	t.Run("the empty block", func(t *testing.T) {
		got, err := railverify.ResultsRoot(nil)
		require.NoError(t, err)
		assert.Equal(t, merkle.HashFromByteSlices(nil), got)
	})
}

func lower(s string) string {
	b, _ := hex.DecodeString(s)
	return hex.EncodeToString(b)
}

// The proof as the live node served it starts at share 0 of the square, so it
// binds the position of the transaction among the block's results.
func TestLiveProofBindsTheIndex(t *testing.T) {
	tx, p, dataHash := live(t)
	info, err := railverify.VerifyShareProofAt(p, tx, dataHash)
	require.NoError(t, err)
	assert.True(t, info.IndexBound)
	assert.Equal(t, 0, info.Index)
	v := loadResultVec(t)
	assert.Equal(t, v.Selected.Index, strconv.Itoa(info.Index))
}

func TestProofIndexOnGeneratedBlocks(t *testing.T) {
	tests := []struct {
		name   string
		layout func([]byte) ([][]byte, int)
		bound  bool
		index  int
	}{
		{"alone in the block", layoutAlone, true, 0},
		{"after a small transaction in share 0", layoutMid, true, 1},
		{"spilling over the share, after a small one", layoutSpill, true, 1},
		{"after big transactions", layoutBig, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := loadVec(t)
			txs, idx := tc.layout(v.txRaw)
			p, root := proofOf(t, txs, idx)
			info, err := railverify.VerifyShareProofAt(p, v.txRaw, root)
			require.NoError(t, err)
			assert.Equal(t, tc.bound, info.IndexBound)
			if tc.bound {
				assert.Equal(t, tc.index, info.Index)
			}
		})
	}
}

// liveHeaders serves the live header at 1442607, as a trusted chain would.
type liveHeaders struct {
	t   testing.TB
	err error
}

func (l liveHeaders) Header(_ context.Context, h uint64) ([]byte, error) {
	if l.err != nil {
		return nil, l.err
	}
	require.Equal(l.t, uint64(1442607), h, "the result proof reads the header after the block")
	raw, err := os.ReadFile(liveDir + "header_1442607.json")
	require.NoError(l.t, err)
	var env struct {
		Result struct {
			Header json.RawMessage `json:"header"`
		} `json:"result"`
	}
	require.NoError(l.t, json.Unmarshal(raw, &env))
	var hd core.Header
	require.NoError(l.t, cmtjson.Unmarshal(env.Result.Header, &hd))
	return cometfake.Encode(l.t, hd), nil
}

// resultsSrc serves fixed results, or a fault.
type resultsSrc struct {
	name    string
	results []railverify.TxResult
	err     error
	asked   int
}

func (r *resultsSrc) Name() string { return r.name }
func (r *resultsSrc) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	r.asked++
	return r.results, r.err
}

func TestResultProofOnTheLiveBlock(t *testing.T) {
	v := loadResultVec(t)
	good := toTxs(t, v.Results)
	bound := railverify.ProofInfo{IndexBound: true, Index: 0}
	run := func(h liveHeaders, info railverify.ProofInfo, srcs ...railverify.ResultsSource) (bool, uint32, error, error) {
		return railverify.ProveResultOf(context.Background(), h, 1442606, "mocha-5", info, srcs)
	}

	t.Run("as served by a live node over HTTP", func(t *testing.T) {
		srv := liveServer(t)
		src, err := cometrpc.New(srv.URL, nil)
		require.NoError(t, err)
		proven, code, problem, err := run(liveHeaders{t: t}, bound, src)
		require.NoError(t, err)
		require.NoError(t, problem)
		assert.True(t, proven)
		assert.Zero(t, code)
	})
	t.Run("without the position, a block of one code proves it", func(t *testing.T) {
		proven, code, problem, err := run(liveHeaders{t: t}, railverify.ProofInfo{}, &resultsSrc{name: "a", results: good})
		require.NoError(t, err)
		require.NoError(t, problem)
		assert.True(t, proven)
		assert.Zero(t, code)
	})
	t.Run("a proven position picks its own result", func(t *testing.T) {
		// A block with mixed codes is tied to the header only if it hashes
		// to last_results_hash, so mix them under a root of their own.
		mixed := append([]railverify.TxResult(nil), good...)
		mixed[0].Code = 11
		root, err := railverify.ResultsRoot(mixed)
		require.NoError(t, err)
		hd := cometfake.MkHeader("mocha-5", 1442607, make([]byte, 32), "app")
		hd.LastResultsHash = root
		chain := fixedHeader{raw: cometfake.Encode(t, hd)}

		proven, code, problem, err := railverify.ProveResultOf(context.Background(), chain, 1442606, "mocha-5", bound, []railverify.ResultsSource{&resultsSrc{name: "a", results: mixed}})
		require.NoError(t, err)
		require.NoError(t, problem)
		assert.True(t, proven)
		assert.Equal(t, uint32(11), code)

		proven, _, problem, err = railverify.ProveResultOf(context.Background(), chain, 1442606, "mocha-5", railverify.ProofInfo{}, []railverify.ResultsSource{&resultsSrc{name: "a", results: mixed}})
		require.NoError(t, err)
		assert.False(t, proven, "codes differ and the position is not bound")
		assert.Equal(t, []string{"a"}, reasonOf(t, problem, verifier.ReasonResultIndexUnbound))
	})
	t.Run("a position outside the results is not bound", func(t *testing.T) {
		mixed := append([]railverify.TxResult(nil), good...)
		mixed[1].Code = 3
		root, err := railverify.ResultsRoot(mixed)
		require.NoError(t, err)
		hd := cometfake.MkHeader("mocha-5", 1442607, make([]byte, 32), "app")
		hd.LastResultsHash = root
		proven, _, problem, err := railverify.ProveResultOf(context.Background(), fixedHeader{raw: cometfake.Encode(t, hd)}, 1442606, "mocha-5",
			railverify.ProofInfo{IndexBound: true, Index: len(mixed)}, []railverify.ResultsSource{&resultsSrc{name: "a", results: mixed}})
		require.NoError(t, err)
		assert.False(t, proven)
		reasonOf(t, problem, verifier.ReasonResultIndexUnbound)
	})
	for _, m := range v.Mutations {
		if m.Expect != "mismatch" {
			continue
		}
		t.Run("mutation "+m.ID+" does not hash to the trusted root", func(t *testing.T) {
			proven, _, problem, err := run(liveHeaders{t: t}, bound, &resultsSrc{name: "liar.example", results: toTxs(t, m.Results)})
			require.NoError(t, err)
			assert.False(t, proven)
			assert.Equal(t, []string{"liar.example"}, reasonOf(t, problem, verifier.ReasonResultsRootMismatch))
			assert.ErrorIs(t, problem, railverify.ErrResultsProof)
		})
	}
	t.Run("a lying source is skipped and the next one proves it", func(t *testing.T) {
		liar := &resultsSrc{name: "liar.example", results: toTxs(t, v.Mutations[2].Results)}
		down := &resultsSrc{name: "down.example", err: errors.New("node is not persisting finalize block responses")}
		honest := &resultsSrc{name: "honest.example", results: good}
		proven, _, problem, err := run(liveHeaders{t: t}, bound, liar, down, honest)
		require.NoError(t, err)
		require.NoError(t, problem)
		assert.True(t, proven)
		assert.Equal(t, 1, honest.asked)
	})
	t.Run("no source serves the results", func(t *testing.T) {
		proven, _, problem, err := run(liveHeaders{t: t}, bound, &resultsSrc{name: "a", err: errors.New("down")})
		require.NoError(t, err)
		assert.False(t, proven)
		assert.NoError(t, problem, "nothing was shown wrong, only nothing proven")
	})
	t.Run("the next header is not on the trusted chain", func(t *testing.T) {
		src := &resultsSrc{name: "a", results: good}
		h := liveHeaders{t: t, err: verifier.WithReason(verifier.ReasonHeaderAboveCheckpoint, nil, errors.New("T is below"))}
		proven, _, problem, err := run(h, bound, src)
		require.NoError(t, err)
		assert.False(t, proven)
		reasonOf(t, problem, verifier.ReasonResultHeaderUnreachable)
		assert.Zero(t, src.asked, "results are not read without a header to hold them to")
	})
	t.Run("a disagreement about the next header ends the check", func(t *testing.T) {
		h := liveHeaders{t: t, err: verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"x.example"}, errors.New("differs"))}
		_, _, _, err := run(h, bound, &resultsSrc{name: "a", results: good})
		assert.Equal(t, []string{"x.example"}, reasonOf(t, err, verifier.ReasonHeaderDisagreement))
	})
	t.Run("the next header is of another chain", func(t *testing.T) {
		hd := cometfake.MkHeader("mocha-4", 1442607, make([]byte, 32), "app")
		root, err := railverify.ResultsRoot(good)
		require.NoError(t, err)
		hd.LastResultsHash = root
		proven, _, problem, err := railverify.ProveResultOf(context.Background(), fixedHeader{raw: cometfake.Encode(t, hd)}, 1442606, "mocha-5", bound, []railverify.ResultsSource{&resultsSrc{name: "a", results: good}})
		require.NoError(t, err)
		assert.False(t, proven)
		reasonOf(t, problem, verifier.ReasonResultHeaderUnreachable)
	})
	t.Run("a cancelled run is a timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, _, err := railverify.ProveResultOf(ctx, errChain{context.Canceled}, 1442606, "mocha-5", bound, nil)
		reasonOf(t, err, verifier.ReasonTimeout)
	})
}

type fixedHeader struct{ raw []byte }

func (f fixedHeader) Header(context.Context, uint64) ([]byte, error) { return f.raw, nil }

type errChain struct{ err error }

func (e errChain) Header(context.Context, uint64) ([]byte, error) { return nil, e.err }

// With a results source and an index bound by the proof, the whole check
// proves the code, and the code that the tx source reported is not used.
func TestCheckerProvesTheResultThroughASource(t *testing.T) {
	prepare := func(t *testing.T, sourceCode uint32, results []railverify.TxResult, mismatchRoot bool) (*world, *resultSource) {
		w := newWorld(t)
		w.opts = []railverify.Option{railverify.WithProofVerifier(func(p, tx, dh []byte) (railverify.ProofInfo, error) {
			info, err := railverify.VerifyShareProofAt(p, tx, dh)
			info.IndexBound, info.Index = true, 0 // the generated square has the transaction behind fillers
			return info, err
		})}
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: sourceCode, Proof: w.proof})
		root, err := railverify.ResultsRoot(results)
		require.NoError(t, err)
		if mismatchRoot {
			root[0] ^= 1
		}
		hd := cometfake.MkHeader(chainID, txH+1, make([]byte, 32), "app")
		hd.LastResultsHash = root
		w.headers.byH[txH+1] = cometfake.Encode(t, hd)
		rs := &resultSource{name: "results.example", results: results}
		w.opts = append(w.opts, railverify.WithResultsSources(rs))
		return w, rs
	}
	ok := []railverify.TxResult{{Code: 0, GasWanted: 1}, {Code: 5}}

	t.Run("the result proof binds the code", func(t *testing.T) {
		w, rs := prepare(t, 0, ok, false)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Equal(t, "success", f.Outcome)
		assert.NoError(t, f.ResultProblem)
		assert.Equal(t, 1, rs.asked)
		assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, txH-10).Status)
	})
	t.Run("a code the proof shows is a violation, whatever the source said", func(t *testing.T) {
		failing := []railverify.TxResult{{Code: 11}, {Code: 0}}
		w, _ := prepare(t, 0, failing, false)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "failure", f.Outcome)
		j := verifier.JudgeCheck(f, err, txH-10)
		assert.Equal(t, verifier.StatusFail, j.Status)
		assert.ErrorIs(t, j.Err, railverify.ErrTxFailed)
	})
	t.Run("a source that says failed while the proof shows success cannot fail it", func(t *testing.T) {
		w, _ := prepare(t, 11, ok, false)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "success", f.Outcome)
		assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, txH-10).Status)
	})
	t.Run("results that do not hash to the root prove nothing", func(t *testing.T) {
		w, _ := prepare(t, 0, ok, true)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "node-attested", f.Result)
		reasonOf(t, f.ResultProblem, verifier.ReasonResultsRootMismatch)
		j := verifier.JudgeCheck(f, err, txH-10)
		assert.Equal(t, verifier.StatusUnchecked, j.Status)
		assert.Equal(t, verifier.ReasonResultsRootMismatch, j.Reason)
	})
	t.Run("the result proof is not tried without a proven inclusion", func(t *testing.T) {
		w, rs := prepare(t, 0, ok, false)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "node-attested", f.Result)
		assert.Zero(t, rs.asked)
	})
}

// withResults serves the results of the block at txH from a source of their
// own, under a header at txH+1 that commits to them.
func withResults(t *testing.T, w *world, results []railverify.TxResult) *resultSource {
	t.Helper()
	root, err := railverify.ResultsRoot(results)
	require.NoError(t, err)
	hd := cometfake.MkHeader(chainID, txH+1, make([]byte, 32), "app")
	hd.LastResultsHash = root
	w.headers.byH[txH+1] = cometfake.Encode(t, hd)
	rs := &resultSource{name: "results.example", results: results}
	w.opts = append(w.opts, railverify.WithResultsSources(rs))
	return rs
}

type resultSource struct {
	name    string
	results []railverify.TxResult
	asked   int
}

func (r *resultSource) Name() string { return r.name }
func (r *resultSource) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	r.asked++
	return r.results, nil
}

// With alternates, a candidate whose answer is unusable is set aside and the
// next one is tried; cross sources are never promoted.
func TestAlternates(t *testing.T) {
	usable := func(w *world, name string) *fakeSource {
		s := newSource(name)
		w.put(s, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: w.proof})
		return s
	}
	t.Run("the primary is not found, the alternate answers", func(t *testing.T) {
		w := newWorld(t)
		delete(w.primary.txs, ref32(t, w.v.railRef))
		alt := usable(w, "rpc-b.example")
		w.alts = []railverify.TxSource{alt}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Inclusion)
		require.Len(t, f.Sources, 2)
		assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result)
		assert.Equal(t, verifier.ReasonTxNotFound, f.Sources[0].Reason)
		assert.Equal(t, verifier.RoleAlternate, f.Sources[1].Role)
		assert.Equal(t, verifier.SourceUsed, f.Sources[1].Result)
	})
	t.Run("the alternate is not asked when the primary's result is proven", func(t *testing.T) {
		w := newWorldIn(t, layoutMid)
		alt := usable(w, "rpc-b.example")
		w.alts = []railverify.TxSource{alt}
		withResults(t, w, []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}})
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Empty(t, alt.calls)
	})
	t.Run("every candidate is set aside: the last one's cause, all named", func(t *testing.T) {
		w := newWorld(t)
		w.primary.err = errors.New("down")
		alt := newSource("rpc-b.example") // knows nothing
		w.alts = []railverify.TxSource{alt}
		f, err := w.ok()
		requireOnly(t, err, railverify.ErrTxNotFound)
		assert.ElementsMatch(t, []string{"rpc-a.example", "rpc-b.example"}, reasonOf(t, err, verifier.ReasonTxNotFound))
		assert.Len(t, f.Sources, 2)
	})
	t.Run("a cross source that knows the transaction is not promoted", func(t *testing.T) {
		w := newWorld(t)
		delete(w.primary.txs, ref32(t, w.v.railRef))
		cross := usable(w, "rpc-c.example")
		w.cross = []railverify.TxSource{cross}
		_, err := w.ok()
		requireOnly(t, err, railverify.ErrTxNotFound)
		assert.Empty(t, cross.calls, "its independence is counted against the used source")
	})
	t.Run("bytes that hash to rail_ref and break the rules end the check", func(t *testing.T) {
		w := newWorld(t)
		w.v.hash[0] ^= 1
		alt := usable(w, "rpc-b.example")
		w.alts = []railverify.TxSource{alt}
		_, err := w.ok()
		requireOnly(t, err, bankaction.ErrBodyMismatch)
		assert.Empty(t, alt.calls)
	})
	t.Run("the same host twice is refused", func(t *testing.T) {
		w := newWorld(t)
		w.alts = []railverify.TxSource{newSource("rpc-a.example")}
		_, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil, railverify.WithAlternates(w.alts...))
		assert.Error(t, err)
	})
}

// A cancelled run gives a timeout reason, not a finding.
func TestACancelledRunIsATimeout(t *testing.T) {
	w := newWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.primary.err = ctx.Err()
	c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil)
	require.NoError(t, err)
	_, err = c.CheckExecution(ctx, w.v.input(w.v.txRaw))
	reasonOf(t, err, verifier.ReasonTimeout)
}
