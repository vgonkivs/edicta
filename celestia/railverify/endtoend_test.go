package railverify_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/verifier"
)

// The proof binds the index through the real share proof: the transaction
// is the second of three, its neighbours carry other codes, and the tx
// source lies about the code.
func TestRealIndexBinding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []railverify.TxResult
		said    uint32
		outcome string
		status  verifier.Status
	}{
		{"ok among failed neighbours, the source says failed", []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}}, 7, "success", verifier.StatusPass},
		{"failed among ok neighbours, the source says ok", []railverify.TxResult{{Code: 0}, {Code: 9}, {Code: 0}}, 0, "failure", verifier.StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorldIn(t, layoutMid)
			w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: tc.said, Proof: w.proof})
			withResults(t, w, tc.results)
			f, err := w.ok()
			require.NoError(t, err)
			assert.Equal(t, "proven", f.Result)
			assert.Equal(t, tc.outcome, f.Outcome)
			assert.Equal(t, tc.status, verifier.JudgeCheck(f, err, txH-10).Status)
		})
	}
}

// A primary without a proof must not keep the alternates from being asked.
func TestAnAnswerWithoutAProofDoesNotStopTheAlternates(t *testing.T) {
	results := []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}}
	t.Run("the alternate proves", func(t *testing.T) {
		w := newWorldIn(t, layoutMid)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
		alt := newSource("rpc-b.example")
		w.put(alt, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: w.proof})
		w.alts = []railverify.TxSource{alt}
		withResults(t, w, results)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Len(t, alt.calls, 1)
		assert.Equal(t, "proven", f.Inclusion)
		assert.Equal(t, "proven", f.Result)
		assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, txH-10).Status)
		require.Len(t, f.Sources, 2)
		assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result)
		assert.Equal(t, verifier.ReasonResultUnproven, f.Sources[0].Reason)
		assert.Equal(t, verifier.SourceUsed, f.Sources[1].Result)
	})
	t.Run("without a better answer the first answer with a proven inclusion is used", func(t *testing.T) {
		w := newWorldIn(t, layoutMid)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
		alt := newSource("rpc-b.example")
		w.put(alt, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Proof: w.proof})
		w.alts = []railverify.TxSource{alt}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Inclusion)
		assert.Equal(t, "node-attested", f.Result)
		j := verifier.JudgeCheck(f, err, txH-10)
		assert.Equal(t, verifier.StatusUnchecked, j.Status)
		assert.Equal(t, verifier.ReasonResultHeaderUnreachable, j.Reason)
		assert.Equal(t, []string{"rpc-b.example"}, j.Sources)
	})
	t.Run("without a better answer the primary is used", func(t *testing.T) {
		w := newWorldIn(t, layoutMid)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
		alt := newSource("rpc-b.example")
		w.put(alt, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
		w.alts = []railverify.TxSource{alt}
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "node-attested", f.Inclusion)
		assert.Equal(t, verifier.SourceUsed, f.Sources[0].Result)
		assert.Equal(t, verifier.SourceSetAside, f.Sources[1].Result)
	})
}

// Two agreeing sources are reported, and they never pass without a proof.
func TestCrossAgreementNeverPasses(t *testing.T) {
	w := newWorldIn(t, layoutMid)
	w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
	cross := newSource("rpc-c.example")
	w.put(cross, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH})
	w.cross = []railverify.TxSource{cross}
	f, err := w.ok()
	require.NoError(t, err)
	assert.Equal(t, "cross-confirmed", f.Result)
	assert.Equal(t, "node-attested", f.Inclusion)
	j := verifier.JudgeCheck(f, err, txH-10)
	assert.Equal(t, verifier.StatusUnchecked, j.Status)
	assert.Equal(t, verifier.ReasonResultUnproven, j.Reason)
}

// A proven result wins over cross sources that lie, and the report says so
// in the rows and in the aggregate.
func TestCrossAggregateFollowsTheRowsAfterAProvenResult(t *testing.T) {
	w := newWorldIn(t, layoutMid)
	w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 5, Proof: w.proof})
	cross := newSource("rpc-c.example")
	w.put(cross, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 5})
	w.cross = []railverify.TxSource{cross}
	withResults(t, w, []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}})
	f, err := w.ok()
	require.NoError(t, err)
	assert.Equal(t, "proven", f.Result)
	assert.Equal(t, "success", f.Outcome)
	assert.Equal(t, verifier.SourceDisagree, f.Sources[len(f.Sources)-1].Result)
	assert.Equal(t, "mismatch", f.CrossCheck)
	assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, txH-10).Status)
}

// blockSrc serves the transactions of a block.
type blockSrc struct {
	mu    sync.Mutex
	name  string
	txs   [][]byte
	err   error
	asked int
}

func (b *blockSrc) Name() string { return b.name }
func (b *blockSrc) BlockTxs(context.Context, uint64) ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked++
	return b.txs, b.err
}

func TestRebuildDataRoot(t *testing.T) {
	for name, layout := range map[string]func([]byte) ([][]byte, int){
		"alone": layoutAlone, "after small ones": layoutMid, "after big ones": layoutBig, "spilling": layoutSpill,
	} {
		t.Run(name, func(t *testing.T) {
			v := loadVec(t)
			txs, idx := layout(v.txRaw)
			_, root := proofOf(t, txs, idx)
			got, err := railverify.RebuildDataRoot(txs)
			require.NoError(t, err)
			assert.Equal(t, root, got, "the root of celestia-app's own proof builder")
		})
	}
	t.Run("no transactions", func(t *testing.T) {
		_, err := railverify.RebuildDataRoot(nil)
		assert.Error(t, err)
	})
}

// On a busy block the transaction is not in share 0, so its proof does not
// bind the index. The block's own transactions do, once their square has the
// trusted data root.
func TestBlockBindsTheIndexWhereTheProofCannot(t *testing.T) {
	results := []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}}
	setupWith := func(t *testing.T, said uint32, results []railverify.TxResult) (*world, []byte) {
		w := newWorld(t)
		w.put(w.primary, w.v.txRaw, railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: said, Proof: w.proof})
		withResults(t, w, results)
		return w, w.v.txRaw
	}
	setup := func(t *testing.T, said uint32) (*world, []byte) { return setupWith(t, said, results) }
	f0 := fillers(2)
	block := func(tx []byte) [][]byte { return [][]byte{f0[0], tx, f0[1]} }

	t.Run("the proof alone leaves the index unbound", func(t *testing.T) {
		w, _ := setup(t, 0)
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "node-attested", f.Result)
		reasonOf(t, f.ResultProblem, verifier.ReasonResultIndexUnbound)
	})
	t.Run("a block source binds it", func(t *testing.T) {
		w, tx := setup(t, 7)
		bs := &blockSrc{name: "blocks.example", txs: block(tx)}
		w.opts = append(w.opts, railverify.WithBlockSources(bs))
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Equal(t, "success", f.Outcome, "result 1, not the source's code and not a neighbour's")
		assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, txH-10).Status)
	})
	t.Run("a block with the failed result at the position fails", func(t *testing.T) {
		w, tx := setupWith(t, 0, []railverify.TxResult{{Code: 0}, {Code: 9}, {Code: 0}})
		w.opts = append(w.opts, railverify.WithBlockSources(&blockSrc{name: "blocks.example", txs: block(tx)}))
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, verifier.StatusFail, verifier.JudgeCheck(f, err, txH-10).Status)
	})
	t.Run("the tx source that serves blocks is used without being added", func(t *testing.T) {
		w, tx := setup(t, 0)
		both := &txAndBlocks{fakeSource: w.primary, txs: block(tx)}
		w.primary = nil
		c, err := railverify.NewBankSend(w.cfg, both, w.headers, nil, w.opts...)
		require.NoError(t, err)
		f, err := c.CheckExecution(bg, w.v.input(w.v.txRaw))
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
	})
	for name, served := range map[string]func(tx []byte) [][]byte{
		"reordered":         func(tx []byte) [][]byte { return [][]byte{tx, f0[0], f0[1]} },
		"another block":     func(tx []byte) [][]byte { return [][]byte{f0[0], f0[1]} },
		"a changed tx":      func(tx []byte) [][]byte { b := block(tx); b[0] = append([]byte{1}, b[0][1:]...); return b },
		"no transactions":   func([]byte) [][]byte { return nil },
		"not a valid block": func(tx []byte) [][]byte { return [][]byte{tx, tx} },
	} {
		t.Run("a block source that serves "+name+" binds nothing", func(t *testing.T) {
			w, tx := setup(t, 0)
			w.opts = append(w.opts, railverify.WithBlockSources(&blockSrc{name: "liar.example", txs: served(tx)}))
			f, err := w.ok()
			require.NoError(t, err)
			assert.Equal(t, "node-attested", f.Result)
			reasonOf(t, f.ResultProblem, verifier.ReasonResultIndexUnbound)
			j := verifier.JudgeCheck(f, err, txH-10)
			assert.Equal(t, verifier.StatusUnchecked, j.Status)
			assert.Equal(t, verifier.ReasonResultIndexUnbound, j.Reason)
		})
	}
	t.Run("as many transactions as results are needed", func(t *testing.T) {
		w, tx := setupWith(t, 0, []railverify.TxResult{{Code: 5}, {Code: 0}, {Code: 5}, {Code: 5}})
		w.opts = append(w.opts, railverify.WithBlockSources(&blockSrc{name: "blocks.example", txs: block(tx)}))
		f, err := w.ok()
		require.NoError(t, err)
		reasonOf(t, f.ResultProblem, verifier.ReasonResultIndexUnbound)
	})
	t.Run("a lying source is skipped and the next one binds it", func(t *testing.T) {
		w, tx := setup(t, 0)
		liar := &blockSrc{name: "liar.example", txs: [][]byte{tx, f0[0], f0[1]}}
		down := &blockSrc{name: "down.example", err: errors.New("pruned")}
		honest := &blockSrc{name: "honest.example", txs: block(tx)}
		w.opts = append(w.opts, railverify.WithBlockSources(liar, down, honest))
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Equal(t, 1, honest.asked)
	})
	t.Run("the share-0 fast path asks no block", func(t *testing.T) {
		w := newWorldIn(t, layoutMid)
		withResults(t, w, results)
		bs := &blockSrc{name: "blocks.example"}
		w.opts = append(w.opts, railverify.WithBlockSources(bs))
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Zero(t, bs.asked)
	})
	t.Run("a block of one code needs no block", func(t *testing.T) {
		w := newWorld(t)
		withResults(t, w, []railverify.TxResult{{Code: 0}, {Code: 0}})
		bs := &blockSrc{name: "blocks.example"}
		w.opts = append(w.opts, railverify.WithBlockSources(bs))
		f, err := w.ok()
		require.NoError(t, err)
		assert.Equal(t, "proven", f.Result)
		assert.Zero(t, bs.asked)
	})
	t.Run("a cancelled run is a timeout", func(t *testing.T) {
		w, tx := setup(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		w.opts = append(w.opts, railverify.WithBlockSources(&cancelling{cancel: cancel, txs: block(tx)}))
		c, err := railverify.NewBankSend(w.cfg, w.primary, w.headers, nil, w.opts...)
		require.NoError(t, err)
		_, err = c.CheckExecution(ctx, w.v.input(w.v.txRaw))
		reasonOf(t, err, verifier.ReasonTimeout)
	})
}

type txAndBlocks struct {
	*fakeSource
	txs [][]byte
}

func (b *txAndBlocks) BlockTxs(context.Context, uint64) ([][]byte, error) { return b.txs, nil }

type cancelling struct {
	cancel context.CancelFunc
	txs    [][]byte
}

func (c *cancelling) Name() string { return "cancel.example" }
func (c *cancelling) BlockTxs(context.Context, uint64) ([][]byte, error) {
	c.cancel()
	return c.txs, nil
}
