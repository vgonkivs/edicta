package execcapture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
)

const chainID = "mocha-4"

// fakeChain serves blocks of normal txs with consistent results and headers.
type fakeChain struct {
	mu      sync.Mutex
	head    uint64
	txs     map[uint64][][]byte
	results map[uint64][]railverify.TxResult
	// badRoot makes the header at height + 1 carry another results hash.
	badRoot  map[uint64]bool
	resErr   error
	txCalls  int
	resCalls int
}

func newFakeChain() *fakeChain {
	return &fakeChain{txs: map[uint64][][]byte{}, results: map[uint64][]railverify.TxResult{}, badRoot: map[uint64]bool{}}
}

// block adds a block of n txs at height and returns their rail refs.
func (f *fakeChain) block(height uint64, n int, code func(i int) uint32) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var refs []string
	for i := 0; i < n; i++ {
		tx := []byte{byte(height), byte(height >> 8), byte(i), 0xaa}
		sum := sha256.Sum256(tx)
		refs = append(refs, hex.EncodeToString(sum[:]))
		f.txs[height] = append(f.txs[height], tx)
		f.results[height] = append(f.results[height], railverify.TxResult{Code: code(i), Data: []byte{byte(i)}, GasWanted: 100, GasUsed: int64(50 + i)})
	}
	return refs
}

func (f *fakeChain) setHead(h uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.head = h
}

func (f *fakeChain) Latest(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.head, nil
}

func (f *fakeChain) Tx(_ context.Context, hash [32]byte, _ bool) (railverify.RawTx, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txCalls++
	for h, txs := range f.txs {
		if h > f.head {
			continue
		}
		for i, tx := range txs {
			if sha256.Sum256(tx) == hash {
				return railverify.RawTx{Bytes: tx, Height: h, Code: f.results[h][i].Code}, nil
			}
		}
	}
	return railverify.RawTx{}, railverify.ErrTxNotFound
}

func (f *fakeChain) BlockTxs(_ context.Context, h uint64) ([][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.txs[h], nil
}

func (f *fakeChain) BlockResults(_ context.Context, h uint64) ([]railverify.TxResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resCalls++
	if f.resErr != nil {
		return nil, f.resErr
	}
	return f.results[h], nil
}

func resultsHash(rs []railverify.TxResult) []byte {
	ar := make([]*abci.ExecTxResult, len(rs))
	for i, r := range rs {
		ar[i] = &abci.ExecTxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}
	}
	return core.NewResults(ar).Hash()
}

func (f *fakeChain) Header(_ context.Context, h uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h > f.head {
		return nil, errors.New("no such header")
	}
	root := resultsHash(f.results[h-1])
	if f.badRoot[h-1] {
		root = bytes.Repeat([]byte{1}, 32)
	}
	ph := cmtproto.Header{ChainID: chainID, Height: int64(h), LastResultsHash: root}
	return ph.Marshal()
}

type rig struct {
	chain *fakeChain
	store *execcapture.Dir
	cap   *execcapture.Capturer
	logs  *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := execcapture.OpenDir(t.TempDir())
	require.NoError(t, err)
	ch := newFakeChain()
	logs := &bytes.Buffer{}
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, ch, st,
		slog.New(slog.NewTextHandler(&syncWriter{w: logs}, nil)))
	require.NoError(t, err)
	return &rig{chain: ch, store: st, cap: c, logs: logs}
}

type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

var hashA = commitment.Hash{1}

func TestCaptureSingleResultWithPath(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(500, 5, func(i int) uint32 { return uint32(i % 2) })
	r.chain.setHead(501)
	ctx := t.Context()

	added, err := r.cap.Track(ctx, refs[3], hashA, false)
	require.NoError(t, err)
	assert.True(t, added)
	r.cap.Pass(ctx)

	done, err := r.store.Captured(ctx, refs[3])
	require.NoError(t, err)
	assert.True(t, done)
	b, err := r.store.Block(ctx, chainID, 500)
	require.NoError(t, err)
	require.Len(t, b.Txs, 1)
	tx := b.Txs[0]
	assert.Equal(t, uint32(3), tx.Index)
	assert.Equal(t, uint32(1), tx.Result.Code)
	assert.EqualValues(t, 5, tx.Proof.Total)
	require.NoError(t, execcapture.VerifyTx(b, tx))

	pend, err := r.store.ListPending(ctx)
	require.NoError(t, err)
	assert.Empty(t, pend)
	assert.Zero(t, r.cap.Overdue())

	t.Run("a tampered result does not verify", func(t *testing.T) {
		bad := tx
		bad.Result.Code = 0
		require.ErrorIs(t, execcapture.VerifyTx(b, bad), execcapture.ErrUnproven)
	})
}

func TestCaptureIsIdempotentAndSharesTheBlock(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(700, 3, func(int) uint32 { return 0 })
	r.chain.setHead(710)
	ctx := t.Context()

	for _, ref := range []string{refs[0], refs[2], refs[0]} {
		_, err := r.cap.Track(ctx, ref, hashA, false)
		require.NoError(t, err)
		r.cap.Pass(ctx)
	}
	added, err := r.cap.Track(ctx, refs[0], hashA, false)
	require.NoError(t, err)
	assert.False(t, added, "a captured reference is not tracked again")

	b, err := r.store.Block(ctx, chainID, 700)
	require.NoError(t, err)
	require.Len(t, b.Txs, 2, "one block record shared by every capture at the height")
	for _, tx := range b.Txs {
		require.NoError(t, execcapture.VerifyTx(b, tx))
	}

	again, err := r.cap.Capture(ctx, refs[2], 700)
	require.NoError(t, err)
	require.NoError(t, r.store.PutBlock(ctx, again), "the same capture again is a no-op")

	other := again
	other.NextHeader = append([]byte(nil), again.NextHeader...)
	other.NextHeader[len(other.NextHeader)-1] ^= 1
	require.ErrorIs(t, r.store.PutBlock(ctx, other), execcapture.ErrConflict, "the first next header stays")
}

func TestCaptureWaitsForTheNextHeader(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(900, 1, func(int) uint32 { return 0 })
	ctx := t.Context()

	r.chain.setHead(899)
	_, err := r.cap.Track(ctx, refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(ctx)
	pend, err := r.store.ListPending(ctx)
	require.NoError(t, err)
	require.Len(t, pend, 1)
	assert.Zero(t, pend[0].ExecHeight, "not on the chain yet")
	assert.EqualValues(t, 899, pend[0].SeenHead)

	r.chain.setHead(900)
	r.cap.Pass(ctx)
	pend, err = r.store.ListPending(ctx)
	require.NoError(t, err)
	require.Len(t, pend, 1)
	assert.EqualValues(t, 900, pend[0].ExecHeight, "the height is kept for the retry")

	r.chain.setHead(901)
	r.cap.Pass(ctx)
	done, err := r.store.Captured(ctx, refs[0])
	require.NoError(t, err)
	assert.True(t, done)
}

func TestCaptureRefusesResultsThatDoNotHashToTheHeader(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(300, 2, func(int) uint32 { return 0 })
	r.chain.badRoot[300] = true
	r.chain.setHead(301)
	_, err := r.cap.Capture(t.Context(), refs[1], 300)
	require.ErrorIs(t, err, execcapture.ErrUnproven)

	_, err = r.cap.Track(t.Context(), refs[1], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(t.Context())
	done, err := r.store.Captured(t.Context(), refs[1])
	require.NoError(t, err)
	assert.False(t, done)
}

// The alert threshold is half the configured prune window, counted from the
// execution height; the late-Record warning is a quarter of it.
func TestCaptureOverdueAlertAndLateWarning(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(1000, 1, func(int) uint32 { return 0 })
	r.chain.resErr = errors.New("pruned")
	ctx := t.Context()

	r.chain.setHead(1000 + 250)
	_, err := r.cap.Track(ctx, refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(ctx)
	assert.Contains(t, r.logs.String(), "Record arrived late")
	assert.Zero(t, r.cap.Overdue(), "below half the window")

	r.chain.setHead(1000 + 499)
	r.cap.Pass(ctx)
	assert.Zero(t, r.cap.Overdue())

	r.chain.setHead(1000 + 500)
	r.cap.Pass(ctx)
	assert.EqualValues(t, 1, r.cap.Overdue())
	assert.Equal(t, 1, strings.Count(r.logs.String(), "still missing past half the node prune window"))
	r.cap.Pass(ctx)
	assert.Equal(t, 1, strings.Count(r.logs.String(), "still missing past half the node prune window"), "the error is logged once per capture")

	r.chain.resErr = nil
	r.cap.Pass(ctx)
	assert.Zero(t, r.cap.Overdue(), "the alert clears once captured")
}

func TestCaptureRecordInTimeIsNotWarned(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(10, 1, func(int) uint32 { return 0 })
	r.chain.setHead(12)
	_, err := r.cap.Track(t.Context(), refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(t.Context())
	assert.NotContains(t, r.logs.String(), "late")
}

func TestCaptureConfigValidateBasic(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg execcapture.Config
		ok  bool
	}{
		"ok":                {execcapture.Config{ChainID: chainID, PruneWindowBlocks: 100}, true},
		"window too small":  {execcapture.Config{ChainID: chainID, PruneWindowBlocks: 99}, false},
		"window zero":       {execcapture.Config{ChainID: chainID}, false},
		"no chain id":       {execcapture.Config{PruneWindowBlocks: 1000}, false},
		"chain id with a /": {execcapture.Config{ChainID: "a/b", PruneWindowBlocks: 1000}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.ValidateBasic()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, execcapture.ErrInvalid)
		})
	}
}

func TestStoreRefusesBadKeys(t *testing.T) {
	st, err := execcapture.OpenDir(t.TempDir())
	require.NoError(t, err)
	ctx := t.Context()
	require.ErrorIs(t, st.PutPending(ctx, execcapture.Pending{RailRef: "../x"}), execcapture.ErrInvalid)
	require.ErrorIs(t, st.PutBlock(ctx, execcapture.Block{ChainID: "..", Height: 1, NextHeader: []byte{1}}), execcapture.ErrInvalid)
	_, err = st.Captured(ctx, strings.Repeat("A", 64))
	require.ErrorIs(t, err, execcapture.ErrInvalid)
}
