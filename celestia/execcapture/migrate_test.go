package execcapture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/test/bankvec"
	"github.com/vgonkivs/edicta/verifier"
)

// bankTx is the signed bank-send transaction of the profile vectors, with
// its action and the commitment hash in its memo.
type bankTx struct {
	raw    []byte
	ref    string
	action []byte
	hash   commitment.Hash
}

func loadBankTx(t *testing.T) bankTx {
	t.Helper()
	var out bankTx
	for _, c := range bankvec.Actions(t).Cases {
		if c.ID == "action_minimal_mocha" {
			out.action = bankvec.Hex(t, c.CBORHex)
		}
	}
	txs := bankvec.Txs(t)
	for _, b := range txs.Body {
		if b.ID == "body_minimal" {
			copy(out.hash[:], bankvec.Hex(t, b.HashHex))
		}
	}
	for _, s := range txs.Signed {
		if s.ID == "signed_minimal_mocha" {
			out.raw, out.ref = bankvec.Hex(t, s.TxRawHex), s.RailRef
		}
	}
	require.NotEmpty(t, out.action)
	require.NotEmpty(t, out.raw)
	return out
}

type archiveRig struct {
	*rig
	dir  string
	arch *fsarchive.Store
}

func newArchiveRig(t *testing.T) *archiveRig {
	t.Helper()
	r := newRig(t)
	dir := t.TempDir()
	arch, err := fsarchive.Open(dir, nil)
	require.NoError(t, err)
	r.cap, err = execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store,
		slog.New(slog.NewTextHandler(&syncWriter{w: r.logs}, nil)), execcapture.WithArchive(arch))
	require.NoError(t, err)
	return &archiveRig{rig: r, dir: dir, arch: arch}
}

// chainTrust is header trust over the fake chain's own headers.
type chainTrust struct{ chain *fakeChain }

func (c chainTrust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	raw, err := c.chain.Header(ctx, height)
	if err != nil {
		return verifier.TrustResult{}, verifier.WithReason(verifier.ReasonHeaderAboveCheckpoint, nil, err)
	}
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return verifier.TrustResult{}, err
	}
	h, err := core.HeaderFromProto(&ph)
	if err != nil {
		return verifier.TrustResult{}, err
	}
	if !bytes.Equal(h.Hash(), hash) {
		return verifier.TrustResult{}, verifier.Reasonf(verifier.ReasonHeaderNotLinking, nil, "not on the chain")
	}
	return verifier.TrustResult{Checked: true, CrossCheck: verifier.CrossOff}, nil
}

// copies serves the archive's record as the verifier's only copy.
type copies struct{ arch archive.ExecResultReader }

func (c copies) ExecutionResults(ctx context.Context, chainID string, ref [32]byte) ([]verifier.ArchivedResult, error) {
	rec, err := c.arch.ExecutionResult(ctx, chainID, ref[:])
	switch {
	case errors.Is(err, archive.ErrNotFound):
		return nil, nil
	case errors.Is(err, archive.ErrCorrupt):
		return []verifier.ArchivedResult{{Copy: "archive", Err: err}}, nil
	case err != nil:
		return nil, err
	}
	return []verifier.ArchivedResult{{Copy: "archive", Record: rec}}, nil
}

type prunedSource struct{}

func (prunedSource) Name() string { return "pruned.example" }

func (prunedSource) Tx(context.Context, [32]byte, bool) (railverify.RawTx, error) {
	return railverify.RawTx{}, railverify.ErrTxNotFound
}

type prunedHeaders struct{}

func (prunedHeaders) Header(context.Context, uint64) ([]byte, error) {
	return nil, errors.New("pruned")
}

// A new capture goes straight into the archive, and once the nodes have
// pruned the block a verifier proves the execution from the record alone.
func TestNewCaptureIsArchivedAndProvesTheExecution(t *testing.T) {
	r := newArchiveRig(t)
	tx := loadBankTx(t)
	const h = 6543290
	r.chain.mu.Lock()
	r.chain.txs[h] = [][]byte{tx.raw, {1, 2, 3}, {4, 5, 6, 7}}
	r.chain.results[h] = []railverify.TxResult{{Code: 0, GasWanted: 100, GasUsed: 90}, {Code: 5}, {Code: 0, Data: []byte{9}}}
	r.chain.mu.Unlock()
	r.chain.setHead(h + 2)

	added, err := r.cap.Track(context.Background(), tx.ref, tx.hash, false)
	require.NoError(t, err)
	require.True(t, added)
	r.cap.Pass(context.Background())

	ref, err := hex.DecodeString(tx.ref)
	require.NoError(t, err)
	rec, err := r.arch.ExecutionResult(context.Background(), chainID, ref)
	require.NoError(t, err)
	assert.EqualValues(t, h, rec.Height)
	_, err = r.store.Block(context.Background(), chainID, h)
	require.ErrorIs(t, err, os.ErrNotExist, "the capture is dropped once its record is archived")
	captured, err := r.store.Captured(context.Background(), tx.ref)
	require.NoError(t, err)
	assert.True(t, captured)
	pend, err := r.store.ListPending(context.Background())
	require.NoError(t, err)
	assert.Empty(t, pend)

	// Tracking it again changes nothing: the reference is done.
	added, err = r.cap.Track(context.Background(), tx.ref, tx.hash, true)
	require.NoError(t, err)
	assert.False(t, added)

	chk, err := railverify.NewBankSend(railverify.Config{ChainID: chainID, HRP: "celestia"}, prunedSource{}, prunedHeaders{}, nil)
	require.NoError(t, err)
	in := verifier.ExecutionInput{
		CommitmentHash: tx.hash, ActionType: bankaction.ActionType, Action: tx.action, RailRef: tx.ref, AnchorHeight: h - 50,
		Archived: copies{r.arch}, Trust: chainTrust{r.chain},
	}
	f, err := chk.CheckExecution(context.Background(), in)
	require.NoError(t, err)
	assert.EqualValues(t, h, f.Height)
	assert.Equal(t, verifier.InclusionProven, f.Inclusion)
	assert.Equal(t, verifier.ResultProven, f.Result)
	assert.Equal(t, []verifier.ExecutionSource{{Name: "archive", Role: verifier.RoleArchive, Result: verifier.SourceUsed}}, f.Sources)
	j := verifier.JudgeCheck(f, err, in.AnchorHeight)
	assert.Equal(t, verifier.StatusPass, j.Status, "%v", j.Err)
}

// Without an archive the capture stays where v1.0 kept it.
func TestCaptureWithoutArchiveStaysInTheStore(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(50, 2, func(int) uint32 { return 0 })
	r.chain.setHead(52)
	_, err := r.cap.Track(context.Background(), refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(context.Background())
	b, err := r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)
	require.Len(t, b.Txs, 1)
	assert.Nil(t, r.cap.Migrate(context.Background()))
	assert.Zero(t, r.cap.Conflicts())
}

// Captures made before the archive took them move on the next run; one the
// archive refuses or that another record holds stays in its block file.
func TestMigrateMovesOldCapturesAndKeepsTheRest(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(50, 3, func(i int) uint32 { return uint32(i) })
	r.chain.setHead(52)
	for _, ref := range refs[:2] {
		_, err := r.cap.Track(context.Background(), ref, hashA, false)
		require.NoError(t, err)
	}
	r.cap.Pass(context.Background())
	b, err := r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)
	require.Len(t, b.Txs, 2)

	dir := t.TempDir()
	arch, err := fsarchive.Open(dir, nil)
	require.NoError(t, err)
	logs := &bytes.Buffer{}
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store,
		slog.New(slog.NewTextHandler(&syncWriter{w: logs}, nil)), execcapture.WithArchive(arch))
	require.NoError(t, err)

	// A squatter holds the key of the second capture.
	ref1, _ := hex.DecodeString(refs[1])
	path, err := archive.ExecResultPath(chainID, ref1)
	require.NoError(t, err)
	squat := filepath.Join(dir, filepath.FromSlash(path))
	require.NoError(t, os.MkdirAll(filepath.Dir(squat), 0o755))
	require.NoError(t, os.WriteFile(squat, []byte("garbage"), 0o644))

	got := c.Migrate(context.Background())
	require.Len(t, got, 2)
	if got[0].RailRef != refs[0] {
		got[0], got[1] = got[1], got[0]
	}
	require.Equal(t, refs[0], got[0].RailRef)
	assert.Equal(t, execcapture.MigrationWritten, got[0].Result, "%v", got[0].Err)
	assert.Equal(t, execcapture.MigrationKept, got[1].Result, "%v", got[1].Err)
	sum := sha256.Sum256([]byte("garbage"))
	assert.Equal(t, sum[:], got[1].StoredHash, "the alert names the stored record by its hash")
	assert.Contains(t, logs.String(), hex.EncodeToString(sum[:]))
	assert.EqualValues(t, 1, c.Conflicts())

	b, err = r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)
	require.Len(t, b.Txs, 1)
	assert.Equal(t, refs[1], b.Txs[0].RailRef)
	for _, ref := range refs[:2] {
		captured, err := r.store.Captured(context.Background(), ref)
		require.NoError(t, err)
		assert.True(t, captured, ref)
	}

	// The operator clears the squat: the next run moves the capture.
	require.NoError(t, os.Remove(squat))
	got = c.Migrate(context.Background())
	require.Len(t, got, 1)
	assert.Equal(t, execcapture.MigrationWritten, got[0].Result)
	assert.Zero(t, c.Conflicts())
	_, err = r.store.Block(context.Background(), chainID, 50)
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Empty(t, c.Migrate(context.Background()))
}

// A capture is dropped only after its record is in the archive: a write
// that fails keeps it, and the next run moves it.
func TestMigrateKeepsTheCaptureWhenTheArchiveFails(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(50, 1, func(int) uint32 { return 0 })
	r.chain.setHead(52)
	_, err := r.cap.Track(context.Background(), refs[0], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(context.Background())

	arch := &flakyArchive{err: errors.New("disk full")}
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, r.chain, r.store,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), execcapture.WithArchive(arch))
	require.NoError(t, err)
	got := c.Migrate(context.Background())
	require.Len(t, got, 1)
	assert.Equal(t, execcapture.MigrationRetry, got[0].Result)
	_, err = r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)

	// Written, but the read back fails: still kept.
	arch.err, arch.readErr = nil, errors.New("read fault")
	got = c.Migrate(context.Background())
	assert.Equal(t, execcapture.MigrationRetry, got[0].Result)
	_, err = r.store.Block(context.Background(), chainID, 50)
	require.NoError(t, err)

	// The record is there from the earlier write: equal bytes, dropped.
	arch.readErr = nil
	got = c.Migrate(context.Background())
	assert.Equal(t, execcapture.MigrationAlreadyStored, got[0].Result)
	assert.Equal(t, execcapture.EquivalentBytes, got[0].Equivalence)
	_, err = r.store.Block(context.Background(), chainID, 50)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// flakyArchive is an in-memory archive whose writes or reads can fail.
type flakyArchive struct {
	recs    map[string]*archive.ExecutionResultRecord
	err     error
	readErr error
}

func (f *flakyArchive) Put(_ context.Context, r archive.Record) (archive.Outcome, error) {
	if f.err != nil {
		return 0, f.err
	}
	p, err := archive.KeyPath(r)
	if err != nil {
		return 0, err
	}
	if f.recs == nil {
		f.recs = map[string]*archive.ExecutionResultRecord{}
	}
	if _, ok := f.recs[p]; ok {
		return archive.Unchanged, nil
	}
	f.recs[p] = r.(*archive.ExecutionResultRecord)
	return archive.Written, nil
}

func (f *flakyArchive) ExecutionResult(_ context.Context, chainID string, railRef []byte) (*archive.ExecutionResultRecord, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	p, err := archive.ExecResultPath(chainID, railRef)
	if err != nil {
		return nil, err
	}
	r, ok := f.recs[p]
	if !ok {
		return nil, archive.ErrNotFound
	}
	return r, nil
}

func TestBlocksSkipsWhatIsNotABlockFile(t *testing.T) {
	root := t.TempDir()
	st, err := execcapture.OpenDir(root)
	require.NoError(t, err)
	r := newRig(t)
	refs := r.chain.block(50, 1, func(int) uint32 { return 0 })
	r.chain.setHead(52)
	b, err := r.cap.Capture(context.Background(), refs[0], 50)
	require.NoError(t, err)
	require.NoError(t, st.PutBlock(context.Background(), b))
	require.NoError(t, os.WriteFile(filepath.Join(root, "blocks", chainID, ".tmp-1"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "blocks", chainID, "007.json"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "blocks", chainID, "51.json"), []byte("not json"), 0o600))

	got, err := st.Blocks(context.Background())
	require.Error(t, err, "a block file that does not decode is named")
	require.Len(t, got, 1)
	assert.EqualValues(t, 50, got[0].Height)

	require.ErrorIs(t, st.MarkArchived(context.Background(), chainID, 50, "nope"), execcapture.ErrInvalid)
	require.NoError(t, st.MarkArchived(context.Background(), chainID, 50, refs[0]))
	require.NoError(t, st.MarkArchived(context.Background(), chainID, 50, refs[0]), "idempotent")
	captured, err := st.Captured(context.Background(), refs[0])
	require.NoError(t, err)
	assert.True(t, captured)
}
