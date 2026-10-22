package railverify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/verifier"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
)

// fixedArchive serves the same archived results for any key.
type fixedArchive struct {
	results []verifier.ArchivedResult
	err     error
	asked   []string
}

func (f *fixedArchive) ExecutionResults(_ context.Context, chainID string, railRef [32]byte) ([]verifier.ArchivedResult, error) {
	f.asked = append(f.asked, chainID+"/"+hex.EncodeToString(railRef[:]))
	return f.results, f.err
}

// countingSource is a tx source that does not know the transaction, unless
// given one.
type countingSource struct {
	name  string
	calls int
	tx    *railverify.RawTx
}

func (s *countingSource) Name() string { return s.name }

func (s *countingSource) Tx(context.Context, [32]byte, bool) (railverify.RawTx, error) {
	s.calls++
	if s.tx != nil {
		return *s.tx, nil
	}
	return railverify.RawTx{}, railverify.ErrTxNotFound
}

// blockChain is one block of a chain as a capture node serves it: the
// profile's signed transaction first, then two other units.
type blockChain struct {
	height  uint64
	txs     [][]byte
	results []railverify.TxResult
}

func (b *blockChain) Latest(context.Context) (uint64, error) { return b.height + 1, nil }

func (b *blockChain) Tx(_ context.Context, hash [32]byte, _ bool) (railverify.RawTx, error) {
	for i, tx := range b.txs {
		if sha256.Sum256(tx) == hash {
			return railverify.RawTx{Bytes: tx, Height: b.height, Code: b.results[i].Code}, nil
		}
	}
	return railverify.RawTx{}, railverify.ErrTxNotFound
}

func (b *blockChain) BlockTxs(context.Context, uint64) ([][]byte, error) { return b.txs, nil }

func (b *blockChain) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	return b.results, nil
}

func (b *blockChain) proto(h uint64) cmtproto.Header {
	ph := cmtproto.Header{
		Version: cmtversion.Consensus{Block: 11, App: 10}, ChainID: chainID, Height: int64(h),
		Time: time.Unix(1_700_000_000+int64(h), 0).UTC(), ValidatorsHash: bytes.Repeat([]byte{2}, 32),
		NextValidatorsHash: bytes.Repeat([]byte{2}, 32), ConsensusHash: bytes.Repeat([]byte{3}, 32),
		ProposerAddress: bytes.Repeat([]byte{4}, 20),
	}
	if h == b.height {
		root, err := railverify.RebuildDataRoot(b.txs)
		if err != nil {
			panic(err)
		}
		ph.DataHash = root
	} else {
		root, err := railverify.ResultsRoot(b.results)
		if err != nil {
			panic(err)
		}
		ph.LastResultsHash = root
		prev := b.proto(b.height)
		hdr, err := core.HeaderFromProto(&prev)
		if err != nil {
			panic(err)
		}
		ph.LastBlockId = cmtproto.BlockID{Hash: hdr.Hash(), PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{5}, 32)}}
	}
	return ph
}

func (b *blockChain) Header(_ context.Context, h uint64) ([]byte, error) {
	ph := b.proto(h)
	return ph.Marshal()
}

// trusted are the hashes header trust reaches for the block and the next.
func (b *blockChain) trusted(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range []uint64{b.height, b.height + 1} {
		ph := b.proto(h)
		hdr, err := core.HeaderFromProto(&ph)
		require.NoError(t, err)
		out[strconv.FormatUint(h, 10)] = hex.EncodeToString(hdr.Hash())
	}
	return out
}

// record is the execution result record the gate builds for tx i.
func (b *blockChain) record(t *testing.T, i int) *archive.ExecutionResultRecord {
	t.Helper()
	c, err := execcapture.New(execcapture.Config{ChainID: chainID, PruneWindowBlocks: 1000}, b, nopStore{}, nil)
	require.NoError(t, err)
	sum := sha256.Sum256(b.txs[i])
	blk, err := c.Capture(context.Background(), hex.EncodeToString(sum[:]), b.height)
	require.NoError(t, err)
	rec, err := execcapture.BuildRecord(blk, blk.Txs[0])
	require.NoError(t, err)
	return rec
}

// nopStore is never used: the tests call Capture directly.
type nopStore struct{ execcapture.Store }

type archivedWorld struct {
	v       vec
	chain   *blockChain
	rec     *archive.ExecutionResultRecord
	in      verifier.ExecutionInput
	primary *countingSource
	arch    *fixedArchive
}

func newArchivedWorld(t *testing.T) *archivedWorld {
	t.Helper()
	v := loadVec(t)
	chain := &blockChain{
		height:  txH,
		txs:     [][]byte{v.txRaw, {1, 2, 3}, {4, 5, 6, 7}},
		results: []railverify.TxResult{{Code: 0, GasWanted: 100, GasUsed: 90}, {Code: 5}, {Code: 0, Data: []byte{9}}},
	}
	rec := chain.record(t, 0)
	w := &archivedWorld{
		v: v, chain: chain, rec: rec,
		primary: &countingSource{name: "rpc-a.example"},
		arch:    &fixedArchive{results: []verifier.ArchivedResult{{Copy: "archive", Record: rec}}},
	}
	w.in = verifier.ExecutionInput{
		CommitmentHash: v.hash, ActionType: bankaction.ActionType, Action: v.action,
		RailRef: v.railRef, AnchorHeight: txH - 10,
		Archived: w.arch, Trust: newMapTrust(t, chain.trusted(t)),
	}
	return w
}

func (w *archivedWorld) check(t *testing.T, cross ...railverify.TxSource) (verifier.ExecutionFacts, error) {
	t.Helper()
	c, err := railverify.NewBankSend(cfg(), w.primary, w.chain, cross)
	require.NoError(t, err)
	return c.CheckExecution(context.Background(), w.in)
}

func TestArchivedAnswerIsUsedFirst(t *testing.T) {
	w := newArchivedWorld(t)
	f, err := w.check(t)
	require.NoError(t, err)

	assert.Equal(t, 0, w.primary.calls, "the archived answer comes before the primary")
	assert.Equal(t, []string{chainID + "/" + w.v.railRef}, w.arch.asked)
	assert.Equal(t, txH, f.Height)
	assert.Equal(t, w.in.Trust.(*mapTrust).hashes[txH], f.HeaderHash)
	assert.Equal(t, verifier.InclusionProven, f.Inclusion)
	assert.Equal(t, verifier.ResultProven, f.Result)
	assert.Equal(t, verifier.OutcomeSuccess, f.Outcome)
	assert.Equal(t, verifier.CrossOff, f.CrossCheck)
	assert.Equal(t, []verifier.ExecutionSource{{Name: "archive", Role: verifier.RoleArchive, Result: verifier.SourceUsed}}, f.Sources)

	j := verifier.JudgeCheck(f, err, w.in.AnchorHeight)
	assert.Equal(t, verifier.StatusPass, j.Status, "%v", j.Err)
}

func TestArchivedAnswerEachCopyIsACandidate(t *testing.T) {
	w := newArchivedWorld(t)
	tampered := *w.rec
	tampered.ResultPath = bytes.Clone(w.rec.ResultPath)
	tampered.ResultPath[0] ^= 1
	w.arch.results = []verifier.ArchivedResult{
		{Copy: "squatted", Record: &tampered},
		{Copy: "broken", Err: archive.ErrCorrupt},
		{Copy: "mirror", Record: w.rec},
	}
	f, err := w.check(t)
	require.NoError(t, err)
	require.Len(t, f.Sources, 3)
	assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result)
	assert.Equal(t, verifier.ReasonResultsRootMismatch, f.Sources[0].Reason)
	assert.Equal(t, verifier.SourceSetAside, f.Sources[1].Result)
	assert.Equal(t, verifier.ReasonTxProofInvalid, f.Sources[1].Reason)
	assert.Equal(t, verifier.ExecutionSource{Name: "mirror", Role: verifier.RoleArchive, Result: verifier.SourceUsed}, f.Sources[2])
	assert.Equal(t, 0, w.primary.calls)
	assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, w.in.AnchorHeight).Status)
}

// A record that fails is set aside and the online sources run as before: it
// never decides the check by itself.
func TestArchivedAnswerSetAsideFallsBackOnline(t *testing.T) {
	w := newArchivedWorld(t)
	short := *w.rec
	short.ResultsTotal--
	w.arch.results = []verifier.ArchivedResult{{Copy: "archive", Record: &short}}
	f, err := w.check(t)
	require.Error(t, err)
	assert.Equal(t, 1, w.primary.calls)
	require.Len(t, f.Sources, 2)
	assert.Equal(t, verifier.ExecutionSource{Name: "archive", Role: verifier.RoleArchive, Result: verifier.SourceSetAside,
		Reason: verifier.ReasonResultIndexUnbound, Detail: f.Sources[0].Detail}, f.Sources[0])
	assert.Equal(t, verifier.RolePrimary, f.Sources[1].Role)
	j := verifier.JudgeCheck(f, err, w.in.AnchorHeight)
	assert.Equal(t, verifier.StatusUnchecked, j.Status)
	assert.Equal(t, verifier.ReasonTxNotFound, j.Reason, "the reported cause is the last candidate's")

	// The online answer is used when the record is set aside.
	w.primary.tx = &railverify.RawTx{Bytes: w.v.txRaw, Height: txH}
	f, err = w.check(t)
	require.NoError(t, err)
	assert.Equal(t, verifier.SourceSetAside, f.Sources[0].Result)
	assert.Equal(t, verifier.SourceUsed, f.Sources[1].Result)
	assert.Equal(t, verifier.InclusionNodeAttested, f.Inclusion)
}

func TestArchivedAnswerReadErrorEndsTheCheck(t *testing.T) {
	w := newArchivedWorld(t)
	fault := errors.New("archive fault")
	w.arch.err = fault
	_, err := w.check(t)
	require.ErrorIs(t, err, fault)
	assert.Equal(t, 0, w.primary.calls)
}

func TestArchivedAnswerNeedsTrust(t *testing.T) {
	w := newArchivedWorld(t)
	w.in.Trust = nil
	_, err := w.check(t)
	require.Error(t, err)
	assert.Empty(t, w.arch.asked, "without header trust no record is taken")
	assert.Equal(t, 1, w.primary.calls)
}

func TestArchivedAnswerProvesTheOrderAfterTheAnchor(t *testing.T) {
	w := newArchivedWorld(t)
	w.in.AnchorHeight = txH
	f, err := w.check(t)
	require.NoError(t, err)
	j := verifier.JudgeCheck(f, err, w.in.AnchorHeight)
	assert.Equal(t, verifier.StatusFail, j.Status)
	require.ErrorIs(t, j.Err, verifier.ErrExecutionBeforeAnchor)
}

func TestArchivedAnswerProvesAFailure(t *testing.T) {
	w := newArchivedWorld(t)
	w.chain.results[0].Code = 13
	w.rec = w.chain.record(t, 0)
	w.arch.results = []verifier.ArchivedResult{{Copy: "archive", Record: w.rec}}
	w.in.Trust = newMapTrust(t, w.chain.trusted(t))
	f, err := w.check(t)
	require.NoError(t, err)
	assert.Equal(t, verifier.ResultProven, f.Result)
	assert.Equal(t, verifier.OutcomeFailure, f.Outcome)
	j := verifier.JudgeCheck(f, err, w.in.AnchorHeight)
	assert.Equal(t, verifier.StatusFail, j.Status)
	require.ErrorIs(t, j.Err, verifier.ErrExecutionFailed)
}

// The bytes a record binds are the transaction's: the profile's byte rules
// apply to them, and a violation fails.
func TestArchivedAnswerBytesAreBound(t *testing.T) {
	w := newArchivedWorld(t)
	other := w.chain.record(t, 1)
	w.arch.results = []verifier.ArchivedResult{{Copy: "archive", Record: other}}
	w.in.RailRef = hex.EncodeToString(other.RailRef)
	f, err := w.check(t)
	require.ErrorIs(t, err, railverify.ErrTxMalformed)
	assert.Equal(t, verifier.StatusFail, verifier.JudgeCheck(f, err, w.in.AnchorHeight).Status)
	assert.Equal(t, verifier.SourceUsed, f.Sources[0].Result)

	// Another commitment in the memo is another transfer.
	w = newArchivedWorld(t)
	w.in.CommitmentHash[0] ^= 1
	_, err = w.check(t)
	require.ErrorIs(t, err, verifier.ErrExecutionViolation)
	require.ErrorIs(t, err, bankaction.ErrBodyMismatch)
}

func TestArchivedAnswerAgainstCrossSources(t *testing.T) {
	w := newArchivedWorld(t)
	agree := &countingSource{name: "rpc-b.example", tx: &railverify.RawTx{Bytes: w.v.txRaw, Height: txH}}
	f, err := w.check(t, agree)
	require.NoError(t, err)
	assert.Equal(t, verifier.CrossPass, f.CrossCheck)
	assert.Equal(t, verifier.ResultProven, f.Result)

	// A cross source contradicting the proven result is reported only.
	disagree := &countingSource{name: "rpc-c.example", tx: &railverify.RawTx{Bytes: w.v.txRaw, Height: txH, Code: 5}}
	f, err = w.check(t, disagree)
	require.NoError(t, err)
	assert.Equal(t, verifier.CrossMismatch, f.CrossCheck)
	assert.Equal(t, verifier.StatusPass, verifier.JudgeCheck(f, err, w.in.AnchorHeight).Status)
}

func TestArchivedAnswerHeaderDisagreementEndsTheCheck(t *testing.T) {
	w := newArchivedWorld(t)
	w.in.Trust = errTrust{verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"rpc-x.example"}, errors.New("cross"))}
	f, err := w.check(t)
	require.Error(t, err)
	reason, _, ok := verifier.ReasonOf(err)
	require.True(t, ok)
	assert.Equal(t, verifier.ReasonHeaderDisagreement, reason)
	assert.Equal(t, 0, w.primary.calls)
	assert.Equal(t, verifier.SourceUsed, f.Sources[0].Result)
}
