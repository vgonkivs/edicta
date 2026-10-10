package edictad

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// idleChain is a capture chain where nothing has landed yet.
type idleChain struct{}

func (idleChain) Latest(context.Context) (uint64, error) { return 10, nil }
func (idleChain) Tx(context.Context, [32]byte, bool) (railverify.RawTx, error) {
	return railverify.RawTx{}, railverify.ErrTxNotFound
}
func (idleChain) BlockTxs(context.Context, uint64) ([][]byte, error) { return nil, nil }
func (idleChain) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	return nil, nil
}
func (idleChain) Header(context.Context, uint64) ([]byte, error) { return nil, nil }

func newCaptureRig(t *testing.T) (*execcapture.Capturer, *execcapture.Dir, *bytes.Buffer) {
	t.Helper()
	st, err := execcapture.OpenDir(t.TempDir())
	require.NoError(t, err)
	logs := &bytes.Buffer{}
	c, err := execcapture.New(execcapture.Config{ChainID: "test-1", PruneWindowBlocks: 1000}, idleChain{}, st, slog.New(slog.NewTextHandler(logs, nil)))
	require.NoError(t, err)
	return c, st, logs
}

func signedEnvelope(t *testing.T, actionType string) ([]byte, commitment.Hash) {
	t.Helper()
	c := gatefix.WithAction(t, gatefix.Template(t), actionType, []byte{0xa1, 0x01, 0x02})
	return gatefix.Sign(t, "agent1", c)
}

func signedReceipt(t *testing.T, h commitment.Hash, railRef string) []byte {
	t.Helper()
	b, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{
		Receipt: commitment.Receipt{
			Version: commitment.Version, CommitmentHash: h[:], GateID: gatefix.GateID, GatePubKey: bytes.Repeat([]byte{1}, 32),
			RailRef: railRef, RecordedAt: 1, ExecutorPubKey: bytes.Repeat([]byte{2}, 32), ExecutorSignature: bytes.Repeat([]byte{3}, 64),
		},
		Signature: bytes.Repeat([]byte{4}, 64),
	})
	require.NoError(t, err)
	return b
}

var railRefA = strings.Repeat("ab", 32)

func pendingRefs(t *testing.T, st *execcapture.Dir) map[string]execcapture.Pending {
	t.Helper()
	ps, err := st.ListPending(t.Context())
	require.NoError(t, err)
	out := map[string]execcapture.Pending{}
	for _, p := range ps {
		out[p.RailRef] = p
	}
	return out
}

func TestRecordTracksTheCaptureOfCelestiaRailsOnly(t *testing.T) {
	c, st, _ := newCaptureRig(t)
	logs := &bytes.Buffer{}
	a := &archivingGate{cap: c, w: &writer{log: slog.New(slog.NewTextHandler(logs, nil))}}

	env, h := signedEnvelope(t, bankaction.ActionType)
	a.trackRecord(t.Context(), env, signedReceipt(t, h, railRefA))
	got := pendingRefs(t, st)
	require.Contains(t, got, railRefA)
	assert.False(t, got[railRefA].FromSweep)

	a.trackRecord(t.Context(), env, signedReceipt(t, h, railRefA))
	assert.Len(t, pendingRefs(t, st), 1, "a retried Record tracks once")

	other := strings.Repeat("cd", 32)
	envX, hx := signedEnvelope(t, gatefix.ActionType)
	a.trackRecord(t.Context(), envX, signedReceipt(t, hx, other))
	assert.NotContains(t, pendingRefs(t, st), other, "a rail without an on-chain result proof is not captured")

	envB, hb := signedEnvelope(t, bankaction.ActionType)
	a.trackRecord(t.Context(), envB, signedReceipt(t, hb, "NOT-A-HASH"))
	assert.Contains(t, logs.String(), "not tracked")
}

type listOnce []registry.Entry

func (l listOnce) List(_ context.Context, after *registry.Key, _ int) ([]registry.Entry, error) {
	if after != nil {
		return nil, nil
	}
	return l, nil
}

func TestCaptureSweepTracksReceiptsWithoutCapture(t *testing.T) {
	c, st, _ := newCaptureRig(t)
	envA, ha := signedEnvelope(t, bankaction.ActionType)
	envX, hx := signedEnvelope(t, gatefix.ActionType)
	envs := map[commitment.Hash][]byte{ha: envA, hx: envX}
	refX := strings.Repeat("cd", 32)
	reads := 0
	sw := &captureSweep{
		lister: listOnce{
			{Key: registry.Key{Nonce: [16]byte{1}}, CommitmentHash: ha, Receipt: signedReceipt(t, ha, railRefA)},
			{Key: registry.Key{Nonce: [16]byte{2}}, CommitmentHash: hx, Receipt: signedReceipt(t, hx, refX)},
			{Key: registry.Key{Nonce: [16]byte{3}}, CommitmentHash: commitment.Hash{9}},
		},
		decision: func(_ context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
			reads++
			if e, ok := envs[h]; ok {
				return &archive.DecisionRecord{Envelope: e}, nil
			}
			return nil, archive.ErrNotFound
		},
		cap: c, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), timeout: time.Second,
	}
	sw.pass(t.Context())
	got := pendingRefs(t, st)
	require.Contains(t, got, railRefA)
	assert.True(t, got[railRefA].FromSweep)
	assert.NotContains(t, got, refX)
	assert.Equal(t, 2, reads, "entries without a receipt are not read")

	sw.pass(t.Context())
	assert.Equal(t, 2, reads, "settled decisions are not read again")
	assert.Len(t, pendingRefs(t, st), 1)
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type overdueN uint64

func (o overdueN) Overdue() uint64 { return uint64(o) }

func TestHealthDegradedWhileACaptureIsOverdue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := &health{clock: fixedClock{now}, log: slog.Default(), lastOK: true, lastAt: now}
	info, err := h.Health(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 1, info.Status)

	h.captures = overdueN(1)
	info, err = h.Health(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 2, info.Status)

	h.captures = overdueN(0)
	info, err = h.Health(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 1, info.Status)
}
