package sdk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// e2e wires the SDK builder, with the stock fake publisher, to a gate whose
// chain, DA and executor are fakes. The builder shares the gate's clock and
// chain parameters, as a node client would.
type e2e struct {
	t    *testing.T
	env  *gatefix.Env
	pub  *sdktest.Publisher
	sign *spySigner
	rig  *rig
	b    *sdk.Builder
}

func newE2E(t *testing.T, opts ...gatefix.Option) *e2e {
	t.Helper()
	env := gatefix.New(t, opts...)
	r := newRig(t)
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	p.SetBlockTime(now - 1000)
	p.SetHeight(height)
	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: p, Signer: r.signer, Clock: env.Clock, Chain: env.Chain})
	require.NoError(t, err)
	return &e2e{t: t, env: env, pub: p, sign: r.signer, rig: r, b: b}
}

// stage publishes the chain facts and the blob the way a Recorder leaves them.
func (e *e2e) stage(res *sdk.Result) {
	e.env.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.BlockTime)
	e.env.DA.Put(res.Published.Ref, res.Blob)
}

func TestEndToEndAdmitAndExecuteOnce(t *testing.T) {
	e := newE2E(t)
	res, err := e.b.Commit(bg, e.rig.payload())
	require.NoError(t, err)
	require.True(t, res.DAChecked)
	e.stage(res)

	gres, err := e.env.Admit(res.Envelope)
	require.NoError(t, err, "the gate admits what the SDK signed")
	assert.Equal(t, res.CommitmentHash, gres.CommitmentHash)
	assert.Equal(t, registry.StateExecuted, gres.State)
	assert.Equal(t, registry.PathDA, gres.Path)

	require.Equal(t, 1, e.env.Exec.Calls())
	req := e.env.Exec.Requests()[0]
	assert.Equal(t, res.CommitmentHash, req.CommitmentHash)
	wantOID, err := commitment.ClientOrderID(commitment.RailIBKR, res.CommitmentHash)
	require.NoError(t, err)
	assert.Equal(t, wantOID, req.ClientOrderID)
	assert.Equal(t, *res.Commitment.Action.IBKROrder, req.Order, "the order is the committed one")
	gatefix.CheckReceipt(t, gres, res.CommitmentHash, gatefix.RailRef, commitment.ReceiptPathDA,
		gatefix.GateID, gatefix.Pub(t, "gate1"), 0)

	t.Run("a second submission is refused and nothing executes again", func(t *testing.T) {
		_, err := e.env.Admit(res.Envelope)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		assert.Equal(t, 1, e.env.Exec.Calls())
	})
	t.Run("every recipient reads the decision that was executed", func(t *testing.T) {
		want := encoded(t, e.rig.payload())
		for _, n := range []string{"gate-paper-1", "auditor-1"} {
			o, err := sdk.OpenPayload(res.Envelope, res.Blob, e.rig.vec.Key(t, n).OpenKey(true))
			require.NoError(t, err)
			assert.Equal(t, want, encoded(t, o.Payload))
			assert.Equal(t, res.CommitmentHash, o.CommitmentHash)
		}
	})
}

func TestEndToEndDeadlineAndRetentionClamp(t *testing.T) {
	t.Run("deadline in the payload", func(t *testing.T) {
		e := newE2E(t)
		p := e.rig.payload()
		p.Constraints.Deadline = u64p(now + 600)
		res, err := e.b.Commit(bg, p)
		require.NoError(t, err)
		assert.EqualValues(t, now+600, res.Validity.Expiry)
		e.stage(res)
		_, err = e.env.Admit(res.Envelope)
		require.NoError(t, err)
		assert.Equal(t, 1, e.env.Exec.Calls())
	})
	t.Run("an old anchor is clamped and still admitted", func(t *testing.T) {
		e := newE2E(t)
		e.pub.SetBlockTime(now - 12000) // 3h20m old: 1800 s of retention left after the margin
		b, err := sdk.New(withTTL(e.rig.cfg, 3600), sdk.Deps{Publisher: e.pub, Signer: e.sign, Clock: e.env.Clock, Chain: e.env.Chain})
		require.NoError(t, err)
		res, err := b.Commit(bg, e.rig.payload())
		require.NoError(t, err)
		assert.True(t, res.Validity.Clamped)
		assert.Equal(t, "retention", res.Validity.ClampedBy)
		assert.EqualValues(t, now+1800, res.Validity.ValidUntil)
		e.stage(res)
		gres, err := e.env.Admit(res.Envelope)
		require.NoError(t, err)
		assert.Equal(t, registry.PathDA, gres.Path)
	})
}

func withTTL(c sdk.Config, ttl uint64) sdk.Config { c.TTLS = ttl; return c }

// The DA fake sees da = 2 blob bytes as published; a Recorder that keeps the
// bytes but anchors a different commitment is caught by the SDK first.
func TestEndToEndCorruptRecorderNeverReachesTheGate(t *testing.T) {
	e := newE2E(t)
	e.pub.CorruptCommitment()
	res, err := e.b.Commit(bg, e.rig.payload())
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
	assert.Nil(t, res)
	assert.Zero(t, e.sign.calls())
	assert.Zero(t, e.env.Exec.Calls())
}

func TestEndToEndFibreWithOptOut(t *testing.T) {
	env := gatefix.New(t)
	dac := gatetest.NewDACommitter()
	env.Deps.Committers[commitment.DAFibre] = dac
	require.NoError(t, env.Restart())

	r := fibreRig(t)
	r.rec.blockTime = now - 1000
	r.rec.retentionStart = now - 1000
	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: r.signer, Clock: env.Clock, Chain: env.Chain})
	require.NoError(t, err)

	res, err := b.Commit(bg, r.payload())
	require.NoError(t, err)
	assert.False(t, res.DAChecked)
	env.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.RetentionStart)
	env.DA.Put(res.Published.Ref, res.Blob)
	dac.Bind(res.Published.Ref.Commitment, res.Blob)

	gres, err := env.Admit(res.Envelope)
	require.NoError(t, err)
	assert.Equal(t, registry.PathDA, gres.Path)
	assert.Equal(t, 1, env.Exec.Calls())
}

// Without the opt-out a da = 1 commitment is never produced.
func TestEndToEndFibreWithoutOptOutProducesNothing(t *testing.T) {
	r := newRig(t)
	r.rec.da = commitment.DAFibre
	r.rec.retentionStart = now - 150
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrDACheckUnavailable)
	assert.Nil(t, res)
}
