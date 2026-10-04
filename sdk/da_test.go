package sdk_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func skipFibre(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre} }

func fibreRig(t *testing.T, mods ...func(*rig)) *rig {
	t.Helper()
	r := newRig(t, append([]func(*rig){skipFibre}, mods...)...)
	r.rec.da = commitment.DAFibre
	r.rec.retentionStart = now - 150
	return r
}

// The check is on by default: a Recorder that anchors another blob is caught
// before anything is signed.
func TestDACheckIsOnByDefault(t *testing.T) {
	t.Run("recorder anchors a different blob", func(t *testing.T) {
		r := newRig(t)
		r.rec.other = []byte("a different blob, anchored by a bad recorder")
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls(), "nothing is signed")
		assert.Equal(t, 1, r.rec.calls())
	})
	t.Run("recorder anchors a blob of the same size", func(t *testing.T) {
		r := newRig(t)
		b := r.builder()
		s, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		other := append([]byte{}, s.Blob()...)
		other[len(other)-1] ^= 1
		r.rec.other = other
		pub, err := b.Publish(bg, s)
		require.NoError(t, err)
		res, err := b.Finalize(bg, s, pub)
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("publisher returns a commitment of another namespace", func(t *testing.T) {
		r := newRig(t)
		r.rec.mutate = func(p *sdk.Published) {
			ns := append([]byte{}, p.Ref.Namespace...)
			ns[len(ns)-1] ^= 1
			p.Ref.Namespace = ns
		}
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("publisher returns a flipped commitment", func(t *testing.T) {
		r := newRig(t)
		r.rec.mutate = func(p *sdk.Published) { p.Ref.Commitment[0] ^= 1 }
		_, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("honest recorder passes and the result says it was checked", func(t *testing.T) {
		r := newRig(t)
		res := r.commit()
		assert.True(t, res.DAChecked)
	})
}

// The stock fake publisher offers the same attack through one call.
func TestSDKTestPublisherCorruptCommitment(t *testing.T) {
	r := newRig(t)
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	p.SetBlockTime(now - 100)
	p.SetHeight(height)
	var pub sdk.Publisher = p
	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: pub, Signer: r.signer, Clock: r.clock, Chain: r.chain})
	require.NoError(t, err)

	res, err := b.Commit(bg, r.payload())
	require.NoError(t, err)
	assert.True(t, res.DAChecked)
	requireValidAtGate(t, res, now)

	p.CorruptCommitment()
	calls := r.signer.calls()
	res, err = b.Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
	assert.Nil(t, res)
	assert.Equal(t, calls, r.signer.calls(), "the signer was not called again")

	p2 := sdktest.NewPublisher(commitment.DACelestiaBlob)
	boom := errors.New("down")
	p2.Fail(boom)
	b2, err := sdk.New(r.cfg, sdk.Deps{Publisher: p2, Signer: r.signer, Clock: r.clock, Chain: r.chain})
	require.NoError(t, err)
	_, err = b2.Commit(bg, r.payload())
	require.ErrorIs(t, err, boom)
}

// No committer for a da and no opt-out is an error, not a silent skip.
func TestMissingCheckerIsRefused(t *testing.T) {
	t.Run("da 1, default config", func(t *testing.T) {
		r := newRig(t)
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACheckUnavailable)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("da 1, explicit committers for da 2 only", func(t *testing.T) {
		r := newRig(t, func(r *rig) {
			r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DACelestiaBlob: sdk.ShareV1Committer()}
		})
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		_, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACheckUnavailable)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("the check runs before the validity window is chosen", func(t *testing.T) {
		r := newRig(t)
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = 0 // would be ErrPublishResult later on
		r.rec.blockTime = now - 100
		_, err := r.builder().Commit(bg, r.payload())
		require.Error(t, err)
		assert.Zero(t, r.signer.calls())
	})
}

func TestExplicitOptOutForFibre(t *testing.T) {
	r := fibreRig(t)
	res := r.commit()
	assert.False(t, res.DAChecked, "the result says the DA commitment was not recomputed")
	assert.Equal(t, commitment.DAFibre, res.Commitment.PayloadRef.DA)
	assert.Empty(t, res.Commitment.PayloadRef.Signer)
	requireValidAtGate(t, res, now)
	assert.Equal(t, 1, r.signer.calls())
}

// An opt-out for one da leaves the other one checked.
func TestOptOutIsPerDA(t *testing.T) {
	r := newRig(t, skipFibre)
	r.rec.other = []byte("something else was anchored")
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch, "da 2 stays checked when only da 1 is opted out")
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
}

// A committer given for a da replaces the missing check; it sees the exact
// bytes and the exact reference, before any signature.
func TestCustomCommitterSeesExactBytes(t *testing.T) {
	var gotRef commitment.PayloadRef
	var gotBlob []byte
	calls := 0
	signedBefore := -1
	r := newRig(t)
	r.deps.Committers = map[commitment.DA]sdk.Committer{
		commitment.DAFibre: committerFn(func(_ context.Context, ref commitment.PayloadRef, blob []byte) error {
			calls++
			gotRef, gotBlob = ref, append([]byte{}, blob...)
			signedBefore = r.signer.calls()
			return nil
		}),
	}
	r.rec.da = commitment.DAFibre
	r.rec.retentionStart = now - 150
	res := r.commit()
	assert.Equal(t, 1, calls)
	assert.Equal(t, 0, signedBefore, "the check precedes the signature")
	assert.Equal(t, res.Blob, gotBlob)
	assert.Equal(t, res.Published.Ref, gotRef)
	assert.True(t, res.DAChecked)
}

func TestCustomCommitterFailureStopsSigning(t *testing.T) {
	for name, cerr := range map[string]error{
		"mismatch": sharev1.ErrMismatch,
		"other":    errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.deps.Committers = map[commitment.DA]sdk.Committer{
				commitment.DAFibre: committerFn(func(context.Context, commitment.PayloadRef, []byte) error { return cerr }),
			}
			r.rec.da = commitment.DAFibre
			r.rec.retentionStart = now - 150
			res, err := r.builder().Commit(bg, r.payload())
			require.Error(t, err)
			require.ErrorIs(t, err, cerr)
			assert.Nil(t, res)
			assert.Zero(t, r.signer.calls())
		})
	}
}

// A mismatch outranks a later failure: the recorder is blamed first.
func TestMismatchIsReportedBeforeTimeProblems(t *testing.T) {
	r := newRig(t)
	r.rec.other = []byte("different")
	r.rec.blockTime = now + 100000 // the clock would be "behind the anchor"
	_, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
}

func TestShareV1Committer(t *testing.T) {
	c := sdk.ShareV1Committer()
	require.NotNil(t, c)
	r := newRig(t)
	res := r.commit()
	require.NoError(t, c.Check(bg, res.Published.Ref, res.Blob))

	bad := append([]byte{}, res.Blob...)
	bad[0] ^= 1
	require.Error(t, c.Check(bg, res.Published.Ref, bad))

	fibre := res.Published.Ref
	fibre.DA = commitment.DAFibre
	require.Error(t, c.Check(bg, fibre, res.Blob), "no recompute exists for da 1")

	// The same vector blob the gate's committer accepts.
	blob := gatefix.Blob(t)
	ref := gatefix.Template(t).PayloadRef
	require.NoError(t, c.Check(bg, ref, blob))
}

// An explicit opt-out for da 2 skips the check even though a committer is
// present, and leaves da 1 behaviour unchanged.
func TestOptOutForDA2(t *testing.T) {
	skip2 := func(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DACelestiaBlob} }
	t.Run("a corrupt anchor is signed and reported unchecked", func(t *testing.T) {
		r := newRig(t, skip2)
		r.rec.other = []byte("something else was anchored")
		res := r.commit()
		assert.False(t, res.DAChecked)
		assert.Equal(t, 1, r.signer.calls())
	})
	t.Run("the committer is not called", func(t *testing.T) {
		called := 0
		r := newRig(t, skip2, func(r *rig) {
			r.deps.Committers = map[commitment.DA]sdk.Committer{
				commitment.DACelestiaBlob: committerFn(func(context.Context, commitment.PayloadRef, []byte) error {
					called++
					return errors.New("must not run")
				}),
			}
		})
		res := r.commit()
		assert.Zero(t, called)
		assert.False(t, res.DAChecked)
	})
	t.Run("da 1 stays refused without its own opt-out", func(t *testing.T) {
		r := newRig(t, skip2)
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		_, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACheckUnavailable)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("both opted out", func(t *testing.T) {
		r := newRig(t, skip2, skipFibre)
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		res := r.commit()
		assert.False(t, res.DAChecked)
	})
}
