package sdk_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestBuildWithMandateHash(t *testing.T) {
	var mh [32]byte
	for i := range mh {
		mh[i] = byte(i + 1)
	}
	r := newRig(t, func(r *rig) { r.cfg.MandateHash = mh })
	res := r.commit()
	c := res.Commitment
	assert.EqualValues(t, commitment.Version, c.Version)
	assert.Equal(t, mh[:], c.MandateRef)
	assert.False(t, c.PayloadRef.Pending())
	requireValidAtGate(t, res, now)
}

func TestBuildWithoutMandateHash(t *testing.T) {
	res := newRig(t).commit()
	assert.Nil(t, res.Commitment.MandateRef)
	requireValidAtGate(t, res, now)
}

// Every seal draws its own salt and writes it into the payload; a salt the
// caller put there is never used.
func TestSealDrawsAFreshSalt(t *testing.T) {
	r := newRig(t)
	p := r.payload()
	chosen := bytes.Repeat([]byte{0x11}, commitment.ActionSaltSize)
	p.Action.Salt = chosen
	a := r.commitPayload(p)
	b := r.commitPayload(p)
	require.Len(t, a.ActionSalt, commitment.ActionSaltSize)
	assert.NotEqual(t, chosen, a.ActionSalt, "the caller's salt is replaced")
	assert.NotEqual(t, a.ActionSalt, b.ActionSalt, "never reused")
	assert.NotEqual(t, a.ActionHash, b.ActionHash, "equal actions hash apart")
	assert.Equal(t, chosen, p.Action.Salt, "the caller's payload is not modified")
}

func TestFinalizeRefusesPendingReference(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	pub.Ref.Anchor = commitment.AnchorPending
	_, err = b.Finalize(bg, s, pub)
	require.ErrorIs(t, err, sdk.ErrPublishResult)
	assert.Zero(t, r.signer.calls(), "nothing is signed for a pending reference")
}

func TestEd25519SignerTag(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	s, err := sdk.NewEd25519Signer(priv)
	require.NoError(t, err)
	h := commitment.Hash{9}
	sig, err := s.SignCommitment(bg, h)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(s.PublicKey(), commitment.SigningMessage(h), sig))
	require.NoError(t, s.Close())
	_, err = s.SignCommitment(bg, h)
	require.ErrorIs(t, err, sdk.ErrSignerClosed)
}
