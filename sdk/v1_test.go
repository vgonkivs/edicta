package sdk_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestBuildV1WithMandateHash(t *testing.T) {
	var mh [32]byte
	for i := range mh {
		mh[i] = byte(i + 1)
	}
	r := newRig(t, func(r *rig) {
		r.cfg.Version = commitment.VersionV1
		r.cfg.MandateHash = mh
	})
	res := r.commit()
	c := res.Commitment
	assert.EqualValues(t, commitment.VersionV1, c.Version)
	assert.Equal(t, mh[:], c.MandateRef)
	assert.False(t, c.PayloadRef.Pending())
	requireValidAtGate(t, res, now)

	s, err := commitment.DecodeSigned(res.Envelope)
	require.NoError(t, err)
	h, err := commitment.Verify(s)
	require.NoError(t, err, "signed under the v1 tags")
	assert.Equal(t, res.CommitmentHash, h)
	pub := gatefix.Key(t, "agent1").Public().(ed25519.PublicKey)
	assert.False(t, ed25519.Verify(pub, commitment.SigningMessage(h), s.Signature), "never under the v0 tag")
}

func TestBuildV1WithoutMandateHash(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.Version = commitment.VersionV1 })
	res := r.commit()
	assert.EqualValues(t, commitment.VersionV1, res.Commitment.Version)
	assert.Nil(t, res.Commitment.MandateRef)
	requireValidAtGate(t, res, now)
}

// v0onlySigner hides the v1 method of the signer it wraps.
type v0onlySigner struct{ inner sdk.Signer }

func (s v0onlySigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s v0onlySigner) SignCommitment(ctx context.Context, h commitment.Hash) ([]byte, error) {
	return s.inner.SignCommitment(ctx, h)
}

func TestNewRejectsBadVersionConfig(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.MandateHash[0] = 1 })
	_, err := r.tryNew()
	require.ErrorIs(t, err, sdk.ErrInvalidConfig, "a mandate hash needs version 1")

	r = newRig(t, func(r *rig) { r.cfg.Version = 2 })
	_, err = r.tryNew()
	require.ErrorIs(t, err, sdk.ErrInvalidConfig)

	r = newRig(t, func(r *rig) { r.cfg.Version = commitment.VersionV1 })
	d := r.deps
	d.Publisher, d.Clock, d.Signer = r.rec, r.clock, v0onlySigner{inner: r.signer}
	_, err = sdk.New(r.cfg, d)
	require.ErrorIs(t, err, sdk.ErrInvalidConfig, "version 1 needs a v1 signer")
}

func TestFinalizeRefusesPendingReference(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.Version = commitment.VersionV1 })
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

func TestEd25519SignerV1Tag(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	s, err := sdk.NewEd25519Signer(priv)
	require.NoError(t, err)
	h := commitment.Hash{9}
	sig, err := s.SignCommitmentV1(bg, h)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(s.PublicKey(), commitment.SignedMessage(commitment.VersionV1, h), sig))
	require.NoError(t, s.Close())
	_, err = s.SignCommitmentV1(bg, h)
	require.ErrorIs(t, err, sdk.ErrSignerClosed)
}
