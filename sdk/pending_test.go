package sdk_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// pendingFake answers VerifyPending with t or err and records the calls.
type pendingFake struct {
	mu          sync.Mutex
	t           uint64
	err         error
	refs        []commitment.PayloadRef
	sizes       []uint64
	independent bool
}

func (p *pendingFake) VerifyPending(_ context.Context, ref commitment.PayloadRef, size uint64) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refs = append(p.refs, ref)
	p.sizes = append(p.sizes, size)
	return p.t, p.err
}

func (p *pendingFake) Independent() bool { return p.independent }

// pendingPub is a publish result turned into a pending reference at the same
// height and time.
func pendingPub(t *testing.T, b *sdk.Builder, s *sdk.Sealed) sdk.Published {
	t.Helper()
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	pub.Ref.Anchor = commitment.AnchorPending
	return pub
}

func TestFinalizeSignsAPendingReferenceAfterTheIntentCheck(t *testing.T) {
	r := newRig(t)
	pv := &pendingFake{}
	r.deps.Pending = pv
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub := pendingPub(t, b, s)
	pv.t = pub.BlockTime

	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)
	assert.True(t, res.Commitment.PayloadRef.Pending(), "the signed reference stays pending")
	assert.Equal(t, pub.Ref.Height, res.Commitment.PayloadRef.Height, "h0 is signed as given")
	require.Len(t, pv.refs, 1)
	assert.True(t, pv.refs[0].Pending())
	assert.Equal(t, uint64(len(res.Blob)), pv.sizes[0])
	assert.Equal(t, 1, r.signer.calls())
	requireValidAtGate(t, res, now)
}

func TestFinalizeRefusesAPendingReferenceTheVerifierRefuses(t *testing.T) {
	r := newRig(t)
	pv := &pendingFake{err: errors.New("certificate below quorum")}
	r.deps.Pending = pv
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	_, err = b.Finalize(bg, s, pendingPub(t, b, s))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.Zero(t, r.signer.calls())
}

func TestFinalizeRefusesAPendingReferenceWithAnotherRefTime(t *testing.T) {
	r := newRig(t)
	pv := &pendingFake{}
	r.deps.Pending = pv
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub := pendingPub(t, b, s)
	pv.t = pub.BlockTime - 1
	_, err = b.Finalize(bg, s, pub)
	require.ErrorIs(t, err, sdk.ErrBlockTimeMismatch)
	assert.Zero(t, r.signer.calls())
}

func TestFinalizeRefusesAnUnknownAnchorValue(t *testing.T) {
	r := newRig(t)
	r.deps.Pending = &pendingFake{}
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	pub.Ref.Anchor = 3
	_, err = b.Finalize(bg, s, pub)
	require.ErrorIs(t, err, sdk.ErrPublishResult)
}

func TestUntrustedSubmitterNeedsAnIndependentPendingVerifier(t *testing.T) {
	r := newRig(t)
	r.cfg.SubmitterTrust = sdk.SubmitterUntrusted
	r.deps.Inclusion = independentInclusion{}
	r.deps.Pending = &pendingFake{}
	_, err := r.tryNew()
	require.ErrorIs(t, err, sdk.ErrInvalidConfig)
	r.deps.Pending = &pendingFake{independent: true}
	_, err = r.tryNew()
	require.NoError(t, err)
}

type independentInclusion struct{}

func (independentInclusion) VerifyInclusion(context.Context, commitment.PayloadRef) (uint64, error) {
	return 0, errors.New("unused")
}
func (independentInclusion) Independent() bool { return true }

type panickingPending struct{ inVerify, inIndependent bool }

func (p panickingPending) VerifyPending(context.Context, commitment.PayloadRef, uint64) (uint64, error) {
	if p.inVerify {
		panic("verifier bug")
	}
	return 0, nil
}

func (p panickingPending) Independent() bool {
	if p.inIndependent {
		panic("reporter bug")
	}
	return true
}

func TestFinalizeRefusesAPendingReferenceWhenTheVerifierPanics(t *testing.T) {
	r := newRig(t)
	r.deps.Pending = panickingPending{inVerify: true}
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	_, err = b.Finalize(bg, s, pendingPub(t, b, s))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.Zero(t, r.signer.calls())
}

func TestPendingVerifierIndependenceIsRequiredOnlyForAnUntrustedSubmitter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trust   sdk.SubmitterTrust
		pending sdk.PendingVerifier
		ok      bool
	}{
		{"same operator, not independent", sdk.SubmitterSameOperator, &pendingFake{}, true},
		{"untrusted, no Independent method", sdk.SubmitterUntrusted, bareVerifier{}, false},
		{"untrusted, Independent panics", sdk.SubmitterUntrusted, panickingPending{inIndependent: true}, false},
		{"untrusted, independent", sdk.SubmitterUntrusted, &pendingFake{independent: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.cfg.SubmitterTrust = tc.trust
			if tc.trust == sdk.SubmitterUntrusted {
				r.deps.Inclusion = independentInclusion{}
			}
			r.deps.Pending = tc.pending
			_, err := r.tryNew()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, sdk.ErrInvalidConfig)
		})
	}
}

// An untrusted submitter with an independent inclusion verifier but no
// pending verifier still never gets a pending reference signed.
func TestUntrustedSubmitterWithoutAPendingVerifierRefusesAPendingReference(t *testing.T) {
	r := newRig(t)
	r.cfg.SubmitterTrust = sdk.SubmitterUntrusted
	r.deps.Inclusion = independentInclusion{}
	b, err := r.tryNew()
	require.NoError(t, err)
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	pub.Ref.Anchor = commitment.AnchorPending
	_, err = b.Finalize(bg, s, pub)
	require.ErrorIs(t, err, sdk.ErrPublishResult)
	assert.Zero(t, r.signer.calls())
}

type bareVerifier struct{}

func (bareVerifier) VerifyPending(context.Context, commitment.PayloadRef, uint64) (uint64, error) {
	return 0, nil
}
