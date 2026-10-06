package verifier_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

func TestVerifyCompleteArchive(t *testing.T) {
	r := newRig(t, newParts(t))
	rep := r.verify(t)

	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.Equal(t, r.p.hash, rep.CommitmentHash)
	assert.Equal(t, archive.StateAuthorized, rep.State)
	assert.True(t, rep.Authorized)
	assert.Equal(t, commitment.DACelestiaBlob, rep.DA)
	assert.Equal(t, anchorHeight, rep.Height)
	assert.Equal(t, blockTime, rep.BlockTime)
	assert.Equal(t, gatefix.GateID, rep.GateID)
	assert.Equal(t, gatefix.ActionType, rep.ActionType)
	require.NotNil(t, rep.Authorization)
	assert.Equal(t, commitment.PathDA, rep.Authorization.Path)
	assert.Equal(t, authExpires, rep.Authorization.Expires)
	assert.Equal(t, authorizedAt, rep.Authorization.AuthorizedAt)
	assert.Nil(t, rep.Cert, "certificate fields exist for da = 1 only")
	assert.Nil(t, rep.Receipt)

	for _, n := range []verifier.CheckName{
		verifier.CheckEnvelope, verifier.CheckAction, verifier.CheckAuthorization,
		verifier.CheckPayload, verifier.CheckAnchor, verifier.CheckAnchorTime, verifier.CheckHeaderTrust,
	} {
		passed(t, rep, n)
	}

	h := sha256.Sum256(goodHeader())
	assert.Equal(t, verifier.TrustValid, rep.HeaderTrust.Status)
	assert.Equal(t, checkpointH, rep.HeaderTrust.CheckpointH)
	assert.Equal(t, r.trust.res.CheckpointHash, rep.HeaderTrust.CheckpointHash)
	assert.Equal(t, "pass", rep.HeaderTrust.CrossCheck)
	assert.Equal(t, []uint64{anchorHeight}, r.trust.asked)
	assert.Equal(t, h[:], rep.HeaderTrust.Hashes[anchorHeight])
}

func TestVerifyTamperedItems(t *testing.T) {
	flip := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[len(out)-1] ^= 1
		return out
	}
	tests := []struct {
		name  string
		tweak func(t *testing.T, p *parts, r *rigOpts)
		check verifier.CheckName
		want  error
		also  error
	}{
		{
			name: "payload byte",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.permissive = true
				p.blob = flip(p.blob)
			},
			check: verifier.CheckPayload, want: verifier.ErrPayloadInvalid, also: commitment.ErrPayloadHashMismatch,
		},
		{
			name: "payload with the right hash but another share commitment",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				// the signed commitment names a share commitment that the
				// real blob does not have; a damaged store holds the blob
				// under that key
				p.permissive = true
				c := gatefix.Clone(p.c)
				c.PayloadRef.Commitment[0] ^= 1
				p.c = c
				p.env, p.hash = gatefix.Sign(t, "agent1", c)
				p.auth = signAuth(t, gateKey(t), p.hash, c, commitment.PathDA, authExpires)
				p.payloadRef = c.PayloadRef.Commitment
				p.ev.Commitment = c.PayloadRef.Commitment
			},
			check: verifier.CheckPayload, want: verifier.ErrPayloadInvalid, also: gate.ErrDACommitmentMismatch,
		},
		{
			name: "envelope signature",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.env = flip(p.env)
			},
			check: verifier.CheckEnvelope, want: verifier.ErrEnvelopeInvalid, also: commitment.ErrSignatureInvalid,
		},
		{
			name: "action bytes",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.action = flip(p.action)
			},
			check: verifier.CheckAction, want: verifier.ErrActionInvalid, also: commitment.ErrActionMismatch,
		},
		{
			name: "authorization signature",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.auth = flip(p.auth)
			},
			check: verifier.CheckAuthorization, want: verifier.ErrGateKeyNotTrusted,
		},
		{
			name: "gate key not trusted",
			tweak: func(t *testing.T, p *parts, o *rigOpts) {
				other := gatefix.Key(t, "agent2").Public().(ed25519.PublicKey)
				o.gateKeys = []ed25519.PublicKey{other}
			},
			check: verifier.CheckAuthorization, want: verifier.ErrGateKeyNotTrusted,
		},
		{
			name: "authorization of another action",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				other := gatefix.Variant(t, p.c, 1)
				p.auth = signAuth(t, gateKey(t), p.hash, other, commitment.PathDA, authExpires)
			},
			check: verifier.CheckAuthorization, want: verifier.ErrAuthorizationInvalid,
		},
		{
			name: "authorization outlives the decision",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.auth = signAuth(t, gateKey(t), p.hash, p.c, commitment.PathDA, p.c.ValidUntil+1)
			},
			check: verifier.CheckAuthorization, want: verifier.ErrAuthorizationInvalid,
		},
		{
			name: "evidence header",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.ev.Header = []byte("garbage")
			},
			check: verifier.CheckAnchor, want: verifier.ErrAnchorInvalid, also: errFakeHeader,
		},
		{
			name: "blob proof",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.ev.BlobProof = flip(p.ev.BlobProof)
			},
			check: verifier.CheckAnchor, want: verifier.ErrAnchorInvalid, also: errFakeProof,
		},
		{
			name: "header and proof replaced together",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.ev.Header = []byte("hdr:forged")
				p.ev.BlobProof = proofFor(p.ev.Header)
			},
			check: verifier.CheckHeaderTrust, want: verifier.ErrHeaderTrust, also: errFakeTrust,
		},
		{
			name: "payload missing",
			tweak: func(t *testing.T, p *parts, _ *rigOpts) {
				p.blob = nil
			},
			check: verifier.CheckPayload, want: verifier.ErrArchiveIncomplete, also: archive.ErrNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			var o rigOpts
			tc.tweak(t, p, &o)
			r := newRig(t, p)
			if o.gateKeys != nil {
				r.deps.Config.GateKeys = o.gateKeys
			}
			rep := r.verify(t)

			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			c := failed(t, rep, tc.check)
			requireOnly(t, c.Err, tc.want)
			if tc.also != nil {
				require.ErrorIs(t, c.Err, tc.also)
			}
			assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
		})
	}
}

// rigOpts carries what a tweak changes outside the archive.
type rigOpts struct{ gateKeys []ed25519.PublicKey }

func TestVerifyBadAuthorizationIsNeverReportedAuthorized(t *testing.T) {
	p := newParts(t)
	p.auth[len(p.auth)-1] ^= 1
	rep := newRig(t, p).verify(t)
	assert.False(t, rep.Authorized)
	assert.Nil(t, rep.Authorization)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
}

func TestVerifyUnknownDecision(t *testing.T) {
	r := newRig(t, newParts(t))
	var h commitment.Hash
	h[0] = 1
	rep, err := r.verifier(t).Verify(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAbsent, rep.State)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	assert.False(t, rep.Authorized)
	c := failed(t, rep, verifier.CheckDecision)
	requireOnly(t, c.Err, verifier.ErrDecisionNotFound)
}

func TestVerifyPendingAndRejectedAreNotAuthorized(t *testing.T) {
	tests := []struct {
		name    string
		markers []string
		state   archive.State
	}{
		{"pending", nil, archive.StatePending},
		{"rejected", []string{"ErrExpired", "ErrNonceUsed"}, archive.StateRejected},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			p.auth, p.k2, p.markers = nil, nil, tc.markers
			r := newRig(t, p)
			rep := r.verify(t, verifier.WithReceipt(validReceipt(t, p)))

			assert.Equal(t, tc.state, rep.State)
			assert.Equal(t, verifier.VerdictNotAuthorized, rep.Verdict)
			assert.False(t, rep.Authorized)
			assert.Nil(t, rep.Authorization)
			assert.Nil(t, rep.Receipt, "no receipt of a decision that was not authorized")
			assert.Equal(t, tc.markers, rep.Rejections)
		})
	}
}

func TestVerifyRejectedDecisionWithForgedAuthorizationAfterMarkers(t *testing.T) {
	p := newParts(t)
	p.markers = []string{"ErrExpired"}
	p.auth[len(p.auth)-1] ^= 1
	rep := newRig(t, p).verify(t)
	assert.False(t, rep.Authorized)
	assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
}

func TestHeaderTrust(t *testing.T) {
	t.Run("nil trust is unchecked, never valid", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.deps.Trust = nil
		rep := r.verify(t)
		assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
		c, ok := rep.Check(verifier.CheckHeaderTrust)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.True(t, rep.Authorized, "the authorization itself is checked without header trust")
	})
	t.Run("trust that did not check is unchecked", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.trust.res = verifier.TrustResult{}
		rep := r.verify(t)
		assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	})
	t.Run("cross-check unavailable is reported and does not fail", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.trust.res.CrossCheck = "unavailable"
		rep := r.verify(t)
		assert.Equal(t, verifier.VerdictValid, rep.Verdict)
		assert.Equal(t, "unavailable", rep.HeaderTrust.CrossCheck)
		assert.NotEmpty(t, rep.Warnings)
	})
	t.Run("cross-check off", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.trust.res.CrossCheck = "off"
		rep := r.verify(t)
		assert.Equal(t, verifier.VerdictValid, rep.Verdict)
		assert.Equal(t, "off", rep.HeaderTrust.CrossCheck)
	})
	t.Run("cross-check mismatch fails", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.trust.res.CrossCheck = "mismatch"
		rep := r.verify(t)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		c := failed(t, rep, verifier.CheckHeaderTrust)
		requireOnly(t, c.Err, verifier.ErrHeaderTrust)
		assert.Equal(t, verifier.TrustFailed, rep.HeaderTrust.Status)
	})
	t.Run("trust error fails and is wrapped", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.trust.err = errFakeTrust
		rep := r.verify(t)
		c := failed(t, rep, verifier.CheckHeaderTrust)
		requireOnly(t, c.Err, verifier.ErrHeaderTrust)
		require.ErrorIs(t, c.Err, errFakeTrust)
		assert.Equal(t, verifier.TrustFailed, rep.HeaderTrust.Status)
	})
	t.Run("a failed anchor leaves trust unchecked", func(t *testing.T) {
		p := newParts(t)
		p.ev.Header = []byte("garbage")
		r := newRig(t, p)
		rep := r.verify(t)
		assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
		assert.NotEqual(t, verifier.TrustValid, rep.HeaderTrust.Status)
	})
}

func TestSettlementIsNeverCalledProven(t *testing.T) {
	t.Run("node-attested is passed through", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.anchor.settlement = "node-attested"
		assert.Equal(t, "node-attested", r.verify(t).Settlement)
	})
	t.Run("a stronger claim than v0 allows fails the anchor", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.anchor.settlement = "proven"
		rep := r.verify(t)
		c := failed(t, rep, verifier.CheckAnchor)
		requireOnly(t, c.Err, verifier.ErrAnchorInvalid)
		assert.NotEqual(t, "proven", rep.Settlement)
	})
}

func TestAnchorTimeRule(t *testing.T) {
	p := newParts(t)
	r := newRig(t, p)
	r.anchor.blockTime = p.c.IssuedAt + r.deps.Config.Params.SkewS + 1
	rep := r.verify(t)
	c := failed(t, rep, verifier.CheckAnchorTime)
	require.ErrorIs(t, c.Err, commitment.ErrIssuedBeforeAnchor)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)

	r.anchor.blockTime = p.c.IssuedAt + r.deps.Config.Params.SkewS
	passed(t, r.verify(t), verifier.CheckAnchorTime)
}

func TestNoAnchorVerifierForDA(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Anchors = map[commitment.DA]verifier.AnchorVerifier{commitment.DAFibre: r.anchor}
	rep := r.verify(t)
	c := failed(t, rep, verifier.CheckAnchor)
	requireOnly(t, c.Err, verifier.ErrAnchorUnsupported)
}

func TestVerifyIsDeterministicAndReadOnly(t *testing.T) {
	r := newRig(t, newParts(t))
	v := r.verifier(t)
	a, err := v.Verify(context.Background(), r.p.hash)
	require.NoError(t, err)
	b, err := v.Verify(context.Background(), r.p.hash)
	require.NoError(t, err)
	assert.Equal(t, a, b)
}

func TestVerifyHonoursCancelledContext(t *testing.T) {
	r := newRig(t, newParts(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.verifier(t).Verify(ctx, r.p.hash)
	require.ErrorIs(t, err, context.Canceled)
}
