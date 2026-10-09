package verifier_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

func TestVerifyStrictDecision(t *testing.T) {
	rep := newRig(t, newParts(t)).verify(t)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	require.NotNil(t, rep.Authorization)
	assert.EqualValues(t, commitment.Version, rep.Authorization.Version)
	assert.EqualValues(t, commitment.ModeStrict, rep.Authorization.Mode)
	assert.Equal(t, verifier.ActionSourceDecisionRecord, rep.ActionSource)
}

func TestVerifyAuthorizationContradictions(t *testing.T) {
	base := func(p *parts) commitment.Authorization {
		return commitment.Authorization{Version: 1, CommitmentHash: p.hash[:], ActionHash: p.c.Action.Hash,
			GateID: gatefix.GateID, Expires: authExpires, Path: commitment.PathDA, Mode: commitment.ModeStrict}
	}
	for _, tc := range []struct {
		name string
		mod  func(p *parts, a *commitment.Authorization)
	}{
		{"strict mode for a pending reference", func(p *parts, a *commitment.Authorization) {
			c := gatefix.Clone(p.c)
			c.PayloadRef.Anchor = commitment.AnchorPending
			p.c = c
			p.env, p.hash = gatefix.Sign(t, "agent1", c)
			a.CommitmentHash = p.hash[:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			a := base(p)
			tc.mod(p, &a)
			p.auth = signAuthorization(t, gateKey(t), a)
			rep := newRig(t, p).verify(t)
			failed(t, rep, verifier.CheckAuthorization)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict, "a gate-signed contradiction with the signed decision")
		})
	}
}

// A decision whose agent signed mandate_ref needs the policy check even when
// the auditor did not ask for it: an Authorization from a gate that skipped
// the mandate is never valid without an allow verdict.
func TestMandateRefMakesPolicyRequired(t *testing.T) {
	p := newParts(t)
	c := gatefix.Clone(p.c)
	c.MandateRef = bytes.Repeat([]byte{7}, 32)
	p.c = c
	p.env, p.hash = gatefix.Sign(t, "agent1", c)
	p.auth = signAuth(t, gateKey(t), p.hash, c, commitment.PathDA, authExpires)
	rep := newRig(t, p).verify(t)
	unchecked(t, rep, verifier.CheckPolicy, verifier.ReasonPolicyVerdictUnavailable)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}

// A public decision record whose salt does not hash to the committed action
// is a bad copy: unchecked, never a fail.
func TestDecisionRecordWithWrongSalt(t *testing.T) {
	p := newParts(t)
	p.salt = bytes.Clone(p.salt)
	p.salt[0] ^= 1
	rep := newRig(t, p).verify(t)
	unchecked(t, rep, verifier.CheckAction, verifier.ReasonSourceCorrupt)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}
