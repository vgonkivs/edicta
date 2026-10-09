package verifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

// newV1Parts is newParts with a v1 commitment and its strict Authorization v1.
func newV1Parts(t *testing.T) *parts {
	p := newParts(t)
	c := gatefix.Clone(p.c)
	c.Version = commitment.VersionV1
	p.c = c
	p.env, p.hash = gatefix.Sign(t, "agent1", c)
	p.auth = signAuth(t, gateKey(t), p.hash, c, commitment.PathDA, authExpires)
	return p
}

func TestVerifyV1StrictDecision(t *testing.T) {
	rep := newRig(t, newV1Parts(t)).verify(t)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	require.NotNil(t, rep.Authorization)
	assert.EqualValues(t, commitment.VersionV1, rep.Authorization.Version)
	assert.EqualValues(t, commitment.ModeStrict, rep.Authorization.Mode)
}

func TestVerifyV1AuthorizationContradictions(t *testing.T) {
	base := func(p *parts) commitment.Authorization {
		return commitment.Authorization{Version: 1, CommitmentHash: p.hash[:], ActionHash: p.c.Action.Hash,
			GateID: gatefix.GateID, Expires: authExpires, Path: commitment.PathDA, Mode: commitment.ModeStrict}
	}
	for _, tc := range []struct {
		name string
		mod  func(p *parts, a *commitment.Authorization)
	}{
		{"version differs from the decision", func(_ *parts, a *commitment.Authorization) { a.Version, a.Mode = 0, 0 }},
		// The other direction (fast for an included reference) cannot be
		// archived until the record carries the fast window.
		{"strict mode for a pending reference", func(p *parts, a *commitment.Authorization) {
			c := gatefix.Clone(p.c)
			c.PayloadRef.Anchor = commitment.AnchorPending
			p.c = c
			p.env, p.hash = gatefix.Sign(t, "agent1", c)
			a.CommitmentHash = p.hash[:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newV1Parts(t)
			a := base(p)
			tc.mod(p, &a)
			p.auth = signAuthorization(t, gateKey(t), a)
			rep := newRig(t, p).verify(t)
			failed(t, rep, verifier.CheckAuthorization)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict, "a gate-signed contradiction with the signed decision")
		})
	}
}

func TestVerifyV0DecisionWithV1AuthorizationFails(t *testing.T) {
	p := newParts(t)
	p.auth = signAuthorization(t, gateKey(t), commitment.Authorization{Version: 1, CommitmentHash: p.hash[:],
		ActionHash: p.c.Action.Hash, GateID: gatefix.GateID, Expires: authExpires, Path: commitment.PathDA,
		Mode: commitment.ModeStrict})
	rep := newRig(t, p).verify(t)
	failed(t, rep, verifier.CheckAuthorization)
}
