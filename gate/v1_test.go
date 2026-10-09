package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func v1Template(t *testing.T) *commitment.Commitment {
	c := gatefix.Template(t)
	c.Version = commitment.VersionV1
	return c
}

func TestV1IncludedReferenceGetsStrictAuthorizationV1(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(func(c *gate.Config) { c.AcceptV0 = false }))
	c := v1Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	sa := gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
	assert.EqualValues(t, commitment.VersionV1, sa.Authorization.Version)
	assert.EqualValues(t, commitment.ModeStrict, sa.Authorization.Mode)
	assert.Zero(t, sa.Authorization.AnchorDeadline)

	_, _, err = commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
		GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: c.Action.Type,
		Action: gatefix.Action(t), Now: gatefix.Now, SkewS: 30, AcceptVersions: []uint64{0},
	})
	require.ErrorIs(t, err, commitment.ErrUnsupportedVersion, "an executor that accepts only v0")

	again, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, res.Authorization, again.Authorization, "the stored v1 Authorization verifies on retry")
}

func TestV0RefusedWhenAcceptV0IsOff(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(func(c *gate.Config) { c.AcceptV0 = false }))
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrVersionNotAccepted)
	e.RequireUntouched(c)
}

func TestV0AcceptedByDefault(t *testing.T) {
	assert.True(t, gate.DefaultConfig().AcceptV0, "until the v1 freeze")
	e, c, b, h := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
}

func TestPendingReferenceRefusedWithoutFastMode(t *testing.T) {
	e := gatefix.New(t)
	c := v1Template(t)
	c.PayloadRef.Anchor = commitment.AnchorPending
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrAnchorPending)
	e.RequireUntouched(c)
}

func TestMandateGateRefusesV0WhateverAcceptV0(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t), gatefix.WithConfig(func(c *gate.Config) { c.AcceptV0 = true }))
	c := gatefix.Clone(p.base)
	c.Version, c.MandateRef = commitment.VersionV0, nil
	c = gatefix.WithAction(t, gatefix.Fresh(c, 1), gatefix.ActionType, gatefix.OtherAction(t, 10))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := p.AuthorizeWith(b, gatefix.OtherAction(t, 10))
	require.ErrorIs(t, err, gate.ErrVersionNotAccepted)
	p.RequireUntouched(c)
}

func TestMandateRefStage(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  func(good []byte) []byte
		want error
	}{
		{"missing", func([]byte) []byte { return nil }, gate.ErrMandateRefMissing},
		{"other mandate", func(good []byte) []byte {
			r := append([]byte(nil), good...)
			r[31] ^= 1
			return r
		}, gate.ErrMandateMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := &recordingArchiver{}
			p := newPolicyEnv(t, baseMandate(t), gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
			p.base.MandateRef = tc.ref(p.base.MandateRef)
			// An amount the mandate would deny: the reference stage runs first.
			c, b, a := p.request(1, "agent1", 70)
			res, err := p.AuthorizeWith(b, a)
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, policy.ErrAmountAboveMax)
			assert.Empty(t, res.PolicyVerdict, "no verdict is signed for a mandate the agent did not name")
			assert.True(t, res.DecisionArchived)
			assert.Equal(t, 1, arch.n)
			p.RequireUntouched(c)
		})
	}
}
