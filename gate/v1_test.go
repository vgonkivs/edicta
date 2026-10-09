package gate_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestIncludedReferenceGetsStrictAuthorization(t *testing.T) {
	e, c, b, h := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	sa := gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
	assert.EqualValues(t, commitment.Version, sa.Authorization.Version)
	assert.EqualValues(t, commitment.ModeStrict, sa.Authorization.Mode)
	assert.Zero(t, sa.Authorization.AnchorDeadline)

	ent, err := e.Entry(c)
	require.NoError(t, err)
	assert.Equal(t, gatefix.Salt(t), ent.ActionSalt, "the nonce entry keeps the salt for the reveal")

	again, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, res.Authorization, again.Authorization, "the stored Authorization verifies on retry")
}

func TestVersionZeroIsUnsupported(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.Template(t)
	c.Version = 0
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, commitment.ErrUnsupportedVersion)
	e.RequireUntouched(c)
}

func TestPendingReferenceRefusedWithoutFastMode(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.Template(t)
	c.PayloadRef.Anchor = commitment.AnchorPending
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrAnchorPending)
	e.RequireUntouched(c)
}

// The salt is checked at stage A, after the signature and the allowlist and
// before anything is archived or read from the registry.
func TestActionSaltStage(t *testing.T) {
	flipped := bytes.Clone(gatefix.Salt(t))
	flipped[0] ^= 1
	for _, tc := range []struct {
		name string
		salt []byte
		want error
	}{
		{"missing", nil, commitment.ErrMissingField},
		{"empty", []byte{}, commitment.ErrMissingField},
		{"31 bytes", gatefix.Salt(t)[:31], commitment.ErrFieldSize},
		{"33 bytes", append(bytes.Clone(gatefix.Salt(t)), 0), commitment.ErrFieldSize},
		{"wrong", flipped, commitment.ErrActionMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := &recordingArchiver{}
			e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			res, err := e.AuthorizeWithSalt(b, gatefix.Action(t), tc.salt)
			require.ErrorIs(t, err, tc.want)
			assert.Empty(t, res.Authorization)
			assert.Zero(t, arch.n, "nothing is archived before stage A passes")
			e.RequireUntouched(c)
		})
	}
}

// M0: a gate without a mandate refuses a commitment that names one, and
// writes nothing.
func TestMandateRefWithoutMandate(t *testing.T) {
	arch := &recordingArchiver{}
	e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
	c := gatefix.Template(t)
	c.MandateRef = bytes.Repeat([]byte{7}, 32)
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrMandateMismatch)
	assert.Empty(t, res.Authorization)
	assert.False(t, res.DecisionArchived)
	assert.Zero(t, arch.n, "no decision record after an M0 refusal")
	e.RequireUntouched(c)
}

func TestMandateRefStage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ref      func(good []byte) []byte
		want     error
		archived bool
	}{
		{"missing", func([]byte) []byte { return nil }, gate.ErrMandateRefMissing, true},
		{"other mandate", func(good []byte) []byte {
			r := append([]byte(nil), good...)
			r[31] ^= 1
			return r
		}, gate.ErrMandateMismatch, false},
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
			assert.Equal(t, tc.archived, res.DecisionArchived)
			if tc.archived {
				assert.Equal(t, 1, arch.n)
			} else {
				assert.Zero(t, arch.n, "a decision naming another mandate is never archived")
			}
			p.RequireUntouched(c)
		})
	}
}
