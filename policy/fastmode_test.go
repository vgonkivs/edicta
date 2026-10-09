package policy_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func TestAdmitFastModeConsent(t *testing.T) {
	m, agent := testMandate(t)
	x, err := policy.NewExtractors(fakeX{id: "t/ok/v1", typ: "a", fn: func([]byte) (policy.Facts, error) {
		return policy.Facts{Kind: "transfer", Asset: "x:a", Amount: []byte{5}}, nil
	}})
	require.NoError(t, err)
	d := policy.Decision{AgentPubKey: agent.Public().(ed25519.PublicKey), ActionType: "a", ValidUntil: 100, Pending: true}

	m.FastModeMaxDelay = 0
	adm, err := policy.Admit(m, x, d)
	require.ErrorIs(t, err, policy.ErrFastModeNotAllowed)
	require.ErrorIs(t, err, policy.ErrDenied)
	assert.Empty(t, adm.ExtractorID, "the consent rule runs before the extractor")
	assert.Equal(t, "ErrFastModeNotAllowed", policy.ReasonOf(err))

	// The agent rule comes first.
	other := d
	other.AgentPubKey = make([]byte, 32)
	_, err = policy.Admit(m, x, other)
	require.ErrorIs(t, err, policy.ErrAgentNotCovered)

	m.FastModeMaxDelay = 10
	_, err = policy.Admit(m, x, d)
	require.NoError(t, err)

	m.FastModeMaxDelay = 0
	d.Pending = false
	_, err = policy.Admit(m, x, d)
	require.NoError(t, err, "an included reference needs no consent")
}

func TestDenyReasonsListFastModeAfterAgent(t *testing.T) {
	require.GreaterOrEqual(t, len(policy.DenyReasons), 2)
	assert.Equal(t, []string{"ErrAgentNotCovered", "ErrFastModeNotAllowed"}, policy.DenyReasons[:2])
	s, ok := policy.DenySentinel("ErrFastModeNotAllowed")
	require.True(t, ok)
	assert.Equal(t, policy.ErrFastModeNotAllowed, s)
}
