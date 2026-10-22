package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An opened PrivatePart is known content even when its facts cannot be
// derived and the fast check ends there.
func TestOpenedPartWithUnderivableFactsIsNotContentPrivate(t *testing.T) {
	c, d := loadPrivCase(t, "private_part_allow_missing_facts")
	v, _ := privVerifier(t, c, d)
	in := c.input(t, d)
	in.Action = nil
	out, err := v.checkPolicy(t.Context(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Info)
	assert.Equal(t, ReasonPolicyPrivate, out.Check.Reason)
	assert.False(t, out.Info.ContentPrivate)
	assert.False(t, out.Info.NoSeq)
}

// An opened PrivatePart without prev_state has no seq; it is not genesis.
func TestOpenedPartWithoutPrevStateHasNoSeq(t *testing.T) {
	c, d := loadPrivCase(t, "private_part_allow_missing_prev_state")
	v, _ := privVerifier(t, c, d)
	out, err := v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	require.NotNil(t, out.Info)
	assert.False(t, out.Info.ContentPrivate)
	assert.True(t, out.Info.NoSeq)
}
