package policy_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

// The public-mode marker is the specific deny name; ErrDenied names only the
// private-mode marker, so ReasonOf must never produce it.
func TestReasonOfNeverReturnsErrDenied(t *testing.T) {
	require.Len(t, policy.DenyReasons, 13)
	for _, name := range policy.DenyReasons {
		sentinel, ok := policy.DenySentinel(name)
		require.True(t, ok, name)
		require.ErrorIs(t, sentinel, policy.ErrDenied)
		for _, err := range []error{sentinel, fmt.Errorf("stage 4p: %w", sentinel)} {
			got := policy.ReasonOf(err)
			assert.Equal(t, name, got)
			assert.NotEqual(t, "ErrDenied", got)
		}
	}
	assert.Empty(t, policy.ReasonOf(policy.ErrDenied), "the bare umbrella is not a reason")
	assert.Equal(t, "ErrHistoryFull", policy.ReasonOf(&policy.HistoryFullError{Cause: "seq"}))
}
