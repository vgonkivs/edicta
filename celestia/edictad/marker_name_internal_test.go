package edictad

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

// A public-mode deny is marked under its own name, never under ErrDenied,
// which names the private-mode marker.
func TestPublicDenyMarkerIsTheSpecificName(t *testing.T) {
	for _, name := range policy.DenyReasons {
		sentinel, ok := policy.DenySentinel(name)
		require.True(t, ok, name)
		got, marked := markerName(fmt.Errorf("gate: %w", sentinel))
		require.True(t, marked, name)
		assert.Equal(t, name, got)
		assert.NotEqual(t, "ErrDenied", got)
	}
	got, _ := markerName(policy.ErrDenied)
	assert.NotEqual(t, "ErrDenied", got, "a bare ErrDenied is never written as a public marker")
}

// Refusals that write nothing at all leave no marker either.
func TestNoMarkerForRefusalsThatWriteNothing(t *testing.T) {
	for _, err := range []error{gate.ErrMandateMismatch, gate.ErrAnchorPending, gate.ErrArchiveUnavailable} {
		_, marked := markerName(fmt.Errorf("x: %w", err))
		assert.False(t, marked, err.Error())
	}
}
