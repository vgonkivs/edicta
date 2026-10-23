package edictad

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/engine/gate"
)

func TestRecorderErrorRulesV11(t *testing.T) {
	first := map[string]bool{}
	for _, r := range recorderFirstErrors {
		first[r.Code] = true
	}
	require.True(t, first["recorder.ErrAnchorRejected"])
	require.ErrorIs(t, fmt.Errorf("x: %w: %w", recorder.ErrAnchorRejected, gate.ErrAnchorNotFound), gate.ErrAnchorNotFound)

	var skew bool
	for _, r := range recorderErrors {
		if r.Err == recorder.ErrClockSkew {
			skew = true
			require.Equal(t, 503, r.Status)
			require.True(t, r.Retryable)
		}
	}
	require.True(t, skew)
}
