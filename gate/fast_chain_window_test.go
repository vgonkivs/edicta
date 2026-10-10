package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// For a pending da = 1 reference the gate enforces the x/fibre height window
// itself at authorization: the deadline never exceeds h0 + the chain's
// window, and a PFF already included beyond it is refused even when the
// gate's and the mandate's windows would allow it.
func TestFastFibreChainWindowBoundsTheAnchor(t *testing.T) {
	const chain = 7
	t.Run("deadline", func(t *testing.T) {
		f := newFastEnv(t, commitment.DAFibre, fastMandate(t, fastDelay))
		f.facts.ChainWindow = chain
		f.stage()
		res, err := f.authorize()
		f.requireFast(res, err, f.h0+chain)
	})
	t.Run("included past the chain window", func(t *testing.T) {
		f := newFastEnv(t, commitment.DAFibre, fastMandate(t, fastDelay))
		f.facts.ChainWindow = chain
		f.stage()
		f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + chain + 1})
		res, err := f.authorize()
		require.ErrorIs(t, err, gate.ErrAnchorWindowClosed)
		assert.Empty(t, res.Authorization)
		f.RequireUntouched(f.c)
	})
}
