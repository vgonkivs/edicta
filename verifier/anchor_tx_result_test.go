package verifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

// The anchor tx result is reported for every da = 1 decision whose anchor
// proof verified, in both modes, and never for da = 2. It is informational:
// the fast-mode assumptions never mention it.
func TestAnchorTxResultIsInformational(t *testing.T) {
	t.Run("fibre, strict", func(t *testing.T) {
		rep := newRig(t, newFibreParts(t)).verify(t)
		require.Equal(t, verifier.VerdictValid, rep.Verdict)
		assert.Equal(t, verifier.AnchorTxResultText, rep.AnchorTxResult)
		assert.Equal(t, "code 0, node-reported, not part of the claim", rep.AnchorTxResult)
	})
	t.Run("fibre, fast", func(t *testing.T) {
		rep := newRig(t, pendingParts(t, newFibreParts(t))).verify(t)
		passed(t, rep, verifier.CheckAnchor)
		assert.Equal(t, verifier.AnchorTxResultText, rep.AnchorTxResult)
	})
	t.Run("blob, strict", func(t *testing.T) {
		rep := newRig(t, newParts(t)).verify(t)
		require.Equal(t, verifier.VerdictValid, rep.Verdict)
		assert.Empty(t, rep.AnchorTxResult)
	})
	t.Run("fibre, anchor proof does not verify", func(t *testing.T) {
		r := newRig(t, newFibreParts(t))
		r.anchor.settlement = ""
		rep := r.verify(t)
		assert.Empty(t, rep.AnchorTxResult)
	})
	t.Run("assumptions", func(t *testing.T) {
		require.Len(t, verifier.FastAssumptions, 4)
		assert.Equal(t, "Proven: payload bytes match the commitment; anchored on L1 no later than T_H (anchor inclusion proven); policy evaluated on T_ref (header h0).",
			verifier.FastAssumptions[1])
		for _, a := range verifier.FastAssumptions {
			assert.NotContains(t, a, "anchor tx result")
			assert.NotContains(t, a, "node-attested")
		}
	})
}
