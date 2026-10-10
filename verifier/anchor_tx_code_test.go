package verifier_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// An included da = 1 reference whose PFF ran with a nonzero code: format 1
// archives only code 0, so its evidence never reaches the archive and the
// decision is unchecked, never invalid.
func TestIncludedAnchorWithNonzeroTxCodeIsNeverInvalid(t *testing.T) {
	p := newFibreParts(t)
	r := newRig(t, p)

	bad := *p.ev
	bad.TxCode = 1
	_, err := r.store.Put(context.Background(), &bad)
	require.ErrorIs(t, err, commitment.ErrIntRange, "the archive refuses a nonzero anchor tx code")

	r.deps.Archive = noEvidence{r.store}
	rep := r.verify(t)
	unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonEvidenceUnavailable)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	assert.Empty(t, rep.AnchorTxResult)
}

// A pending da = 2 reference whose PFB ran with a nonzero code: the blob is
// in the square, the absence proofs read no code and show it present, and
// without archived evidence the decision is unchecked, never invalid.
func TestPendingBlobWithFailedPFBIsNeverInvalid(t *testing.T) {
	r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{})
	withoutEvidence(r)
	h := r.p.c.PayloadRef.Height + 1
	fp.window = verifier.AbsenceWindow{Result: verifier.AbsencePresent, AnchorHeight: h}
	rep := r.verify(t)
	unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonEvidenceUnavailable)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	assert.Equal(t, h, rep.Fast.AnchorHeight)
	assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
}
