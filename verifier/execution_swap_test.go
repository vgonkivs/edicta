package verifier_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// swapReader answers every Decision read after the first with another action,
// the way an archive that lies on the second read would.
type swapReader struct {
	verifier.Reader
	reads int
}

func (s *swapReader) Decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	d, err := s.Reader.Decision(ctx, h)
	if err != nil {
		return d, err
	}
	s.reads++
	if s.reads >= 2 {
		c := *d
		c.Action = []byte("a different action the gate never authorized")
		return &c, nil
	}
	return d, nil
}

func TestExecutionUsesTheActionTheCheckMatched(t *testing.T) {
	p := newParts(t)
	e := newExecRig(t, p, nil)
	sw := &swapReader{Reader: e.rig.store}
	e.rig.deps.Archive = sw
	rep := e.run(t)

	require.Len(t, e.chk.calls, 1)
	assert.Equal(t, p.action, e.chk.calls[0].Action, "the checker gets the bytes the action check matched")
	assert.Equal(t, 1, sw.reads, "the decision record is read once")
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
}
