package gate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// A commitment without a mandate reference at a mandate gate gets its
// decision record before the refusal. When that write fails, nothing is
// signed yet, so the answer is the archive fault and the unchanged retry
// meets the refusal once the archive is back.
func TestMandateRefMissingArchiveFault(t *testing.T) {
	arch := &recordingArchiver{fail: errors.New("archive down")}
	p := newPolicyEnv(t, baseMandate(t), gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
	p.base.MandateRef = nil
	c, b, a := p.request(1, "agent1", 10)

	res, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
	assert.NotErrorIs(t, err, gate.ErrMandateRefMissing, "an operational failure is not a verdict")
	assert.False(t, res.DecisionArchived)
	assert.Empty(t, res.Authorization)
	assert.Empty(t, res.PolicyVerdict)
	p.RequireUntouched(c)

	arch.mu.Lock()
	arch.fail = nil
	arch.mu.Unlock()
	res, err = p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrMandateRefMissing)
	assert.True(t, res.DecisionArchived)
	p.RequireUntouched(c)
}
