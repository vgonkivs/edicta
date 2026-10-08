package verifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/verifier"
)

func TestVerifyWithoutPolicyRecordsHasNoPolicyCheck(t *testing.T) {
	rep := newRig(t, newParts(t)).verify(t)
	_, ok := rep.Check(verifier.CheckPolicy)
	assert.False(t, ok)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.Equal(t, verifier.IntegrityNotChecked, rep.GateIntegrity.Status)
}

func TestRequirePolicyWithoutAllowRecordIsUnchecked(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Config.RequirePolicy = true
	rep := r.verify(t)
	c, ok := rep.Check(verifier.CheckPolicy)
	require.True(t, ok)
	assert.Equal(t, verifier.StatusUnchecked, c.Status)
	assert.Equal(t, verifier.ReasonPolicyVerdictUnavailable, c.Reason)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}

func TestConfigRejectsBadPolicyInputs(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Config.MaxWalkSteps = -1
	_, err := verifier.New(r.deps)
	require.ErrorIs(t, err, verifier.ErrInvalidConfig)

	r = newRig(t, newParts(t))
	r.deps.Config.PrincipalKeys = r.deps.Config.GateKeys
	_, err = verifier.New(r.deps)
	require.ErrorIs(t, err, verifier.ErrInvalidConfig)
}
