package verifier_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
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
	r.deps.Config.PrincipalKeys = []policy.PrincipalID{{Principal: r.deps.Config.GateKeys[0]}}
	_, err = verifier.New(r.deps)
	require.ErrorIs(t, err, verifier.ErrInvalidConfig)

	for _, bad := range []policy.PrincipalID{
		{SigType: 2, Principal: []byte("celestia1notanaddress")},
		{SigType: 3, Principal: make([]byte, 21)},
		{SigType: 4, Principal: make([]byte, 20)},
	} {
		r = newRig(t, newParts(t))
		r.deps.Config.PrincipalKeys = []policy.PrincipalID{bad}
		_, err = verifier.New(r.deps)
		require.ErrorIs(t, err, verifier.ErrInvalidConfig)
	}
}

func TestConfigAcceptsTypedPrincipalPins(t *testing.T) {
	r := newRig(t, newParts(t))
	for _, s := range []string{"cosmos:celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7", "eth:0xda9588643fa4376845af5352ffba44f5e4b0e40f"} {
		id, err := policy.ParsePrincipal(s)
		require.NoError(t, err)
		r.deps.Config.PrincipalKeys = append(r.deps.Config.PrincipalKeys, id)
	}
	_, err := verifier.New(r.deps)
	require.NoError(t, err)
}
