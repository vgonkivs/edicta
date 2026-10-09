package verifier

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The mandate_ref cases of the policy verify vectors: the allow records are
// signed by the vectors' gate key, so a mismatch is a finding from signed data.
func TestMandateRefVectors(t *testing.T) {
	d := loadVec(t)
	n := 0
	for _, c := range d.Cases {
		if !strings.HasPrefix(c.ID, "mandate_ref_") {
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) {
			v, _ := c.verifier(t, d)
			out, err := v.checkPolicy(t.Context(), c.input(t, d))
			require.NoError(t, err)
			require.True(t, out.Ran)
			assert.Equal(t, Status(c.Expect.Policy.Status), out.Check.Status, "%v", out.Check.Err)
			if out.Check.Status == StatusFail {
				var pf *PolicyFailure
				require.ErrorAs(t, out.Check.Err, &pf)
				assert.Equal(t, c.Expect.Policy.Rule, pf.Rule)
			}
			if want := c.Expect.Policy.MandateRef; want != "" {
				require.NotNil(t, out.Info)
				assert.Equal(t, MandateRefStatus(want), out.Info.MandateRef)
			}
			rep := verdictOf(v, out)
			assert.Equal(t, Verdict(c.Expect.Verdict), rep.Verdict)
			assert.Equal(t, c.Expect.Exit, exitFor(rep))
		})
	}
	assert.Equal(t, 3, n)
}

func TestFastModeAuthorizationRequiresPolicy(t *testing.T) {
	d := loadVec(t)
	for _, c := range d.Cases {
		if c.ID != "mandate_ref_match" {
			continue
		}
		c.Archive = nil
		v, _ := c.verifier(t, d)
		in := c.input(t, d)
		out, err := v.checkPolicy(t.Context(), in)
		require.NoError(t, err)
		assert.False(t, out.Ran, "no allow record and policy not required: no check")

		in.RequirePolicy = true
		out, err = v.checkPolicy(t.Context(), in)
		require.NoError(t, err)
		require.True(t, out.Ran)
		assert.Equal(t, StatusUnchecked, out.Check.Status)
		assert.Equal(t, ReasonPolicyVerdictUnavailable, out.Check.Reason)
		return
	}
	require.FailNow(t, "no mandate_ref_match case")
}
