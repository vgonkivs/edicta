package verifier

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

// An archive that reads no policy records cannot show a policy allow, so a
// verifier told to require one must not pass.
func TestRequirePolicyWithAnArchiveThatReadsNoPolicyRecords(t *testing.T) {
	d := loadVec(t)
	c := d.Cases[0]
	v, _ := c.verifier(t, d)
	v.archive = struct{ Reader }{}

	out, err := v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	assert.False(t, out.Ran, "not required: no check, as before")

	v.cfg.RequirePolicy = true
	out, err = v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	require.True(t, out.Ran)
	assert.Equal(t, StatusUnchecked, out.Check.Status)
	assert.Equal(t, ReasonPolicyVerdictUnavailable, out.Check.Reason)
	rep := verdictOf(v, out)
	assert.Equal(t, VerdictUnchecked, rep.Verdict)
	assert.Equal(t, "2", exitFor(rep))
}

// Withholding a record is a source problem. It is never a failed check and
// never a gate fault, and the verdict is never valid when the record decides
// the outcome.
func TestRequirePolicyWithheldRecords(t *testing.T) {
	d := loadVec(t)
	n, decisive := 0, 0
	for _, c := range d.Cases {
		if c.Expect.Policy.Status != "pass" || !strings.HasPrefix(c.ID, "pass_") {
			continue
		}
		for _, drop := range c.Archive {
			raw := unhex(t, d.Records[drop])
			rec, err := archive.Decode(raw)
			require.NoError(t, err)
			kind := rec.Kind()
			t.Run(c.ID+"/without "+kind.String(), func(t *testing.T) {
				cc := c
				cc.Config.RequirePolicy = true
				cc.Archive = nil
				for _, p := range c.Archive {
					if p != drop {
						cc.Archive = append(cc.Archive, p)
					}
				}
				v, _ := cc.verifier(t, d)
				out, err := v.checkPolicy(t.Context(), cc.input(t, d))
				require.NoError(t, err)
				require.True(t, out.Ran)
				rep := verdictOf(v, out)
				assert.NotEqual(t, VerdictInvalid, rep.Verdict, "%v", out.Check.Err)
				assert.NotEqual(t, IntegrityViolated, out.Integrity.Status)
				assert.NotEqual(t, "5", exitFor(rep))
				if kind == archive.KindMandate || (kind == archive.KindPolicyAllow && strings.Contains(drop, c.Decision.CommitmentHash)) {
					decisive++
					assert.Equal(t, StatusUnchecked, out.Check.Status)
					assert.Equal(t, VerdictUnchecked, rep.Verdict)
				}
			})
			n++
		}
	}
	require.NotZero(t, n)
	require.NotZero(t, decisive, "the decisive records were dropped and checked")
}
