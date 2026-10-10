package verifier

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrivateTwinsOfVerifyVectors replays every public case of
// spec/vectors/policy/verify.json with the mandate in private mode
// (test/privatetwin/twins.json, built by gen_twins.py from the reference
// scenario). With an auditor key the outcome must be exactly the public one;
// without it the verifier must not claim more than the public fields prove.
func TestPrivateTwinsOfVerifyVectors(t *testing.T) {
	pub := map[string]vecCase{}
	for _, c := range loadVec(t).Cases {
		pub[c.ID] = c
	}
	raw, err := os.ReadFile("../test/privatetwin/twins.json")
	require.NoError(t, err)
	var d privDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Len(t, d.Cases, len(pub), "one twin per public case")

	for _, rc := range d.Cases {
		withKey := parsePrivCase(t, rc)
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rc, &fields))
		fields["expect"] = fields["expect_without_key"]
		var cfg map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(fields["config"], &cfg))
		delete(cfg, "auditor_keys")
		fields["config"], err = json.Marshal(cfg)
		require.NoError(t, err)
		keylessRaw, err := json.Marshal(fields)
		require.NoError(t, err)
		keyless := parsePrivCase(t, keylessRaw)
		require.Empty(t, keyless.Config.AuditorKeys)
		require.NotEmpty(t, withKey.Config.AuditorKeys)

		p, ok := pub[withKey.ID]
		require.True(t, ok, "%s has no public case", withKey.ID)

		t.Run(withKey.ID+"/with_key", func(t *testing.T) {
			// The twin's reference expectation, then the public one.
			out := runPrivCase(t, withKey, d.vecDoc)
			assert.Equal(t, p.Expect.Policy.Status, withKey.vecCase.Expect.Policy.Status)
			assert.Equal(t, Status(p.Expect.Policy.Status), out.Check.Status)
			switch out.Check.Status {
			case StatusFail:
				var pf *PolicyFailure
				require.ErrorAs(t, out.Check.Err, &pf)
				assert.Equal(t, p.Expect.Policy.Rule, pf.Rule)
			case StatusUnchecked:
				assert.Equal(t, Reason(p.Expect.Policy.Reason), out.Check.Reason)
			}
			assert.Equal(t, IntegrityStatus(p.Expect.Integrity.Status), out.Integrity.Status)
			want := ""
			if p.Expect.Integrity.Reason != nil {
				want = *p.Expect.Integrity.Reason
			}
			assert.Equal(t, want, string(out.Integrity.Reason))
			assert.Len(t, out.Integrity.EvidenceHashes, len(p.Expect.Integrity.Evidence))
			if w := p.Expect.Integrity.Walk; w != nil {
				require.NotNil(t, out.Integrity.Walk)
				assert.Equal(t, w.Steps, uintString(out.Integrity.Walk.Steps))
				assert.Equal(t, w.ToSeq, uintString(out.Integrity.Walk.ToSeq))
				assert.Equal(t, w.Total, uintString(out.Integrity.Walk.Total))
				assert.Equal(t, WalkEnd(w.End), out.Integrity.Walk.End)
				assert.False(t, out.Integrity.Walk.SeqPrivate)
			}
			if out.Info != nil && out.Info.Mode != "" {
				assert.Equal(t, PolicyModePrivate, out.Info.Mode)
			}
			// runPrivCase checked the report against the twin's expectation.
			assert.Equal(t, p.Expect.Verdict, withKey.vecCase.Expect.Verdict)
			assert.Equal(t, p.Expect.Exit, withKey.vecCase.Expect.Exit)
		})

		t.Run(withKey.ID+"/wrong_key", func(t *testing.T) {
			// A key the envelopes do not list opens nothing: exactly the
			// keyless outcome.
			c := keyless
			c.Config.AuditorKeys = []string{strangerKeyHex}
			runPrivCase(t, c, d.vecDoc)
		})

		t.Run(withKey.ID+"/without_key", func(t *testing.T) {
			out := runPrivCase(t, keyless, d.vecDoc)
			// Facts, limits, times and state live in the PrivatePart: without a
			// key nothing that depends on them can pass or fail.
			assert.NotEqual(t, StatusPass, out.Check.Status)
			if out.Check.Status == StatusFail {
				var pf *PolicyFailure
				require.ErrorAs(t, out.Check.Err, &pf)
				assert.Equal(t, "mandate_ref_mismatch", pf.Rule, "only the public binding can fail")
			}
			assert.NotEqual(t, IntegrityOK, out.Integrity.Status, "a walk without the salt is never ok")
			if out.Integrity.Walk != nil {
				assert.True(t, out.Integrity.Walk.SeqPrivate)
			}
			if out.Info != nil {
				assert.Empty(t, out.Info.AuditorKid)
			}
			// A public outcome that is not violated can never become violated
			// without the key.
			if p.Expect.Integrity.Status != string(IntegrityViolated) {
				assert.NotEqual(t, IntegrityViolated, out.Integrity.Status)
			}
		})
	}
}

var strangerKeyHex = strings.Repeat("07", 32)

func parsePrivCase(t *testing.T, raw []byte) privCase {
	t.Helper()
	var c privCase
	require.NoError(t, json.Unmarshal(raw, &c.vecCase))
	require.NoError(t, json.Unmarshal(raw, &c))
	return c
}

func uintString(n uint64) string { return strconv.FormatUint(n, 10) }
