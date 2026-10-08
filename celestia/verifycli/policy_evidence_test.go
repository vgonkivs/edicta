package verifycli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// rivalAllow is a gate-signed allow from the same state as the archived one
// but for another commitment.
func rivalAllow(t *testing.T, s *scenario, key ed25519.PrivateKey) []byte {
	t.Helper()
	st, err := fsarchive.Open(s.archiveDir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	rec, err := st.PolicyAllow(context.Background(), s.hash)
	require.NoError(t, err)
	sv, _, err := policy.DecodeSignedVerdict(rec.SignedVerdict)
	require.NoError(t, err)
	v := sv.Verdict
	v.CommitmentHash = append([]byte(nil), v.CommitmentHash...)
	v.CommitmentHash[0] ^= 0xff
	canon, err := policy.EncodeVerdict(&v)
	require.NoError(t, err)
	sig := ed25519.Sign(key, policy.VerdictSigningMessage(policy.HashVerdict(canon)))
	out, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: v, Signature: sig})
	require.NoError(t, err)
	return out
}

func writeEvidence(t *testing.T, b []byte) string {
	p := filepath.Join(t.TempDir(), "evidence.bin")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

func TestPolicyEvidenceForkEndToEnd(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	pub := addPolicy(t, s, false)
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	base := func(extra ...string) []string {
		return s.args("verify", append([]string{"--trusted", trusted, "--principal-key", hexOf(pub), "--require-policy"}, extra...)...)
	}
	gateKey := gatefix.Key(t, "gate1")

	code, out := exec(t, base())
	require.Equal(t, exitValid, code, out)

	t.Run("a second allow from the same state is equivocation", func(t *testing.T) {
		ev := writeEvidence(t, rivalAllow(t, s, gateKey))
		code, out := exec(t, base("--policy-evidence", ev))
		assert.Equal(t, 5, code, out)
		assert.Contains(t, out, "GATE INTEGRITY VIOLATED (gate_equivocation)")
		assert.NotContains(t, out, "verdict: valid")

		code, out = exec(t, base("--policy-evidence", ev, "--json"))
		assert.Equal(t, 5, code, out)
		assert.Contains(t, out, `"violated"`)
	})
	t.Run("also without the walk", func(t *testing.T) {
		ev := writeEvidence(t, rivalAllow(t, s, gateKey))
		code, out := exec(t, base("--policy-full", "--policy-evidence", ev))
		assert.Equal(t, 5, code, out)
	})
	t.Run("the verdict held by the auditor is no fork of itself", func(t *testing.T) {
		st, err := fsarchive.Open(s.archiveDir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
		require.NoError(t, err)
		rec, err := st.PolicyAllow(context.Background(), s.hash)
		require.NoError(t, err)
		code, out := exec(t, base("--policy-evidence", writeEvidence(t, rec.SignedVerdict), "--policy-full"))
		assert.Equal(t, exitValid, code, out)
	})
	t.Run("evidence signed by another key proves nothing", func(t *testing.T) {
		_, other, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		code, out := exec(t, base("--policy-evidence", writeEvidence(t, rivalAllow(t, s, other))))
		assert.Equal(t, exitValid, code, out)
		assert.NotContains(t, out, "GATE INTEGRITY")
	})
	t.Run("garbage evidence proves nothing", func(t *testing.T) {
		code, out := exec(t, base("--policy-evidence", writeEvidence(t, []byte("not a verdict"))))
		assert.Equal(t, exitValid, code, out)
	})
	t.Run("an unreadable evidence file is a usage error", func(t *testing.T) {
		code, out := exec(t, base("--policy-evidence", filepath.Join(t.TempDir(), "missing.bin")))
		assert.Equal(t, 4, code, out)
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("an oversized evidence file is refused", func(t *testing.T) {
		code, out := exec(t, base("--policy-evidence", writeEvidence(t, make([]byte, maxEvidenceFile+1))))
		assert.Equal(t, 4, code, out)
	})
}

// A decision that breaks the mandate stays invalid (1) when the gate is also
// caught equivocating, and the banner still shows.
func TestPolicyInvalidAndEquivocationIsExitOneWithTheBanner(t *testing.T) {
	s := newScenario(t, scenarioOpts{bank: true})
	pub := addPolicy(t, s, true)
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	ev := writeEvidence(t, rivalAllow(t, s, gatefix.Key(t, "gate1")))
	code, out := exec(t, s.args("verify", "--trusted", trusted, "--principal-key", hexOf(pub), "--require-policy", "--policy-evidence", ev))
	assert.Equal(t, exitInvalid, code, out)
	first, _, _ := cutLine(out)
	assert.Equal(t, "GATE INTEGRITY VIOLATED (gate_equivocation)", first)
}

func cutLine(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
