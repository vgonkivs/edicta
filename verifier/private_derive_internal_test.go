package verifier

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

func loadPrivCase(t *testing.T, id string) (privCase, vecDoc) {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(t, err)
	var d privDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	for _, rc := range d.Cases {
		c := parsePrivCase(t, rc)
		if c.ID == id {
			return c, d.vecDoc
		}
	}
	require.FailNow(t, "no case "+id)
	return privCase{}, vecDoc{}
}

func privVerifier(t *testing.T, c privCase, d vecDoc) (*Verifier, vecArchive) {
	t.Helper()
	v, arch := c.vecCase.verifier(t, d)
	v.archive = privArchive{arch}
	v.cfg.PrincipalSchemes = principalSchemes(t, c.vecCase.Config.PrincipalSchemes)
	for _, k := range c.Config.AuditorKeys {
		v.cfg.AuditorKeys = append(v.cfg.AuditorKeys, auditorRecipientKey(t, k))
	}
	return v, arch
}

// A self-inconsistent PrivatePart without anchor_time and an unverified
// header block only the evaluation on the state: the facts are still
// compared, and a mismatch decides.
func TestPrivateMissingAnchorTimeStillChecksTheFacts(t *testing.T) {
	c, d := loadPrivCase(t, "private_part_allow_missing_times")
	c.TH = nil

	v, _ := privVerifier(t, c, d)
	out, err := v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	assert.Equal(t, StatusUnchecked, out.Check.Status, "matching facts: only the state evaluation is blocked")
	assert.Equal(t, ReasonBlocked, out.Check.Reason)
	assert.Equal(t, []string{string(CheckHeaderTrust)}, out.Check.Sources)

	// The amount of the action bytes no longer matches the signed facts.
	require.True(t, strings.Contains(c.Decision.Action, "034164"))
	c.Decision.Action = strings.Replace(c.Decision.Action, "034164", "034165", 1)
	v, _ = privVerifier(t, c, d)
	out, err = v.checkPolicy(t.Context(), c.input(t, d))
	require.NoError(t, err)
	require.Equal(t, StatusFail, out.Check.Status, "%v", out.Check.Err)
	var pf *PolicyFailure
	require.ErrorAs(t, out.Check.Err, &pf)
	assert.Equal(t, "facts_mismatch", pf.Rule)
}

// Two signed verdicts naming one private_hash are each merged with their own
// public fields and checked against their own blinded state hash.
func TestPrivatePartSharedByTwoVerdictsIsJudgedPerVerdict(t *testing.T) {
	c, d := loadPrivCase(t, "private_with_key_pass")
	v, arch := privVerifier(t, c, d)
	in := c.input(t, d)
	rec, err := arch.PolicyAllow(t.Context(), in.Hash)
	require.NoError(t, err)
	sv, _, err := policy.DecodeSignedVerdict(rec.SignedVerdict)
	require.NoError(t, err)
	first := sv.Verdict
	require.True(t, first.Private())

	mh := commitment.Hash(first.MandateHash)
	pt, _, st, err := v.readPrivate(t.Context(), policy.PrivateMandate, mh, mh, "")
	require.NoError(t, err)
	require.Equal(t, srcOK, st)
	sm, _, err := policy.DecodeSignedMandate(pt)
	require.NoError(t, err)
	m := &sm.Mandate

	p := &policyRun{v: v, ctx: t.Context(), in: in, parts: map[commitment.Hash]partRead{}}
	l, err := p.logical(&first, m)
	require.NoError(t, err)
	require.Equal(t, logicalOK, l.st)
	assert.Equal(t, first.CommitmentHash, l.v.CommitmentHash)

	second := first
	second.CommitmentHash = bytes.Repeat([]byte{0xab}, 32)
	l, err = p.logical(&second, m)
	require.NoError(t, err)
	assert.Equal(t, logicalOK, l.st)
	assert.Equal(t, second.CommitmentHash, l.v.CommitmentHash, "the merge carries the second verdict's own fields")

	third := second
	third.BlindPrevStateHash = bytes.Repeat([]byte{0xcd}, 32)
	l, err = p.logical(&third, m)
	require.NoError(t, err)
	assert.Equal(t, logicalInconsistent, l.st, "the state check runs against the third verdict's key 20")
	assert.Len(t, p.parts, 1, "the PrivatePart is read once")
}
