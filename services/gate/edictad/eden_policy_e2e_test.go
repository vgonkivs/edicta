// SPDX-License-Identifier: Apache-2.0

package edictad_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/gate/edictad"
)

// edenVector returns the action bytes of a case or reject of the profile's
// action vectors.
func edenVector(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile(testkit.SpecPath(t, "vectors/profiles/eden-escrow/action.json"))
	require.NoError(t, err)
	type vec struct {
		ID      string `json:"id"`
		CBORHex string `json:"cbor_hex"`
	}
	var v struct {
		Cases  []vec `json:"cases"`
		Reject []vec `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	for _, c := range append(v.Cases, v.Reject...) {
		if c.ID == id {
			b, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)
			return b
		}
	}
	require.FailNow(t, "no vector "+id)
	return nil
}

func (p *policyEnv) edenDecision(tag byte, action []byte) decision {
	p.t.Helper()
	return p.decisionAct(p.base, tag, action, func(c *commitment.Commitment) {
		h, err := commitment.ActionHash(edenescrow.ActionType, testSalt, action)
		require.NoError(p.t, err)
		c.Action.Type, c.Action.Hash = edenescrow.ActionType, h[:]
	})
}

// An operator admits Eden escrow deposits by listing the type in
// gate.action_types; the mandate then sees the deposit's cap as the amount.
func TestPolicyEdenEscrowDeposit(t *testing.T) {
	p := newPolicyEnv(t)
	// tx_f14_714 deposits 16170471215597597 wei.
	p.mandate.Assets = []policy.AssetRule{{Asset: "eip155:714/native", Scale: 18,
		PerActionMax: policy.AmountFromUint64(20_000_000_000_000_000)}}
	p.file = p.sign(p.principal, p.mandate)
	p.start(
		rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`, `action_types = ["`+edenescrow.ActionType+`"]`),
		rep("[http]", "[policy]\nmandate_file = \""+p.file+"\"\n\n[http]"),
	)
	n := len(p.fs.puts)

	d := p.edenDecision(1, edenVector(t, "tx_f14_714"))
	st, _, body := p.authorizeRaw(d)
	require.Equal(t, 200, st, "%s", body)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization},
		p.fs.puts[n:])
	allow, err := p.real.PolicyAllow(bg, d.hash)
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(allow.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	assert.Equal(t, edenescrow.RegisteredExtractorID(), sv.Verdict.Extractor)

	// A deposit on a chain that is no row of the table is a deny, never an
	// authorization.
	d = p.edenDecision(2, edenVector(t, "tx_chain_1"))
	st, _, body = p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.True(t, hasCode(body, "policy.ErrFactsInvalid"), "body %q", body)
	_, err = p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

// A dev binary says so at start; a production binary does not.
func TestEdictadevBuildWarnsAtStart(t *testing.T) {
	e := newEnv(t)
	e.start()
	const warning = "edictadev build, the Eden escrow table includes the dev chain 31337"
	if edenescrow.RegisteredExtractorID() == edenescrow.DevExtractorID {
		assert.Contains(t, e.logs.String(), warning)
		return
	}
	assert.NotContains(t, e.logs.String(), warning)
}

// The executed transaction does not reveal the resource URL and the
// requirements hash, so the action type is never public on execution.
func TestEdenEscrowIsNotRevealedOnExecution(t *testing.T) {
	e := newEnv(t)
	_, err := edictad.ParseConfig([]byte(e.tomlOf(
		rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`,
			`action_types = ["`+edenescrow.ActionType+`"]`+"\nreveal_on_execution = [\""+edenescrow.ActionType+"\"]"),
	)))
	require.ErrorIs(t, err, edictad.ErrConfig)
}
