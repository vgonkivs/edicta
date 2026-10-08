package gate_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type adoptionStep struct {
	SignedMandateHex string            `json:"signed_mandate_hex"`
	Expect           string            `json:"expect"`
	Error            string            `json:"error"`
	Cause            string            `json:"cause"`
	VersionAfter     string            `json:"version_after"`
	ScalesAfter      map[string]string `json:"scales_after"`
}

func TestPolicyAdoptionVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "policy", "mandate.json"))
	require.NoError(t, err)
	var d struct {
		Adoption []struct {
			ID    string         `json:"id"`
			Steps []adoptionStep `json:"steps"`
		} `json:"adoption"`
	}
	require.NoError(t, json.Unmarshal(b, &d))
	require.NotEmpty(t, d.Adoption)

	for _, c := range d.Adoption {
		t.Run(c.ID, func(t *testing.T) {
			signed := func(s adoptionStep) []byte {
				raw, err := hex.DecodeString(s.SignedMandateHex)
				require.NoError(t, err)
				return raw
			}
			x, err := policy.NewExtractors(lastByteExtractor{typ: gatefix.ActionType})
			require.NoError(t, err)
			var env *gatefix.Env
			for i, s := range c.Steps {
				raw := signed(s)
				sm, _, err := policy.VerifyMandate(raw)
				require.NoError(t, err)
				var rerr error
				if i == 0 {
					env = gatefix.New(t,
						gatefix.WithConfig(func(c *gate.Config) { c.Mandate = raw }),
						gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))
				} else {
					env.Cfg.Mandate = raw
					rerr = env.Restart()
				}
				if s.Expect == "refuse" {
					require.ErrorIs(t, rerr, gate.ErrInvalidConfig, "step %d", i)
					if s.Cause == "scale" {
						require.ErrorIs(t, rerr, policy.ErrScaleChanged, "step %d", i)
					}
				} else {
					require.NoError(t, rerr, "step %d", i)
				}

				cell, err := env.Reg.(registry.StateRegistry).State(context.Background(), registry.StateKey(sm.Mandate.CounterKey()))
				require.NoError(t, err)
				ctr, err := policy.DecodeCounter(cell.Value)
				require.NoError(t, err)
				ver, err := strconv.ParseUint(s.VersionAfter, 10, 64)
				require.NoError(t, err)
				assert.Equal(t, ver, ctr.Version, "step %d", i)
				want := map[string]uint64{}
				for a, sc := range s.ScalesAfter {
					v, err := strconv.ParseUint(sc, 10, 64)
					require.NoError(t, err)
					want[a] = v
				}
				assert.Equal(t, want, ctr.Scales, "step %d", i)
			}
		})
	}
}

func TestPolicyRetryAfterAMandateChangeGetsTheStoredAuthorization(t *testing.T) {
	p := newPolicyEnv(t, baseMandate(t))
	_, b, a := p.request(1, "agent1", 40)
	first, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)

	v2 := baseMandate(t)
	v2.Version = 2
	v2.Assets[0].PerActionMax = []byte{10}
	p.Cfg.Mandate = signedMandate(t, v2)
	require.NoError(t, p.Restart())

	again, err := p.AuthorizeWith(b, a)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.NotErrorIs(t, err, policy.ErrDenied)
	assert.Equal(t, first.Authorization, again.Authorization)
	assert.Equal(t, first.PolicyVerdict, again.PolicyVerdict)

	_, b2, a2 := p.request(2, "agent1", 40)
	res, err := p.AuthorizeWith(b2, a2)
	require.ErrorIs(t, err, policy.ErrAmountAboveMax, "a new decision meets the new limit")
	assert.NotEmpty(t, res.PolicyVerdict)
}

func TestPolicyEntryKeepsTheClosedHistoryOfARollover(t *testing.T) {
	m := baseMandate(t)
	m.MaxDecisionAge = 4000
	p := newPolicyEnv(t, m)
	_, b, a := p.requestAt(1, "agent1", 40, gatefix.Now-2000)
	first, err := p.AuthorizeWith(b, a)
	require.NoError(t, err)
	assert.Empty(t, first.ClosedBucket)

	c, b2, a2 := p.requestAt(2, "agent1", 10, gatefix.Now-10)
	res, err := p.AuthorizeWith(b2, a2)
	require.NoError(t, err)
	require.NotEmpty(t, res.ClosedBucket)
	require.NotEmpty(t, res.ClosedSet)
	var key registry.Key
	copy(key.PubKey[:], c.AgentPubKey)
	copy(key.Nonce[:], c.Nonce)
	e, err := p.Reg.Get(context.Background(), key)
	require.NoError(t, err)
	assert.Equal(t, res.ClosedBucket, e.ClosedBucket)
	assert.Equal(t, res.ClosedSet, e.ClosedSet)
}
