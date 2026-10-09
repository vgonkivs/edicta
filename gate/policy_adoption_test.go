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

type adoptionStart struct {
	Version     string            `json:"version"`
	MandateHash string            `json:"mandate_hash_hex"`
	Scales      map[string]string `json:"scales"`
}

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
			Start *adoptionStart `json:"start"`
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
				if i == 0 && c.Start != nil {
					env = gatefix.New(t,
						gatefix.WithConfig(func(c *gate.Config) { c.Mandate = raw }),
						gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))
					seedStart(t, env, sm, c.Start)
					rerr = env.Restart()
				} else if i == 0 {
					env = gatefix.New(t,
						gatefix.WithConfig(func(c *gate.Config) { c.Mandate = raw }),
						gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))
				} else {
					env.Cfg.Mandate = raw
					rerr = env.Restart()
				}
				if s.Expect == "refuse" {
					require.ErrorIs(t, rerr, gate.ErrInvalidConfig, "step %d", i)
					switch s.Cause {
					case "scale":
						require.ErrorIs(t, rerr, policy.ErrScaleChanged, "step %d", i)
					case "scales_full":
						require.ErrorIs(t, rerr, policy.ErrScalesFull, "step %d", i)
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

// seedStart overwrites the genesis cell the fixture wrote with the vector's
// starting cell: earlier versions already adopted.
func seedStart(t *testing.T, env *gatefix.Env, sm *policy.SignedMandate, st *adoptionStart) {
	t.Helper()
	sr := env.Reg.(registry.StateRegistry)
	key := registry.StateKey(sm.Mandate.CounterKey())
	cell, err := sr.State(context.Background(), key)
	require.NoError(t, err)
	ctr, err := policy.DecodeCounter(cell.Value)
	require.NoError(t, err)
	ctr.Version, err = strconv.ParseUint(st.Version, 10, 64)
	require.NoError(t, err)
	mh, err := hex.DecodeString(st.MandateHash)
	require.NoError(t, err)
	ctr.MandateHash = mh
	ctr.Scales = map[string]uint64{}
	for a, sc := range st.Scales {
		ctr.Scales[a], err = strconv.ParseUint(sc, 10, 64)
		require.NoError(t, err)
	}
	enc, err := policy.EncodeCounter(ctr)
	require.NoError(t, err)
	require.NoError(t, sr.UpdateState(context.Background(), registry.StateTx{Key: key, Expect: cell.Version, Next: registry.NewStateCell(enc)}))
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
	require.ErrorIs(t, err, gate.ErrMandateMismatch, "a new decision that names the old mandate")
	assert.Empty(t, res.PolicyVerdict, "no verdict under a mandate the agent did not name")

	p.rebase()
	_, b3, a3 := p.request(3, "agent1", 40)
	res, err = p.AuthorizeWith(b3, a3)
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
