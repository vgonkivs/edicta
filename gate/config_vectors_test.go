package gate_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type gateConfigCase struct {
	ID     string `json:"id"`
	Config struct {
		FastMode          bool     `json:"fast_mode"`
		PendingNamespaces []string `json:"pending_namespaces"`
		FastWindowBlocks  string   `json:"fast_window_blocks"`
		MaxH0AgeBlocks    string   `json:"max_h0_age_blocks"`
		MinFastSlack      string   `json:"min_fast_slack_blocks"`
		MinPromiseSlack   string   `json:"min_promise_slack_seconds"`
		RevealOnExecution []string `json:"reveal_on_execution"`
	} `json:"config"`
	Mandate      bool     `json:"mandate"`
	MandateDelay string   `json:"mandate_fast_mode_max_delay"`
	Allowlist    []string `json:"allowlist"`
	Expect       struct {
		Result string `json:"result"`
		Error  string `json:"error"`
		Cause  string `json:"cause"`
	} `json:"expect"`
}

// TestGateConfigVectors builds a gate from every configuration vector: the
// stateless checks, then the constructor's mandate checks.
func TestGateConfigVectors(t *testing.T) {
	var f struct {
		Allowlist       []string        `json:"allowlist"`
		ProfileRegistry map[string]bool `json:"profile_registry"`
		Cases           []gateConfigCase
	}
	gatefix.ReadVector(t, "gate.json", &f)
	require.NotEmpty(t, f.Cases)
	for _, tc := range f.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			allow := f.Allowlist
			if tc.Allowlist != nil {
				allow = tc.Allowlist
			}
			var xs []policy.Extractor
			for _, typ := range allow {
				xs = append(xs, typedExtractor{lastByteExtractor{typ: typ}})
			}
			x, err := policy.NewExtractors(xs...)
			require.NoError(t, err)
			opts := []gatefix.Option{
				gatefix.WithDeps(func(d *gate.Deps) {
					d.Archiver, d.Extractors, d.Profiles = &recordingArchiver{}, x, gate.ProfileSet(f.ProfileRegistry)
				}),
				gatefix.WithConfig(func(c *gate.Config) {
					c.Scope.ActionTypes = allow
					c.FastMode = tc.Config.FastMode
					for _, ns := range tc.Config.PendingNamespaces {
						c.PendingNamespaces = append(c.PendingNamespaces, gatefix.MustHex(t, ns))
					}
					if v := optU64(t, tc.Config.FastWindowBlocks); v != 0 {
						c.FastWindowBlocks = v
					}
					if v := optU64(t, tc.Config.MaxH0AgeBlocks); v != 0 {
						c.MaxH0AgeBlocks = v
					}
					if tc.Config.MinFastSlack != "" {
						c.MinFastSlackBlocks = gatefix.U64(t, tc.Config.MinFastSlack)
					}
					if tc.Config.MinPromiseSlack != "" {
						c.MinPromiseSlackSeconds = gatefix.U64(t, tc.Config.MinPromiseSlack)
					}
					c.RevealOnExecution = tc.Config.RevealOnExecution
					if tc.Mandate {
						m := baseMandate(t)
						m.FastModeMaxDelay = optU64(t, tc.MandateDelay)
						c.Mandate = signedMandate(t, m)
					}
				}),
			}
			_, err = gatefix.TryNew(t, opts...)
			if tc.Expect.Result == "ok" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, gate.ErrInvalidConfig)
			assert.True(t, strings.Contains(err.Error(), tc.Expect.Cause+":"), "cause %s in %v", tc.Expect.Cause, err)
		})
	}
}

// typedExtractor is lastByteExtractor with an id per action type, so one
// registry can serve several types.
type typedExtractor struct{ lastByteExtractor }

func (x typedExtractor) ID() string {
	sum := sha256.Sum256([]byte(x.typ))
	return fmt.Sprintf("test/type-%x/v1", sum[:4])
}

// A zero bound means the default, so the vectors' zero values are set
// explicitly and must be refused by the stateless check.
func TestGateConfigZeroBoundsAfterDefaults(t *testing.T) {
	c := gate.DefaultConfig()
	c.Scope.GateID, c.Scope.ActionTypes = gatefix.GateID, []string{gatefix.ActionType}
	c.MinFastSlackBlocks = 0
	require.ErrorIs(t, c.ValidateBasic(), gate.ErrInvalidConfig)
}
