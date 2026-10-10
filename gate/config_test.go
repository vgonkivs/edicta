package gate_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func validConfig() gate.Config {
	c := gate.DefaultConfig()
	c.Scope = commitment.GateScope{GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType}}
	return c
}

func TestConfigValidateBasic(t *testing.T) {
	require.NoError(t, validConfig().ValidateBasic())

	cases := []struct {
		name string
		mod  func(*gate.Config)
	}{
		{"skew above 300", func(c *gate.Config) { c.SkewS = 301 }},
		{"blob retention zero", func(c *gate.Config) { c.BlobRetentionS = 0 }},
		{"blob retention above int64", func(c *gate.Config) { c.BlobRetentionS = 1 << 63 }},
		{"da timeout zero", func(c *gate.Config) { c.DATimeout = 0 }},
		{"archive timeout negative", func(c *gate.Config) { c.ArchiveTimeout = -time.Second }},
		{"sign timeout zero", func(c *gate.Config) { c.SignTimeout = 0 }},
		{"chain timeout zero", func(c *gate.Config) { c.ChainTimeout = 0 }},
		{"max fetch bytes zero", func(c *gate.Config) { c.MaxFetchBytes = 0 }},
		{"prune grace not above tolerance", func(c *gate.Config) { c.PruneGrace = c.ClockTolerance }},
		{"authorization ttl not above skew", func(c *gate.Config) { c.MaxAuthorizationTTL = c.SkewS }},
		{"authorization ttl above int64", func(c *gate.Config) { c.MaxAuthorizationTTL = 1 << 63 }},
		{"fibre cap above 2^27-5", func(c *gate.Config) { c.FibreMaxDataBytes = 1<<27 - 4 }},
		{"empty gate id", func(c *gate.Config) { c.Scope.GateID = "" }},
		{"bad gate id character", func(c *gate.Config) { c.Scope.GateID = "gate id" }},
		{"no action types", func(c *gate.Config) { c.Scope.ActionTypes = nil }},
		{"action type not a media type", func(c *gate.Config) { c.Scope.ActionTypes = []string{"nope"} }},
		{"duplicate action type", func(c *gate.Config) { c.Scope.ActionTypes = []string{gatefix.ActionType, gatefix.ActionType} }},
		{"unknown da", func(c *gate.Config) { c.AllowedDA = []commitment.DA{3} }},
		{"duplicate da", func(c *gate.Config) { c.AllowedDA = []commitment.DA{2, 2} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mod(&c)
			require.ErrorIs(t, c.ValidateBasic(), gate.ErrInvalidConfig)
		})
	}

	t.Run("fibre cap at 2^27-5 is valid", func(t *testing.T) {
		c := validConfig()
		c.FibreMaxDataBytes = 1<<27 - 5
		require.NoError(t, c.ValidateBasic())
	})
}

type cappedCommitter struct {
	fibreCommitter
	max uint64
}

func (c *cappedCommitter) MaxDataSize() uint64 { return c.max }

func TestNewRefusesFibreCommitterMismatches(t *testing.T) {
	build := func(t *testing.T, cm gate.DACommitter, mod func(*gate.Config)) error {
		t.Helper()
		_, err := gatefix.TryNew(t,
			gatefix.WithConfig(mod),
			gatefix.WithDeps(func(d *gate.Deps) { d.Committers[commitment.DAFibre] = cm }),
		)
		return err
	}
	t.Run("committer cap below the gate cap", func(t *testing.T) {
		err := build(t, &cappedCommitter{max: 1 << 20}, func(c *gate.Config) { c.FibreMaxDataBytes = 2 << 20 })
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("committer cap equal to the gate cap", func(t *testing.T) {
		require.NoError(t, build(t, &cappedCommitter{max: 1 << 20}, func(c *gate.Config) { c.FibreMaxDataBytes = 1 << 20 }))
	})
	t.Run("default cap above a smaller committer cap", func(t *testing.T) {
		err := build(t, &cappedCommitter{max: 1 << 20}, func(*gate.Config) {})
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("fetch budget below 13 times the cap", func(t *testing.T) {
		err := build(t, &fibreCommitter{}, func(c *gate.Config) { c.FibreMaxDataBytes = 1024; c.MaxFetchBytes = 13*1024 - 1 })
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("fetch budget of exactly 13 times the cap", func(t *testing.T) {
		require.NoError(t, build(t, &fibreCommitter{}, func(c *gate.Config) { c.FibreMaxDataBytes = 1024; c.MaxFetchBytes = 13 * 1024 }))
	})
	t.Run("budget check does not apply without a da=1 committer", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.FibreMaxDataBytes = 1 << 20; c.MaxFetchBytes = 1024 }))
		require.NoError(t, err)
	})
	t.Run("typed nil da=1 committer counts as missing", func(t *testing.T) {
		var nilFC *fibreCommitter
		e, err := gatefix.TryNew(t, gatefix.WithDeps(func(d *gate.Deps) { d.Committers[commitment.DAFibre] = nilFC }),
			gatefix.WithConfig(func(c *gate.Config) { c.MaxFetchBytes = 1024 }))
		require.NoError(t, err, "a nil committer must not trigger the committer checks")
		c := gatefix.FibreTemplate(t)
		e.StageDA(c, gatefix.FibreBlob())
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err, "behaves as no da=1 committer, without a nil dereference")
		assert.NotEmpty(t, res.Authorization)
	})
	t.Run("typed nil da=2 committer is refused", func(t *testing.T) {
		var nilBlob *fibreCommitter
		_, err := gatefix.TryNew(t, gatefix.WithDeps(func(d *gate.Deps) { d.Committers[commitment.DACelestiaBlob] = nilBlob }))
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("New applies ValidateBasic", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.FibreMaxDataBytes = 1<<27 - 4 }))
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
}

// TestConfigValidateBasicWrapsMandateErrors: the cause of a refused mandate
// stays reachable through errors.Is, next to ErrInvalidConfig.
func TestConfigValidateBasicWrapsMandateErrors(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/policy/mandate.json")
	require.NoError(t, err)
	var f struct {
		Reject []struct {
			ID     string `json:"id"`
			Signed string `json:"signed_mandate_hex"`
		} `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	var signed []byte
	for _, r := range f.Reject {
		if r.ID == "auditor_kid_mismatch" {
			signed, err = hex.DecodeString(r.Signed)
			require.NoError(t, err)
		}
	}
	require.NotEmpty(t, signed)

	c := validConfig()
	c.Mandate = signed
	err = c.ValidateBasic()
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorIs(t, err, policy.ErrAuditorKidMismatch)
	require.ErrorIs(t, err, policy.ErrMandateInvalid)

	c = validConfig()
	c.Mandate = []byte{0xa0}
	err = c.ValidateBasic()
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorIs(t, err, policy.ErrMandateInvalid)
}
