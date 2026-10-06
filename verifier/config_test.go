package verifier_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func TestConfigValidateBasic(t *testing.T) {
	key := gatePub(t)
	good := func() verifier.Config {
		return verifier.Config{Params: commitment.DefaultParams(), GateKeys: []ed25519.PublicKey{key}}
	}
	tests := []struct {
		name string
		mod  func(*verifier.Config)
		ok   bool
	}{
		{"valid", func(*verifier.Config) {}, true},
		{"no gate keys", func(c *verifier.Config) { c.GateKeys = nil }, false},
		{"short gate key", func(c *verifier.Config) { c.GateKeys = []ed25519.PublicKey{key[:31]} }, false},
		{"nil gate key", func(c *verifier.Config) { c.GateKeys = []ed25519.PublicKey{nil} }, false},
		{"duplicate gate key", func(c *verifier.Config) { c.GateKeys = []ed25519.PublicKey{key, key} }, false},
		{"zero params", func(c *verifier.Config) { c.Params = commitment.Params{} }, false},
		{"skew above the cap", func(c *verifier.Config) { c.Params.SkewS = 301 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mod(&c)
			err := c.ValidateBasic()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, verifier.ErrInvalidConfig)
		})
	}
}

func TestNewRejectsBadDeps(t *testing.T) {
	r := newRig(t, newParts(t))
	tests := []struct {
		name string
		mod  func(*verifier.Deps)
	}{
		{"nil archive", func(d *verifier.Deps) { d.Archive = nil }},
		{"invalid config", func(d *verifier.Deps) { d.Config.GateKeys = nil }},
		{"no committers", func(d *verifier.Deps) { d.Committers = nil }},
		{"no anchor verifiers", func(d *verifier.Deps) { d.Anchors = nil }},
		{"nil anchor verifier", func(d *verifier.Deps) {
			d.Anchors = map[commitment.DA]verifier.AnchorVerifier{commitment.DACelestiaBlob: nil}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := r.deps
			tc.mod(&d)
			v, err := verifier.New(d)
			require.ErrorIs(t, err, verifier.ErrInvalidConfig)
			assert.Nil(t, v)
		})
	}
	t.Run("nil trust is allowed", func(t *testing.T) {
		d := r.deps
		d.Trust = nil
		_, err := verifier.New(d)
		require.NoError(t, err)
	})
}

func TestGateKeysAreCopiedAtNew(t *testing.T) {
	r := newRig(t, newParts(t))
	v := r.verifier(t)
	r.deps.Config.GateKeys[0][0] ^= 1
	rep, err := v.Verify(t.Context(), r.p.hash)
	require.NoError(t, err)
	assert.True(t, rep.Authorized, "later changes of the caller's key slice do not reach the verifier")
}
