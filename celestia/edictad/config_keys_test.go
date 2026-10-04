package edictad_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
)

// Keys that did nothing are gone: they must be refused, not silently ignored.
func TestRemovedKeysAreRefused(t *testing.T) {
	e := newEnv(t)
	for name, edit := range map[string][2]string{
		"anchor_verifier light": rep(`anchor_verifier = "self"`, `anchor_verifier = "light"`),
		"consensus_rpc table":   rep("[network]\n", "[network.consensus_rpc]\nprimary = \"x\"\n\n[network]\n"),
		"gate.limits table":     rep("[http]\n", "[gate.limits]\nskew_s = 1\n\n[http]\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := edictad.ParseConfig([]byte(e.tomlOf(edit)))
			require.ErrorIs(t, err, edictad.ErrConfig)
		})
	}
}
