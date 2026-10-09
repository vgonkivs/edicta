package edictad

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
)

type noChain struct{ node.FibreChainReader }

// storeOnly hides every optional read side of the archive.
type storeOnly struct{ archive.Store }

func TestFastDepsWireTheVerifierOfTheInstanceDA(t *testing.T) {
	st, err := fsarchive.Open(t.TempDir(), map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	cons := nodefake.NewConsensus("test-1")
	chain := nodefake.NewChain(make([]byte, 20))

	for name, tc := range map[string]struct {
		da   string
		want any
	}{
		"celestia_blob": {DAConfigBlob, &gatechain.BlobIntents{}},
		"fibre":         {DAConfigFibre, &gatechain.FibreIntents{}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Network: NetworkConfig{DA: tc.da}}
			d := Deps{Reader: chain, Consensus: cons, Fibre: &FibreDeps{Chain: noChain{}}}
			var gd gate.Deps
			require.NoError(t, fastDeps(cfg, d, st, "test-1", &gd))
			require.Len(t, gd.IntentVerifiers, 1)
			assert.IsType(t, tc.want, gd.IntentVerifiers[cfg.DA()])
			assert.NotNil(t, gd.Intents)
			assert.IsType(t, &gatechain.Broadcaster{}, gd.Broadcaster)
		})
	}

	var gd gate.Deps
	err = fastDeps(Config{Network: NetworkConfig{DA: DAConfigBlob}}, Deps{Reader: chain, Consensus: cons}, storeOnly{st}, "test-1", &gd)
	require.ErrorIs(t, err, ErrConfig)
	assert.Nil(t, gd.Intents, "nothing is wired on a refusal")
}
