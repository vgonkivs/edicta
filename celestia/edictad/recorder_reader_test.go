package edictad_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
)

// plainReader exposes only the node.Reader methods of the fake.
type plainReader struct{ node.Reader }

func TestStartRefusesARecorderWhoseReaderCannotReturnSignedHeaders(t *testing.T) {
	t.Run("recorder enabled", func(t *testing.T) {
		e := newEnv(t)
		e.deps.Reader = plainReader{e.chain}
		srv, err := edictad.Start(bg, e.cfg(), e.deps)
		require.ErrorIs(t, err, edictad.ErrConfig)
		require.Nil(t, srv)
		assert.Zero(t, e.listens)
	})
	t.Run("recorder disabled needs no signed headers", func(t *testing.T) {
		e := newEnv(t)
		e.deps.Reader = plainReader{e.chain}
		cfg := e.cfg(rep("enabled = true", "enabled = false"))
		srv, err := edictad.Start(bg, cfg, e.deps)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Shutdown(bg) })
	})
}
