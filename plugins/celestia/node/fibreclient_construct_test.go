package node

import (
	"context"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/stretchr/testify/require"
)

type stubFibreState struct {
	state.Client
	stops int
}

func (s *stubFibreState) ChainID() string            { return "test-chain" }
func (s *stubFibreState) Stop(context.Context) error { s.stops++; return nil }

func TestFibreDownloadOnlyClientConstructs(t *testing.T) {
	stub := &stubFibreState{}
	cfg := fibre.DefaultClientConfig()
	cfg.StateClientFn = func() (state.Client, error) { return stub, nil }

	var c *fibre.Client
	require.NotPanics(t, func() {
		var err error
		c, err = fibre.NewClient(nil, cfg)
		require.NoError(t, err)
	})
	require.NotNil(t, c)
	require.NoError(t, c.Stop(t.Context()))
}
