package memreg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/gate/registry"
	"github.com/vgonkivs/prior/gate/registry/memreg"
	"github.com/vgonkivs/prior/gate/registry/regtest"
)

func TestConformance(t *testing.T) {
	regtest.Run(t, func(t *testing.T, epoch uint64) registry.Registry {
		r, err := memreg.New(epoch)
		require.NoError(t, err)
		return r
	})
}
