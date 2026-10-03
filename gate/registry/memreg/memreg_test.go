package memreg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/memreg"
	"github.com/vgonkivs/edicta/gate/registry/regtest"
)

func TestConformance(t *testing.T) {
	regtest.Run(t, func(t *testing.T, epoch uint64) registry.Registry {
		r, err := memreg.New(epoch)
		require.NoError(t, err)
		return r
	})
}
