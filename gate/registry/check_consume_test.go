package registry_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate/registry"
)

func TestCheckConsumeBoundsThePrivatePart(t *testing.T) {
	e := registry.Entry{Authorization: []byte{1}, Path: registry.PathDA, PrivatePart: make([]byte, registry.MaxPrivatePart)}
	require.NoError(t, registry.CheckConsume(e))
	e.PrivatePart = make([]byte, registry.MaxPrivatePart+1)
	require.ErrorIs(t, registry.CheckConsume(e), registry.ErrInvalidEntry)
}
