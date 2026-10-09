package gatechain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

func TestFibreUploadSizeMatchesTheEncoder(t *testing.T) {
	for _, n := range []uint64{1, 4091, 4092, 262139, 262140, 1 << 20, 1<<27 - 5} {
		want, err := fibrecommit.UploadSize(n)
		require.NoError(t, err)
		got, ok := fibreUploadSize(n)
		require.True(t, ok)
		assert.Equal(t, want, got, "n = %d", n)
	}
	for n, want := range map[uint64]uint64{1: 262144, 262139: 262144, 262140: 524288, 1<<27 - 5: 1 << 27} {
		got, ok := fibreUploadSize(n)
		require.True(t, ok)
		assert.Equal(t, want, got, "n = %d", n)
	}
	_, ok := fibreUploadSize(0)
	assert.False(t, ok)
}
