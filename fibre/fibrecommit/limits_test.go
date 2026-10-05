package fibrecommit_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

// An oversize input must be refused from its length alone: the encoding of
// 16 MiB is far larger than the bound below.
func TestOversizeDoesNotAllocateEncoding(t *testing.T) {
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	big := make([]byte, fibrecommit.DefaultMaxDataSize+1)
	r := commitment.PayloadRef{DA: commitment.DAFibre, Commitment: make([]byte, 32)}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = cm.Check(r, big)
	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, fibrecommit.ErrTooLarge)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
	const bound = 1 << 20
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(bound))

	allocs := testing.AllocsPerRun(5, func() { _ = cm.Check(r, big) })
	require.Less(t, allocs, float64(16))
}

func TestOversizeCommitmentFunctionWithoutBlob(t *testing.T) {
	_, err := fibrecommit.UploadSize(fibrecommit.MaxDataSize + 1)
	require.Error(t, err)
}
