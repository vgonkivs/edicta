package fibrecommit_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

func FuzzCheck(f *testing.F) {
	cm, err := fibrecommit.New(1 << 16)
	require.NoError(f, err)

	seed := []byte{0x65}
	good, err := fibrecommit.Commitment(seed)
	require.NoError(f, err)
	f.Add(uint64(1), good[:], seed)
	f.Add(uint64(1), good[:], []byte{})
	f.Add(uint64(1), good[:], append(append([]byte{}, seed...), 0))
	f.Add(uint64(2), good[:], seed)
	f.Add(uint64(1), []byte{1, 2, 3}, seed)
	f.Add(uint64(1), []byte(nil), []byte(nil))
	f.Add(uint64(1), good[:], make([]byte, 1<<16+1))

	f.Fuzz(func(t *testing.T, da uint64, c []byte, blob []byte) {
		orig := bytes.Clone(blob)
		err := cm.Check(commitment.PayloadRef{DA: commitment.DA(da), Commitment: c}, blob)
		require.Equal(t, orig, blob)

		if err == nil {
			require.EqualValues(t, commitment.DAFibre, da)
			got, cerr := fibrecommit.Commitment(blob)
			require.NoError(t, cerr)
			require.Equal(t, got[:], c)
			return
		}
		if len(blob) > 1<<16 {
			require.ErrorIs(t, err, fibrecommit.ErrTooLarge)
			return
		}
		if da == uint64(commitment.DAFibre) {
			require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
		}
	})
}
