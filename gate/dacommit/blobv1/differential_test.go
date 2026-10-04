package blobv1_test

import (
	"bytes"
	"context"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// same requires the gate adapter and the shared package to give one verdict,
// each with its own sentinel on rejection.
func same(t *testing.T, ref commitment.PayloadRef, blob []byte) (accepted bool) {
	t.Helper()
	gErr := blobv1.New().Check(context.Background(), ref, blob)
	sErr := sharev1.Check(ref, blob)
	require.Equalf(t, gErr == nil, sErr == nil, "verdicts differ: blobv1 %v, sharev1 %v", gErr, sErr)
	if gErr != nil {
		require.ErrorIs(t, gErr, gate.ErrDACommitmentMismatch)
		require.ErrorIs(t, sErr, sharev1.ErrMismatch)
	}
	return gErr == nil
}

func TestDifferentialOnVectors(t *testing.T) {
	var f struct {
		Cases  []vecCase `json:"cases"`
		Reject []vecCase `json:"reject"`
	}
	gatefix.ReadVector(t, "da_blob.json", &f)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) { require.True(t, same(t, ref(t, c), blob(t, c))) })
	}
	for _, c := range f.Reject {
		t.Run(c.ID, func(t *testing.T) { require.False(t, same(t, ref(t, c), blob(t, c))) })
	}
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// validNS is a version-0 namespace: 18 zero bytes then 10 id bytes.
func validNS(r *rand.Rand) []byte {
	return append(make([]byte, 19), randBytes(r, 10)...)
}

func TestDifferentialOnRandomBlobs(t *testing.T) {
	r := rand.New(rand.NewPCG(0xed1c7a, 0x0b10b))
	sizes := []int{1, 2, 100, 477, 478, 479, 481, 482, 483, 511, 512, 955, 956, 957, 4000, 4096, 20000, 70000}
	for i := range 120 {
		n := sizes[i%len(sizes)]
		if i >= len(sizes) {
			n = 1 + r.IntN(6000)
		}
		ns, signer, data := validNS(r), randBytes(r, 20), randBytes(r, n)
		cm, err := sharev1.Commitment(ns, signer, data)
		require.NoError(t, err)
		ref := commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: cm, Height: 1, Signer: signer}

		require.Truef(t, same(t, ref, data), "honest blob of %d bytes", n)

		bad := func(name string, mod func(r *commitment.PayloadRef) []byte) {
			rc := ref
			rc.Namespace, rc.Commitment, rc.Signer = bytes.Clone(ns), bytes.Clone(cm), bytes.Clone(signer)
			b := mod(&rc)
			require.Falsef(t, same(t, rc, b), "%s, size %d", name, n)
		}
		bad("flipped data byte", func(*commitment.PayloadRef) []byte {
			b := bytes.Clone(data)
			b[r.IntN(len(b))] ^= 1 << r.IntN(8)
			return b
		})
		bad("flipped commitment", func(rc *commitment.PayloadRef) []byte { rc.Commitment[r.IntN(32)] ^= 1; return data })
		bad("other signer", func(rc *commitment.PayloadRef) []byte { rc.Signer[r.IntN(20)] ^= 1; return data })
		bad("other namespace", func(rc *commitment.PayloadRef) []byte { rc.Namespace[19+r.IntN(10)] ^= 1; return data })
		bad("trailing zero", func(*commitment.PayloadRef) []byte { return append(bytes.Clone(data), 0) })
		bad("fibre da", func(rc *commitment.PayloadRef) []byte { rc.DA = commitment.DAFibre; return data })
		bad("short commitment", func(rc *commitment.PayloadRef) []byte { rc.Commitment = rc.Commitment[:31]; return data })
		bad("short signer", func(rc *commitment.PayloadRef) []byte { rc.Signer = rc.Signer[:19]; return data })
		bad("namespace version 1", func(rc *commitment.PayloadRef) []byte { rc.Namespace[0] = 1; return data })
	}
}

// Whatever the bytes are, the two never disagree, panics included.
func TestDifferentialOnGarbageRefs(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 11))
	for range 300 {
		ref := commitment.PayloadRef{
			DA:         commitment.DA(r.IntN(4)),
			Namespace:  randBytes(r, []int{0, 28, 29, 29, 30}[r.IntN(5)]),
			Commitment: randBytes(r, []int{0, 31, 32, 32, 33}[r.IntN(5)]),
			Height:     uint64(r.IntN(3)),
			Signer:     randBytes(r, []int{0, 19, 20, 20, 21}[r.IntN(5)]),
		}
		require.NotPanics(t, func() { same(t, ref, randBytes(r, r.IntN(2000))) })
	}
}
