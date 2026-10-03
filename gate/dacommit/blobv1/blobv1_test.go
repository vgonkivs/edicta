package blobv1_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type vecCase struct {
	ID          string `json:"id"`
	Namespace   string `json:"namespace_hex"`
	Signer      string `json:"signer_hex"`
	Size        string `json:"size"`
	BlobHex     string `json:"blob_hex"`
	BlobPattern string `json:"blob_pattern"`
	Commitment  string `json:"commitment_hex"`
	ExpectError string `json:"expect_error"`
}

func blob(t *testing.T, c vecCase) []byte {
	t.Helper()
	if c.BlobHex != "" || c.BlobPattern == "" {
		return gatefix.MustHex(t, c.BlobHex)
	}
	require.EqualValuesf(t, "affine-7-3", c.BlobPattern, "unknown pattern %q", c.BlobPattern)
	b := make([]byte, gatefix.U64(t, c.Size))
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

func ref(t *testing.T, c vecCase) commitment.PayloadRef {
	return commitment.PayloadRef{
		DA:         commitment.DACelestiaBlob,
		Namespace:  gatefix.MustHex(t, c.Namespace),
		Commitment: gatefix.MustHex(t, c.Commitment),
		Height:     1,
		Signer:     gatefix.MustHex(t, c.Signer),
	}
}

var _ gate.DACommitter = blobv1.New()

// TestVectors: the committer reproduces the commitments computed by upstream
// code and rejects every reject case.
func TestVectors(t *testing.T) {
	var f struct {
		Cases  []vecCase `json:"cases"`
		Reject []vecCase `json:"reject"`
	}
	gatefix.ReadVector(t, "da_blob.json", &f)
	require.GreaterOrEqualf(t, len(f.Cases), 10, "loaded %d cases, %d rejects", len(f.Cases), len(f.Reject))
	require.GreaterOrEqualf(t, len(f.Reject), 4, "loaded %d cases, %d rejects", len(f.Cases), len(f.Reject))
	dc := blobv1.New()
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			err := dc.Check(context.Background(), ref(t, c), blob(t, c))
			require.NoError(t, err, "Check")
		})
	}
	for _, c := range f.Reject {
		t.Run(c.ID, func(t *testing.T) {
			err := dc.Check(context.Background(), ref(t, c), blob(t, c))
			require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
		})
	}
}

func TestRejectsMalformedRefs(t *testing.T) {
	var f struct {
		Cases []vecCase `json:"cases"`
	}
	gatefix.ReadVector(t, "da_blob.json", &f)
	c := f.Cases[0]
	good := ref(t, c)
	b := blob(t, c)
	dc := blobv1.New()
	mut := map[string]func(r *commitment.PayloadRef){
		"fibre":            func(r *commitment.PayloadRef) { r.DA = commitment.DAFibre },
		"da zero":          func(r *commitment.PayloadRef) { r.DA = 0 },
		"short namespace":  func(r *commitment.PayloadRef) { r.Namespace = r.Namespace[:28] },
		"nil namespace":    func(r *commitment.PayloadRef) { r.Namespace = nil },
		"short signer":     func(r *commitment.PayloadRef) { r.Signer = r.Signer[:19] },
		"nil signer":       func(r *commitment.PayloadRef) { r.Signer = nil },
		"short commitment": func(r *commitment.PayloadRef) { r.Commitment = r.Commitment[:31] },
		"nil commitment":   func(r *commitment.PayloadRef) { r.Commitment = nil },
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			r := good
			r.Namespace = append([]byte(nil), good.Namespace...)
			r.Signer = append([]byte(nil), good.Signer...)
			r.Commitment = append([]byte(nil), good.Commitment...)
			m(&r)
			err := dc.Check(context.Background(), r, b)
			require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
		})
	}
	t.Run("empty blob", func(t *testing.T) {
		err := dc.Check(context.Background(), good, nil)
		require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
	})
	t.Run("one flipped byte", func(t *testing.T) {
		bad := append([]byte(nil), b...)
		bad[len(bad)/2] ^= 1
		err := dc.Check(context.Background(), good, bad)
		require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
	})
}
