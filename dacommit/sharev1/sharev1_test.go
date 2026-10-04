package sharev1_test

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
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
}

type vecFile struct {
	Cases  []vecCase `json:"cases"`
	Reject []vecCase `json:"reject"`
}

func load(t testing.TB) vecFile {
	var f vecFile
	gatefix.ReadVector(t, "da_blob.json", &f)
	require.GreaterOrEqual(t, len(f.Cases), 10)
	require.GreaterOrEqual(t, len(f.Reject), 4)
	return f
}

func blobOf(t testing.TB, c vecCase) []byte {
	t.Helper()
	if c.BlobHex != "" || c.BlobPattern == "" {
		return gatefix.MustHex(t, c.BlobHex)
	}
	require.EqualValues(t, "affine-7-3", c.BlobPattern)
	b := make([]byte, gatefix.U64(t, c.Size))
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

func refOf(t testing.TB, c vecCase) commitment.PayloadRef {
	return commitment.PayloadRef{
		DA:         commitment.DACelestiaBlob,
		Namespace:  gatefix.MustHex(t, c.Namespace),
		Commitment: gatefix.MustHex(t, c.Commitment),
		Height:     1,
		Signer:     gatefix.MustHex(t, c.Signer),
	}
}

// The recompute reproduces the commitments computed by upstream code.
func TestCommitmentVectors(t *testing.T) {
	for _, c := range load(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := sharev1.Commitment(gatefix.MustHex(t, c.Namespace), gatefix.MustHex(t, c.Signer), blobOf(t, c))
			require.NoError(t, err)
			assert.Equal(t, gatefix.MustHex(t, c.Commitment), got)
			require.NoError(t, sharev1.Check(refOf(t, c), blobOf(t, c)))
		})
	}
}

func TestCheckRejectVectors(t *testing.T) {
	for _, c := range load(t).Reject {
		t.Run(c.ID, func(t *testing.T) {
			err := sharev1.Check(refOf(t, c), blobOf(t, c))
			require.ErrorIs(t, err, sharev1.ErrMismatch)
		})
	}
}

func TestCheckRejectsMalformedRefs(t *testing.T) {
	f := load(t)
	c := f.Cases[0]
	blob := blobOf(t, c)
	good := refOf(t, c)
	clone := func() commitment.PayloadRef {
		r := good
		r.Namespace = bytes.Clone(good.Namespace)
		r.Commitment = bytes.Clone(good.Commitment)
		r.Signer = bytes.Clone(good.Signer)
		return r
	}
	tests := []struct {
		name string
		mod  func(r *commitment.PayloadRef)
		blob []byte
	}{
		{"fibre da", func(r *commitment.PayloadRef) { r.DA = commitment.DAFibre }, blob},
		{"da 0", func(r *commitment.PayloadRef) { r.DA = 0 }, blob},
		{"da 3", func(r *commitment.PayloadRef) { r.DA = 3 }, blob},
		{"nil commitment", func(r *commitment.PayloadRef) { r.Commitment = nil }, blob},
		{"31-byte commitment", func(r *commitment.PayloadRef) { r.Commitment = r.Commitment[:31] }, blob},
		{"33-byte commitment", func(r *commitment.PayloadRef) { r.Commitment = append(r.Commitment, 0) }, blob},
		{"nil namespace", func(r *commitment.PayloadRef) { r.Namespace = nil }, blob},
		{"28-byte namespace", func(r *commitment.PayloadRef) { r.Namespace = r.Namespace[:28] }, blob},
		{"30-byte namespace", func(r *commitment.PayloadRef) { r.Namespace = append(r.Namespace, 0) }, blob},
		{"namespace version 1", func(r *commitment.PayloadRef) { r.Namespace[0] = 1 }, blob},
		{"nil signer", func(r *commitment.PayloadRef) { r.Signer = nil }, blob},
		{"19-byte signer", func(r *commitment.PayloadRef) { r.Signer = r.Signer[:19] }, blob},
		{"32-byte signer", func(r *commitment.PayloadRef) { r.Signer = append(r.Signer, make([]byte, 12)...) }, blob},
		{"other signer", func(r *commitment.PayloadRef) { r.Signer[0] ^= 1 }, blob},
		{"other namespace", func(r *commitment.PayloadRef) { r.Namespace[28] ^= 1 }, blob},
		{"flipped commitment", func(r *commitment.PayloadRef) { r.Commitment[0] ^= 1 }, blob},
		{"nil blob", func(*commitment.PayloadRef) {}, nil},
		{"empty blob", func(*commitment.PayloadRef) {}, []byte{}},
		{"truncated blob", func(*commitment.PayloadRef) {}, blob[:len(blob)-1]},
		{"blob with trailing zero", func(*commitment.PayloadRef) {}, append(bytes.Clone(blob), 0)},
		{"flipped blob", func(*commitment.PayloadRef) {}, append([]byte{blob[0] ^ 1}, blob[1:]...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := clone()
			tt.mod(&r)
			require.NotPanics(t, func() {
				err := sharev1.Check(r, tt.blob)
				require.ErrorIs(t, err, sharev1.ErrMismatch)
			})
		})
	}
}

func TestCommitmentRejectsMalformedInputs(t *testing.T) {
	c := load(t).Cases[0]
	ns, signer, blob := gatefix.MustHex(t, c.Namespace), gatefix.MustHex(t, c.Signer), blobOf(t, c)
	for name, args := range map[string][3][]byte{
		"nil namespace":     {nil, signer, blob},
		"short namespace":   {ns[:28], signer, blob},
		"nil signer":        {ns, nil, blob},
		"short signer":      {ns, signer[:19], blob},
		"empty blob":        {ns, signer, nil},
		"namespace version": {append([]byte{1}, ns[1:]...), signer, blob},
	} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				got, err := sharev1.Commitment(args[0], args[1], args[2])
				if err == nil {
					// A path that does not error must not hand back the real commitment.
					assert.NotEqual(t, gatefix.MustHex(t, c.Commitment), got)
				}
			})
		})
	}
}

// Check and Commitment copy what they need: the caller's slices are left as
// they were, so one reference can be checked many times.
func TestInputsAreNotModified(t *testing.T) {
	c := load(t).Cases[0]
	ref, blob := refOf(t, c), blobOf(t, c)
	ns, sg, cm, bl := bytes.Clone(ref.Namespace), bytes.Clone(ref.Signer), bytes.Clone(ref.Commitment), bytes.Clone(blob)
	require.NoError(t, sharev1.Check(ref, blob))
	_, err := sharev1.Commitment(ref.Namespace, ref.Signer, blob)
	require.NoError(t, err)
	assert.Equal(t, ns, ref.Namespace)
	assert.Equal(t, sg, ref.Signer)
	assert.Equal(t, cm, ref.Commitment)
	assert.Equal(t, bl, blob)
}

func TestConcurrentUse(t *testing.T) {
	f := load(t)
	var wg sync.WaitGroup
	for i := range 16 {
		c := f.Cases[i%len(f.Cases)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, sharev1.Check(refOf(t, c), blobOf(t, c)))
		}()
	}
	wg.Wait()
}

// The package must stay light: no gate, no celestia-core or CometBFT.
func TestDependencies(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)
	for _, p := range pkgs {
		for name, file := range p.Files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				assert.NotContainsf(t, path, "/edicta/gate", "%s imports %s", name, path)
				assert.NotContainsf(t, path, "celestia-core", "%s imports %s", name, path)
				assert.NotContainsf(t, path, "cometbft", "%s imports %s", name, path)
			}
		}
	}
	mod, err := os.ReadFile("../../go.mod")
	require.NoError(t, err)
	assert.NotContains(t, string(mod), "celestia-core")
	assert.NotContains(t, string(mod), "cometbft")
}
