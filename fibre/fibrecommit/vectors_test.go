package fibrecommit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

type vecCase struct {
	ID            string `json:"id"`
	Size          string `json:"size"`
	BlobHex       string `json:"blob_hex"`
	BlobPattern   string `json:"blob_pattern"`
	BlobSHA       string `json:"blob_sha256_hex"`
	UploadSize    string `json:"upload_size"`
	BlobIDHex     string `json:"blob_id_hex"`
	CommitmentHex string `json:"commitment_hex"`
	ExpectError   string `json:"expect_error"`
}

type vecFile struct {
	Cases  []vecCase `json:"cases"`
	Reject []vecCase `json:"reject"`
}

func loadVectors(t *testing.T) vecFile {
	t.Helper()
	b, err := os.ReadFile("../../spec/vectors/da/fibre_commit.json")
	require.NoError(t, err)
	var f vecFile
	require.NoError(t, json.Unmarshal(b, &f))
	require.NotEmpty(t, f.Cases)
	require.NotEmpty(t, f.Reject)
	return f
}

func (c vecCase) blob(t *testing.T) []byte {
	t.Helper()
	if c.BlobPattern != "" {
		require.Equal(t, "affine-7-3", c.BlobPattern)
		n, err := strconv.Atoi(c.Size)
		require.NoError(t, err)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(7*i + 3)
		}
		return b
	}
	b, err := hex.DecodeString(c.BlobHex)
	require.NoError(t, err)
	return b
}

func ref(t *testing.T, commitHex string) commitment.PayloadRef {
	t.Helper()
	c, err := hex.DecodeString(commitHex)
	require.NoError(t, err)
	return commitment.PayloadRef{DA: commitment.DAFibre, Commitment: c}
}

func TestVectorsAccept(t *testing.T) {
	f := loadVectors(t)
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)

	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			blob := c.blob(t)
			sum := sha256.Sum256(blob)
			require.Equal(t, c.BlobSHA, hex.EncodeToString(sum[:]), "vector blob reconstruction")

			require.NoError(t, cm.Check(ref(t, c.CommitmentHex), blob))

			got, err := fibrecommit.Commitment(blob)
			require.NoError(t, err)
			assert.Equal(t, c.CommitmentHex, hex.EncodeToString(got[:]))

			id := fibrecommit.BlobID(got)
			assert.Equal(t, c.BlobIDHex, hex.EncodeToString(id[:]))

			up, err := fibrecommit.UploadSize(uint64(len(blob)))
			require.NoError(t, err)
			want, err := strconv.ParseUint(c.UploadSize, 10, 64)
			require.NoError(t, err)
			assert.Equal(t, want, up)
		})
	}
}

func TestVectorsReject(t *testing.T) {
	f := loadVectors(t)
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)

	for _, c := range f.Reject {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "ErrDACommitmentMismatch", c.ExpectError)
			blob := c.blob(t)
			err := cm.Check(ref(t, c.CommitmentHex), blob)
			require.Error(t, err)

			require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
			if uint64(len(blob)) > fibrecommit.DefaultMaxDataSize {
				require.ErrorIs(t, err, fibrecommit.ErrTooLarge)
			}
		})
	}
}

func TestUpstreamLimitBoundary(t *testing.T) {
	up, err := fibrecommit.UploadSize(fibrecommit.MaxDataSize)
	require.NoError(t, err)
	assert.NotZero(t, up)

	_, err = fibrecommit.UploadSize(fibrecommit.MaxDataSize + 1)
	require.Error(t, err)
	_, err = fibrecommit.UploadSize(0)
	require.Error(t, err)
}

func TestLiveMochaVector(t *testing.T) {
	f := loadVectors(t)
	require.Equal(t, "fibre_live_mocha_popsmin1", f.Cases[0].ID)
	live := f.Cases[0]

	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	require.NoError(t, cm.Check(ref(t, live.CommitmentHex), []byte{0x65}))
	require.NoError(t, fibrecommit.SelfTest())
}

func TestCheckRejectsOtherDA(t *testing.T) {
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	r := ref(t, "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e")
	r.DA = commitment.DACelestiaBlob

	err = cm.Check(r, []byte{0x65})
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
	require.NotErrorIs(t, err, fibrecommit.ErrTooLarge)
}

func TestCheckRejectsMalformedCommitment(t *testing.T) {
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	for name, c := range map[string][]byte{
		"nil":   nil,
		"short": make([]byte, 31),
		"long":  make([]byte, 33),
	} {
		t.Run(name, func(t *testing.T) {
			err := cm.Check(commitment.PayloadRef{DA: commitment.DAFibre, Commitment: c}, []byte{0x65})
			require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
		})
	}
}

func TestNewCap(t *testing.T) {
	tests := []struct {
		name string
		max  uint64
		ok   bool
	}{
		{"zero", 0, false},
		{"one", 1, true},
		{"default", fibrecommit.DefaultMaxDataSize, true},
		{"above default", fibrecommit.DefaultMaxDataSize + 1, true},
		{"upstream limit", fibrecommit.MaxDataSize, true},
		{"above upstream limit", fibrecommit.MaxDataSize + 1, false},
		{"max uint64", ^uint64(0), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := fibrecommit.New(tc.max)
			if !tc.ok {
				require.Error(t, err)
				require.Nil(t, cm)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.max, cm.MaxDataSize())
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "v10.4.0-mocha", fibrecommit.PinnedAppVersion)
	assert.EqualValues(t, 1<<27-5, fibrecommit.MaxDataSize)
	assert.EqualValues(t, 16<<20, fibrecommit.DefaultMaxDataSize)
}

func TestConfiguredCapApplies(t *testing.T) {
	cm, err := fibrecommit.New(300)
	require.NoError(t, err)
	r := ref(t, "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e")

	err = cm.Check(r, make([]byte, 301))
	require.ErrorIs(t, err, fibrecommit.ErrTooLarge)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)

	err = cm.Check(r, make([]byte, 300))
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)
}

func TestCheckDoesNotModifyInput(t *testing.T) {
	f := loadVectors(t)
	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)

	for _, c := range f.Cases {
		blob := c.blob(t)
		orig := append([]byte(nil), blob...)
		cap0 := cap(blob)
		require.NoError(t, cm.Check(ref(t, c.CommitmentHex), blob), c.ID)
		require.Equal(t, orig, blob, c.ID)
		require.Equal(t, cap0, cap(blob), c.ID)

		_, err := fibrecommit.Commitment(blob)
		require.NoError(t, err)
		require.Equal(t, orig, blob, c.ID)
	}
}

func TestConcurrentCheckSharedInput(t *testing.T) {
	f := loadVectors(t)
	var c vecCase
	for _, v := range f.Cases {
		if v.ID == "fibre_size_262140" {
			c = v
		}
	}
	require.NotEmpty(t, c.ID)
	shared := c.blob(t)
	orig := append([]byte(nil), shared...)
	r := ref(t, c.CommitmentHex)

	cm, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)

	const workers = 16
	errs := make([]error, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[i] = cm.Check(r, shared)
		}()
		go func() {
			defer wg.Done()
			_, errs[workers+i] = fibrecommit.Commitment(shared)
		}()
	}
	wg.Wait()

	for _, e := range errs {
		require.NoError(t, e)
	}
	require.Equal(t, orig, shared)
}
