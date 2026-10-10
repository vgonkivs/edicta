package verifycli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/absence"
)

// withRecord is ac with the record of h replaced.
func (ac absenceCase) withRecord(h uint64, r *archive.AbsenceProofRecord) absenceCase {
	out := ac
	out.recs = make(map[uint64]*archive.AbsenceProofRecord, len(ac.recs))
	for k, v := range ac.recs {
		out.recs[k] = v
	}
	out.recs[h] = r
	return out
}

// badDAH is the record of h with its DAH changed, so that it decodes but
// does not verify.
func (ac absenceCase) badDAH(h uint64) *archive.AbsenceProofRecord {
	r := *ac.recs[h]
	r.DAH = append([]byte(nil), r.DAH...)
	r.DAH[len(r.DAH)-1] ^= 1
	return &r
}

func runAbsenceJSON(t *testing.T, args ...string) (int, absenceView, string) {
	t.Helper()
	code, out := exec(t, append(args, "--json"))
	var v absenceView
	require.NoError(t, json.Unmarshal([]byte(out), &v), out)
	return code, v, out
}

// The absence command replaces an archived proof that does not verify and
// keeps one that does: write-once by key would otherwise leave a bad copy
// in place for good.
func TestAbsenceCommandRepairsTheArchive(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	serveProofs(t, ac)
	gk := gatePubHex(t)
	trusted := ac.trustedAt(t)
	mid := ac.ref.Height + 1
	args := func(dir string, h [32]byte) []string {
		return []string{"absence", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", trusted,
			"--absence-source", "http://bridge.test:26658"}
	}

	t.Run("a bad archived proof is replaced, good ones kept", func(t *testing.T) {
		dir, h := ac.withRecord(mid, ac.badDAH(mid)).pendingArchive(t, ac.ref.Height, mid, ac.deadline)
		code, v, out := runAbsenceJSON(t, args(dir, h)...)
		require.Equal(t, codeValid, code, out)
		assert.Equal(t, "absent", v.Result)
		assert.Equal(t, 1, v.Written)
		assert.Equal(t, 2, v.Kept)
		for _, hv := range v.PerHeight {
			assert.Equal(t, hv.Height == mid, hv.Replaced, "height %d", hv.Height)
			assert.Equal(t, hv.Height != mid, hv.Kept, "height %d", hv.Height)
		}

		s, err := fsarchive.OpenReadOnly(dir, nil)
		require.NoError(t, err)
		got, err := s.Absence(context.Background(), ac.ref.DA, ac.ref.Commitment, mid)
		require.NoError(t, err)
		assert.Equal(t, ac.recs[mid].DAH, got.DAH)

		code, fv := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", trusted)
		assert.Equal(t, codeInvalid, code)
		assert.Equal(t, "failed", fv.Publication)

		_, text := exec(t, args(dir, h))
		assert.Contains(t, text, "a verifying proof is already archived")
		assert.Contains(t, text, "3 already archived")
	})
	t.Run("an archived proof without a header is replaced", func(t *testing.T) {
		headerless, err := (&cmtproto.SignedHeader{Commit: &cmtproto.Commit{Height: int64(mid)}}).Marshal()
		require.NoError(t, err)
		bad := *ac.recs[mid]
		bad.Header = headerless
		dir, h := ac.withRecord(mid, &bad).pendingArchive(t, mid)
		var (
			code int
			v    absenceView
			out  string
		)
		require.NotPanics(t, func() { code, v, out = runAbsenceJSON(t, args(dir, h)...) })
		require.Equal(t, codeValid, code, out)
		for _, hv := range v.PerHeight {
			assert.Equal(t, hv.Height == mid, hv.Replaced, "height %d", hv.Height)
		}
	})
	t.Run("a corrupt file under the key is replaced", func(t *testing.T) {
		dir, h := ac.pendingArchive(t)
		rel, err := archive.AbsencePath(ac.ref.DA, ac.ref.Commitment, mid)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), []byte{0xff, 0x00}, 0o600))
		code, _, out := runAbsenceJSON(t, args(dir, h)...)
		require.Equal(t, codeValid, code, out)
		s, err := fsarchive.OpenReadOnly(dir, nil)
		require.NoError(t, err)
		got, err := s.Absence(context.Background(), ac.ref.DA, ac.ref.Commitment, mid)
		require.NoError(t, err)
		assert.Equal(t, ac.recs[mid].Header, got.Header)
	})
	t.Run("a proven height that is not written exits 2 and names the path", func(t *testing.T) {
		dir, h := ac.pendingArchive(t)
		rel, err := archive.AbsencePath(ac.ref.DA, ac.ref.Commitment, mid)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, rel), 0o700), "a directory where the record goes")
		code, v, out := runAbsenceJSON(t, args(dir, h)...)
		require.Equal(t, codeUnchecked, code, out)
		assert.Equal(t, "absent", v.Result, "every height verified")
		assert.Equal(t, 2, v.Written)
		for _, hv := range v.PerHeight {
			if hv.Height == mid {
				assert.False(t, hv.Written)
				assert.Contains(t, hv.Error, rel)
			}
		}
		code, text := exec(t, args(dir, h))
		assert.Equal(t, codeUnchecked, code)
		assert.Contains(t, text, "verified, not written to "+rel)
	})
}

// countingProofs counts the signed header reads of each height.
type countingProofs struct {
	vectorProofs
	mu    sync.Mutex
	reads map[uint64]int
}

func (c *countingProofs) SignedHeader(ctx context.Context, h uint64) ([]byte, error) {
	c.mu.Lock()
	c.reads[h]++
	c.mu.Unlock()
	return c.vectorProofs.SignedHeader(ctx, h)
}

// An archived proof whose header is not the chain's does not break the walk
// or block the height: --absence-source is asked first, and one walk from
// the checkpoint serves every height of the window.
func TestVerifyBadArchivedHeaderWithAbsenceSource(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	src := &countingProofs{vectorProofs: vectorProofs{ac}, reads: map[uint64]int{}}
	prev := newProofSource
	newProofSource = func(context.Context, string) (absence.ProofSource, string, func(), error) {
		return src, "bridge.test", func() {}, nil
	}
	t.Cleanup(func() { newProofSource = prev })

	mid := ac.ref.Height + 1
	forged := *ac.recs[mid]
	forged.Header = ac.recs[ac.ref.Height].Header
	dir, h := ac.withRecord(mid, &forged).pendingArchive(t, ac.ref.Height, mid, ac.deadline)
	code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gatePubHex(t),
		"--trusted", ac.trustedAt(t), "--absence-source", "http://bridge.test:26658")
	assert.Equal(t, codeInvalid, code)
	assert.Equal(t, "fail", v.check("anchor").Status, v.check("anchor").Error)
	assert.Equal(t, "failed", v.Publication)
	require.NotNil(t, v.Absence)
	assert.Equal(t, "absent", v.Absence.Result)

	// The walk reads each header below the checkpoint once; the fetcher
	// reads the header of the height whose archived proof failed.
	for x := ac.ref.Height; x <= ac.deadline; x++ {
		want := 1
		if x == mid {
			want = 2
		}
		assert.Equal(t, want, src.reads[x], "height %d", x)
	}
}
