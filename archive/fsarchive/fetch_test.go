package fsarchive_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func refOf(p *archive.PayloadRecord) commitment.PayloadRef {
	return commitment.PayloadRef{DA: p.DA, Namespace: p.Namespace, Commitment: p.Commitment, Height: 1, Signer: p.Signer}
}

// plantBlob stores a payload record with the given blob under its key and
// bypasses the store's recompute check.
func plantBlob(t *testing.T, fx *archivefix.Fixture, dir string, blob []byte) (*archive.PayloadRecord, []byte) {
	t.Helper()
	p := *fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	p.Blob = blob
	b, err := archive.Encode(&p)
	require.NoError(t, err)
	key, err := archive.KeyPath(&p)
	require.NoError(t, err)
	plant(t, dir, key, b)
	return &p, b
}

func TestFetchHugeBlobIsBounded(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	const maxSize = 1 << 20
	blob := make([]byte, 16<<20)
	for i := range blob {
		blob[i] = byte(i)
	}
	p, _ := plantBlob(t, fx, dir, blob)
	src := archive.NewGateSource(s)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := src.Fetch(bg, refOf(p), maxSize)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Len(t, got, maxSize+1)
	assert.Equal(t, blob[:maxSize+1], got)
	t.Logf("TotalAlloc delta: %d", after.TotalAlloc-before.TotalAlloc)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(2*maxSize+1<<20))
}

func TestFetchBlobAtLimitIsExact(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	blob := make([]byte, 200_000)
	p, _ := plantBlob(t, fx, dir, blob)
	got, err := archive.NewGateSource(s).Fetch(bg, refOf(p), uint64(len(blob)))
	require.NoError(t, err)
	assert.Len(t, got, len(blob))
}

func TestFetchTruncatedBlobIsCorrupt(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	blob := make([]byte, 200_000)
	p, enc := plantBlob(t, fx, dir, blob)
	key, err := archive.KeyPath(p)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(key)), enc[:len(enc)-len(blob)/2], 0o644))

	_, err = archive.NewGateSource(s).Fetch(bg, refOf(p), 1<<20)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
}

func TestFetchHeaderMismatchIsCorrupt(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	src := archive.NewGateSource(s)
	c := fx.Cases["payload_da2_minimal_lmt"]
	p := c.Record.(*archive.PayloadRecord)

	// A record of another commitment stored under this key.
	other := fx.Cases["payload_da2_256k"].Record.(*archive.PayloadRecord)
	otherBytes, err := archive.Encode(other)
	require.NoError(t, err)
	plant(t, dir, c.Key, otherBytes)
	_, err = src.Fetch(bg, refOf(p), 1<<20)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	// A da = 2 record stored under the da = 1 key of the same commitment.
	plant(t, dir, "payload/1/"+hexOf(p.Commitment), c.CBOR)
	ref := refOf(p)
	ref.DA = commitment.DAFibre
	_, err = src.Fetch(bg, ref, 1<<20)
	require.ErrorIs(t, err, archive.ErrCorrupt)
}

type cancelStore struct {
	archive.Store
	cancel context.CancelFunc
	inner  archive.PayloadStreamer
}

func (c cancelStore) PayloadReader(ctx context.Context, da commitment.DA, commit []byte) (io.ReadCloser, error) {
	rc, err := c.inner.PayloadReader(ctx, da, commit)
	if err != nil {
		return nil, err
	}
	return &cancelReader{ReadCloser: rc, cancel: c.cancel}, nil
}

// cancelReader cancels the context once the record header has been read.
type cancelReader struct {
	io.ReadCloser
	cancel context.CancelFunc
	n      int
}

func (r *cancelReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.n += n
	if r.n > 1000 {
		r.cancel()
	}
	return n, err
}

func TestFetchCancelledMidRead(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	p, _ := plantBlob(t, fx, dir, make([]byte, 1<<20))
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	src := archive.NewGateSource(cancelStore{Store: s, cancel: cancel, inner: s})

	_, err := src.Fetch(ctx, refOf(p), 1<<22)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFetchCancelledBeforeRead(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	p, _ := plantBlob(t, fx, dir, make([]byte, 1000))
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err := archive.NewGateSource(s).Fetch(ctx, refOf(p), 1<<20)
	require.ErrorIs(t, err, context.Canceled)
}

func TestK2DAMismatch(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	_, err := s.Put(bg, fx.Cases["decision_minimal_lmt"].Record)
	require.NoError(t, err)

	bad := *fx.Cases["authorization_minimal_lmt_da"].Record.(*archive.AuthorizationRecord)
	k := *fx.Cases["authorization_fibre_small_payload"].Record.(*archive.AuthorizationRecord).K2
	bad.K2 = &k
	_, err = s.Put(bg, &bad)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotContains(t, archivefix.Files(t, dir), fx.Cases["authorization_minimal_lmt_da"].Key)

	b, err := archive.Encode(&bad)
	require.NoError(t, err)
	plant(t, dir, fx.Cases["authorization_minimal_lmt_da"].Key, b)
	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	_, err = s.Authorization(bg, h)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	_, err = s.State(bg, h)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	good := fx.Cases["authorization_minimal_lmt_da"]
	plant(t, dir, good.Key, good.CBOR)
	_, err = s.Authorization(bg, h)
	require.NoError(t, err)
}

func TestOpenRemovesStaleTempFiles(t *testing.T) {
	fx := archivefix.Load(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "payload", "2")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	old, fresh, record := filepath.Join(sub, ".tmp-old"), filepath.Join(sub, ".tmp-fresh"), filepath.Join(sub, "keep")
	oldRoot := filepath.Join(dir, ".tmp-oldroot")
	for _, p := range []string{old, fresh, record, oldRoot} {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
	}
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, past, past))
	require.NoError(t, os.Chtimes(oldRoot, past, past))
	require.NoError(t, os.Chtimes(record, past, past))

	_, err := fsarchiveOpen(dir, fx)
	require.NoError(t, err)
	assert.NoFileExists(t, old)
	assert.NoFileExists(t, oldRoot)
	assert.FileExists(t, fresh)
	assert.FileExists(t, record)
}

func TestStoredRecordReads(t *testing.T) {
	fx := archivefix.Load(t)
	require.NotEmpty(t, fx.Reads)
	for _, r := range fx.Reads {
		t.Run(r.ID, func(t *testing.T) {
			s, dir := open(t, fx)
			for _, id := range r.Stored {
				c := fx.Cases[id]
				require.NotNil(t, c.CBOR, id)
				plant(t, dir, c.Key, c.CBOR)
			}
			require.Equal(t, "authorization", r.Kind)
			_, err := s.Authorization(bg, hashOf(t, r.Hash))
			if want := archivefix.ExpectedErr(t, r.Expect); want != nil {
				require.ErrorIs(t, err, want)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFetchTrailingGarbageIsCorrupt(t *testing.T) {
	fx := archivefix.Load(t)
	blob := make([]byte, 5000)
	for name, tail := range map[string][]byte{"one byte": {0xff}, "two bytes": {0x00, 0x00}, "an item": {0x01, 0x02}} {
		t.Run(name, func(t *testing.T) {
			s, dir := open(t, fx)
			p, enc := plantBlob(t, fx, dir, blob)
			key, err := archive.KeyPath(p)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(key)), append(append([]byte(nil), enc...), tail...), 0o644))

			_, err = archive.NewGateSource(s).Fetch(bg, refOf(p), 1<<20)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			assert.NotErrorIs(t, err, gate.ErrBlobNotFound)

			src, err := archive.NewStreamGateSource(s)
			require.NoError(t, err)
			_, err = src.Fetch(bg, refOf(p), 1<<20)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			assert.ErrorIs(t, err, gate.ErrArchiveUnavailable)
		})
	}
}
