package gatechain_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

type fakeDL struct {
	mu      sync.Mutex
	data    []byte
	err     error
	calls   int
	ids     [][33]byte
	heights []uint64
	limits  []uint64
}

var _ node.FibreDownloader = (*fakeDL)(nil)

func (d *fakeDL) Download(_ context.Context, id [33]byte, promiseHeight, maxSize uint64) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	d.ids = append(d.ids, id)
	d.heights = append(d.heights, promiseHeight)
	d.limits = append(d.limits, maxSize)
	if d.err != nil {
		return nil, d.err
	}
	if d.data == nil {
		return nil, node.ErrNotFound
	}
	return d.data, nil
}

func (d *fakeDL) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func committer(t testing.TB) *fibrecommit.Committer {
	t.Helper()
	c, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	return c
}

func blobsOver(t *testing.T, l live, direct, bridge node.FibreDownloader) gate.BlobSource {
	t.Helper()
	a := anchorsOver(liveBlock(t).chain(t, l), mochaID, func(o *gatechain.FibreAnchorOptions) { o.CacheBytes = 1 << 24 })
	return gatechain.NewFibreBlobs(a, direct, bridge, committer(t))
}

func TestFibreFetchDirectFirst(t *testing.T) {
	l := loadLive(t)
	direct, bridge := &fakeDL{data: l.payload}, &fakeDL{data: l.payload}
	got, err := blobsOver(t, l, direct, bridge).Fetch(bg, l.ref(), 1<<20)
	require.NoError(t, err)
	assert.Equal(t, l.payload, got)
	assert.Equal(t, 1, direct.count())
	assert.Zero(t, bridge.count(), "the bridge is only a fallback")
	assert.Equal(t, fibrecommit.BlobID([32]byte(l.commit)), direct.ids[0], "download by 0x00 || commitment")
	assert.Equal(t, l.promiseH, direct.heights[0], "the promise height, not the PFF height")
	assert.EqualValues(t, l.blobSize, direct.limits[0], "the downloader is bounded by the promised upload size")
}

func TestFibreFetchFallsBackToTheBridge(t *testing.T) {
	l := loadLive(t)
	tooBig := make([]byte, 300000)
	up, err := fibrecommit.UploadSize(uint64(len(tooBig)))
	require.NoError(t, err)
	require.NotEqual(t, uint64(l.blobSize), up)

	cases := []struct {
		name   string
		direct *fakeDL
	}{
		{"direct does not have it", &fakeDL{}},
		{"direct fails", &fakeDL{err: fmt.Errorf("%w: down", node.ErrUnavailable)}},
		{"direct bytes of another blob_size", &fakeDL{data: tooBig}},
		{"direct empty bytes", &fakeDL{data: []byte{}}},
		{"direct bytes the committer refuses", &fakeDL{data: []byte{0x66}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bridge := &fakeDL{data: l.payload}
			got, err := blobsOver(t, l, tc.direct, bridge).Fetch(bg, l.ref(), 1<<20)
			require.NoError(t, err)
			assert.Equal(t, l.payload, got)
			assert.Equal(t, 1, tc.direct.count())
			assert.Equal(t, 1, bridge.count())
			assert.Equal(t, l.promiseH, bridge.heights[0])
		})
	}
}

func TestFibreFetchNeverReturnsUncheckedBytes(t *testing.T) {
	l := loadLive(t)
	tooBig := make([]byte, 300000)
	t.Run("bridge-substituted blob is caught by the committer", func(t *testing.T) {
		bridge := &fakeDL{data: []byte{0x66}}
		got, err := blobsOver(t, l, &fakeDL{}, bridge).Fetch(bg, l.ref(), 1<<20)
		require.Error(t, err)
		assert.Empty(t, got)
		assert.Equal(t, 1, bridge.count())
	})
	t.Run("direct-substituted blob falls through and is not returned", func(t *testing.T) {
		got, err := blobsOver(t, l, &fakeDL{data: []byte{0x66}}, &fakeDL{}).Fetch(bg, l.ref(), 1<<20)
		require.Error(t, err)
		assert.Empty(t, got)
	})
	t.Run("blob_size mismatch from every source", func(t *testing.T) {
		got, err := blobsOver(t, l, &fakeDL{data: tooBig}, &fakeDL{data: tooBig}).Fetch(bg, l.ref(), 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
	})
	t.Run("nothing anywhere is not found", func(t *testing.T) {
		got, err := blobsOver(t, l, &fakeDL{}, &fakeDL{}).Fetch(bg, l.ref(), 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
	})
	t.Run("transport failures are not absence", func(t *testing.T) {
		down := fmt.Errorf("%w: down", node.ErrUnavailable)
		got, err := blobsOver(t, l, &fakeDL{err: down}, &fakeDL{err: down}).Fetch(bg, l.ref(), 1<<20)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
	})
	t.Run("one source down and the other missing is not absence", func(t *testing.T) {
		down := fmt.Errorf("%w: down", node.ErrUnavailable)
		_, err := blobsOver(t, l, &fakeDL{err: down}, &fakeDL{}).Fetch(bg, l.ref(), 1<<20)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
	})
	t.Run("not a Fibre reference", func(t *testing.T) {
		direct := &fakeDL{data: l.payload}
		ref := l.ref()
		ref.DA = commitment.DACelestiaBlob
		_, err := blobsOver(t, l, direct, nil).Fetch(bg, ref, 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Zero(t, direct.count())
	})
	t.Run("no anchor for the reference, nothing is downloaded", func(t *testing.T) {
		direct := &fakeDL{data: l.payload}
		ref := l.ref()
		ref.Commitment[0] ^= 1
		got, err := blobsOver(t, l, direct, nil).Fetch(bg, ref, 1<<20)
		require.ErrorIs(t, err, gate.ErrAnchorNotFound)
		assert.Empty(t, got)
		assert.Zero(t, direct.count())
	})
	t.Run("incomplete source fails closed", func(t *testing.T) {
		a := anchorsOver(liveBlock(t).chain(t, l), mochaID)
		for name, src := range map[string]gate.BlobSource{
			"no direct":    gatechain.NewFibreBlobs(a, nil, nil, committer(t)),
			"no committer": gatechain.NewFibreBlobs(a, &fakeDL{data: l.payload}, nil, nil),
			"no anchors":   gatechain.NewFibreBlobs(nil, &fakeDL{data: l.payload}, nil, committer(t)),
		} {
			got, err := src.Fetch(bg, l.ref(), 1<<20)
			require.ErrorIs(t, err, gate.ErrChainUnavailable, name)
			assert.Empty(t, got, name)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		direct := &fakeDL{data: l.payload}
		_, err := blobsOver(t, l, direct, nil).Fetch(ctx, l.ref(), 1<<20)
		require.Error(t, err)
		assert.Zero(t, direct.count())
	})
}

func TestFibreFetchWithoutBridgeFallbackUsesDirectOnly(t *testing.T) {
	l := loadLive(t)
	t.Run("direct serves", func(t *testing.T) {
		got, err := blobsOver(t, l, &fakeDL{data: l.payload}, nil).Fetch(bg, l.ref(), 1<<20)
		require.NoError(t, err)
		assert.Equal(t, l.payload, got)
	})
	t.Run("direct misses", func(t *testing.T) {
		direct := &fakeDL{}
		got, err := blobsOver(t, l, direct, nil).Fetch(bg, l.ref(), 1<<20)
		require.ErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
		assert.Equal(t, 1, direct.count())
	})
}

func TestFibreFetchHonoursMaxSize(t *testing.T) {
	l := loadLive(t)
	const max = 1000
	big := make([]byte, 262139)
	up, err := fibrecommit.UploadSize(uint64(len(big)))
	require.NoError(t, err)
	require.EqualValues(t, l.blobSize, up, "the blob fits the promised upload size")

	t.Run("returns maxSize+1 bytes of a larger blob and allocates no more", func(t *testing.T) {
		direct := &fakeDL{data: big}
		a := anchorsOver(liveBlock(t).chain(t, l), mochaID, func(o *gatechain.FibreAnchorOptions) { o.CacheBytes = 1 << 24 })
		src := gatechain.NewFibreBlobs(a, direct, nil, committer(t))
		_, err := a.FindAnchor(bg, l.ref())
		require.NoError(t, err)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		got, err := src.Fetch(bg, l.ref(), max)
		runtime.ReadMemStats(&after)
		require.NoError(t, err)
		assert.Len(t, got, max+1, "enough for the caller to see the blob is too big")
		assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(128<<10), "a copy of the whole blob was made")
	})
	t.Run("the oversized prefix is a copy", func(t *testing.T) {
		src := make([]byte, 262139)
		src[0] = 9
		got, err := blobsOver(t, l, &fakeDL{data: src}, nil).Fetch(bg, l.ref(), max)
		require.NoError(t, err)
		got[0] ^= 0xff
		assert.EqualValues(t, 9, src[0])
	})
	t.Run("blob_size above what maxSize+1 bytes can need is refused before the download", func(t *testing.T) {
		tx := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.BlobSize = 8 << 20 })
		a := anchorsOver(buildBlock(t, l.pffHeight, tx).chain(t, l), mochaID, skipCert)
		direct, bridge := &fakeDL{data: big}, &fakeDL{data: big}
		got, err := gatechain.NewFibreBlobs(a, direct, bridge, committer(t)).Fetch(bg, l.ref(), max)
		require.ErrorIs(t, err, gate.ErrPayloadAboveCap)
		assert.Empty(t, got)
		assert.Zero(t, direct.count()+bridge.count())
	})
	t.Run("exactly maxSize bytes are returned whole", func(t *testing.T) {
		got, err := blobsOver(t, l, &fakeDL{data: l.payload}, nil).Fetch(bg, l.ref(), uint64(len(l.payload)))
		require.NoError(t, err)
		assert.Equal(t, l.payload, got)
	})
	t.Run("the result is a copy of the source bytes", func(t *testing.T) {
		src := []byte{0x65}
		got, err := blobsOver(t, l, &fakeDL{data: src}, nil).Fetch(bg, l.ref(), 10)
		require.NoError(t, err)
		got[0] ^= 0xff
		assert.Equal(t, byte(0x65), src[0])
	})
	t.Run("an oversized bridge answer is never returned and is not absence", func(t *testing.T) {
		bridge := &fakeDL{data: big}
		got, err := blobsOver(t, l, &fakeDL{}, bridge).Fetch(bg, l.ref(), max)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
		assert.Equal(t, 1, bridge.count())
	})
	t.Run("a too-large error of the bridge is not absence", func(t *testing.T) {
		bridge := &fakeDL{err: fmt.Errorf("%w: %w", node.ErrUnavailable, node.ErrTooLarge)}
		got, err := blobsOver(t, l, &fakeDL{}, bridge).Fetch(bg, l.ref(), max)
		require.Error(t, err)
		assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
		assert.Empty(t, got)
	})
	t.Run("an oversized direct answer does not stop the fallback from being tried", func(t *testing.T) {
		direct, bridge := &fakeDL{data: big}, &fakeDL{data: l.payload}
		got, err := blobsOver(t, l, direct, bridge).Fetch(bg, l.ref(), max)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(got), max+1)
	})
}
