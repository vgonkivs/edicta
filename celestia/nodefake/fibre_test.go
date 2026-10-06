package nodefake_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

var (
	_ node.FibreAnchorReader = (*nodefake.FibreChain)(nil)
	_ node.FibreDownloader   = (*nodefake.Downloader)(nil)
)

var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func TestFibreChainServesWhatWasAdded(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewFibreChain()
	hash := [32]byte{1}
	c.AddHeader(10, []byte("dh10"), t0)
	c.SetDAH(10, [][]byte{[]byte("r0"), []byte("r1")}, [][]byte{[]byte("c0"), []byte("c1")})
	nd := shwap.NamespaceData{{}}
	c.SetNamespaceData(10, nd)
	c.SetTxCode(10, hash, 7)
	c.SetHistoricalInfo(4, []byte("hi"))
	c.SetSignedHeader(4, []byte("hdr"))

	h, err := c.Header(ctx, 10)
	require.NoError(t, err)
	assert.EqualValues(t, 10, h.Height)
	assert.Equal(t, []byte("dh10"), h.DataHash)
	assert.True(t, t0.Equal(h.Time))

	dah, err := c.DAH(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("r0"), []byte("r1")}, dah.RowRoots)
	assert.Equal(t, [][]byte{[]byte("c0"), []byte("c1")}, dah.ColumnRoots)

	got, err := c.NamespaceData(ctx, 10, libshare.PayForFibreNamespace)
	require.NoError(t, err)
	assert.Len(t, got, 1)

	code, err := c.TxCode(ctx, 10, hash)
	require.NoError(t, err)
	assert.EqualValues(t, 7, code)
	code, err = c.TxCode(ctx, 10, [32]byte{2})
	require.NoError(t, err)
	assert.Zero(t, code, "a tx without a scripted result has code 0")
	code, err = c.TxCode(ctx, 11, hash)
	require.NoError(t, err)
	assert.Zero(t, code, "the script is per height")

	hi, err := c.HistoricalInfo(ctx, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), hi)
	hdr, err := c.SignedHeader(ctx, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("hdr"), hdr)

	assert.Equal(t, 1, c.HeaderReads())
	dr, nr := c.BridgeReads()
	assert.Equal(t, 1, dr)
	assert.Equal(t, 1, nr)
}

func TestFibreChainMissingIsNotFound(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewFibreChain()
	_, err := c.Header(ctx, 1)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.DAH(ctx, 1)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.NamespaceData(ctx, 1, libshare.PayForFibreNamespace)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.HistoricalInfo(ctx, 1)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.SignedHeader(ctx, 1)
	assert.ErrorIs(t, err, node.ErrNotFound)
}

func TestFibreChainFailSplitsConsensusAndBridge(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewFibreChain()
	c.AddHeader(1, []byte("d"), t0)
	c.SetDAH(1, nil, nil)
	c.SetNamespaceData(1, nil)

	c.Fail = nodefake.ErrInjected
	_, e1 := c.Header(ctx, 1)
	_, e2 := c.TxCode(ctx, 1, [32]byte{})
	_, e3 := c.HistoricalInfo(ctx, 1)
	_, e4 := c.SignedHeader(ctx, 1)
	for _, err := range []error{e1, e2, e3, e4} {
		assert.ErrorIs(t, err, nodefake.ErrInjected)
	}
	_, err := c.DAH(ctx, 1)
	require.NoError(t, err, "Fail does not touch the bridge")
	_, err = c.NamespaceData(ctx, 1, libshare.PayForFibreNamespace)
	require.NoError(t, err)

	c.Fail = nil
	c.FailBridge = nodefake.ErrInjected
	_, err = c.DAH(ctx, 1)
	assert.ErrorIs(t, err, nodefake.ErrInjected)
	_, err = c.NamespaceData(ctx, 1, libshare.PayForFibreNamespace)
	assert.ErrorIs(t, err, nodefake.ErrInjected)
	_, err = c.Header(ctx, 1)
	require.NoError(t, err, "FailBridge does not touch the consensus reads")
}

func TestFibreChainHeightIgnoringAnswersWithTheOtherHeader(t *testing.T) {
	c := nodefake.NewFibreChain()
	c.AddHeader(10, []byte("dh10"), t0)
	c.AddHeader(11, []byte("dh11"), t0)
	c.IgnoreHeights(11)
	h, err := c.Header(context.Background(), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 11, h.Height, "the answer names its own height, so a caller can catch it")
	assert.Equal(t, []byte("dh11"), h.DataHash)
}

func TestFibreChainReturnsCopies(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewFibreChain()
	dh, row, hist := []byte("dh"), []byte("row"), []byte("hist")
	c.AddHeader(1, dh, t0)
	c.SetDAH(1, [][]byte{row}, [][]byte{row})
	c.SetHistoricalInfo(1, hist)
	c.SetSignedHeader(1, hist)
	dh[0] ^= 0xff
	row[0] ^= 0xff
	hist[0] ^= 0xff

	h, err := c.Header(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("dh"), h.DataHash)
	h.DataHash[0] ^= 0xff
	again, err := c.Header(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("dh"), again.DataHash)

	d, err := c.DAH(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("row"), d.RowRoots[0])
	d.RowRoots[0][0] ^= 0xff
	d, err = c.DAH(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("row"), d.RowRoots[0])

	b, err := c.HistoricalInfo(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hist"), b)
	b[0] ^= 0xff
	b, err = c.SignedHeader(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hist"), b)
}

func TestFibreChainConcurrentUse(t *testing.T) {
	c := nodefake.NewFibreChain()
	c.AddHeader(1, []byte("d"), t0)
	c.SetDAH(1, [][]byte{{1}}, [][]byte{{2}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, err := c.Header(context.Background(), 1)
				assert.NoError(t, err)
				_, err = c.DAH(context.Background(), 1)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 400, c.HeaderReads())
	dr, _ := c.BridgeReads()
	assert.Equal(t, 400, dr)
}

func TestDownloaderRefusesAboveMaxSize(t *testing.T) {
	d := nodefake.NewDownloader()
	var id [33]byte
	d.Put(id, []byte("blob"))
	_, err := d.Download(context.Background(), id, 1, 3)
	require.ErrorIs(t, err, node.ErrTooLarge)
	got, err := d.Download(context.Background(), id, 1, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), got)
}

func TestAddHeaderCarriesTheFibreAppVersion(t *testing.T) {
	c := nodefake.NewFibreChain()
	c.AddHeader(5, []byte{1}, time.Unix(1, 0))
	h, err := c.Header(context.Background(), 5)
	require.NoError(t, err)
	assert.EqualValues(t, node.FibreAppVersion, h.AppVersion)
	c.SetAppVersion(5, 9)
	h, err = c.Header(context.Background(), 5)
	require.NoError(t, err)
	assert.EqualValues(t, 9, h.AppVersion)
}

func TestDownloaderServesByBlobID(t *testing.T) {
	ctx := context.Background()
	d := nodefake.NewDownloader()
	var id, other [33]byte
	id[1], other[1] = 1, 2
	d.Put(id, []byte("blob"))

	got, err := d.Download(ctx, id, 99, 1<<20)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), got)
	_, err = d.Download(ctx, other, 99, 1<<20)
	assert.ErrorIs(t, err, node.ErrNotFound)
	assert.Equal(t, 2, d.Calls())

	d.Fail = nodefake.ErrInjected
	_, err = d.Download(ctx, id, 99, 1<<20)
	assert.ErrorIs(t, err, nodefake.ErrInjected)
	assert.Equal(t, 3, d.Calls(), "failed calls are counted too")
}

func TestDownloaderCanceledContext(t *testing.T) {
	d := nodefake.NewDownloader()
	var id [33]byte
	d.Put(id, []byte("blob"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.Download(ctx, id, 1, 1<<20)
	assert.ErrorIs(t, err, context.Canceled)
}
