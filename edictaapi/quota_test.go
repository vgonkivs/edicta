package edictaapi_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
)

func TestQuotaBlobsPerHour(t *testing.T) {
	clk := newClock(nowVec)
	q := edictaapi.NewQuota(edictaapi.QuotaConfig{BlobsPerHour: 3, BytesPerDay: 1 << 20}, clk)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		require.NoError(t, q.Allow(ctx, "a", 1))
	}
	require.ErrorIs(t, q.Allow(ctx, "a", 1), edictaapi.ErrQuotaExceeded)
	require.NoError(t, q.Allow(ctx, "b", 1), "per-agent")
	clk.Advance(time.Hour)
	require.NoError(t, q.Allow(ctx, "a", 1), "tokens return")
}

func TestQuotaBytesPerDay(t *testing.T) {
	clk := newClock(nowVec)
	q := edictaapi.NewQuota(edictaapi.QuotaConfig{BlobsPerHour: 100, BytesPerDay: 100}, clk)
	ctx := context.Background()
	require.NoError(t, q.Allow(ctx, "a", 60))
	require.ErrorIs(t, q.Allow(ctx, "a", 60), edictaapi.ErrQuotaExceeded)
	require.NoError(t, q.Allow(ctx, "a", 40), "a refused request consumes nothing")
	require.ErrorIs(t, q.Allow(ctx, "a", 1), edictaapi.ErrQuotaExceeded)
	require.ErrorIs(t, q.Allow(ctx, "c", 101), edictaapi.ErrQuotaExceeded, "larger than the daily budget never fits")
	clk.Advance(24 * time.Hour)
	require.NoError(t, q.Allow(ctx, "a", 100))
}

func TestQuotaRefusalIsAtomic(t *testing.T) {
	q := edictaapi.NewQuota(edictaapi.QuotaConfig{BlobsPerHour: 2, BytesPerDay: 10}, newClock(nowVec))
	ctx := context.Background()
	require.ErrorIs(t, q.Allow(ctx, "a", 20), edictaapi.ErrQuotaExceeded)
	require.NoError(t, q.Allow(ctx, "a", 5), "refusal on bytes did not take a blob token")
	require.NoError(t, q.Allow(ctx, "a", 5))
	require.ErrorIs(t, q.Allow(ctx, "a", 0), edictaapi.ErrQuotaExceeded)
}

func TestQuotaConcurrent(t *testing.T) {
	q := edictaapi.NewQuota(edictaapi.QuotaConfig{BlobsPerHour: 10, BytesPerDay: 1 << 20}, newClock(nowVec))
	var ok, refused atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := q.Allow(context.Background(), "a", 1); {
			case err == nil:
				ok.Add(1)
			default:
				require.ErrorIs(t, err, edictaapi.ErrQuotaExceeded)
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int64(10), ok.Load())
	require.Equal(t, int64(90), refused.Load())
}
