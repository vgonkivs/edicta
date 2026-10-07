package cometrpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
)

const statusBody = `{"result":{"node_info":{"id":"ab"},"sync_info":{"latest_block_height":"7"}}}`

// busyThenOK answers busy times with code, then with a status result.
func busyThenOK(t *testing.T, busy int32, code int, retryAfter string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= busy {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(code)
			return
		}
		_, _ = w.Write([]byte(statusBody))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestRetryRidesOutBusyAnswers(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		srv, n := busyThenOK(t, 2, code, "")
		s, err := cometrpc.New(srv.URL, nil)
		require.NoError(t, err)
		h, err := s.WithRetry(3, time.Millisecond).Latest(bg)
		require.NoError(t, err, "status %d", code)
		assert.Equal(t, uint64(7), h)
		assert.EqualValues(t, 3, n.Load())
	}
}

func TestRetryHonoursRetryAfter(t *testing.T) {
	srv, n := busyThenOK(t, 1, http.StatusTooManyRequests, "1")
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	start := time.Now()
	_, err = s.WithRetry(2, time.Millisecond).Latest(bg)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, time.Since(start), time.Second)
	assert.EqualValues(t, 2, n.Load())
}

func TestRetryIsBounded(t *testing.T) {
	srv, n := busyThenOK(t, 100, http.StatusTooManyRequests, "")
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	_, err = s.WithRetry(2, time.Millisecond).Latest(bg)
	require.ErrorIs(t, err, cometrpc.ErrUnavailable)
	assert.EqualValues(t, 3, n.Load(), "one call and two retries")
}

func TestOtherFaultsAreNotRetried(t *testing.T) {
	srv, n := busyThenOK(t, 100, http.StatusInternalServerError, "")
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	_, err = s.WithRetry(3, time.Millisecond).Latest(bg)
	require.ErrorIs(t, err, cometrpc.ErrUnavailable)
	assert.EqualValues(t, 1, n.Load())
}

func TestRetryStopsWithTheContext(t *testing.T) {
	srv, _ := busyThenOK(t, 100, http.StatusTooManyRequests, "5")
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.WithRetry(3, time.Millisecond).Latest(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second)
}
