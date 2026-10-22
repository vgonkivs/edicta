//go:build unix

package fsarchive_test

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/test/archivefix"
)

func TestLockWaitHonoursContext(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	_, err := s.Put(bg, fx.Cases["decision_minimal_lmt"].Record)
	require.NoError(t, err)

	f, err := os.Open(dir)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX))

	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err = s.Put(ctx, fx.Cases["rejection_minimal_lmt_not_yet_valid"].Record)
	require.ErrorIs(t, err, context.Canceled)

	dctx, dcancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
	defer dcancel()
	_, err = s.Put(dctx, fx.Cases["authorization_minimal_lmt_da"].Record)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_UN))
	_, err = s.Put(bg, fx.Cases["rejection_minimal_lmt_not_yet_valid"].Record)
	require.NoError(t, err)
}
