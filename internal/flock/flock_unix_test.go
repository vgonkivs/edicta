// SPDX-License-Identifier: Apache-2.0

//go:build unix

package flock_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/flock"
)

func TestTryLockCreatesAndExcludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	unlock, err := flock.TryLock(path)
	require.NoError(t, err)
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	_, err = flock.TryLock(path)
	require.ErrorIs(t, err, flock.ErrLocked)
	var errno syscall.Errno
	require.ErrorAs(t, err, &errno)
	assert.Equal(t, syscall.EWOULDBLOCK, errno)

	unlock()
	again, err := flock.TryLock(path)
	require.NoError(t, err)
	again()
}

func TestTryLockRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	_, err := flock.TryLock(link)
	require.Error(t, err)
	assert.NotErrorIs(t, err, flock.ErrLocked)
	assert.ErrorIs(t, err, syscall.ELOOP)
}

func TestTryLockOpenFailureIsNotLocked(t *testing.T) {
	_, err := flock.TryLock(t.TempDir())
	require.Error(t, err)
	assert.NotErrorIs(t, err, flock.ErrLocked)
	var pe *os.PathError
	assert.ErrorAs(t, err, &pe)
}

func TestLockWaitsForTheHolder(t *testing.T) {
	dir := t.TempDir()
	unlock, err := flock.Lock(context.Background(), dir, 5*time.Millisecond)
	require.NoError(t, err)
	released := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(released)
		unlock()
	}()
	second, err := flock.Lock(context.Background(), dir, 5*time.Millisecond)
	require.NoError(t, err)
	select {
	case <-released:
	default:
		t.Fatal("the second lock was taken while the first was held")
	}
	second()
}

func TestLockEndsWithTheContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "held")
	unlock, err := flock.TryLock(path)
	require.NoError(t, err)
	defer unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = flock.Lock(ctx, path, time.Millisecond)
	require.ErrorIs(t, err, context.Canceled)

	dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer dcancel()
	_, err = flock.Lock(dctx, path, 0)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestLockNeedsAnExistingPath(t *testing.T) {
	_, err := flock.Lock(context.Background(), filepath.Join(t.TempDir(), "missing"), time.Millisecond)
	require.ErrorIs(t, err, os.ErrNotExist)
}
