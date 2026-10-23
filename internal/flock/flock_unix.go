// SPDX-License-Identifier: Apache-2.0

//go:build unix

package flock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// TryLock takes an exclusive lock on the file at path, creating it with mode
// 0600 when missing, and does not wait. A symlink at path is refused. Any
// refusal of the lock itself is ErrLocked, wrapping the system's error; a
// failure to open the file is returned as it is, so callers word both.
func TryLock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %w", ErrLocked, err)
	}
	return release(f), nil
}

// Lock opens the existing file or directory at path and waits for an
// exclusive lock on it. It polls rather than blocks so that ctx ends the
// wait: the pauses start at a millisecond and double up to poll (at least a
// millisecond). Errors, the ctx's included, are returned as they are.
func Lock(ctx context.Context, path string, poll time.Duration) (unlock func(), err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	poll = max(poll, time.Millisecond)
	wait := time.Millisecond
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return release(f), nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, ctx.Err()
		case <-t.C:
		}
		wait = min(wait*2, poll)
	}
}

func release(f *os.File) func() {
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}
