//go:build unix

package fsarchive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func checkPlatform() error { return nil }

// lockDir takes an exclusive advisory lock on the store directory, so that
// writers in other processes serialize too. It polls so that a cancelled ctx
// ends the wait.
func lockDir(ctx context.Context, dir string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: lock: %w", err)
	}
	wait := time.Millisecond
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("fsarchive: lock: %w", err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, fmt.Errorf("fsarchive: lock: %w", ctx.Err())
		case <-t.C:
		}
		wait = min(wait*2, 50*time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
