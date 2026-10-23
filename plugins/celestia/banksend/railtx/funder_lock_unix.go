//go:build unix

package railtx

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/vgonkivs/edicta/internal/flock"
)

// lockState takes an exclusive advisory lock on the file at path so two
// processes cannot hold the same funder key. The lock lives as long as the
// returned release function has not run. It is not reliable on network
// filesystems.
func lockState(path string) (release func(), err error) {
	release, err = flock.TryLock(path)
	var errno syscall.Errno
	if errors.Is(err, flock.ErrLocked) && errors.As(err, &errno) {
		return nil, fmt.Errorf("held by another process: %w", errno)
	}
	return release, err
}

// ownedByCaller reports whether fi belongs to the effective user.
func ownedByCaller(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// noFollow makes opening a symlink fail.
const noFollow = syscall.O_NOFOLLOW

// checkPlatform reports whether the state guards work here.
func checkPlatform() error { return nil }
