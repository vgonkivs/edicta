//go:build unix

package railtx

import (
	"fmt"
	"os"
	"syscall"
)

// lockState takes an exclusive advisory lock on the file at path so two
// processes cannot hold the same funder key. The lock lives as long as the
// returned release function has not run. It is not reliable on network
// filesystems.
func lockState(path string) (release func(), err error) {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("held by another process: %w", err)
	}
	return func() { _ = fh.Close() }, nil
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
