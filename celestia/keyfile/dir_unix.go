//go:build darwin || linux

package keyfile

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CheckDir refuses a directory that another local user could change: it must
// be a directory itself (not a symlink to one), owned by the effective user
// and not writable by group or others. Whoever can write a directory can
// delete or replace the keys in it, even when the key files are 0600.
func CheckDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (a symlink is refused too)", ErrUnsafeDir, dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not by you (uid %d): use a directory you own, then chmod 700 %s", ErrUnsafeDir, dir, st.Uid, os.Geteuid(), dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others: run chmod 700 %s", ErrUnsafeDir, dir, dir)
	}
	return nil
}

// LockDir takes an exclusive lock on the file name in dir, creating it with
// mode 0600 when missing. A second holder, in this process or another, gets
// ErrLocked at once instead of waiting. The lock ends with unlock or with the
// process.
func LockDir(dir, name string) (unlock func(), err error) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keyfile: lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s: another run holds it; wait for it to finish", ErrLocked, path)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
