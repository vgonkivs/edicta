//go:build darwin || linux

package keyfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/vgonkivs/edicta/internal/flock"
)

// geteuid is replaced by tests to look at the files as another user.
var geteuid = os.Geteuid

// maxLinks bounds the symlinks ResolveDir follows, so a loop ends.
const maxLinks = 40

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
	if uid, ok := owner(fi); ok && uid != geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not by you (uid %d): use a directory you own, then chmod 700 %s", ErrUnsafeDir, dir, uid, geteuid(), dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others: run chmod 700 %s", ErrUnsafeDir, dir, dir)
	}
	return nil
}

// ResolveDir follows every symlink in the absolute path dir and returns the
// directory it names, with no symlink left in it. Each step on the way must
// be safe from other local users: a directory must be owned by root or the
// effective user and not writable by group or others unless it is sticky (as
// /tmp is), and a symlink must be owned by root or the effective user.
// Otherwise someone else could move or re-point the path after it was
// checked. The directory itself must pass CheckDir.
func ResolveDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("keyfile: %s is not an absolute path", dir)
	}
	done := string(filepath.Separator)
	fi, err := os.Lstat(done)
	if err != nil {
		return "", fmt.Errorf("keyfile: %w", err)
	}
	if err := checkParent(done, fi); err != nil {
		return "", err
	}
	rest := splitPath(dir)
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			// done holds no symlink, so its parent is the one the kernel
			// would take, and it was checked on the way down.
			done = filepath.Dir(done)
			continue
		}
		next := filepath.Join(done, name)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", fmt.Errorf("keyfile: %w", err)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			if links++; links > maxLinks {
				return "", fmt.Errorf("keyfile: %s: too many symlinks", dir)
			}
			if uid, ok := owner(fi); ok && uid != 0 && uid != geteuid() {
				return "", fmt.Errorf("%w: the symlink %s is owned by uid %d, neither root nor you (uid %d): anyone who owns it can re-point it", ErrUnsafeDir, next, uid, geteuid())
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", fmt.Errorf("keyfile: %w", err)
			}
			if filepath.IsAbs(target) {
				done = string(filepath.Separator)
			}
			rest = slices.Concat(splitPath(target), rest)
		case fi.IsDir():
			// The directory the path ends in gets the stricter CheckDir.
			if !last(rest) {
				if err := checkParent(next, fi); err != nil {
					return "", err
				}
			}
			done = next
		default:
			return "", fmt.Errorf("%w: %s is not a directory", ErrUnsafeDir, next)
		}
	}
	if err := CheckDir(done); err != nil {
		return "", err
	}
	return done, nil
}

// checkParent applies the rule for a directory above a key directory.
func checkParent(dir string, fi fs.FileInfo) error {
	if uid, ok := owner(fi); ok && uid != 0 && uid != geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, neither root nor you (uid %d): its owner can move what is inside", ErrUnsafeDir, dir, uid, geteuid())
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%w: %s is writable by group or others and not sticky: they can move what is inside; use a directory only you can change", ErrUnsafeDir, dir)
	}
	return nil
}

func owner(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// last reports whether the components left name no other directory.
func last(rest []string) bool {
	for _, name := range rest {
		if name != "" && name != "." {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	return strings.Split(p, string(filepath.Separator))
}

// LockDir takes an exclusive lock on the file name in dir, creating it with
// mode 0600 when missing. A second holder, in this process or another, gets
// ErrLocked at once instead of waiting. The lock ends with unlock or with the
// process.
func LockDir(dir, name string) (unlock func(), err error) {
	path := filepath.Join(dir, name)
	unlock, err = flock.TryLock(path)
	switch {
	case errors.Is(err, flock.ErrLocked):
		return nil, fmt.Errorf("%w: %s: another run holds it; wait for it to finish", ErrLocked, path)
	case err != nil:
		return nil, fmt.Errorf("keyfile: lock %s: %w", path, err)
	}
	return unlock, nil
}
