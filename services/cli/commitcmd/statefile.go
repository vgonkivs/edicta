// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/vgonkivs/edicta/internal/flock"
)

var hashName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// StateLockFile is the file in the state directory that a serving process
// keeps locked.
const StateLockFile = ".serve.lock"

// ErrStateDirInUse is returned when another process holds the state
// directory.
var ErrStateDirInUse = errors.New("commitcmd: state directory in use")

// maxStateFile bounds a stored state when it is read back.
const maxStateFile = 1 << 20

// FileStateStore keeps one file per commitment hash in a directory only the
// operator can read. A write goes to a temporary file that is synced and
// renamed over the target.
type FileStateStore struct{ dir string }

// NewFileStateStore creates dir (mode 0700) if it is missing.
func NewFileStateStore(dir string) (*FileStateStore, error) {
	if dir == "" {
		return nil, errors.New("commitcmd: empty state directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("commitcmd: state directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("commitcmd: state directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("commitcmd: state directory %s must be a directory only its owner can access", dir)
	}
	return &FileStateStore{dir: dir}, nil
}

// Save stores st under hash.
func (f *FileStateStore) Save(hash string, st State) error {
	if !hashName.MatchString(hash) {
		return fmt.Errorf("commitcmd: bad state name %q", hash)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(f.dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(f.dir, hash+".json")); err != nil {
		return err
	}
	// The rename is durable only once the directory entry is.
	d, err := os.Open(f.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Load returns the state stored under hash, if any.
func (f *FileStateStore) Load(hash string) (State, bool, error) {
	if !hashName.MatchString(hash) {
		return State{}, false, fmt.Errorf("commitcmd: bad state name %q", hash)
	}
	file, err := os.Open(filepath.Join(f.dir, hash+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	defer file.Close()
	var st State
	dec := json.NewDecoder(io.LimitReader(file, maxStateFile))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return State{}, false, fmt.Errorf("commitcmd: state %s: %w", hash, err)
	}
	return st, true, nil
}

// LockStateDir takes the state directory for this process, creating it as
// NewFileStateStore does, until unlock runs or the process ends. The relay
// handoff's once mark lives in the state files and the writes to them are
// ordered only inside one process, so a second process on the same directory
// could hand off the same deposit again: it gets ErrStateDirInUse at once
// instead of waiting. The lock is not reliable on network filesystems, and
// platforms without file locks are refused.
func LockStateDir(dir string) (unlock func(), err error) {
	if _, err := NewFileStateStore(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, StateLockFile)
	unlock, err = flock.TryLock(path)
	switch {
	case errors.Is(err, flock.ErrLocked):
		return nil, fmt.Errorf("%w: %s is held by another process", ErrStateDirInUse, path)
	case err != nil:
		return nil, fmt.Errorf("commitcmd: lock state directory: %w", err)
	}
	return unlock, nil
}
