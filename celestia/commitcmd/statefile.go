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
)

var hashName = regexp.MustCompile(`^[0-9a-f]{64}$`)

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
	return os.Rename(tmp.Name(), filepath.Join(f.dir, hash+".json"))
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
