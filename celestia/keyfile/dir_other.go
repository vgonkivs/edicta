//go:build !(darwin || linux)

package keyfile

import (
	"errors"
	"fmt"
	"os"
)

var errPlatform = errors.New("keyfile: this platform is not supported")

// CheckDir cannot check ownership on this platform; it refuses instead of
// passing a directory it did not check.
func CheckDir(dir string) error {
	if _, err := os.Lstat(dir); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return errPlatform
}

// LockDir is not available on this platform.
func LockDir(string, string) (func(), error) { return nil, errPlatform }
