//go:build !unix

package railtx

import (
	"errors"
	"os"
)

// The funder needs a file lock and an owner check; without them it refuses to
// run rather than guard nothing.
func lockState(string) (func(), error) {
	return nil, errors.New("funder state locking is not supported on this platform")
}

func ownedByCaller(os.FileInfo) bool { return false }

const noFollow = 0
