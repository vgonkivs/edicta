// SPDX-License-Identifier: Apache-2.0

// Package flock takes exclusive advisory locks (flock(2)) on files and
// directories, so that processes sharing a path serialize. The locks are not
// reliable on network filesystems.
package flock

import "errors"

var (
	// ErrLocked: TryLock could not take the lock, normally because another
	// holder has it.
	ErrLocked = errors.New("flock: locked")
	// ErrUnsupported: this platform has no file locks.
	ErrUnsupported = errors.New("flock: not supported on this platform")
)
