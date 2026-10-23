// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package flock

import (
	"context"
	"time"
)

// TryLock is not available on this platform.
func TryLock(string) (func(), error) { return nil, ErrUnsupported }

// Lock is not available on this platform.
func Lock(context.Context, string, time.Duration) (func(), error) { return nil, ErrUnsupported }
