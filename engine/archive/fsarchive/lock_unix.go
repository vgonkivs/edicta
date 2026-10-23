// SPDX-License-Identifier: Apache-2.0

//go:build unix

package fsarchive

import (
	"context"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/internal/flock"
)

func checkPlatform() error { return nil }

// lockDir takes an exclusive advisory lock on the store directory, so that
// writers in other processes serialize too. A cancelled ctx ends the wait.
func lockDir(ctx context.Context, dir string) (func(), error) {
	unlock, err := flock.Lock(ctx, dir, 50*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: lock: %w", err)
	}
	return unlock, nil
}
