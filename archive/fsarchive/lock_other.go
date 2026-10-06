//go:build !unix

package fsarchive

import (
	"context"
	"errors"
)

func checkPlatform() error {
	return errors.New("fsarchive: unsupported platform: no directory locks")
}

func lockDir(context.Context, string) (func(), error) { return nil, checkPlatform() }
