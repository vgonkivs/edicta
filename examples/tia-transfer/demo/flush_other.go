//go:build !linux && !darwin

package demo

import "errors"

func flushInput(int) error { return errors.New("demo: cannot flush the terminal on this platform") }
