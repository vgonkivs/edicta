//go:build linux

package demo

import "golang.org/x/sys/unix"

// flushInput drops the terminal's unread input.
func flushInput(fd int) error { return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) }
