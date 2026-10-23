//go:build darwin

package demo

import "golang.org/x/sys/unix"

// flushInput drops the terminal's unread input.
func flushInput(fd int) error {
	const fread = 1 // FREAD: flush the input queue only
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread)
}
