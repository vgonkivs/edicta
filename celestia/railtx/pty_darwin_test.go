//go:build darwin

package railtx_test

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	require.NoError(t, err)
	fd := m.Fd()
	require.NoError(t, unix.IoctlSetInt(int(fd), unix.TIOCPTYGRANT, 0))
	require.NoError(t, unix.IoctlSetInt(int(fd), unix.TIOCPTYUNLK, 0))
	var name [128]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	require.Zero(t, errno)
	path, _, _ := strings.Cut(string(name[:]), "\x00")
	s, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	return m, s
}
