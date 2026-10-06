//go:build !unix

package fsarchive

// lockDir has no cross-process lock on this platform; writers in one process
// still serialize.
func lockDir(string) (func(), error) { return func() {}, nil }
