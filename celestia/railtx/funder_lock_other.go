//go:build !unix

package railtx

import "os"

func lockState(string) (func(), error) { return func() {}, nil }

func ownedByCaller(os.FileInfo) bool { return true }

const noFollow = 0
