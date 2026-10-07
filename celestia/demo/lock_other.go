//go:build !(darwin || linux)

package demo

import "errors"

func lockHome(string) (func(), error) {
	return nil, errors.New("demo: this platform is not supported")
}
