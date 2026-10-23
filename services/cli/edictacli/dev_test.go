// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package edictacli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/services/cli/devinitcmd"
)

func TestDevInitRunsTheDevInitBody(t *testing.T) {
	r := edicta(t)
	assert.Contains(t, r.stdout, "dev init", "the usage offers it")
	r = edicta(t, "--help")
	assert.Contains(t, r.stdout, "\n  dev ")

	for _, a := range [][]string{{"-h"}, {}, {"--bogus"}, {"--home", t.TempDir(), "extra"}, {"-home", t.TempDir(), "-escrow-address", "0x01"}} {
		var o, e bytes.Buffer
		want := devinitcmd.Main(append([]string{os.Args[0] + " dev init"}, a...), &o, &e)
		got := edicta(t, append([]string{"dev", "init"}, a...)...)
		assert.Equal(t, result{want, o.String(), e.String()}, got, "%q", a)
	}

	r = edicta(t, "dev")
	assert.Equal(t, exitUsage, r.code)
}
