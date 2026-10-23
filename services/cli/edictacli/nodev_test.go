// SPDX-License-Identifier: Apache-2.0

//go:build !edictadev

package edictacli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDevExistsOnlyWithTheTag(t *testing.T) {
	r := edicta(t, "dev", "init")
	assert.Equal(t, exitUsage, r.code)
	assert.Contains(t, r.stdout, `unknown subcommand "dev"`)
	assert.NotContains(t, r.stdout, "dev init", "the usage does not offer it")

	r = edicta(t, "--help")
	assert.NotContains(t, r.stdout, "\n  dev ")
}
