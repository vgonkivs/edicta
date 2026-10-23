// SPDX-License-Identifier: Apache-2.0

package signercmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The exit codes and texts are those of the global ExitOnError flag set the
// command parsed with before: 0 on -h, 2 on a flag error, 1 on a run error.
func TestMainExitCodes(t *testing.T) {
	example, err := filepath.Abs("../signer.example.toml")
	assert.NoError(t, err)
	tests := []struct {
		args       []string
		code       int
		out, inErr string
	}{
		{[]string{"x", "-h"}, 0, "", "Usage of x:\n  -check-config\n"},
		{[]string{"x", "--help"}, 0, "", "Usage of x:"},
		{[]string{"x", "--bogus"}, 2, "", "flag provided but not defined: -bogus\nUsage of x:"},
		{[]string{"x", "-config"}, 2, "", "flag needs an argument: -config"},
		{[]string{"x"}, 1, "", "edicta-signer: -config is required\n"},
		{nil, 1, "", "edicta-signer: -config is required\n"},
		{[]string{"x", "-config", "/nonexistent", "-check-config"}, 1, "", "edicta-signer: reading config:"},
		{[]string{"x", "-config", example, "-check-config"}, 0, "configuration ok\n", ""},
		{[]string{"x", "extra", "-config", example, "-check-config"}, 1, "", "-config is required"},
		{[]string{"/usr/local/bin/edicta signer serve"}, 1, "", "edicta signer serve: -config is required\n"},
		{[]string{"/usr/local/bin/edicta-signer"}, 1, "", "edicta-signer: -config is required\n"},
	}
	for _, tc := range tests {
		var out, errOut bytes.Buffer
		assert.Equal(t, tc.code, Main(tc.args, &out, &errOut), "%q: %s", tc.args, errOut.String())
		assert.Equal(t, tc.out, out.String(), "%q", tc.args)
		assert.Contains(t, errOut.String(), tc.inErr, "%q", tc.args)
	}
}
