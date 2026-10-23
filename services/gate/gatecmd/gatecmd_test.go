// SPDX-License-Identifier: Apache-2.0

package gatecmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exit codes and texts are those of the global ExitOnError flag set the
// daemon parsed with before: 0 on -h, 2 on a flag error, 1 on a run error.
func TestMainExitCodes(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "edicta.toml")
	require.NoError(t, os.WriteFile(cfg, edictaTOML(t, t.TempDir()), 0o600))
	tests := []struct {
		args         []string
		code         int
		inOut, inErr string
	}{
		{[]string{"x", "-h"}, 0, "", "Usage of x:\n  -config string\n"},
		{[]string{"x", "-help"}, 0, "", "Usage of x:"},
		{[]string{"x", "--bogus"}, 2, "", "flag provided but not defined: -bogus\nUsage of x:"},
		{[]string{"x", "--print-config=maybe"}, 2, "", "invalid boolean value"},
		{[]string{"x"}, 1, "", "edicta gate serve: -config is required\n"},
		{nil, 1, "", "edicta gate serve: -config is required\n"},
		{[]string{"x", "-config", "/nonexistent"}, 1, "", "edicta gate serve: reading config:"},
		{[]string{"x", "-config", cfg, "-print-config"}, 0, "gate_id = 'g'", ""},
	}
	for _, tc := range tests {
		var out, errOut bytes.Buffer
		assert.Equal(t, tc.code, Main(tc.args, &out, &errOut), "%q: %s", tc.args, errOut.String())
		assert.Contains(t, out.String(), tc.inOut, "%q", tc.args)
		assert.Contains(t, errOut.String(), tc.inErr, "%q", tc.args)
		if tc.inOut == "" {
			assert.Empty(t, out.String(), "%q", tc.args)
		}
	}
}
