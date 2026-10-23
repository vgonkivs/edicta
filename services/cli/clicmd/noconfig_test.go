// SPDX-License-Identifier: Apache-2.0

package clicmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/verifycli"
)

func TestWithoutNoConfig(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
		on   bool
	}{
		{nil, nil, false},
		{[]string{"verify"}, []string{"verify"}, false},
		{[]string{"verify", "H", "--json"}, []string{"verify", "H", "--json"}, false},
		{[]string{"verify", "--no-config", "H"}, []string{"verify", "H"}, true},
		{[]string{"replay", "H", "-no-config"}, []string{"replay", "H"}, true},
		{[]string{"absence", "--no-config=true", "H"}, []string{"absence", "H"}, true},
		{[]string{"verify", "--no-config=false", "H"}, []string{"verify", "H"}, false},
		{[]string{"verify", "--no-config", "--no-config=0", "H"}, []string{"verify", "H"}, false},
		{[]string{"verify", "--no-config=maybe", "H"}, []string{"verify", "--no-config=maybe", "H"}, false},
		{[]string{"verify", "---no-config", "H"}, []string{"verify", "---no-config", "H"}, false},
		{[]string{"verify", "H", "--", "--no-config"}, []string{"verify", "H", "--", "--no-config"}, false},
	}
	for _, tc := range tests {
		got, on := withoutNoConfig(tc.in)
		assert.Equal(t, tc.want, got, "%q", tc.in)
		assert.Equal(t, tc.on, on, "%q", tc.in)
	}
}

// With --no-config the merged command is the former standalone verifier: the
// same output and exit code as the library entry point without defaults,
// whatever edicta.toml says.
func TestNoConfigIsVerifyWithoutDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv(config.EnvHome, home)
	require.NoError(t, os.WriteFile(filepath.Join(home, config.FileName), []byte("this is = = not toml\n"), 0o600))

	h := hex.EncodeToString(make([]byte, 32))
	key := hex.EncodeToString(make([]byte, 32))
	archive := t.TempDir()
	for _, args := range [][]string{
		{"verify"},
		{"verify", "-h"},
		{"verify", "--help", "--json"},
		{"replay", "--help"},
		{"absence", "--help"},
		{"verify", h},
		{"verify", h, "--bogus"},
		{"verify", h, "--config", filepath.Join(home, config.FileName)},
		{"verify", h, "--gate-key", key, "--archive", archive},
		{"verify", "--gate-key", key, "--archive", archive, "--json", h},
		{"replay", h, "--gate-key", key},
		{"absence", h, "--gate-key", key, "--archive", archive},
	} {
		var want bytes.Buffer
		wantCode := verifycli.Run(context.Background(), args, &want)
		for _, at := range []int{1, len(args)} {
			withFlag := append(append(append([]string{}, args[:at]...), "--no-config"), args[at:]...)
			code, out := edicta(t, withFlag...)
			assert.Equal(t, wantCode, code, "%q", withFlag)
			assert.Equal(t, want.String(), out, "%q", withFlag)
		}
	}
}

// Without --no-config the default edicta.toml is read, so a broken one stops
// the run; --no-config=false keeps that.
func TestWithoutNoConfigTheDefaultFileIsRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv(config.EnvHome, home)
	require.NoError(t, os.WriteFile(filepath.Join(home, config.FileName), []byte("this is = = not toml\n"), 0o600))
	h := hex.EncodeToString(make([]byte, 32))
	key := hex.EncodeToString(make([]byte, 32))
	archive := t.TempDir()

	for _, extra := range [][]string{nil, {"--no-config=false"}} {
		args := append([]string{"verify", h, "--gate-key", key, "--archive", archive}, extra...)
		code, out := edicta(t, args...)
		assert.Equal(t, exitUsage, code, out)
		assert.Contains(t, out, "invalid configuration", "the config file was read")
	}

	code, out := edicta(t, "verify", h, "--gate-key", key, "--archive", archive, "--no-config")
	assert.NotContains(t, out, "invalid configuration", "the config file is not read")
	var want bytes.Buffer
	assert.Equal(t, verifycli.Run(context.Background(), []string{"verify", h, "--gate-key", key, "--archive", archive}, &want), code)
	assert.Equal(t, want.String(), out)
	assert.False(t, strings.Contains(out, "flag provided but not defined"), out)
}
