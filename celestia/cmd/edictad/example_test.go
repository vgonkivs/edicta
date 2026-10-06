package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
)

// TestExampleConfigParses keeps the example the README points to in step with
// the parser.
func TestExampleConfigParses(t *testing.T) {
	b, err := os.ReadFile("edictad.example.toml")
	require.NoError(t, err)
	s := strings.ReplaceAll(string(b), "<58 hex characters>", strings.Repeat("ab", 29))
	s = strings.ReplaceAll(s, "<64 hex characters>", strings.Repeat("cd", 32))
	_, err = edictad.ParseConfig([]byte(s))
	require.NoError(t, err)
}

// The example is the one place an operator learns the keys of both modes.
func TestExampleConfigCoversBothModes(t *testing.T) {
	b, err := os.ReadFile("edictad.example.toml")
	require.NoError(t, err)
	s := string(b)
	for _, want := range []string{`da = "celestia_blob"`, "[archive]", "fibre_chain_ids", "[fibre]", "bridge_fallback"} {
		require.Contains(t, s, want)
	}
	require.NotContains(t, s, `da = "blob"`)
}
