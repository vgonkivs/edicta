package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMandateHash = "6d616e646174652d686173682d6f662d7468652d676174652d6d616e64617465"

func TestFastFlag(t *testing.T) {
	c, err := parse(t)
	require.NoError(t, err)
	assert.False(t, c.Fast, "off by default")

	c, err = parse(t, "--fast", "--archive-url", "https://archive.example.invalid/v1", "--mandate-hash", testMandateHash)
	require.NoError(t, err)
	assert.True(t, c.Fast)
	assert.Equal(t, "https://archive.example.invalid/v1", c.ArchiveURL)

	c, err = parse(t, "--da", "fibre", "--fast", "--archive-url", "http://127.0.0.1:8081", "--mandate-hash", testMandateHash)
	require.NoError(t, err)
	assert.True(t, c.Fast)

	for name, extra := range map[string][]string{
		"no archive":           {"--fast", "--mandate-hash", testMandateHash},
		"archive without fast": {"--archive-url", "https://archive.example.invalid"},
		"relative archive":     {"--fast", "--archive-url", "archive.example.invalid", "--mandate-hash", testMandateHash},
		"light inclusion": {"--fast", "--archive-url", "https://archive.example.invalid", "--mandate-hash", testMandateHash, "--inclusion", "light",
			"--rpc-primary", "https://rpc.example.invalid", "--rpc-witness", "https://w.example.invalid",
			"--trust-height", "1", "--trust-hash", "0000000000000000000000000000000000000000000000000000000000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, extra...)
			require.ErrorIs(t, err, ErrConfig)
		})
	}
}

// Each blob inclusion mode other than self is valid on its own and refused
// only together with --fast.
func TestFastNeedsSelfInclusion(t *testing.T) {
	fast := []string{"--fast", "--archive-url", "https://archive.example.invalid", "--mandate-hash", testMandateHash}
	for name, mode := range map[string][]string{
		"light": {"--inclusion", "light", "--rpc-primary", "https://rpc.example.invalid", "--rpc-witness", "https://w.example.invalid",
			"--trust-height", "1", "--trust-hash", "0000000000000000000000000000000000000000000000000000000000000000"},
		"crosscheck": {"--inclusion", "crosscheck", "--crosscheck-bridge", "a.invalid:1", "--crosscheck-bridge", "b.invalid:1", "--crosscheck-tls"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, mode...)
			require.NoError(t, err, "valid without --fast")
			_, err = parse(t, append(mode, fast...)...)
			require.ErrorIs(t, err, ErrConfig)
		})
	}
	c, err := parse(t, append([]string{"--inclusion", "self"}, fast...)...)
	require.NoError(t, err)
	assert.True(t, c.Fast)
}
