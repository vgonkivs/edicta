package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFastFlag(t *testing.T) {
	c, err := parse(t)
	require.NoError(t, err)
	assert.False(t, c.Fast, "off by default")

	c, err = parse(t, "--fast", "--archive-url", "https://archive.example.invalid/v1")
	require.NoError(t, err)
	assert.True(t, c.Fast)
	assert.Equal(t, "https://archive.example.invalid/v1", c.ArchiveURL)

	c, err = parse(t, "--da", "fibre", "--fast", "--archive-url", "http://127.0.0.1:8081")
	require.NoError(t, err)
	assert.True(t, c.Fast)

	for name, extra := range map[string][]string{
		"no archive":           {"--fast"},
		"archive without fast": {"--archive-url", "https://archive.example.invalid"},
		"relative archive":     {"--fast", "--archive-url", "archive.example.invalid"},
		"light inclusion": {"--fast", "--archive-url", "https://archive.example.invalid", "--inclusion", "light",
			"--rpc-primary", "https://rpc.example.invalid", "--rpc-witness", "https://w.example.invalid",
			"--trust-height", "1", "--trust-hash", "0000000000000000000000000000000000000000000000000000000000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, extra...)
			require.ErrorIs(t, err, ErrConfig)
		})
	}
}
