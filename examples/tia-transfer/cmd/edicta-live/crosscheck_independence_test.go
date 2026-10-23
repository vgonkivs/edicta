package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// At the flag level (no network): the bridge list is judged by provider
// identity, not by how many flags were given. The refusal is an ErrConfig
// from parseFlags.

func TestCrosscheckRefusesTheSameBridgeListedTwice(t *testing.T) {
	for name, extra := range map[string][]string{
		"identical":            {"--crosscheck-bridge", "a.invalid:1", "--crosscheck-bridge", "a.invalid:1"},
		"case":                 {"--crosscheck-bridge", "A.invalid:1", "--crosscheck-bridge", "a.INVALID:1"},
		"scheme":               {"--crosscheck-bridge", "a.invalid:1", "--crosscheck-bridge", "https://a.invalid:1"},
		"slash":                {"--crosscheck-bridge", "https://a.invalid:1", "--crosscheck-bridge", "https://a.invalid:1/"},
		"https default port":   {"--crosscheck-bridge", "https://Node.invalid:443/", "--crosscheck-bridge", "https://node.invalid"},
		"scheme case":          {"--crosscheck-bridge", "HTTPS://a.invalid", "--crosscheck-bridge", "https://a.invalid:443"},
		"same host other port": {"--crosscheck-bridge", "https://a.invalid:1", "--crosscheck-bridge", "https://a.invalid:2"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, append([]string{"--inclusion", "crosscheck", "--crosscheck-tls"}, extra...)...)
			require.ErrorIs(t, err, ErrConfig, "one provider counted twice is not two independent sources")
		})
	}
	t.Run("http default port", func(t *testing.T) {
		_, err := parse(t, "--inclusion", "crosscheck",
			"--crosscheck-bridge", "http://a.invalid:80", "--crosscheck-bridge", "http://a.invalid")
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("two distinct pass", func(t *testing.T) {
		_, err := parse(t, "--inclusion", "crosscheck", "--crosscheck-tls",
			"--crosscheck-bridge", "a.invalid:1", "--crosscheck-bridge", "b.invalid:1")
		require.NoError(t, err)
	})
}

func TestCrosscheckCountsTheSubmittersBridgeAsControlled(t *testing.T) {
	own := "bridge.example.invalid:26658" // --bridge-addr in goodArgs
	t.Run("own bridge plus one other is one independent source", func(t *testing.T) {
		_, err := parse(t, "--inclusion", "crosscheck", "--crosscheck-tls",
			"--crosscheck-bridge", own, "--crosscheck-bridge", "b.invalid:1")
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("own bridge written differently is still the own bridge", func(t *testing.T) {
		_, err := parse(t, "--inclusion", "crosscheck", "--crosscheck-tls",
			"--crosscheck-bridge", "https://Bridge.example.invalid:26658", "--crosscheck-bridge", "b.invalid:1")
		require.ErrorIs(t, err, ErrConfig)
	})
	t.Run("own bridge plus two others is fine", func(t *testing.T) {
		_, err := parse(t, "--inclusion", "crosscheck", "--crosscheck-tls",
			"--crosscheck-bridge", own, "--crosscheck-bridge", "b.invalid:1", "--crosscheck-bridge", "c.invalid:1")
		require.NoError(t, err)
	})
	assert.NotEmpty(t, own)
}
