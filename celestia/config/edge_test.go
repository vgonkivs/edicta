package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
)

func TestOverrideValueMayContainEquals(t *testing.T) {
	c, err := config.Parse([]byte(selfHosted), map[string]string{"agent.id": "a=b=c"})
	require.NoError(t, err)
	assert.Equal(t, "a=b=c", c.Agent.ID)
}

func TestDuplicateKeysAreRefused(t *testing.T) {
	_, err := config.Parse([]byte("[agent]\nid = \"a\"\nid = \"b\"\n"), nil)
	require.ErrorIs(t, err, config.ErrConfig)
	_, err = config.Parse([]byte("[agent]\nid = \"a\"\n[agent]\nid = \"b\"\n"), nil)
	require.ErrorIs(t, err, config.ErrConfig)
}

func TestOverrideThroughANonTableIsRefused(t *testing.T) {
	_, err := config.Parse([]byte(selfHosted), map[string]string{"agent.id.x": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
	_, err = config.Parse([]byte(selfHosted), map[string]string{"agent..id": "1"})
	require.ErrorIs(t, err, config.ErrConfig)
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(selfHosted), "agent.id", "x")
	f.Add([]byte(""), "a.b", "[1,")
	f.Fuzz(func(t *testing.T, data []byte, k, v string) {
		_, err := config.Parse(data, map[string]string{k: v})
		if err != nil {
			require.ErrorIs(t, err, config.ErrConfig)
		}
	})
}
