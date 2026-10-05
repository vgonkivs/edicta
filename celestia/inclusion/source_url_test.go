package inclusion_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/inclusion"
)

func TestNormalizeSourceURL(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://node.example", "https://node.example:443"},
		{"HTTPS://Node.Example:443/", "https://node.example:443"},
		{"http://node.example", "http://node.example:80"},
		{"http://NODE.example:80/", "http://node.example:80"},
		{"https://node.example:8443///", "https://node.example:8443"},
		{"https://node.example/rpc/", "https://node.example:443/rpc"},
	} {
		got, err := inclusion.NormalizeSourceURL(c.in)
		require.NoError(t, err, c.in)
		assert.Equal(t, c.want, got, c.in)
	}
	for _, bad := range []string{"", "node.example", "ftp://node.example", "https://", "://x"} {
		_, err := inclusion.NormalizeSourceURL(bad)
		assert.ErrorIs(t, err, inclusion.ErrConfig, bad)
	}
}

func TestSourcesOnTheSameHostAreDuplicates(t *testing.T) {
	for name, pair := range map[string][2]string{
		"default port and case":  {"https://Node.example:443/", "https://node.example"},
		"http default port":      {"http://n.example:80", "http://n.example"},
		"same host other port":   {"https://n.example:1", "https://n.example:2"},
		"same host other scheme": {"http://n.example", "https://n.example"},
		"scheme case":            {"HTTPS://n.example", "https://n.example:443"},
		"same host other path":   {"https://n.example/a", "https://n.example/b"},
	} {
		t.Run(name, func(t *testing.T) {
			err := inclusion.CheckDistinctSources(pair[:])
			require.ErrorIs(t, err, inclusion.ErrDuplicateSource)
			assert.ErrorIs(t, err, inclusion.ErrConfig)
		})
	}
	require.NoError(t, inclusion.CheckDistinctSources([]string{"https://a.example", "https://b.example"}))
}
