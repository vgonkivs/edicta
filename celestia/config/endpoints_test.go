package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
)

func validateWith(t *testing.T, data string, ov map[string]string) error {
	t.Helper()
	c, err := config.Parse([]byte(data), ov)
	require.NoError(t, err)
	require.NoError(t, c.ApplyDefaults(config.Builtin{}))
	return c.ValidateBasic()
}

func TestEndpointShapes(t *testing.T) {
	const capture = `"/h/capture"`
	tests := []struct {
		name string
		ov   map[string]string
		want string // empty: accepted
	}{
		{"capture rpc with credentials", map[string]string{"capture.dir": capture, "capture.comet_rpc": `"https://u:SECRET@rpc.example"`}, "credentials"},
		{"capture rpc wrong scheme", map[string]string{"capture.dir": capture, "capture.comet_rpc": `"ftp://rpc.example"`}, "capture.comet_rpc"},
		{"capture rpc without host", map[string]string{"capture.dir": capture, "capture.comet_rpc": `"https://:443"`}, "capture.comet_rpc"},
		{"capture rpc with key in path", map[string]string{"capture.dir": capture, "capture.comet_rpc": `"https://rpc.example/v2/k"`}, ""},
		{"bridge host only", map[string]string{"network.bridge.addr": `"bridge.example:26658"`}, ""},
		{"bridge url agrees with tls", map[string]string{"network.bridge.addr": `"https://bridge.example/k"`, "network.bridge.tls": "true"}, ""},
		{"bridge url disagrees with tls", map[string]string{"network.bridge.addr": `"https://bridge.example"`, "network.bridge.tls": "false"}, "network.bridge.addr"},
		{"bridge scheme", map[string]string{"network.bridge.addr": `"ws://bridge.example"`}, "network.bridge.addr"},
		{"bridge credentials", map[string]string{"network.bridge.addr": `"u:p@bridge.example"`}, "credentials"},
		{"bridge no host", map[string]string{"network.bridge.addr": `"http://"`}, "network.bridge.addr"},
		{"grpc host:port", map[string]string{"network.consensus_grpc.addr": `"grpc.example:9090"`}, ""},
		{"grpc ipv6", map[string]string{"network.consensus_grpc.addr": `"[::1]:9090"`}, ""},
		{"grpc scheme", map[string]string{"network.consensus_grpc.addr": `"https://grpc.example:9090"`}, "network.consensus_grpc.addr"},
		{"grpc credentials", map[string]string{"network.consensus_grpc.addr": `"u:p@grpc.example:9090"`}, "network.consensus_grpc.addr"},
		{"grpc path", map[string]string{"network.consensus_grpc.addr": `"grpc.example:9090/k"`}, "network.consensus_grpc.addr"},
		{"grpc no host", map[string]string{"network.consensus_grpc.addr": `":9090"`}, "network.consensus_grpc.addr"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWith(t, selfHosted, tc.ov)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, config.ErrConfig)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "SECRET", "a refusal never quotes the endpoint")
		})
	}
}

func TestHexValuesCompareIgnoringCase(t *testing.T) {
	upper := strings.ToUpper(ns)
	require.NotEqual(t, ns, upper)
	withPublisher := selfHosted + `
[publisher]
keyring_dir = "/h/keyring/publisher"
key_name = "publisher"
passphrase_file = "/h/keyring/publisher/publisher.pass"
namespace = "` + upper + `"
`
	err := validateWith(t, withPublisher, nil)
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "publisher.namespace equals recorder.namespace")

	k := pub(0xab)
	err = validateWith(t, selfHosted, map[string]string{"gate.executor_keys": `["` + k + `", "` + strings.ToUpper(k) + `"]`})
	require.ErrorIs(t, err, config.ErrConfig)
	assert.Contains(t, err.Error(), "gate.executor_keys[1] is a duplicate")
}
