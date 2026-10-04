package edictad_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
)

// Assumed: ParseConfig normalises [network.bridge] addr to a URL with
// node.BridgeURL(addr, tls); a scheme that disagrees with tls is ErrConfig.
func TestBridgeAddrForms(t *testing.T) {
	e := newEnv(t)
	base := `addr = "bn.invalid:26658"`
	for _, tc := range []struct {
		name string
		addr string
		tls  bool
		want string
		bad  bool
	}{
		{"host port plain", "bn.example.invalid:26658", false, "http://bn.example.invalid:26658", false},
		{"host port tls", "bn.example.invalid:26658", true, "https://bn.example.invalid:26658", false},
		{"http url", "http://bn.example.invalid:26658", false, "http://bn.example.invalid:26658", false},
		{"https url tls", "https://bn.example.invalid:26658", true, "https://bn.example.invalid:26658", false},
		{"http url with tls", "http://bn.example.invalid:26658", true, "", true},
		{"https url without tls", "https://bn.example.invalid:26658", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tls := "tls = false"
			if tc.tls {
				tls = "tls = true"
			}
			s := e.tomlOf(rep(base, `addr = "`+tc.addr+`"`), rep("tls = false\n\n[network.consensus_grpc]", tls+"\n\n[network.consensus_grpc]"))
			cfg, err := edictad.ParseConfig([]byte(s))
			if tc.bad {
				require.ErrorIs(t, err, edictad.ErrConfig)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, cfg.Network.Bridge.Addr)
		})
	}
}
