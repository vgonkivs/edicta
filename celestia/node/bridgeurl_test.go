package node

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Assumed symbol: BridgeURL(addr string, tls bool) (string, error). A bare
// host:port becomes http:// or https:// by the flag; a URL must agree with the flag.
func TestBridgeURL(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		tls        bool
		want       string
		bad        bool
	}{
		{"host port plain", "bn.example.invalid:26658", false, "http://bn.example.invalid:26658", false},
		{"host port tls", "bn.example.invalid:26658", true, "https://bn.example.invalid:26658", false},
		{"loopback plain", "127.0.0.1:26658", false, "http://127.0.0.1:26658", false},
		{"http url plain", "http://bn.example.invalid:26658", false, "http://bn.example.invalid:26658", false},
		{"https url tls", "https://bn.example.invalid:26658", true, "https://bn.example.invalid:26658", false},
		{"http url with tls flag", "http://bn.example.invalid:26658", true, "", true},
		{"https url without tls flag", "https://bn.example.invalid:26658", false, "", true},
		{"empty", "", false, "", true},
		{"unknown scheme", "ftp://bn.example.invalid:26658", false, "", true},
		{"scheme without host", "http://", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BridgeURL(tc.addr, tc.tls)
			if tc.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
