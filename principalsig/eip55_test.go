package principalsig_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/principalsig"
)

// The checksummed addresses are the examples of EIP-55.
func TestParseEthAddress(t *testing.T) {
	for _, a := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		want, err := hex.DecodeString(strings.ToLower(a[2:]))
		require.NoError(t, err)
		for _, in := range []string{a, a[2:], strings.ToLower(a), "0x" + strings.ToUpper(a[2:])} {
			got, err := principalsig.ParseEthAddress(in)
			require.NoError(t, err, in)
			assert.Equal(t, want, got, in)
		}
		// Flip the case of one letter: still mixed case, wrong checksum.
		b := []byte(a)
		for i := 2; i < len(b); i++ {
			if c := b[i]; c >= 'a' && c <= 'f' {
				b[i] = c - 'a' + 'A'
				break
			} else if c >= 'A' && c <= 'F' {
				b[i] = c - 'A' + 'a'
				break
			}
		}
		_, err = principalsig.ParseEthAddress(string(b))
		require.ErrorIs(t, err, principalsig.ErrPrincipal, string(b))
	}
	for _, bad := range []string{"0x1234", "0x" + strings.Repeat("g", 40), ""} {
		_, err := principalsig.ParseEthAddress(bad)
		require.ErrorIs(t, err, principalsig.ErrPrincipal, bad)
	}
}
