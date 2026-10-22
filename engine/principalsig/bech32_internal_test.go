package principalsig

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// BIP-173 test vectors: valid and invalid bech32 strings.
func TestBech32BIP173(t *testing.T) {
	for _, s := range []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		"?1ezyfcl",
	} {
		_, _, err := bech32Decode(s)
		require.NoError(t, err, s)
	}
	for _, s := range []string{
		"\x201nwldj5",
		"\x7f1axkwrx",
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
		"pzry9x0s0muk",
		"1pzry9x0s0muk",
		"x1b4n0q5v",
		"li1dgmt3",
		"de1lg7wt\xff",
		"A1G7SGD8",
		"10a06t8",
		"1qzzfhee",
	} {
		_, _, err := bech32Decode(s)
		require.ErrorIs(t, err, ErrPrincipal, s)
	}
}

func TestBech32RoundTrip(t *testing.T) {
	for n := 0; n <= 40; n++ {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*37 + n)
		}
		s, err := bech32Encode("celestia", data)
		require.NoError(t, err)
		hrp, got, err := bech32Decode(s)
		require.NoError(t, err)
		require.Equal(t, "celestia", hrp)
		require.Equal(t, data, got)
	}
}
