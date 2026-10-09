package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

// A mixed-case eth pin is an EIP-55 checksum: a right one parses to the same
// identity as the lowercase pin, a wrong one is refused.
func TestParsePrincipalEthChecksum(t *testing.T) {
	lower, err := policy.ParsePrincipal("eth:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
	require.NoError(t, err)
	sum, err := policy.ParsePrincipal("eth:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	require.NoError(t, err)
	require.Equal(t, lower, sum)
	_, err = policy.ParsePrincipal("eth:0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	require.ErrorIs(t, err, policy.ErrPrincipalPin)
}
