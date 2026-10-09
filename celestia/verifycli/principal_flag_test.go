package verifycli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func TestTypedPrincipalFlag(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	key := strings.Repeat("cd", 32)
	base := []string{"verify", hash, "--gate-key", key, "--archive", t.TempDir()}
	var out bytes.Buffer
	f, err := parseFlags(append(base[:len(base):len(base)],
		"--principal", "cosmos:celestia1hjlq8g26hnkwsegd75vwqqlf39a7gch9u7yer7,eth:0xda9588643fa4376845af5352ffba44f5e4b0e40f",
		"--principal-key", strings.Repeat("01", 32),
	), &out)
	require.NoError(t, err)
	require.Len(t, f.principalKeys, 3)
	assert.Equal(t, uint8(0), f.principalKeys[0].SigType)
	assert.Equal(t, uint8(policy.SigTypeADR036), f.principalKeys[1].SigType)
	assert.Equal(t, uint8(policy.SigTypeEIP712), f.principalKeys[2].SigType)

	for _, bad := range []string{"cosmos:celestia1abc", "eth:0x12", "btc:abc"} {
		_, err = parseFlags(append(base[:len(base):len(base)], "--principal", bad), &out)
		var ue usageError
		require.ErrorAs(t, err, &ue, bad)
	}
}
