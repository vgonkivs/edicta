// SPDX-License-Identifier: Apache-2.0

package eden_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/signer/eden"
)

// FuzzCheckRelayAnswer: the relay answer reader never panics, and an
// answer it accepts names no transaction other than the rail_ref at the top
// level.
func FuzzCheckRelayAnswer(f *testing.F) {
	rail := strings.Repeat("ab", 32)
	f.Add([]byte(`{"txHash":"0x` + rail + `"}`))
	f.Add([]byte(`{"result":{"hash":"0x` + strings.Repeat("cd", 32) + `"}}`))
	f.Add([]byte(`{"error":"failed to broadcast transaction"}`))
	f.Add([]byte(``))
	f.Add([]byte(`[1,2]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if eden.CheckRelayAnswer(b, rail) != nil {
			return
		}
		var top map[string]json.RawMessage
		if json.Unmarshal(b, &top) != nil {
			return
		}
		for _, k := range []string{"txHash", "hash", "transactionHash"} {
			var h string
			if raw, ok := top[k]; ok && json.Unmarshal(raw, &h) == nil {
				require.True(t, strings.EqualFold(h, "0x"+rail), "accepted %q", b)
			}
		}
	})
}
