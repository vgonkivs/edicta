// SPDX-License-Identifier: Apache-2.0

package edictaapi_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A key that a case-insensitive or Unicode-folding decoder would read as a
// known field must be refused, as must a duplicate hidden behind an escape.
func TestJSONKeyTricksAreRefused(t *testing.T) {
	salt := b64(testSalt)
	rest := `"action":"YWN0","action_salt":"` + salt + `"`
	cases := []struct{ name, body string }{
		{"duplicate through a unicode escape", `{"envelope":"ZW52",` + rest + `,"envelope":"b3RoZXI="}`},
		{"escaped first, plain second", `{"envelope":"ZW52","envelope":"ZW52",` + rest + `}`},
		{"duplicate with an escaped underscore", `{"envelope":"ZW52",` + rest + `,"action_salt":"` + salt + `"}`},
		{"long s in place of s", `{"envelope":"ZW52","action":"YWN0","action_ſalt":"` + salt + `"}`},
		{"long s next to the real salt", `{"envelope":"ZW52",` + rest + `,"action_ſalt":"` + salt + `"}`},
		{"kelvin sign", `{"envelope":"ZW52",` + rest + `,"K":"x"}`},
		{"fullwidth letters", `{"ｅnvelope":"ZW52",` + rest + `}`},
		{"upper case duplicate", `{"envelope":"ZW52",` + rest + `,"ENVELOPE":"ZW52"}`},
		{"nul in a key", `{"envelope\u0000":"ZW52",` + rest + `}`},
		{"nul as a key", `{"envelope":"ZW52",` + rest + `,"\u0000":"x"}`},
		{"empty key", `{"envelope":"ZW52",` + rest + `,"":"x"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			rec := e.postJSON("/v1/authorize", []byte(c.body))
			requireJSONErr(t, rec, 400, "ErrMalformed")
			require.Zero(t, e.gate.calls())
			require.Zero(t, e.pub.count())
		})
	}
}
