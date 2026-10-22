// SPDX-License-Identifier: Apache-2.0

package edictaapi

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// FuzzJSONToCBOR: the JSON decoder never panics, refuses with ErrMalformed or
// ErrWrongType, and whatever it accepts is canonical CBOR that renders back to
// JSON and converts to the same bytes.
func FuzzJSONToCBOR(f *testing.F) {
	for _, s := range []string{
		`{"envelope":"ZW52","action":"YWN0","action_salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"envelope":"ZW52","rail_ref":"aé😀","executor_pubkey":"","executor_signature":""}`,
		`{"envelope":"ZW52","envelope":"ZW52"}`,
		`{"blob":"YQ==","agent_id":"a","requested_at":9007199254740991,"signature":""}`,
		`{"allowed_da":[1,2]}`,
		`{}`, `[]`, ``, `{"a":`, "\xef\xbb\xbf{}",
	} {
		f.Add([]byte(s))
	}
	schemas := [][]fspec{authorizeSchema, recordSchema, publishRequestSchema, healthSchema}
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, schema := range schemas {
			out, err := jsonToCBOR(in, schema)
			if err != nil {
				require.True(t, errors.Is(err, commitment.ErrMalformed) || errors.Is(err, commitment.ErrWrongType), "%v", err)
				continue
			}
			root, err := scanTop(out)
			require.NoError(t, err, "accepted JSON must give well-formed canonical CBOR")
			require.Equal(t, byte(majMap), root.major)
			rendered, err := cborToJSON(out, schema)
			require.NoError(t, err)
			again, err := jsonToCBOR(rendered, schema)
			require.NoError(t, err)
			require.Equal(t, out, again)
		}
	})
}
