package absence_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/absence"
)

// FuzzVerifyHeight: any bytes in the parts of a proof give an outcome, never
// a panic, with an error exactly when the height is not proven; and a height
// that holds the anchor never reads absent, whatever the parts say.
func FuzzVerifyHeight(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0x05, 0x01}, uint8(1))
	f.Add([]byte(`{"txs_results":[{"code":1},{"code":1},{"code":1}]}`), uint8(2))
	f.Fuzz(func(t *testing.T, part []byte, which uint8) {
		ref, d, m, trusted := caseOf(t, "fibre_present")
		q := absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment, ChainID: loadAbsence(t).ChainID}
		rec := m.recs[d]
		require.Equal(t, absence.Present, absence.VerifyHeight(rec, q, d, trusted).Result)

		r := *rec
		switch which % 4 {
		case 0:
			r.NamespaceData = part
		case 1:
			r.DAH = part
		case 2:
			r.Results = bytes.Clone(part)
		default:
			r.Header = part
		}
		o := absence.VerifyHeight(&r, q, d, trusted)
		assert.Equal(t, o.Result == absence.Unproven, o.Err != nil)
		assert.NotEqual(t, absence.Absent, o.Result, "a height with the anchor never reads absent")
	})
}
