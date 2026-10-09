package absence_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/absence"
)

// fixture returns the query, the one record and the trusted hashes of a
// single-height synthetic case.
func fixture(t *testing.T, id string) (absence.Query, absence.Record, absence.TrustedHashes) {
	t.Helper()
	f := loadAbsence(t)
	for _, c := range f.Synthetic {
		if c.ID != id {
			continue
		}
		require.Len(t, c.Records, 1)
		q := absence.Query{DA: u64(t, c.Query.DA), Namespace: unhex(t, c.Query.Namespace),
			Commitment: unhex(t, c.Query.Commitment), ChainID: c.Query.ChainID}
		rec, err := absence.DecodeRecord(unhex(t, c.Records[0].RecordHex))
		require.NoError(t, err)
		trusted := absence.TrustedHashes{}
		for h, x := range c.TrustedHeaders {
			trusted[u64(t, h)] = unhex(t, x)
		}
		return q, rec, trusted
	}
	require.Fail(t, "no case "+id)
	return absence.Query{}, absence.Record{}, nil
}

func TestVerifyHeightFailClosed(t *testing.T) {
	q, rec, trusted := fixture(t, "fibre_candidate_nonzero_code")
	h := rec.Height
	require.Equal(t, absence.Absent, absence.VerifyHeight(rec, q, h, trusted).Result)

	t.Run("another commitment", func(t *testing.T) {
		q2 := q
		q2.Commitment = append([]byte{q.Commitment[0] ^ 1}, q.Commitment[1:]...)
		o := absence.VerifyHeight(rec, q2, h, trusted)
		assert.Equal(t, absence.Unproven, o.Result)
		assert.Equal(t, absence.RuleRecord, o.Rule)
		require.ErrorIs(t, o.Err, absence.ErrRecordMismatch)
	})
	t.Run("another height", func(t *testing.T) {
		o := absence.VerifyHeight(rec, q, h+1, trusted)
		require.ErrorIs(t, o.Err, absence.ErrRecordMismatch)
	})
	t.Run("no trusted hash at h", func(t *testing.T) {
		tr := absence.TrustedHashes{h + 1: trusted[h+1]}
		o := absence.VerifyHeight(rec, q, h, tr)
		assert.Equal(t, absence.RuleHeader, o.Rule)
		require.ErrorIs(t, o.Err, absence.ErrHeader)
	})
	t.Run("no trusted hash at h + 1", func(t *testing.T) {
		tr := absence.TrustedHashes{h: trusted[h]}
		o := absence.VerifyHeight(rec, q, h, tr)
		assert.Equal(t, absence.Unproven, o.Result)
		assert.Equal(t, absence.RuleResults, o.Rule)
		require.ErrorIs(t, o.Err, absence.ErrResultUnproven)
	})
	t.Run("garbage dah", func(t *testing.T) {
		r := rec
		r.DAH = []byte{0xff, 0xff}
		o := absence.VerifyHeight(r, q, h, trusted)
		require.ErrorIs(t, o.Err, absence.ErrDAH)
	})
	t.Run("garbage namespace data", func(t *testing.T) {
		r := rec
		r.NamespaceData = []byte{0x05, 0x01}
		o := absence.VerifyHeight(r, q, h, trusted)
		require.ErrorIs(t, o.Err, absence.ErrNamespaceData)
	})
	t.Run("empty namespace data where rows hold PFF_NS", func(t *testing.T) {
		r := rec
		r.NamespaceData = nil
		o := absence.VerifyHeight(r, q, h, trusted)
		assert.Equal(t, absence.Unproven, o.Result)
		require.ErrorIs(t, o.Err, absence.ErrNamespaceData)
	})
	t.Run("garbage results", func(t *testing.T) {
		r := rec
		r.Results = []byte("not json")
		o := absence.VerifyHeight(r, q, h, trusted)
		require.ErrorIs(t, o.Err, absence.ErrResultUnproven)
	})
	t.Run("invalid query", func(t *testing.T) {
		q2 := q
		q2.ChainID = ""
		o := absence.VerifyHeight(rec, q2, h, trusted)
		assert.Equal(t, absence.Unproven, o.Result)
		require.ErrorIs(t, o.Err, absence.ErrQuery)
	})
}

func TestVerifyWindowArguments(t *testing.T) {
	q, rec, trusted := fixture(t, "fibre_candidate_nonzero_code")
	recs := map[uint64]absence.Record{rec.Height: rec}
	for _, w := range [][2]uint64{{0, 0}, {5, 4}, {1, 1 + absence.MaxWindow + 1}, {math.MaxUint64 - 1, math.MaxUint64}} {
		_, err := absence.VerifyWindow(q, w[0], w[1], recs, trusted)
		require.ErrorIs(t, err, absence.ErrWindow, "%v", w)
	}
	bad := q
	bad.DA = 3
	_, err := absence.VerifyWindow(bad, rec.Height, rec.Height, recs, trusted)
	require.ErrorIs(t, err, absence.ErrQuery)

	w, err := absence.VerifyWindow(q, rec.Height, rec.Height+1, recs, trusted)
	require.NoError(t, err)
	assert.Equal(t, absence.Unproven, w.Result)
	assert.Equal(t, rec.Height+1, w.FirstUnproven)
	require.ErrorIs(t, w.Heights[1].Err, absence.ErrNoProof)
	assert.Equal(t, absence.RuleNoProof, w.Heights[1].Rule)
}

func TestQueryValidateBasic(t *testing.T) {
	q, _, _ := fixture(t, "fibre_candidate_nonzero_code")
	require.NoError(t, q.ValidateBasic())
	for name, mut := range map[string]func(*absence.Query){
		"da":               func(q *absence.Query) { q.DA = 0 },
		"commitment":       func(q *absence.Query) { q.Commitment = q.Commitment[:31] },
		"namespace":        func(q *absence.Query) { q.Namespace = make([]byte, 29) },
		"signer on fibre":  func(q *absence.Query) { q.Signer = make([]byte, 20) },
		"no chain id":      func(q *absence.Query) { q.ChainID = "" },
		"blob, no signer":  func(q *absence.Query) { q.DA = absence.DACelestiaBlob },
		"blob, short sign": func(q *absence.Query) { q.DA = absence.DACelestiaBlob; q.Signer = make([]byte, 19) },
	} {
		x := q
		mut(&x)
		require.ErrorIs(t, x.ValidateBasic(), absence.ErrQuery, name)
	}
}
