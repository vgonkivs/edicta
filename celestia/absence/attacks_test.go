package absence_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func queryOf(t *testing.T, ref commitment.PayloadRef) absence.Query {
	t.Helper()
	q := absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}
	if ref.DA == commitment.DACelestiaBlob {
		q.Signer = ref.Signer
	} else {
		q.ChainID = loadAbsence(t).ChainID
	}
	return q
}

func otherNamespace(ns []byte) []byte {
	out := bytes.Clone(ns)
	out[len(out)-1] ^= 1
	return out
}

// A proof is only about the anchor it names: a record for another target
// proves nothing, and the anchor of another signer is not this anchor.
func TestVerifyHeightOtherTarget(t *testing.T) {
	for _, tc := range []struct {
		id   string
		mut  func(q *absence.Query, r *archive.AbsenceProofRecord)
		want error
	}{
		{"blob_empty_namespace", func(q *absence.Query, _ *archive.AbsenceProofRecord) { q.Namespace = otherNamespace(q.Namespace) }, absence.ErrRecordMismatch},
		{"blob_present", func(q *absence.Query, _ *archive.AbsenceProofRecord) { q.Namespace = otherNamespace(q.Namespace) }, absence.ErrRecordMismatch},
		{"blob_present", func(_ *absence.Query, r *archive.AbsenceProofRecord) { r.DA = commitment.DAFibre }, absence.ErrRecordMismatch},
		{"fibre_present", func(q *absence.Query, _ *archive.AbsenceProofRecord) { q.Namespace = otherNamespace(q.Namespace) }, absence.ErrRecordMismatch},
		{"fibre_present", func(_ *absence.Query, r *archive.AbsenceProofRecord) { r.Commitment = otherNamespace(r.Commitment) }, absence.ErrRecordMismatch},
		{"fibre_present", func(_ *absence.Query, r *archive.AbsenceProofRecord) { r.DA = commitment.DACelestiaBlob }, absence.ErrRecordMismatch},
	} {
		ref, d, m, trusted := caseOf(t, tc.id)
		q := queryOf(t, ref)
		r := *m.recs[d]
		tc.mut(&q, &r)
		o := absence.VerifyHeight(&r, q, d, trusted)
		assert.Equal(t, absence.Unproven, o.Result, tc.id)
		require.ErrorIs(t, o.Err, tc.want, tc.id)
	}

	t.Run("the blob of another signer is not this anchor", func(t *testing.T) {
		ref, d, m, trusted := caseOf(t, "blob_present")
		q := queryOf(t, ref)
		require.Equal(t, absence.Present, absence.VerifyHeight(m.recs[d], q, d, trusted).Result)
		q.Signer = otherNamespace(q.Signer)
		assert.Equal(t, absence.Absent, absence.VerifyHeight(m.recs[d], q, d, trusted).Result)
	})
	t.Run("a fibre promise for another chain is not this anchor", func(t *testing.T) {
		ref, d, m, trusted := caseOf(t, "fibre_present")
		q := queryOf(t, ref)
		q.ChainID = "other-chain"
		assert.NotEqual(t, absence.Present, absence.VerifyHeight(m.recs[d], q, d, trusted).Result)
	})
}

// Parts of a proof spliced from another height never make a height absent:
// every part is tied to the trusted header of its own height.
func TestVerifyHeightSplicedParts(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "fibre_present")
	q := queryOf(t, ref)
	target := m.recs[d]
	require.Equal(t, absence.Present, absence.VerifyHeight(target, q, d, trusted).Result)
	_, _, other, _ := caseOf(t, "window_three_heights_proven")
	donor := other.recs[4200202]
	require.NotNil(t, donor)

	for name, tc := range map[string]struct {
		mut  func(r *archive.AbsenceProofRecord)
		want error
	}{
		"header":         {func(r *archive.AbsenceProofRecord) { r.Header = donor.Header }, absence.ErrHeader},
		"dah":            {func(r *archive.AbsenceProofRecord) { r.DAH = donor.DAH }, absence.ErrDAH},
		"namespace data": {func(r *archive.AbsenceProofRecord) { r.NamespaceData = donor.NamespaceData }, nil},
		"results":        {func(r *archive.AbsenceProofRecord) { r.Results = []byte(`{"txs_results":[{"code":1}]}`) }, absence.ErrResultUnproven},
		"next header":    {func(r *archive.AbsenceProofRecord) { r.NextHeader = donor.Header }, absence.ErrResultUnproven},
		"no next header": {func(r *archive.AbsenceProofRecord) { r.NextHeader = nil }, absence.ErrResultUnproven},
	} {
		t.Run(name, func(t *testing.T) {
			r := *target
			tc.mut(&r)
			o := absence.VerifyHeight(&r, q, d, trusted)
			assert.NotEqual(t, absence.Absent, o.Result, "rule %s: %v", o.Rule, o.Err)
			if tc.want != nil {
				assert.Equal(t, absence.Unproven, o.Result)
				require.ErrorIs(t, o.Err, tc.want)
			}
		})
	}
}

// badSource is a proof and results source whose answers can be broken one
// at a time.
type badSource struct {
	*recordSource
	// from is the first height whose answers are broken.
	from    uint64
	header  func(h uint64) ([]byte, error)
	dah     func(h uint64) (*da.DataAvailabilityHeader, error)
	nsData  func(h uint64) (shwap.NamespaceData, error)
	results func(h uint64) ([]railverify.TxResult, error)
}

func (b *badSource) SignedHeader(ctx context.Context, h uint64) ([]byte, error) {
	if b.header != nil && h >= b.from {
		return b.header(h)
	}
	return b.recordSource.SignedHeader(ctx, h)
}

func (b *badSource) DAH(ctx context.Context, h uint64) (*da.DataAvailabilityHeader, error) {
	if b.dah != nil && h >= b.from {
		return b.dah(h)
	}
	return b.recordSource.DAH(ctx, h)
}

func (b *badSource) NamespaceData(ctx context.Context, h uint64, ns libshare.Namespace) (shwap.NamespaceData, error) {
	if b.nsData != nil && h >= b.from {
		return b.nsData(h)
	}
	return b.recordSource.NamespaceData(ctx, h, ns)
}

func (b *badSource) BlockResults(ctx context.Context, h uint64) ([]railverify.TxResult, error) {
	if b.results != nil && h >= b.from {
		return b.results(h)
	}
	return b.recordSource.BlockResults(ctx, h)
}

// A bridge or RPC that answers with garbage, nothing or the wrong thing
// yields no record, or a record that does not verify: never a panic and
// never an absent height.
func TestFetcherMalformedAnswers(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	q := queryOf(t, ref)
	fq := absence.Query{DA: q.DA, Namespace: q.Namespace, Commitment: q.Commitment}
	extra := map[uint64][]byte{}
	for _, r := range m.recs {
		if r.NextHeader != nil {
			extra[r.Height+1] = r.NextHeader
		}
	}
	errDown := errors.New("down")
	// d is the height with a candidate, so its results and next header are
	// read too.
	for name, mut := range map[string]func(b *badSource){
		"header error":   func(b *badSource) { b.header = func(uint64) ([]byte, error) { return nil, errDown } },
		"header garbage": func(b *badSource) { b.header = func(uint64) ([]byte, error) { return []byte{0xff, 0x01, 0x02}, nil } },
		"header of the height before": func(b *badSource) {
			b.header = func(h uint64) ([]byte, error) { return m.recs[h-1].Header, nil }
		},
		"next header error": func(b *badSource) {
			b.header = func(h uint64) ([]byte, error) {
				if h == d+1 {
					return nil, errDown
				}
				return m.recs[h].Header, nil
			}
		},
		"next header for another height": func(b *badSource) {
			b.header = func(h uint64) ([]byte, error) {
				if h == d+1 {
					return m.recs[d].Header, nil
				}
				return m.recs[h].Header, nil
			}
		},
		"dah error": func(b *badSource) { b.dah = func(uint64) (*da.DataAvailabilityHeader, error) { return nil, errDown } },
		"dah nil":   func(b *badSource) { b.dah = func(uint64) (*da.DataAvailabilityHeader, error) { return nil, nil } },
		"dah empty": func(b *badSource) {
			b.dah = func(uint64) (*da.DataAvailabilityHeader, error) { return &da.DataAvailabilityHeader{}, nil }
		},
		"namespace error": func(b *badSource) { b.nsData = func(uint64) (shwap.NamespaceData, error) { return nil, errDown } },
		"namespace cut": func(b *badSource) {
			b.nsData = func(h uint64) (shwap.NamespaceData, error) {
				nd, err := b.recordSource.NamespaceData(context.Background(), h, libshare.PayForFibreNamespace)
				if err != nil || len(nd) == 0 {
					return nd, err
				}
				return nd[:len(nd)-1], nil
			}
		},
		"results error": func(b *badSource) { b.results = func(uint64) ([]railverify.TxResult, error) { return nil, errDown } },
		"results empty": func(b *badSource) { b.results = func(uint64) ([]railverify.TxResult, error) { return nil, nil } },
		"results all nonzero": func(b *badSource) {
			b.results = func(uint64) ([]railverify.TxResult, error) {
				return []railverify.TxResult{{Code: 5}, {Code: 5}, {Code: 5}, {Code: 5}}, nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := &badSource{recordSource: &recordSource{recs: m.recs, extra: extra}, from: d}
			mut(b)
			f, err := absence.NewFetcher(b, b, "bridge.bad")
			require.NoError(t, err)
			rec, err := f.Fetch(t.Context(), fq, d)
			if err == nil {
				o := absence.VerifyHeight(rec, q, d, trusted)
				assert.Equal(t, absence.Unproven, o.Result, "rule %s", o.Rule)
				require.Error(t, o.Err)
			}
			w, err := absence.NewChain(absence.ChainDeps{Fetch: f}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
			require.NoError(t, err)
			assert.Equal(t, verifier.AbsenceUnproven, w.Result, "%v", w.Cause)
			assert.Equal(t, d, w.FirstUnproven)
		})
	}
}

// The byte bound holds for the whole record, results and next header
// included, not only for the namespace data.
func TestFetcherBoundCountsResults(t *testing.T) {
	ref, d, m, _ := caseOf(t, "window_three_heights_proven")
	extra := map[uint64][]byte{}
	for _, r := range m.recs {
		if r.NextHeader != nil {
			extra[r.Height+1] = r.NextHeader
		}
	}
	huge := make([]railverify.TxResult, 0, 1)
	huge = append(huge, railverify.TxResult{Code: 1, Data: make([]byte, absence.MaxHeightBytes)})
	b := &badSource{recordSource: &recordSource{recs: m.recs, extra: extra}, from: d,
		results: func(uint64) ([]railverify.TxResult, error) { return huge, nil }}
	f, err := absence.NewFetcher(b, b, "bridge.big")
	require.NoError(t, err)
	_, err = f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d)
	require.ErrorIs(t, err, absence.ErrTooLarge)
}

// A corrupt archived record is not the last word: the window still names
// the height as not proven, never absent.
func TestChainCorruptArchivedRecord(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	// The deadline height holds a candidate with a non-zero code, which
	// decides ahead of absence and of heights not proven; the window ends
	// before it so that only absent and unproven heights are in play.
	d--
	recs := map[uint64]*archive.AbsenceProofRecord{}
	for h, r := range m.recs {
		recs[h] = r
	}
	bad := *recs[ref.Height+1]
	bad.NamespaceData = []byte{0x05, 0x01}
	recs[ref.Height+1] = &bad
	w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
	require.NoError(t, err)
	assert.Equal(t, verifier.AbsenceUnproven, w.Result)
	assert.Equal(t, ref.Height+1, w.FirstUnproven)
}

// The header the verifier takes T_ref from must be the header of that
// height, whatever the source.
type rawHeaders map[uint64][]byte

func (r rawHeaders) Header(_ context.Context, h uint64) ([]byte, error) {
	b, ok := r[h]
	if !ok {
		return nil, errors.New("no header")
	}
	return b, nil
}

func TestChainHeaderRefusesAnotherHeight(t *testing.T) {
	ref, _, m, _ := caseOf(t, "window_three_heights_proven")
	shifted := map[uint64]*archive.AbsenceProofRecord{ref.Height: m.recs[ref.Height+1]}
	_, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: shifted}}).Header(t.Context(), ref, ref.Height)
	require.Error(t, err)
	_, err = absence.NewChain(absence.ChainDeps{Headers: rawHeaders{ref.Height: []byte{0xff, 0xff}}}).Header(t.Context(), ref, ref.Height)
	require.Error(t, err)
}

// A source that serves a SignedHeader without its header (an empty answer
// decodes as one) must leave the height unproven, not crash the verifier.
func TestHeaderlessSignedHeaderIsNotProven(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	headerless, err := (&cmtproto.SignedHeader{Commit: &cmtproto.Commit{Height: int64(d)}}).Marshal()
	require.NoError(t, err)

	t.Run("archived record", func(t *testing.T) {
		recs := map[uint64]*archive.AbsenceProofRecord{}
		for h, r := range m.recs {
			recs[h] = r
		}
		bad := *recs[d]
		bad.Header = headerless
		b, err := archive.Encode(&bad)
		require.NoError(t, err, "the archive takes the record: header bytes are opaque to it")
		_, err = archive.Decode(b)
		require.NoError(t, err)
		recs[d] = &bad
		var w verifier.AbsenceWindow
		require.NotPanics(t, func() {
			w, err = absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		})
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, d, w.FirstUnproven)
	})
	for name, raw := range map[string][]byte{"empty answer": {}, "commit only": headerless, "unknown field only": {0x4b, 0x3c}} {
		t.Run("bridge, "+name, func(t *testing.T) {
			b := &badSource{recordSource: &recordSource{recs: m.recs}, from: d,
				header: func(uint64) ([]byte, error) { return raw, nil }}
			f, err := absence.NewFetcher(b, nil, "bridge.bad")
			require.NoError(t, err)
			require.NotPanics(t, func() {
				_, err = f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d)
			})
			require.Error(t, err)
		})
	}
}

// An included candidate with a proven non-zero result code published the
// payload, so whatever the other heights of the window show, the window is
// never absent and names the unpaid height.
func TestUnpaidCandidateIsNeverAbsence(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	for name, mut := range map[string]func(recs map[uint64]*archive.AbsenceProofRecord){
		"every other height absent": func(map[uint64]*archive.AbsenceProofRecord) {},
		"a height missing":          func(recs map[uint64]*archive.AbsenceProofRecord) { delete(recs, ref.Height) },
		"a height corrupt": func(recs map[uint64]*archive.AbsenceProofRecord) {
			bad := *recs[ref.Height+1]
			bad.NamespaceData = []byte{0x05, 0x01}
			recs[ref.Height+1] = &bad
		},
		"only the unpaid height": func(recs map[uint64]*archive.AbsenceProofRecord) {
			delete(recs, ref.Height)
			delete(recs, ref.Height+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			recs := cloneRecs(m)
			mut(recs)
			w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}}).
				Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
			require.NoError(t, err)
			assert.Equal(t, verifier.AbsencePresentUnpaid, w.Result, "%v", w.Cause)
			assert.Equal(t, d, w.UnpaidHeight)
		})
	}
}
