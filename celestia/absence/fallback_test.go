package absence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// windowSource is a fetcher over the records of a vector case, next headers
// included.
func windowSource(m *memRecords) *recordSource {
	src := &recordSource{recs: m.recs, extra: map[uint64][]byte{}}
	for _, r := range m.recs {
		if r.NextHeader != nil {
			src.extra[r.Height+1] = r.NextHeader
		}
	}
	return src
}

func cloneRecs(m *memRecords) map[uint64]*archive.AbsenceProofRecord {
	recs := make(map[uint64]*archive.AbsenceProofRecord, len(m.recs))
	for h, r := range m.recs {
		recs[h] = r
	}
	return recs
}

// errRecords is an archive copy that fails every read with err.
type errRecords struct{ err error }

func (e errRecords) Absence(context.Context, commitment.DA, []byte, uint64) (*archive.AbsenceProofRecord, error) {
	return nil, e.err
}

// An archived proof that does not verify does not shadow the source the
// auditor chose: the fetched proof of that height decides.
func TestChainBadArchivedProofFallsBackToFetcher(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	// The deadline height holds a candidate with a non-zero code, which
	// decides ahead of absence and of heights not proven; the window ends
	// before it so that only absent and unproven heights are in play.
	d--
	src := windowSource(m)
	f, err := absence.NewFetcher(src, src, "bridge.good")
	require.NoError(t, err)

	for name, mut := range map[string]func(r *archive.AbsenceProofRecord){
		"namespace data":           func(r *archive.AbsenceProofRecord) { r.NamespaceData = []byte{0x05, 0x01} },
		"header of another height": func(r *archive.AbsenceProofRecord) { r.Header = m.recs[ref.Height].Header },
		"headerless header": func(r *archive.AbsenceProofRecord) {
			b, err := (&cmtproto.SignedHeader{Commit: &cmtproto.Commit{Height: int64(r.Height)}}).Marshal()
			require.NoError(t, err)
			r.Header = b
		},
	} {
		t.Run(name, func(t *testing.T) {
			recs := cloneRecs(m)
			bad := *recs[ref.Height+1]
			mut(&bad)
			recs[ref.Height+1] = &bad
			w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}, Fetch: f}).
				Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
			require.NoError(t, err)
			assert.Equal(t, verifier.AbsenceAbsent, w.Result, "%v", w.Cause)
			assert.Equal(t, []string{absence.SourceArchive, "bridge.good"}, w.Sources)
		})
	}
	t.Run("a corrupt archive read", func(t *testing.T) {
		w, err := absence.NewChain(absence.ChainDeps{Records: errRecords{archive.ErrCorrupt}, Fetch: f}).
			Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceAbsent, w.Result, "%v", w.Cause)
		assert.Equal(t, []string{"bridge.good"}, w.Sources)
	})
	t.Run("a verifying archived proof is not fetched again", func(t *testing.T) {
		calls := 0
		b := &badSource{recordSource: src, from: 0, header: func(h uint64) ([]byte, error) {
			calls++
			return src.SignedHeader(context.Background(), h)
		}}
		fc, err := absence.NewFetcher(b, b, "bridge.counted")
		require.NoError(t, err)
		w, err := absence.NewChain(absence.ChainDeps{Records: m, Fetch: fc}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceAbsent, w.Result, "%v", w.Cause)
		assert.Zero(t, calls)
		assert.Equal(t, []string{absence.SourceArchive}, w.Sources)
	})
}

// When neither the archived proof nor the fetched one proves a height, the
// cause names both.
func TestChainKeepsBothCauses(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	// The deadline height holds a candidate with a non-zero code, which
	// decides ahead of absence and of heights not proven; the window ends
	// before it so that only absent and unproven heights are in play.
	d--
	errDown := errors.New("bridge down")
	down := &badSource{recordSource: windowSource(m), from: 0,
		header: func(uint64) ([]byte, error) { return nil, errDown }}
	f, err := absence.NewFetcher(down, nil, "bridge.down")
	require.NoError(t, err)

	t.Run("archived proof does not verify, fetch fails", func(t *testing.T) {
		recs := cloneRecs(m)
		bad := *recs[ref.Height]
		bad.NamespaceData = []byte{0x05, 0x01}
		recs[ref.Height] = &bad
		w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}, Fetch: f}).
			Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, ref.Height, w.FirstUnproven)
		require.ErrorIs(t, w.Cause, errDown)
		assert.Contains(t, w.Cause.Error(), absence.SourceArchive+":")
		assert.Contains(t, w.Cause.Error(), "bridge.down:")
	})
	t.Run("no archived proof, fetch fails", func(t *testing.T) {
		w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: map[uint64]*archive.AbsenceProofRecord{}}, Fetch: f}).
			Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		require.ErrorIs(t, w.Cause, absence.ErrNoProof)
		require.ErrorIs(t, w.Cause, archive.ErrNotFound)
		require.ErrorIs(t, w.Cause, errDown)
	})
	t.Run("both proofs fail to verify", func(t *testing.T) {
		recs := cloneRecs(m)
		bad := *recs[ref.Height]
		bad.NamespaceData = []byte{0x05, 0x01}
		recs[ref.Height] = &bad
		cut := &badSource{recordSource: windowSource(m), from: 0,
			dah: func(uint64) (*da.DataAvailabilityHeader, error) { return &da.DataAvailabilityHeader{}, nil }}
		fc, err := absence.NewFetcher(cut, nil, "bridge.bad")
		require.NoError(t, err)
		w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}, Fetch: fc}).
			Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, ref.Height, w.FirstUnproven)
		assert.Contains(t, w.Cause.Error(), absence.SourceArchive+":")
		assert.Contains(t, w.Cause.Error(), "bridge.bad:")
		assert.Equal(t, []string{absence.SourceArchive, "bridge.bad"}, w.Sources)
	})
}

// Only a results proof that waits for the header after the deadline can be
// completed by a newer checkpoint. A proof with no results at all cannot,
// so it is not reported as waiting.
func TestChainResultsAtDeadlineOnlyForNextHeader(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	f, err := absence.NewFetcher(windowSource(m), nil, "bridge.noresults")
	require.NoError(t, err)
	recs := cloneRecs(m)
	delete(recs, d)
	w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}, Fetch: f}).
		Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
	require.NoError(t, err)
	assert.Equal(t, verifier.AbsenceUnproven, w.Result)
	assert.Equal(t, d, w.FirstUnproven)
	require.ErrorIs(t, w.Cause, absence.ErrResultsMissing)
	assert.False(t, w.ResultsAtDeadline)
}

// SignedHeaderHash is the one decoder of untrusted SignedHeaders: it refuses
// one without a header, and gives the hash and chain id of a good one.
func TestSignedHeaderHash(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	hash, chainID, err := absence.SignedHeaderHash(m.recs[d].Header, d)
	require.NoError(t, err)
	assert.Equal(t, trusted[d], hash)
	assert.Equal(t, loadAbsence(t).ChainID, chainID)
	_, _, err = absence.SignedHeaderHash(m.recs[d].Header, d+1)
	require.Error(t, err, "a header of another height")

	commitOnly, err := (&cmtproto.SignedHeader{Commit: &cmtproto.Commit{Height: int64(d)}}).Marshal()
	require.NoError(t, err)
	for name, raw := range map[string][]byte{
		"nil": nil, "empty": {}, "commit only": commitOnly, "unknown field only": {0x4b, 0x3c}, "garbage": {0xff, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() { _, _, err = absence.SignedHeaderHash(raw, d) })
			require.Error(t, err)
		})
	}

	// Every reader of untrusted signed headers goes through it.
	t.Run("archived next header", func(t *testing.T) {
		recs := cloneRecs(m)
		bad := *recs[d]
		bad.NextHeader = commitOnly
		recs[d] = &bad
		w, err := absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, d, w.FirstUnproven)
	})
	t.Run("fetched next header", func(t *testing.T) {
		src := windowSource(m)
		b := &badSource{recordSource: src, from: d + 1, header: func(uint64) ([]byte, error) { return commitOnly, nil }}
		f, err := absence.NewFetcher(b, b, "bridge.bad")
		require.NoError(t, err)
		require.NotPanics(t, func() {
			_, err = f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d)
		})
		require.Error(t, err)
	})
	t.Run("header at h0 from the archive and the fetcher", func(t *testing.T) {
		recs := map[uint64]*archive.AbsenceProofRecord{}
		bad := *m.recs[ref.Height]
		bad.Header = commitOnly
		recs[ref.Height] = &bad
		b := &badSource{recordSource: windowSource(m), from: 0, header: func(uint64) ([]byte, error) { return commitOnly, nil }}
		f, err := absence.NewFetcher(b, nil, "bridge.bad")
		require.NoError(t, err)
		require.NotPanics(t, func() {
			_, err = absence.NewChain(absence.ChainDeps{Records: &memRecords{recs: recs}, Fetch: f}).Header(t.Context(), ref, ref.Height)
		})
		require.Error(t, err)
	})
}
