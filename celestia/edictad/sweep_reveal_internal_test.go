package edictad

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

type revealStore struct {
	memStore
	reads atomic.Int32
}

func (r *revealStore) Reveal(context.Context, commitment.Hash) (*archive.RevealRecord, error) {
	r.reads.Add(1)
	return &archive.RevealRecord{}, nil
}

// A reveal seen in the archive is not read again by later passes.
func TestSweepReadsAConfirmedRevealOnce(t *testing.T) {
	st := &revealStore{}
	m := &policy.Mandate{MandateID: make([]byte, 16), Auditors: []policy.Auditor{{Kid: make([]byte, 16), Pubkey: make([]byte, 32)}}}
	s := &sweeper{io: newArchiveIO(st), q: &retryQueue{}, log: discard, timeout: time.Second,
		pol: newPolInfo("gate", m, nil), reveals: func(string) bool { return true }}
	e := entryOf(1)
	e.Receipt, e.ActionSalt = []byte{1}, make([]byte, 32)

	var stats sweepStats
	for range 3 {
		assert.True(t, s.repairReveal(t.Context(), e, &stats))
	}
	assert.EqualValues(t, 1, st.reads.Load())

	other := entryOf(2)
	other.Receipt, other.ActionSalt = []byte{1}, make([]byte, 32)
	assert.True(t, s.repairReveal(t.Context(), other, &stats))
	assert.EqualValues(t, 2, st.reads.Load(), "another decision is read")
}
