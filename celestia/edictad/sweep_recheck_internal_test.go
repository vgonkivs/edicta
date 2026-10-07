package edictad

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/memreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// stepLoop runs the sweeper loop on a tick channel and returns a function
// that makes n ticks and waits until the last one has been fully processed.
func stepLoop(t *testing.T, sw *sweeper, needFull bool) (tick func(n int), stop func()) {
	t.Helper()
	ch := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sw.loop(ctx, ch, time.Hour, needFull) }()
	return func(n int) {
			for range n {
				ch <- time.Time{}
			}
		}, func() {
			cancel()
			<-done
		}
}

// A scan that meets a held entry must come back to it once the hold ends,
// without any other trigger.
func TestHeldEntrySkippedByAScanIsRepairedOnALaterTick(t *testing.T) {
	mine := entryOf(3)
	st := &memStore{}
	sw := newSweeper(st, &memLister{entries: []registry.Entry{mine}})

	sw.q.begin(mine.CommitmentHash)
	tick, stop := stepLoop(t, sw, true)
	tick(1) // returns once the immediate full pass is over
	assert.False(t, st.putAuthFor(mine.CommitmentHash), "held: left alone")

	sw.q.end(mine.CommitmentHash)
	tick(3) // the third returns only after the second has been processed
	stop()
	assert.True(t, st.putAuthFor(mine.CommitmentHash), "repaired after the hold ended")
}

// A held entry stays on the recheck list while it is held.
func TestHeldEntryIsKeptWhileItStaysHeld(t *testing.T) {
	mine := entryOf(4)
	st := &memStore{}
	sw := newSweeper(st, &memLister{entries: []registry.Entry{mine}})

	sw.q.begin(mine.CommitmentHash)
	tick, stop := stepLoop(t, sw, true)
	tick(4)
	assert.False(t, st.putAuthFor(mine.CommitmentHash))
	sw.q.end(mine.CommitmentHash)
	tick(3)
	stop()
	assert.True(t, st.putAuthFor(mine.CommitmentHash))
}

// Once repaired, the entry is not checked again on every tick.
func TestRecheckListEmptiesAfterTheRepair(t *testing.T) {
	mine := entryOf(5)
	var reads atomic.Int32
	st := &countingAuthStore{memStore: &memStore{}, reads: &reads}
	sw := newSweeper(st, &memLister{entries: []registry.Entry{mine}})

	sw.q.begin(mine.CommitmentHash)
	tick, stop := stepLoop(t, sw, true)
	tick(1)
	sw.q.end(mine.CommitmentHash)
	tick(3)
	n := reads.Load()
	tick(3)
	stop()
	assert.Equal(t, n, reads.Load(), "no further reads once the entry is settled")
}

type countingAuthStore struct {
	*memStore
	reads *atomic.Int32
}

func (c *countingAuthStore) Authorization(ctx context.Context, h commitment.Hash) (*archive.AuthorizationRecord, error) {
	c.reads.Add(1)
	return c.memStore.Authorization(ctx, h)
}

// The writer raises the dropped flag only after the hold of its request ends:
// a tick in between could take the flag and run a pass that skips the entry.
func TestWriterDoesNotRaiseDroppedWhileTheRequestHoldsTheEntry(t *testing.T) {
	h := commitment.Hash{7}
	sa, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{
		Authorization: commitment.Authorization{
			Version: 1, CommitmentHash: h[:], ActionHash: make([]byte, 32), GateID: "g", Expires: 1, Path: 1,
		},
		Signature: make([]byte, 64),
	})
	require.NoError(t, err)
	rec := &archive.AuthorizationRecord{SignedAuthorization: sa, AuthorizedAt: 1}
	got, ok := authorizationHash(rec)
	require.True(t, ok)
	require.Equal(t, h, got)

	sw := newSweeper(&memStore{putErr: fmt.Errorf("put: %w", archive.ErrCorrupt)}, &memLister{})
	w := &writer{io: sw.io, q: sw.q, log: discard, timeout: time.Second}
	sw.q.begin(h)
	w.write(context.Background(), rec)
	assert.False(t, sw.q.takeDropped(), "the request still holds the entry")
}

// panicRegistry panics right after a successful mark.
type panicRegistry struct {
	*memreg.Registry
	armed atomic.Bool
}

func (p *panicRegistry) Consume(ctx context.Context, e registry.Entry, tol uint64) error {
	err := p.Registry.Consume(ctx, e, tol)
	if err == nil && p.armed.Load() {
		panic("after the mark")
	}
	return err
}

// A panic after the registry mark must not leave the archive without the
// record until the next start: a later tick repairs it.
func TestPanicAfterTheMarkIsRepairedOnALaterTick(t *testing.T) {
	reg := &panicRegistry{Registry: gatefix.MemReg(t, gatefix.Epoch)}
	st := &memStore{}
	arch := &archiver{io: newArchiveIO(st)}
	env := gatefix.New(t, gatefix.WithRegistry(reg), gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch }))
	c := gatefix.Template(t)
	env.StageDA(c, gatefix.Blob(t))
	b, h := gatefix.Sign(t, "agent1", c)

	q := &retryQueue{}
	ag := &archivingGate{g: env.Gate, clock: env.Clock, gateID: gatefix.GateID, q: q,
		w: &writer{io: arch.io, q: q, log: discard, timeout: time.Second}}
	reg.armed.Store(true)
	func() {
		defer func() { _ = recover() }()
		_, _ = ag.Authorize(context.Background(), b, gatefix.Action(t))
	}()
	assert.False(t, q.holds(h), "the hold is released")
	_, err := reg.Get(context.Background(), gatefix.KeyOf(c))
	require.NoError(t, err, "the nonce was marked")

	sw := &sweeper{lister: reg, io: arch.io, q: q, log: discard, timeout: time.Second}
	tick, stop := stepLoop(t, sw, false)
	tick(3)
	stop()
	var repaired bool
	st.mu.Lock()
	for _, r := range st.puts {
		_, isAuth := r.(*archive.AuthorizationRecord)
		repaired = repaired || isAuth
	}
	st.mu.Unlock()
	assert.True(t, repaired, "a later tick writes the Authorization record")
}

// A request can start its hold between recheckHeld's own check and the one in
// entry; entry must then say the entry is not settled, or recheckHeld would
// forget it.
func TestEntryDeferringToAHoldReportsItUnsettled(t *testing.T) {
	mine := entryOf(9)
	sw := newSweeper(&memStore{}, &memLister{})
	sw.q.begin(mine.CommitmentHash)

	assert.False(t, sw.entry(context.Background(), mine, &sweepStats{}))
	assert.Contains(t, sw.recheck, mine.Key, "the entry stays for the next look")

	sw.recheck = map[registry.Key]registry.Entry{mine.Key: mine}
	sw.recheckHeld(context.Background(), &sweepStats{})
	assert.Contains(t, sw.recheck, mine.Key, "still held: kept")
}
