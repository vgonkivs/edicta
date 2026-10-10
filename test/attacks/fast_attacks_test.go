package attacks_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

const fastDelay = 50

// fastCase is one pending celestia_blob decision at a fast gate, with its
// intent and the facts the chain reports for it.
type fastCase struct {
	e     *gatefix.Env
	arch  *countingArchiver
	c     *commitment.Commitment
	b     []byte
	rec   gate.AnchorIntent
	facts gate.IntentFacts
}

func newFastCase(t *testing.T, opts ...gatefix.Option) *fastCase {
	t.Helper()
	m := mandate(t, 1, 1)
	m.FastModeMaxDelay = fastDelay
	arch := &countingArchiver{}
	e, ref := fastGate(t, m, arch, true, opts...)
	issued := gatefix.Now - 10
	c := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 1), issued, issued+600)
	c.MandateRef = ref
	c.PayloadRef.Anchor = commitment.AnchorPending
	e.StageArchive(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	fc := &fastCase{e: e, arch: arch, c: c, b: b}
	fc.rec = gate.AnchorIntent{DA: commitment.DACelestiaBlob, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace,
		RefHeight: c.PayloadRef.Height, Tx: []byte("signed pfb"), Signer: c.PayloadRef.Signer, CreatedAt: issued - 19}
	fc.facts = gate.IntentFacts{DA: commitment.DACelestiaBlob, RefTime: issued - 20, Head: c.PayloadRef.Height + 2, HeadTime: issued - 8}
	e.Intents.Put(fc.rec)
	e.Verifier.Set(fc.rec.Tx, fc.facts)
	return fc
}

func (fc *fastCase) refused(t *testing.T, res gate.Result, err, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	assert.Empty(t, res.Authorization, "no Authorization")
	fc.e.RequireUntouched(fc.c)
}

// Concurrent double-spend of one pending decision: exactly one request
// issues the fast-mode Authorization, every other one gets the stored one.
func TestFastAttackConcurrentDoubleSpend(t *testing.T) {
	fc := newFastCase(t)
	const n = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		fresh int
		auths [][]byte
		other []error
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := fc.e.Authorize(fc.b)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				fresh++
			case !errors.Is(err, gate.ErrNonceUsed):
				other = append(other, err)
				return
			}
			auths = append(auths, res.Authorization)
		}()
	}
	wg.Wait()
	require.Empty(t, other)
	assert.Equal(t, 1, fresh, "one Authorization per (agent, nonce)")
	require.Len(t, auths, n)
	for _, a := range auths {
		assert.Equal(t, auths[0], a, "every answer is the one stored Authorization")
	}
	sa, _, err := commitment.DecodeSignedAuthorization(auths[0])
	require.NoError(t, err)
	assert.EqualValues(t, commitment.ModeFast, sa.Authorization.Mode)
	assert.Equal(t, fc.c.PayloadRef.Height+fastDelay, sa.Authorization.AnchorDeadline)
}

// Stale h0: a reference height older than MaxH0AgeBlocks at the head is
// final, even if the anchor tx is already on chain.
func TestFastAttackStaleH0(t *testing.T) {
	fc := newFastCase(t)
	fc.facts.Head = fc.c.PayloadRef.Height + fc.e.Cfg.MaxH0AgeBlocks + 1
	fc.e.Verifier.Set(fc.rec.Tx, fc.facts)
	fc.e.Broadcaster.SetStatus(fc.rec.Tx, gate.TxStatus{Included: true, Height: fc.c.PayloadRef.Height + 1})
	res, err := fc.e.Authorize(fc.b)
	fc.refused(t, res, err, gate.ErrH0TooOld)
	assert.Empty(t, fc.e.Broadcaster.Broadcasts())
}

// A deadline at or below the head cannot be met: without the anchor already
// in the window, the request is refused and nothing is broadcast.
func TestFastAttackDeadlineAtOrBelowTheHead(t *testing.T) {
	for name, head := range map[string]uint64{"at": fastDelay, "below": fastDelay + 1} {
		t.Run(name, func(t *testing.T) {
			fc := newFastCase(t, gatefix.WithConfig(func(c *gate.Config) {
				c.FastWindowBlocks, c.MaxH0AgeBlocks = 1000, 100
			}))
			fc.facts.Head = fc.c.PayloadRef.Height + head
			fc.e.Verifier.Set(fc.rec.Tx, fc.facts)
			res, err := fc.e.Authorize(fc.b)
			fc.refused(t, res, err, gate.ErrAnchorWindowClosed)
			assert.Empty(t, fc.e.Broadcaster.Broadcasts())
		})
	}
}

// A pending reference in a namespace the operator did not list is refused
// before the archive stage: the gate never looks up or rebroadcasts there.
func TestFastAttackWrongNamespace(t *testing.T) {
	fc := newFastCase(t, gatefix.WithConfig(func(c *gate.Config) {
		c.PendingNamespaces = [][]byte{gatefix.MustHex(t, "000000000000000000000000000000000000006564696374612f6f7468")}
	}))
	before := snapshot(t, fc.e, fc.arch)
	res, err := fc.e.Authorize(fc.b)
	require.ErrorIs(t, err, gate.ErrNamespaceNotAllowed)
	requireNothingWritten(t, fc.e, fc.arch, before, fc.c, res)
	requireNoIntentWork(t, fc.e)
}

// An intent the archive holds for another commitment under the same h0 is
// not the intent of this decision: the archive-backed source finds nothing,
// and the request is a retryable refusal with nothing issued.
func TestFastAttackIntentForAnotherCommitment(t *testing.T) {
	st, err := fsarchive.Open(t.TempDir(), map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	fc := newFastCase(t, gatefix.WithDeps(func(d *gate.Deps) { d.Intents = archive.NewIntentSource(st) }))
	other := make([]byte, 32)
	other[0] = 1
	_, err = st.Put(t.Context(), &archive.AnchorIntentRecord{DA: fc.rec.DA, Commitment: other, Namespace: fc.rec.Namespace,
		RefHeight: fc.rec.RefHeight, Tx: fc.rec.Tx, Signer: fc.rec.Signer, CreatedAt: fc.rec.CreatedAt})
	require.NoError(t, err)

	res, err := fc.e.Authorize(fc.b)
	fc.refused(t, res, err, gate.ErrAnchorIntentUnavailable)
	assert.Zero(t, fc.e.Verifier.Calls())
	assert.Empty(t, fc.e.Broadcaster.Broadcasts())

	// The intent of this decision, archived later, is accepted.
	_, err = st.Put(t.Context(), &archive.AnchorIntentRecord{DA: fc.rec.DA, Commitment: fc.rec.Commitment, Namespace: fc.rec.Namespace,
		RefHeight: fc.rec.RefHeight, Tx: fc.rec.Tx, Signer: fc.rec.Signer, CreatedAt: fc.rec.CreatedAt})
	require.NoError(t, err)
	_, err = fc.e.Authorize(fc.b)
	require.NoError(t, err)
}

// Intent replay: an anchor tx already included before h0 (an old PFB reused
// under a new reference height) or after the deadline is never the anchor
// of this decision.
func TestFastAttackIntentReplay(t *testing.T) {
	for name, at := range map[string]func(h0 uint64) uint64{
		"included before h0":        func(h0 uint64) uint64 { return h0 - 1 },
		"included after the window": func(h0 uint64) uint64 { return h0 + fastDelay + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			fc := newFastCase(t)
			fc.e.Broadcaster.SetStatus(fc.rec.Tx, gate.TxStatus{Included: true, Height: at(fc.c.PayloadRef.Height)})
			res, err := fc.e.Authorize(fc.b)
			fc.refused(t, res, err, gate.ErrAnchorWindowClosed)
			assert.Empty(t, fc.e.Broadcaster.Broadcasts())
		})
	}

	// A replayed request after the Authorization gets the stored bytes and
	// never re-runs K-fast: no second verification, no second broadcast.
	t.Run("request replay", func(t *testing.T) {
		fc := newFastCase(t)
		first, err := fc.e.Authorize(fc.b)
		require.NoError(t, err)
		calls, sent := fc.e.Verifier.Calls(), len(fc.e.Broadcaster.Broadcasts())
		again, err := fc.e.Authorize(fc.b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		assert.Equal(t, first.Authorization, again.Authorization)
		assert.Equal(t, calls, fc.e.Verifier.Calls())
		assert.Len(t, fc.e.Broadcaster.Broadcasts(), sent)
	})
}

// A mandate whose fast_mode_max_delay leaves no room for the slack would
// refuse every pending reference, so the gate refuses it at start.
func TestFastAttackMandateDelayBelowTheSlack(t *testing.T) {
	for delay, ok := range map[uint64]bool{1: false, 3: false, 4: true} {
		m := mandate(t, 1, 1)
		m.FastModeMaxDelay = delay
		x, err := policy.NewExtractors(lastByteExtractor{})
		require.NoError(t, err)
		mb, _ := signMandate(t, m)
		_, err = gatefix.TryNew(t,
			gatefix.WithConfig(func(c *gate.Config) {
				c.Mandate = mb
				c.FastMode = true
				c.PendingNamespaces = [][]byte{gatefix.Template(t).PayloadRef.Namespace}
			}),
			gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }),
			withArchiver(&countingArchiver{}))
		if ok {
			require.NoError(t, err, "delay %d", delay)
			continue
		}
		require.ErrorIs(t, err, gate.ErrInvalidConfig, "delay %d", delay)
		require.ErrorContains(t, err, gate.CauseFastDelayBelowSlack)
	}
}
