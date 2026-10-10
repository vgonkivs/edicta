package edictad_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// intentStore is the fault store with the real store's intent read side, so
// a fast-mode daemon starts and every put stays observable.
type intentStore struct {
	*faultStore
	ir    archive.IntentReader
	mu    sync.Mutex
	reads int
}

func (s *intentStore) Intent(ctx context.Context, da commitment.DA, commit []byte, h uint64) (*archive.AnchorIntentRecord, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.ir.Intent(ctx, da, commit, h)
}

func (s *intentStore) intentReads() int { s.mu.Lock(); defer s.mu.Unlock(); return s.reads }

// pendingFast makes the decisions of p pending and wires an intent store.
// With intent set, the archived blob and a PFB intent for it are stored.
func pendingFast(t *testing.T, p *policyEnv, intent bool) (*intentStore, commitment.PayloadRef) {
	t.Helper()
	pending := *p.base
	pending.PayloadRef.Anchor = commitment.AnchorPending
	p.base = &pending
	ref := pending.PayloadRef
	if intent {
		putIntent(t, p, ref)
	}
	s := &intentStore{faultStore: p.fs, ir: p.real}
	p.deps.Archive = s
	return s, ref
}

func putIntent(t *testing.T, p *policyEnv, ref commitment.PayloadRef) {
	t.Helper()
	blob := gatefix.Blob(t)
	_, err := p.real.Put(bg, &archive.PayloadRecord{DA: ref.DA, Commitment: ref.Commitment, Namespace: ref.Namespace,
		Signer: ref.Signer, Blob: blob, IntentHeight: ref.Height})
	require.NoError(t, err)
	_, err = p.real.Put(bg, &archive.AnchorIntentRecord{DA: ref.DA, Commitment: ref.Commitment, Namespace: ref.Namespace,
		RefHeight: ref.Height, Tx: pfbTx(t, ref, len(blob)), Signer: ref.Signer, CreatedAt: uint64(t0.Unix()) - 900})
	require.NoError(t, err)
}

// A fast-mode daemon whose mandate never consented to fast mode (no key 16)
// answers a pending decision with the signed fast-mode consent deny and archives exactly
// the decision, the deny verdict and its marker. It never reads the intent,
// never broadcasts and never issues an Authorization.
func TestFastModeWithoutConsentWritesOnlyTheDeny(t *testing.T) {
	p := newPolicyEnv(t)
	require.Zero(t, p.mandate.FastModeMaxDelay)
	s, _ := pendingFast(t, p, true)
	p.startPolicy(p.fastTable())
	assert.Contains(t, p.logs.String(), "does not allow it", "the gate warns at start")
	n := len(p.fs.puts)

	d := p.send(1, 1_000_000)
	st, body := p.authorizeOn("/v1/authorize", d)
	require.GreaterOrEqual(t, st, 400)
	assert.True(t, hasCode(body, "ErrFastModeNotAllowed"), "body %q", body)
	require.NoError(t, p.srv.Shutdown(bg))

	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindPolicyDeny, archive.KindRejection}, kindsOf(p.fs.puts, n),
		"exactly the decision, the deny and the marker")
	deny, err := p.real.PolicyDeny(bg, d.hash, "ErrFastModeNotAllowed")
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(deny.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	assert.EqualValues(t, policy.OutcomeDeny, sv.Verdict.Outcome)
	assert.Equal(t, "ErrFastModeNotAllowed", sv.Verdict.Reason)
	_, err = p.real.Rejection(bg, d.hash, "ErrFastModeNotAllowed")
	require.NoError(t, err)
	_, err = p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	assert.Zero(t, s.intentReads(), "K-fast never runs without consent")
	assert.Empty(t, p.cons.Sent, "nothing is broadcast")
}

// A missing intent is an operational 503: no marker, no nonce, and the same
// decision authorizes once the intent is archived.
func TestFastModeMissingIntentIsRetryable(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	_, ref := pendingFast(t, p, false)
	p.startPolicy(p.fastTable())

	d := p.send(1, 1_000_000)
	st, body := p.authorizeOn("/v1/authorize", d)
	assert.Equal(t, 503, st, "%q", body)
	assert.True(t, hasCode(body, "ErrAnchorIntentUnavailable"), "body %q", body)
	assert.Zero(t, p.fs.putCount(archive.KindRejection), "an operational failure leaves no marker")
	assert.Zero(t, p.fs.putCount(archive.KindPolicyDeny))
	_, err := p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	putIntent(t, p, ref)
	st, body = p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 200, st, "%q", body)
	rec, err := p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
	sa, _, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
	require.NoError(t, err)
	assert.EqualValues(t, commitment.ModeFast, sa.Authorization.Mode)
	assert.Equal(t, ref.Height+fastDelay, sa.Authorization.AnchorDeadline)
}

// A pending reference in a namespace the operator did not list is refused
// before anything is archived or read from the chain.
func TestFastModeUnlistedNamespace(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	s, _ := pendingFast(t, p, true)
	other := "000000000000000000000000000000000000006564696374612f6f7468"
	p.startPolicy(p.fastTable("enabled = true", "own_node = true", `pending_namespaces = ["`+other+`"]`))
	n := len(p.fs.puts)

	st, body := p.authorizeOn("/v1/authorize", p.send(1, 1_000_000))
	assert.GreaterOrEqual(t, st, 400)
	assert.True(t, hasCode(body, "ErrNamespaceNotAllowed"), "body %q", body)
	require.NoError(t, p.srv.Shutdown(bg))
	assert.Empty(t, kindsOf(p.fs.puts, n), "a stage 1 refusal archives nothing")
	assert.Zero(t, s.intentReads())
	assert.Empty(t, p.cons.Sent)
}

// A mandate whose delay cannot leave the slack above the head would refuse
// every pending reference, so the daemon does not start with it; one block
// more is enough.
func TestFastStartRefusesAMandateDelayBelowTheSlack(t *testing.T) {
	for delay, ok := range map[uint64]bool{1: false, 3: false, 4: true} {
		p := newPolicyEnv(t)
		p.mandate.FastModeMaxDelay = delay
		p.file = p.sign(p.principal, p.mandate)
		pendingFast(t, p, false)
		srv, err := edictad.Start(bg, p.cfg(p.edits(p.fastTable())...), p.deps)
		if ok {
			require.NoError(t, err, "delay %d", delay)
			require.NoError(t, srv.Shutdown(bg))
			continue
		}
		require.ErrorIs(t, err, gate.ErrInvalidConfig, "delay %d", delay)
		assert.Contains(t, err.Error(), gate.CauseFastDelayBelowSlack)
		assert.Zero(t, p.listens, "delay %d: no listener", delay)
	}
}
