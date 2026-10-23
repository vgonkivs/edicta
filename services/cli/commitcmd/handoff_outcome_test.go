// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

// handOff makes the two recognised refusals and returns the answer to the
// second, reported on ctx.
func (r *handoffRig) handOff(t *testing.T, ctx context.Context) commitcmd.PaidRetryResult {
	t.Helper()
	_, err := r.svc.PaidRetry(context.Background(), r.report(403, "", buyerText))
	require.NoError(t, err)
	r.after(10 * time.Second)
	out, err := r.svc.PaidRetry(ctx, r.report(403, "", buyerText))
	require.NoError(t, err)
	require.True(t, out.HandedOff)
	return out
}

func TestHandoffIsSentWhenTheCallerHasGone(t *testing.T) {
	r := newHandoffRig(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	out := r.handOff(t, gone)
	assert.Equal(t, commitcmd.HandoffOutcomeSent, out.HandoffOutcome)
	assert.Empty(t, out.RelayFault)
	assert.Equal(t, 1, r.relay.calls(), "a cancelled request does not cancel the one handoff")
	assert.Equal(t, commitcmd.HandoffOutcomeSent, r.state(t).HandoffOutcome)

	r.after(10 * time.Second)
	last, err := r.svc.PaidRetry(context.Background(), r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextOperator, last.Next)
	assert.Equal(t, commitcmd.HandoffOutcomeSent, last.HandoffOutcome)
	assert.Equal(t, 1, r.relay.calls())
}

func TestHandoffThatNeverLeftIsRecordedAndNotRepeated(t *testing.T) {
	r := newHandoffRig(t)
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	base := closed.URL
	closed.Close()
	r.svc.Handoff = r.handoff(t, base)

	out := r.handOff(t, context.Background())
	assert.Equal(t, commitcmd.HandoffOutcomeNotSent, out.HandoffOutcome)
	assert.NotEmpty(t, out.RelayFault)
	assert.Equal(t, commitcmd.NextRetry, out.Next)
	st := r.state(t)
	assert.NotZero(t, st.HandoffAtMS, "the mark stays spent")
	assert.Equal(t, commitcmd.HandoffOutcomeNotSent, st.HandoffOutcome, "an operator can see the bytes never left")

	// Even with the payment server back, nothing sends again on its own.
	r.svc.Handoff = r.handoff(t, r.relay.srv.URL)
	for range 3 {
		r.after(time.Minute)
		again, err := r.svc.PaidRetry(context.Background(), r.report(402, liveHeader(t), ""))
		require.NoError(t, err)
		assert.Equal(t, commitcmd.NextOperator, again.Next)
		assert.False(t, again.HandedOff)
		assert.Equal(t, commitcmd.HandoffOutcomeNotSent, again.HandoffOutcome)
	}
	assert.Zero(t, r.relay.calls())
}

func TestHandoffRelayFaultOutcomeIsStored(t *testing.T) {
	r := newHandoffRig(t)
	r.relay.status = http.StatusBadRequest
	out := r.handOff(t, context.Background())
	assert.Equal(t, commitcmd.HandoffOutcomeRelayFault, out.HandoffOutcome)
	assert.Equal(t, commitcmd.HandoffOutcomeRelayFault, r.state(t).HandoffOutcome)
	assert.Equal(t, 1, r.relay.calls())
}

func TestHandoffMarkWithoutOutcomeReadsUnknown(t *testing.T) {
	r := newHandoffRig(t)
	// A process that stopped between the mark and the outcome.
	st := r.state(t)
	st.RefusedAtMS = r.now.Add(-20 * time.Second).UnixMilli()
	st.HandoffAtMS = r.now.UnixMilli()
	require.NoError(t, r.svc.State.Save(r.resp.CommitmentHash, st))

	early, err := r.svc.PaidRetry(context.Background(), r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextRetry, early.Next)
	assert.Equal(t, commitcmd.HandoffOutcomeUnknown, early.HandoffOutcome)

	r.after(10 * time.Second)
	last, err := r.svc.PaidRetry(context.Background(), r.report(403, "", buyerText))
	require.NoError(t, err)
	assert.Equal(t, commitcmd.NextOperator, last.Next)
	assert.Equal(t, commitcmd.HandoffOutcomeUnknown, last.HandoffOutcome)
	assert.Zero(t, r.relay.calls())
}

func TestResumeKeepsTheHandoffOutcome(t *testing.T) {
	r := newHandoffRig(t)
	r.handOff(t, context.Background())
	for name, req := range map[string]commitcmd.Request{
		"by hash": {ResumeHash: r.resp.CommitmentHash, Eden: &commitcmd.EdenInput{PaymentRequired: liveHeader(t)}},
		"by material": {
			Resume: &commitcmd.Resume{Envelope: r.resp.Envelope, Action: r.resp.Action, Salt: r.resp.Salt},
			Eden:   &commitcmd.EdenInput{PaymentRequired: liveHeader(t)},
		},
	} {
		req.Sign, req.Broadcast, req.Record, req.PaymentSignature = true, true, true, true
		_, err := r.svc.Commit(context.Background(), req)
		require.NoError(t, err, name)
		st := r.state(t)
		assert.NotZero(t, st.HandoffAtMS, name)
		assert.Equal(t, commitcmd.HandoffOutcomeSent, st.HandoffOutcome, name)
	}
}
