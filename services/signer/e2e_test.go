// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

// TestEndToEnd: agent decision and gate Authorization in, over the HTTP API;
// the signed deposit goes to the (fake) chain, lands, is seen at the
// confirmation depth, and the gate (fake) records its rail_ref under the
// executor key. A settlement check of the receipt's claim then passes.
func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	d := e.decision(signertest.DecisionOpts{})
	resp, body := post(t, srv, "application/cbor", signerapi.EncodeSignRequest(request(d)))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	out, err := signerapi.DecodeSignResponse(body)
	require.NoError(t, err)

	var got signer.Entry
	require.Eventually(t, func() bool {
		got = e.entry(d.Hash)
		return got.State == signer.StateRecorded
	}, 10*time.Second, 10*time.Millisecond)

	r, _, err := commitment.VerifyReceipt(got.Receipt)
	require.NoError(t, err)
	assert.Equal(t, d.Hash[:], r.Receipt.CommitmentHash)
	assert.Equal(t, out.RailRef, r.Receipt.RailRef)
	assert.Equal(t, edenescrow.RailRef(out.Signed), r.Receipt.RailRef)
	assert.Equal(t, 1, e.gate.Calls(), "one record request")

	// What the receipt claims checks out against the chain.
	cfg := edenexec.Config{MinLevel: edenexec.LevelNodeAttested}
	cfg.ApplyDefaults()
	checker, err := edenexec.NewChecker(cfg, []edenexec.Source{e.chain}, nil)
	require.NoError(t, err)
	rep, err := checker.SettlementOfAction(context.Background(), d.Action, r.Receipt.RailRef, d.Expires, 0)
	require.NoError(t, err)
	assert.Equal(t, edenexec.StatusPass, rep.Status)
	assert.Equal(t, e.keys.PayerAddress(), rep.Payer)

	// A retry of the same request returns the same bytes and does nothing else.
	resp, body = post(t, srv, "application/cbor", signerapi.EncodeSignRequest(request(d)))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	again, err := signerapi.DecodeSignResponse(body)
	require.NoError(t, err)
	assert.True(t, again.Repeat)
	assert.Equal(t, out.Signed, again.Signed)
	assert.Equal(t, signer.StateRecorded, e.entry(d.Hash).State)
}
