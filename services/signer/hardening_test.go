// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

func TestTheCommitmentBoundsWhatAGateMayAuthorize(t *testing.T) {
	t.Run("commitment for another gate", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.svc.Sign(context.Background(), request(e.decision(signertest.DecisionOpts{ScopeGateID: "gate2"})))
		require.ErrorIs(t, err, signer.ErrNotAuthorized)
		require.ErrorIs(t, err, commitment.ErrScopeMismatch)
	})
	t.Run("Authorization outliving the commitment", func(t *testing.T) {
		e := newEnv(t)
		now := uint64(e.clk.Now().Unix())
		d := e.decision(signertest.DecisionOpts{ValidUntil: now + 400, Expires: now + 500})
		_, err := e.svc.Sign(context.Background(), request(d))
		require.ErrorIs(t, err, signer.ErrNotAuthorized)
	})
	t.Run("commitment and Authorization ending within skew", func(t *testing.T) {
		e := newEnv(t)
		now := uint64(e.clk.Now().Unix())
		d := e.decision(signertest.DecisionOpts{ValidUntil: now + 20, Expires: now + 20})
		_, err := e.svc.Sign(context.Background(), request(d))
		require.ErrorIs(t, err, signer.ErrExpired)
	})
}

func TestReservedDecisionKeepsItsPayer(t *testing.T) {
	e := newEnv(t)
	d := e.decision(signertest.DecisionOpts{})
	a, err := edenescrow.DecodeTxAction(d.Action)
	require.NoError(t, err)
	_, _, err = e.store.Reserve(context.Background(), signer.Entry{
		CommitmentHash: d.Hash, Digest: a.SigHash(), Payer: [20]byte{0x01}, State: signer.StateReserved,
	}, 0, admitAll)
	require.NoError(t, err)
	_, err = e.svc.Sign(context.Background(), request(d))
	require.ErrorIs(t, err, signer.ErrPinMismatch)
	assert.Zero(t, e.chain.SentCount())
}

func TestOnePayerKeyForTwoChainsIsRefused(t *testing.T) {
	e := newEnv(t)
	svc, err := signer.New(e.cfg, signer.Deps{
		Store: e.store, Handlers: []signer.Handler{e.h},
		Wallets: map[signer.WalletKey]signer.WalletBackend{
			walletKey(t, e.keys, 714): mustWallet(t, e.keys), walletKey(t, e.keys, 3735928814): mustWallet(t, e.keys),
		},
	})
	require.NoError(t, err)
	require.ErrorContains(t, svc.Start(context.Background()), "serves agent")
}

func TestOnePayerKeyForTwoAgentsIsRefused(t *testing.T) {
	e := newEnv(t)
	other := signertest.NewKeys(t.Name() + "/other")
	cfg := e.cfg
	cfg.AgentKeys = append(cfg.AgentKeys, other.AgentPub())
	svc, err := signer.New(cfg, signer.Deps{
		Store: e.store, Handlers: []signer.Handler{e.h},
		Wallets: map[signer.WalletKey]signer.WalletBackend{
			walletKey(t, e.keys, 714): mustWallet(t, e.keys), walletKey(t, other, 714): mustWallet(t, e.keys),
		},
	})
	require.NoError(t, err)
	require.ErrorContains(t, svc.Start(context.Background()), "serves agent")
}

func TestWalletForAnAgentNotServedIsRefused(t *testing.T) {
	e := newEnv(t)
	other := signertest.NewKeys(t.Name() + "/other")
	_, err := signer.New(e.cfg, signer.Deps{
		Store: e.store, Handlers: []signer.Handler{e.h},
		Wallets: map[signer.WalletKey]signer.WalletBackend{walletKey(t, other, 714): mustWallet(t, other)},
	})
	require.ErrorContains(t, err, "not served")
}

const adminToken = "fedcba9876543210-admin"

func admin(t *testing.T, srv string, tok string, h []byte) (int, string) {
	t.Helper()
	body := edictaapi.EncodeWrapper(edictaapi.BytesItem(1, h))
	req, err := http.NewRequest(http.MethodPost, srv+signerapi.RouteRequeue, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errorCode(t, "application/cbor", b.Bytes())
	}
	f, err := edictaapi.DecodeWrapper(b.Bytes(), signerapi.RequeueResponseSchema)
	require.NoError(t, err)
	return resp.StatusCode, f.Text(1)
}

func TestOperatorRequeuesADecisionTheGateRefused(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{AdminToken: []byte(adminToken)})
	// A wrong gate token: the gate answers a non-retryable 401.
	e.gate.err = &edictaapi.Error{Status: 401, Code: "edictaapi.ErrTokenInvalid", Message: "bad token"}
	d := e.decision(signertest.DecisionOpts{})
	_, err := e.svc.Sign(context.Background(), request(d))
	require.NoError(t, err)
	e.waitState(d.Hash, signer.StateWrong)

	status, code := admin(t, srv.URL, token, d.Hash[:])
	assert.Equal(t, http.StatusUnauthorized, status, "the agents' token never reaches the operator route")
	assert.Equal(t, "edictaapi.ErrTokenInvalid", code)
	status, code = admin(t, srv.URL, adminToken, make([]byte, 32))
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "signer.ErrUnknownDecision", code)

	e.gate.mu.Lock()
	e.gate.err = nil
	e.gate.mu.Unlock()
	status, state := admin(t, srv.URL, adminToken, d.Hash[:])
	require.Equal(t, http.StatusOK, status, state)
	assert.Equal(t, string(signer.StateExecuted), state)
	got := e.waitState(d.Hash, signer.StateRecorded)
	assert.NotEmpty(t, got.Receipt)

	status, code = admin(t, srv.URL, adminToken, d.Hash[:])
	assert.Equal(t, http.StatusConflict, status, "only a decision in state wrong")
	assert.Equal(t, "signer.ErrNotRequeueable", code)
}

func TestOperatorRouteIsOffWithoutAnAdminToken(t *testing.T) {
	e := newEnv(t)
	srv := newAPI(t, e, signer.HTTPOptions{})
	status, code := admin(t, srv.URL, token, make([]byte, 32))
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "edictaapi.ErrRouteNotFound", code)
	require.Error(t, signer.HTTPOptions{Token: []byte(token), AdminToken: []byte(token)}.ValidateBasic())
}

// N parallel copies of one request: one entry, one signature, equal outputs,
// counted once.
func TestParallelIdenticalRequestsSignOnce(t *testing.T) {
	value := signertest.NewDeposit(time.Now()).Value
	e := newEnv(t, func(c *signer.Config) { c.Caps.MaxValuePerAction, c.Caps.MaxValuePerHour = value, value })
	d := e.decision(signertest.DecisionOpts{})
	const n = 16
	outs := make([]signer.Output, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], errs[i] = e.svc.Sign(context.Background(), request(d))
		}()
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, outs[0].Signed, outs[i].Signed)
		assert.Equal(t, outs[0].RailRef, outs[i].RailRef)
	}
	assert.Equal(t, outs[0].Signed, e.entry(d.Hash).Signed)
	for _, s := range e.chain.Sent {
		assert.Equal(t, outs[0].Signed, s, "only the one stored transaction is ever sent")
	}

	// The cap admits exactly one deposit: had a copy been counted twice,
	// nothing else could be reserved, and it still cannot.
	e.chain.Set(func(c *signertest.Chain) { c.Nonce = 8 })
	other := e.decision(signertest.DecisionOpts{Label: "other"}, func(dep *signertest.Deposit) { dep.Nonce = 8 })
	_, err := e.svc.Sign(context.Background(), request(other))
	require.ErrorIs(t, err, signer.ErrRiskLimit)
}

// N parallel distinct decisions against an hourly cap of k: exactly k are
// stored and the counted sum never passes the cap.
// ownSlots gives every decision its own slot, so that only the caps decide
// between decisions that share the payer's nonce.
type ownSlots struct{ signer.Handler }

func (o ownSlots) Check(ctx context.Context, v signer.Verified, now time.Time) (signer.Plan, error) {
	p, err := o.Handler.Check(ctx, v, now)
	p.Slot += fmt.Sprintf("/%x", v.CommitmentHash)
	return p, err
}

func TestParallelDistinctRequestsNeverPassTheCap(t *testing.T) {
	const n, k = 20, 5
	value := signertest.NewDeposit(time.Now()).Value
	wrap := func(h signer.Handler) signer.Handler { return ownSlots{h} }
	e := newEnvOpts(t, envOpts{wrap: wrap}, func(c *signer.Config) {
		c.Caps.MaxValuePerAction = value
		c.Caps.MaxValuePerHour = new(big.Int).Mul(value, big.NewInt(k))
	})
	reqs := make([]signer.Request, n)
	for i := range n {
		reqs[i] = request(e.decision(signertest.DecisionOpts{Label: fmt.Sprint("d", i)}))
	}
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.svc.Sign(context.Background(), reqs[i])
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		require.ErrorIs(t, err, signer.ErrRiskLimit)
	}
	assert.Equal(t, k, ok)
	stored, err := e.store.Unfinished(context.Background(), signer.StateReserved, signer.StateSigned)
	require.NoError(t, err)
	assert.Len(t, stored, k)
	sum := new(big.Int)
	for _, s := range stored {
		sum.Add(sum, new(big.Int).SetBytes(s.Value))
	}
	assert.LessOrEqual(t, sum.Cmp(e.cfg.Caps.MaxValuePerHour), 0)
}

func TestStateIndexFollowsEveryChange(t *testing.T) {
	ctx := context.Background()
	st, err := signer.OpenBoltStore(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	defer st.Close()
	for i := range 3 {
		_, _, err := st.Reserve(ctx, signer.Entry{CommitmentHash: commitment.Hash{byte(i + 1)}, State: signer.StateReserved}, 0, admitAll)
		require.NoError(t, err)
	}
	_, err = st.Update(ctx, commitment.Hash{1}, func(e *signer.Entry) error { e.State = signer.StateSigned; return nil })
	require.NoError(t, err)
	_, err = st.Update(ctx, commitment.Hash{2}, func(e *signer.Entry) error { e.State = signer.StateRecorded; return nil })
	require.NoError(t, err)

	count := func(states ...signer.State) int {
		l, err := st.Unfinished(ctx, states...)
		require.NoError(t, err)
		return len(l)
	}
	assert.Equal(t, 1, count(signer.StateReserved))
	assert.Equal(t, 1, count(signer.StateSigned))
	assert.Equal(t, 1, count(signer.StateRecorded))
	assert.Equal(t, 2, count(signer.StateSigned, signer.StateReserved, signer.StateSigned))
	assert.Equal(t, 0, count(signer.StateWrong))
	_, err = st.Update(ctx, commitment.Hash{9}, func(*signer.Entry) error { return nil })
	require.ErrorIs(t, err, signer.ErrUnknownDecision)
}
