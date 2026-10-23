// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/signer"
)

func TestStatusShowsTheAgentsOwnDecision(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a")

	_, err := e.svc.Status(context.Background(), d.Hash, e.keys.AgentPub())
	require.ErrorIs(t, err, signer.ErrUnknownDecision, "nothing reserved yet")

	out := e.executed(d, dep)
	st, err := e.svc.Status(context.Background(), d.Hash, e.keys.AgentPub())
	require.NoError(t, err)
	assert.Equal(t, signer.StateRecorded, st.State)
	assert.True(t, st.Sent)
	assert.Equal(t, out.Signed, st.Signed)
	assert.Equal(t, out.RailRef, st.RailRef)
	assert.True(t, st.PaymentProofAllowed)
	assert.NotEmpty(t, st.Receipt)
}

func TestStatusDoesNotLeakAnotherAgentsDecision(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	e.executed(d, dep)

	_, err := e.svc.Status(context.Background(), d.Hash, otherAgent.Public().(ed25519.PublicKey))
	require.ErrorIs(t, err, signer.ErrUnknownDecision)
	_, err = e.svc.Status(context.Background(), d.Hash, nil)
	require.ErrorIs(t, err, signer.ErrSharedCredential, "a shared credential is refused before any lookup")
	_, err = e.svc.Status(context.Background(), [32]byte{}, nil)
	require.ErrorIs(t, err, signer.ErrSharedCredential, "and the answer does not depend on the hash")
	_, err = e.svc.Status(context.Background(), d.Hash, otherAgent.Public().(ed25519.PublicKey))
	var unknown [32]byte
	_, err2 := e.svc.Status(context.Background(), unknown, otherAgent.Public().(ed25519.PublicKey))
	assert.Equal(t, err.Error(), err2.Error(), "an unknown hash reads the same")
}

func TestHTTPStatus(t *testing.T) {
	e := paymentEnv(t)
	d, dep := e.quoted("a")
	out := e.executed(d, dep)
	const agentToken, otherToken = "agent-a-token-0123456789", "agent-b-token-0123456789"
	h, err := signer.NewHandler(e.svc, signer.HTTPOptions{Credentials: []signer.Credential{
		{Token: []byte(agentToken), Agent: e.keys.AgentPub()},
		{Token: []byte(otherToken), Agent: otherAgent.Public().(ed25519.PublicKey)},
	}}, quiet)
	require.NoError(t, err)
	srv := httptest.NewServer(h)
	defer srv.Close()

	get := func(tok, path string) (int, []byte) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}
	path := signer.RouteStatusPrefix + hex.EncodeToString(d.Hash[:])

	status, b := get(agentToken, path)
	require.Equal(t, http.StatusOK, status, string(b))
	st, err := signer.DecodeStatusResponse(b)
	require.NoError(t, err)
	assert.Equal(t, signer.StateRecorded, st.State)
	assert.Equal(t, out.Signed, st.Signed)
	assert.Equal(t, out.RailRef, st.RailRef)

	status, other := get(otherToken, path)
	assert.Equal(t, http.StatusNotFound, status)
	status, missing := get(otherToken, signer.RouteStatusPrefix+hex.EncodeToString(make([]byte, 32)))
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, string(other), string(missing), "another agent's decision reads like an unknown one")

	status, _ = get("not-a-token-0123456789", path)
	assert.Equal(t, http.StatusUnauthorized, status)
	for _, bad := range []string{"zz", hex.EncodeToString(make([]byte, 31)), "", "x", hex.EncodeToString(d.Hash[:])[:63] + "G"} {
		status, _ = get(agentToken, signer.RouteStatusPrefix+bad)
		assert.Equal(t, http.StatusNotFound, status, bad)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
