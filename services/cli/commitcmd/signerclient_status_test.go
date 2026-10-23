// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/internal/secret"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
	"github.com/vgonkivs/edicta/services/signer"
)

func TestSignerClientStatus(t *testing.T) {
	var hash commitment.Hash
	hash[0] = 9
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, signer.RouteStatusPrefix+hex.EncodeToString(hash[:]), r.URL.Path)
		cbor(w, 200, edictaapi.EncodeWrapper(edictaapi.TextItem(1, "executed"), edictaapi.BytesItem(2, hash[:]),
			edictaapi.UintItem(3, 1), edictaapi.TextItem(4, "ref"), edictaapi.BytesItem(5, []byte("tx")), edictaapi.UintItem(8, 1)))
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)
	st, err := c.Status(context.Background(), hash)
	require.NoError(t, err)
	assert.Equal(t, signer.StateExecuted, st.State)
	assert.True(t, st.Sent)
	assert.True(t, st.PaymentProofAllowed)
	assert.Equal(t, []byte("tx"), st.Signed)
}

func TestSignerClientNeverFollowsARedirect(t *testing.T) {
	var reached bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)
	_, err = c.Sign(context.Background(), signer.Request{})
	require.Error(t, err)
	assert.False(t, reached, "the token was not sent on")
}

func TestSignerClientServerFailureWithoutABodyIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>"))
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)
	_, err = c.Sign(context.Background(), signer.Request{})
	var se *commitcmd.SignerError
	require.ErrorAs(t, err, &se)
	assert.True(t, se.Retryable)
}

func TestFileStateStoreRefusesAnOpenDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o755))
	_, err := commitcmd.NewFileStateStore(dir)
	require.Error(t, err)
}
