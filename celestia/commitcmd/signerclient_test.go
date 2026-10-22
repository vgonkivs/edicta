// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/signer"
)

func cbor(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func TestSignerClientSignAndPaymentSignature(t *testing.T) {
	var hash commitment.Hash
	hash[0] = 7
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer tok-0123456789abcdef", r.Header.Get("Authorization"))
		assert.Equal(t, "application/cbor", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case signer.RouteSign:
			req, err := signer.DecodeSignRequest(body)
			require.NoError(t, err)
			assert.Equal(t, []byte("R"), req.Requirements)
			cbor(w, 200, edictaapi.EncodeWrapper(edictaapi.BytesItem(1, []byte("tx")), edictaapi.TextItem(2, "ref"),
				edictaapi.BytesItem(3, hash[:]), edictaapi.UintItem(4, 1)))
		case signer.RoutePaymentSignature:
			req, err := signer.DecodePaymentRequest(body)
			require.NoError(t, err)
			assert.Equal(t, "paymentId", req.Field)
			cbor(w, 200, edictaapi.EncodeWrapper(edictaapi.TextItem(1, "0xabc"), edictaapi.BytesItem(2, make([]byte, 32)), edictaapi.UintItem(3, 0)))
		default:
			cbor(w, 404, edictaapi.ErrorBody("edictaapi.ErrRouteNotFound", "no", false))
		}
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)

	out, err := c.Sign(context.Background(), signer.Request{
		Envelope: []byte("e"), Action: []byte("a"), Salt: make([]byte, 32), Authorization: []byte("z"), Requirements: []byte("R"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("tx"), out.Signed)
	assert.Equal(t, "ref", out.RailRef)
	assert.Equal(t, hash, out.CommitmentHash)
	assert.True(t, out.Repeat)

	proof, err := c.PaymentSignature(context.Background(), signer.PaymentProofRequest{
		CommitmentHash: hash, Field: "paymentId",
		Request: signer.Request{Envelope: []byte("e"), Action: []byte("a"), Salt: make([]byte, 32), Authorization: []byte("z")},
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("0xabc"), proof.Signature)
}

func TestSignerClientMapsErrorBodies(t *testing.T) {
	status, retry := 409, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cbor(w, status, edictaapi.ErrorBody("signer.ErrNotExecuted", "not yet", retry))
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)
	_, err = c.PaymentSignature(context.Background(), signer.PaymentProofRequest{})
	var se *commitcmd.SignerError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "signer.ErrNotExecuted", se.Code)
	assert.Equal(t, 409, se.Status)
	assert.True(t, se.Retryable)
}

func TestSignerClientRefusesGarbageAndWrongMediaType(t *testing.T) {
	mode := "garbage"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if mode == "garbage" {
			cbor(w, 500, []byte("<html>"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := commitcmd.NewSignerClient(srv.URL, secret.New([]byte("tok-0123456789abcdef")), nil)
	require.NoError(t, err)
	_, err = c.Sign(context.Background(), signer.Request{})
	var se *commitcmd.SignerError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, 500, se.Status)

	mode = "json"
	_, err = c.Sign(context.Background(), signer.Request{})
	require.Error(t, err)
}

func TestSignerClientTokenRules(t *testing.T) {
	tok := secret.New([]byte("tok-0123456789abcdef"))
	_, err := commitcmd.NewSignerClient("http://signer.example:8600", tok, nil)
	require.Error(t, err, "a token never goes over plain http to a remote host")
	_, err = commitcmd.NewSignerClient("http://127.0.0.1:8600", tok, nil)
	require.NoError(t, err)
	_, err = commitcmd.NewSignerClient("https://signer.example", tok, nil)
	require.NoError(t, err)
	_, err = commitcmd.NewSignerClient("https://signer.example", secret.Secret{}, nil)
	require.Error(t, err, "no token")
	_, err = commitcmd.NewSignerClient("ftp://x", tok, nil)
	require.Error(t, err)
}

func TestFileStateStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, err := commitcmd.NewFileStateStore(dir)
	require.NoError(t, err)
	hash := strings.Repeat("ab", 32)

	_, ok, err := st.Load(hash)
	require.NoError(t, err)
	assert.False(t, ok)

	want := commitcmd.State{Envelope: []byte("e"), Action: []byte("a"), Salt: []byte("s"), Requirements: []byte("r"), Mode: "fast"}
	require.NoError(t, st.Save(hash, want))
	want.Signed, want.RailRef = []byte("t"), "ref"
	require.NoError(t, st.Save(hash, want), "a later save replaces the file")
	got, ok, err := st.Load(hash)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, want, got)

	info, err := os.Stat(filepath.Join(dir, hash+".json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	di, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left")

	for _, bad := range []string{"", "../x", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		require.Error(t, st.Save(bad, want), bad)
		_, _, err := st.Load(bad)
		require.Error(t, err, bad)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, strings.Repeat("c", 64)+".json"), []byte(`{"unknown":1}`), 0o600))
	_, _, err = st.Load(strings.Repeat("c", 64))
	require.Error(t, err)
}
