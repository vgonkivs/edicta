package clearerr_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/clearerr"
)

func TestMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
		kind string
	}{
		{"scheme", clearerr.Scheme("rpc.example:26657", "https", "http", "http://rpc.example:26657"),
			"endpoint rpc.example:26657: scheme https but server speaks http; use http://rpc.example:26657", clearerr.KindScheme},
		{"tls", clearerr.TLS("rpc.example:443", errors.New("x509: certificate has expired")),
			"endpoint rpc.example:443: TLS: x509: certificate has expired; check the certificate or set tls = false for a local node", clearerr.KindTLS},
		{"fee", clearerr.FeeTooLow("0.002"),
			"fee below the node's minimum gas price 0.002 utia/gas; doctor reads it from the node", clearerr.KindFee},
		{"passphrase", clearerr.KeyringPassphrase("/h/k.pass", "recorder"),
			"keyring passphrase file /h/k.pass does not open recorder", clearerr.KindPassphrase},
		{"chain", clearerr.WrongChain("grpc.example:9090", "celestia", "mocha-5"),
			"node at grpc.example:9090 is chain celestia, config expects mocha-5", clearerr.KindChain},
		{"escrow", clearerr.EscrowLow(10, 20),
			"escrow 10 utia below headroom 20 (one upload of max_blob_bytes)", clearerr.KindEscrow},
		{"facilitator", clearerr.Facilitator("invalid_exact_evm_payload_authorization_valid_before", "validBefore is in the past"),
			"facilitator refused the payment: invalid_exact_evm_payload_authorization_valid_before; validBefore is in the past", clearerr.KindFacilitate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.EqualError(t, tc.err, tc.want)
			assert.Equal(t, tc.kind, clearerr.KindOf(tc.err))
		})
	}
	assert.Equal(t, "facilitator refused the payment: bad", clearerr.Facilitator("bad", "").Error())
	assert.Empty(t, clearerr.KindOf(errors.New("x")))
}

func TestTLSKeepsItsCause(t *testing.T) {
	cause := errors.New("x509: expired")
	assert.ErrorIs(t, clearerr.TLS("e", cause), cause)
}

func get(url string) error {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(b), "HTTP request to an HTTPS server") {
		return errors.New("Client sent an HTTP request to an HTTPS server")
	}
	return nil
}

func TestDialClassifiesRealFailures(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer secure.Close()

	// https:// to a plain server.
	host := strings.TrimPrefix(plain.URL, "http://")
	err := clearerr.Dial(host, "https", true, get("https://"+host))
	require.Equal(t, clearerr.KindScheme, clearerr.KindOf(err), "%v", err)
	assert.Contains(t, err.Error(), "scheme https but server speaks http; use http://"+host)

	// http:// to a TLS server.
	shost := strings.TrimPrefix(secure.URL, "https://")
	err = clearerr.Dial(shost, "http", false, get("http://"+shost))
	require.Equal(t, clearerr.KindScheme, clearerr.KindOf(err), "%v", err)
	assert.Contains(t, err.Error(), "scheme http but server speaks https; use https://"+shost)

	// https:// to a TLS server with an untrusted certificate.
	err = clearerr.Dial(shost, "https", true, get("https://"+shost))
	require.Equal(t, clearerr.KindTLS, clearerr.KindOf(err), "%v", err)
	assert.Contains(t, err.Error(), "x509:")
	assert.Contains(t, err.Error(), "set tls = false for a local node")
}

func TestDialTLSHandshakeToAPlainPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}).DialContext(ctx, "tcp", l.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	got := clearerr.Dial(l.Addr().String(), "", true, err)
	require.Equal(t, clearerr.KindScheme, clearerr.KindOf(got), "%v", got)
	assert.Contains(t, got.Error(), "use tls = false")
}

func TestDialLeavesOtherErrors(t *testing.T) {
	e := errors.New("connection refused")
	assert.Same(t, e, clearerr.Dial("x", "", false, e))
	assert.NoError(t, clearerr.Dial("x", "", false, nil))
}

func TestIsFeeTooLow(t *testing.T) {
	assert.True(t, clearerr.IsFeeTooLow(errors.New("rpc error: insufficient fee; got: 1utia required: 2utia")))
	assert.True(t, clearerr.IsFeeTooLow(errors.New("insufficient minimum gas price for this node")))
	assert.False(t, clearerr.IsFeeTooLow(errors.New("out of gas")))
	assert.False(t, clearerr.IsFeeTooLow(nil))
}
