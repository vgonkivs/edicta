package clearerr_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/cli/internal/clearerr"
)

func TestRedactURL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://rpc.example/v2/SECRET", "https://rpc.example"},
		{"https://rpc.example?key=SECRET", "https://rpc.example"},
		{"https://rpc.example:8545/v2/SECRET?key=SECRET#frag", "https://rpc.example:8545"},
		{"https://user:SECRET@rpc.example:443/x", "https://rpc.example:443"},
		{"https://SECRET@rpc.example", "https://rpc.example"},
		{"https://[::1]:8545/SECRET", "https://[::1]:8545"},
		{"rpc.example:9090", "rpc.example:9090"},
		{"rpc.example:9090/SECRET", "rpc.example:9090"},
		{"u:SECRET@rpc.example:9090", "rpc.example:9090"},
		{"https://rpc.example", "https://rpc.example"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, clearerr.RedactURL(tc.in), tc.in)
	}
}

func TestRedactText(t *testing.T) {
	in := `Post "https://u:SECRET@a.example/v2/SECRET?key=SECRET": dial tcp; see http://b.example:80/SECRET and grpc://c.example/SECRET`
	assert.Equal(t, `Post "https://a.example": dial tcp; see http://b.example:80 and grpc://c.example`, clearerr.RedactText(in))
	assert.Equal(t, "no url here", clearerr.RedactText("no url here"))
}

func TestRedactEndpointsFindsSchemelessAddresses(t *testing.T) {
	out := clearerr.RedactEndpoints(`dial "bridge.example/SECRET" and bridge.example/SECRET/x`, "bridge.example/SECRET", "plain.example:1")
	assert.Equal(t, `dial "bridge.example" and bridge.example/x`, out)
	assert.NotContains(t, out, "SECRET")
}

func TestRedactErrKeepsTheChain(t *testing.T) {
	cause := errors.New("connection refused")
	err := clearerr.RedactErr(&wrapped{msg: "get https://a.example/SECRET: connection refused", err: cause})
	assert.Equal(t, "get https://a.example: connection refused", err.Error())
	assert.ErrorIs(t, err, cause)

	plain := errors.New("nothing to hide")
	assert.Same(t, plain, clearerr.RedactErr(plain), "an error with no URL is returned as is")
	assert.NoError(t, clearerr.RedactErr(nil))
}

type wrapped struct {
	msg string
	err error
}

func (w *wrapped) Error() string { return w.msg }
func (w *wrapped) Unwrap() error { return w.err }

func TestMessagesNeverCarryTheURLKey(t *testing.T) {
	const ep = "https://u:SECRET@rpc.example/v2/SECRET?key=SECRET"
	for _, err := range []error{
		clearerr.Scheme(ep, "https", "http", "http://rpc.example/v2/SECRET"),
		clearerr.TLS(ep, errors.New(`Get "`+ep+`": x509: expired`)),
		clearerr.WrongChain(ep, "a", "b"),
		clearerr.Facilitator("see "+ep, ""),
		clearerr.Dial(ep, "https", true, errors.New("dial "+ep+": refused")),
	} {
		assert.NotContains(t, err.Error(), "SECRET")
	}
}

func TestDialRedactsAnUnknownURLError(t *testing.T) {
	// Port 1 on loopback refuses: a real *url.Error, no network needed.
	const ep = "http://127.0.0.1:1/v2/SECRET?key=SECRET"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ep, nil)
	require.NoError(t, err)
	_, cause := http.DefaultClient.Do(req)
	require.Error(t, cause)
	require.Contains(t, cause.Error(), "SECRET", "the raw error carries the key")
	err = clearerr.Dial("127.0.0.1:1", "http", false, cause)
	assert.NotContains(t, err.Error(), "SECRET")
	assert.ErrorIs(t, err, cause)
}
