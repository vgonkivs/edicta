package edictaapi_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
)

// The alias answers exactly like the base path: one handler, the version is
// read from the signed bytes by the gate, never from the path.
func TestAuthorizeAliasIsTheSameHandler(t *testing.T) {
	for _, p := range []string{"/v0/authorize", "/v1/authorize"} {
		e := newEnv(t, nil)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{Authorization: []byte("auth")}, nil
		}
		rec := e.post(p, authReq(t))
		require.Equal(t, 200, rec.Code, p)
		assert.Equal(t, 1, e.gate.authCalls, p)
		assert.Equal(t, []byte("envelope"), e.gate.lastEnv, p)
	}
}

func TestAnchorIntent503sCarryRetryAfter(t *testing.T) {
	for _, s := range []error{gate.ErrAnchorIntentUnavailable, gate.ErrAnchorIntentRejected} {
		e := newEnv(t, nil)
		e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
			return gate.Result{}, fmt.Errorf("k-fast: %w", s)
		}
		rec := e.post("/v1/authorize", authReq(t))
		require.Equal(t, 503, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"), s.Error())
	}
}
