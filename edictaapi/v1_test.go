package edictaapi_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
)

// Paths are /v1/* only: there is no other version and no alias.
func TestOnlyV1Paths(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.post("/v1/authorize", authReq(t))
	require.Equal(t, 200, rec.Code)
	assert.Equal(t, testSalt, e.gate.lastSalt, "the salt reaches the gate as sent")
	for _, p := range []string{"/v0/authorize", "/v0/publish", "/v0/record", "/v2/authorize", "/authorize"} {
		rec := e.post(p, authReq(t))
		assert.Equal(t, 404, rec.Code, p)
	}
}

// Key 3 of the authorize request is required and exactly 32 bytes; the
// wrapper refuses it before the gate is called.
func TestAuthorizeSaltKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  map[uint64]any
		code string
	}{
		{"missing", map[uint64]any{1: []byte("envelope"), 2: []byte("action")}, "ErrMissingField"},
		{"text", map[uint64]any{1: []byte("envelope"), 2: []byte("action"), 3: string(testSalt)}, "ErrWrongType"},
		{"31 bytes", map[uint64]any{1: []byte("envelope"), 2: []byte("action"), 3: testSalt[:31]}, "ErrFieldSize"},
		{"33 bytes", map[uint64]any{1: []byte("envelope"), 2: []byte("action"), 3: append(bytes.Clone(testSalt), 0)}, "ErrFieldSize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			rec := e.post("/v1/authorize", encMap(t, tc.req))
			require.Equal(t, 400, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.code)
			assert.Zero(t, e.gate.authCalls)
		})
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
