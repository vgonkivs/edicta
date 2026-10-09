package edictaapi_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
)

// An archive write that timed out wraps a context deadline. It is still the
// archive's failure: 503 with Retry-After, never the handler's 504.
func TestArchiveUnavailableWinsOverContextErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		own  bool
	}{
		{"plain", fmt.Errorf("gate: archive: %w", gate.ErrArchiveUnavailable), false},
		{"wrapping a deadline", fmt.Errorf("%w: %w", gate.ErrArchiveUnavailable, context.DeadlineExceeded), false},
		{"wrapping a deadline while the handler deadline fired", fmt.Errorf("%w: %w", gate.ErrArchiveUnavailable, context.DeadlineExceeded), true},
		{"wrapping a cancellation", fmt.Errorf("%w: %w", gate.ErrArchiveUnavailable, context.Canceled), false},
		{"deadline listed first", fmt.Errorf("%w: %w", context.DeadlineExceeded, gate.ErrArchiveUnavailable), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			if tc.own {
				e.useRequestTimeout(time.Nanosecond)
			}
			e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) { return gate.Result{}, tc.err }
			rec := e.post("/v1/authorize", authReq(t))
			requireErr(t, rec, 503, "ErrArchiveUnavailable", true)
			assert.Equal(t, "5", rec.Header().Get("Retry-After"))
			require.NotEmpty(t, rec.Header().Get("Retry-After"))
		})
	}
}
