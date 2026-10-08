package edictaapi_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

func TestPolicyErrorMapping(t *testing.T) {
	ctx := context.Background()
	ce := newClientEnv(t)
	cases := []struct {
		err    error
		status int
		code   string
		retry  bool
		verdct bool
	}{
		{policy.ErrAgentNotCovered, 403, "policy.ErrAgentNotCovered", false, true},
		{policy.ErrAmountAboveMax, 403, "policy.ErrAmountAboveMax", false, true},
		{fmt.Errorf("x: %w", &policy.HistoryFullError{Cause: "sum"}), 403, "policy.ErrHistoryFull", false, true},
		{policy.ErrDecisionAge, 410, "policy.ErrDecisionAge", false, true},
		{fmt.Errorf("%w: boom", policy.ErrFactsInvalid), 422, "policy.ErrFactsInvalid", false, true},
		{gate.ErrPolicyStateConflict, 503, "ErrPolicyStateConflict", true, false},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
				return gate.Result{PolicyVerdict: []byte("verdict")}, c.err
			}
			_, _, err := ce.client.AuthorizeWithVerdict(ctx, []byte("e"), []byte("a"))
			var ae *edictaapi.Error
			require.ErrorAs(t, err, &ae)
			require.Equal(t, c.status, ae.Status)
			require.Equal(t, c.code, ae.Code)
			require.Equal(t, c.retry, ae.Retryable)
			if c.verdct {
				require.Equal(t, []byte("verdict"), ae.PolicyVerdict)
			} else {
				require.Nil(t, ae.PolicyVerdict)
			}
		})
	}
}

func TestAuthorizeResponseCarriesTheVerdict(t *testing.T) {
	ce := newClientEnv(t)
	ce.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{Authorization: []byte("auth"), PolicyVerdict: []byte("verdict")}, nil
	}
	auth, verdict, err := ce.client.AuthorizeWithVerdict(context.Background(), []byte("e"), []byte("a"))
	require.NoError(t, err)
	require.Equal(t, []byte("auth"), auth)
	require.Equal(t, []byte("verdict"), verdict)
	auth, err = ce.client.Authorize(context.Background(), []byte("e"), []byte("a"))
	require.NoError(t, err)
	require.Equal(t, []byte("auth"), auth)
}
