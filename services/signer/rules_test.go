// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/api/signerapi"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

// railHandler is a handler with its own request bound and error rules, and
// whose checks refuse with err when it is set.
type railHandler struct {
	signer.Handler
	bound int64
	rules []signer.ErrorRule
	err   error
}

func (r railHandler) MaxRequestBytes() int64         { return r.bound }
func (r railHandler) ErrorRules() []signer.ErrorRule { return r.rules }
func (r railHandler) Check(ctx context.Context, v signer.Verified, now time.Time) (signer.Plan, error) {
	if r.err != nil {
		return signer.Plan{}, r.err
	}
	return r.Handler.Check(ctx, v, now)
}

func railEnv(t *testing.T, r railHandler) *env {
	t.Helper()
	return newEnvOpts(t, envOpts{wrap: func(h signer.Handler) signer.Handler { r.Handler = h; return r }})
}

func TestSignerRefusalsAreTheAPIValues(t *testing.T) {
	assert.Same(t, signerapi.ErrUnknownDecision, signer.ErrUnknownDecision)
	assert.Same(t, signerapi.ErrNotExecuted, signer.ErrNotExecuted)
	assert.EqualError(t, signer.ErrUnknownDecision, "signer: unknown decision")
	assert.EqualError(t, signer.ErrNotExecuted, "signer: not executed")
}

func TestHandlerRequestBoundOutsideTheWireRefusesTheAPI(t *testing.T) {
	for _, n := range []int64{-1, signerapi.MaxRequirementsSize + 1} {
		e := railEnv(t, railHandler{bound: n})
		_, err := signer.NewHandler(e.svc, signer.HTTPOptions{Token: []byte(token)}, quiet)
		require.Error(t, err, "bound %d", n)
	}
}

func TestHandlerRequestBoundSetsTheBodyLimits(t *testing.T) {
	core := signerapi.SignLimit - signerapi.MaxRequirementsSize
	for _, tc := range []struct {
		bound  int64
		body   int
		status int
	}{
		{0, core, http.StatusBadRequest},
		{0, core + 1, http.StatusRequestEntityTooLarge},
		{100, core + 100, http.StatusBadRequest},
		{100, core + 101, http.StatusRequestEntityTooLarge},
		{signerapi.MaxRequirementsSize, signerapi.SignLimit, http.StatusBadRequest},
		{signerapi.MaxRequirementsSize, signerapi.SignLimit + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(fmt.Sprint(tc.bound, "/", tc.body), func(t *testing.T) {
			srv := newAPI(t, railEnv(t, railHandler{bound: tc.bound}), signer.HTTPOptions{})
			resp, _ := post(t, srv, "application/cbor", make([]byte, tc.body))
			assert.Equal(t, tc.status, resp.StatusCode)
		})
	}

	srv := newAPI(t, railEnv(t, railHandler{bound: 0}), signer.HTTPOptions{})
	paymentCore := signerapi.PaymentLimit - signerapi.MaxRequirementsSize
	for body, status := range map[int]int{paymentCore: http.StatusBadRequest, paymentCore + 1: http.StatusRequestEntityTooLarge} {
		resp, _ := post(t, srv, "application/cbor", make([]byte, body), func(r *http.Request) { r.URL.Path = signerapi.RoutePaymentSignature })
		assert.Equal(t, status, resp.StatusCode, "payment body of %d bytes", body)
	}
}

func TestMalformedErrorRuleRefusesTheAPI(t *testing.T) {
	errRail := errors.New("rail: refused")
	for name, r := range map[string]signer.ErrorRule{
		"no error":   {Status: 422, Code: "rail.ErrRefused"},
		"no code":    {Err: errRail, Status: 422},
		"status 200": {Err: errRail, Status: 200, Code: "rail.ErrRefused"},
		"status 600": {Err: errRail, Status: 600, Code: "rail.ErrRefused"},
	} {
		e := railEnv(t, railHandler{bound: signerapi.MaxRequirementsSize, rules: []signer.ErrorRule{r}})
		_, err := signer.NewHandler(e.svc, signer.HTTPOptions{Token: []byte(token)}, quiet)
		assert.Error(t, err, name)
	}
}

// A handler's rule answers its own refusal, cannot change the answer to one
// of the signer's refusals, and comes before the encoding errors.
func TestHandlerErrorRulesMatchBetweenTheSignersAndTheTransports(t *testing.T) {
	errRail := errors.New("rail: refused")
	rules := []signer.ErrorRule{
		{Err: errRail, Status: 418, Code: "rail.ErrRefused"},
		{Err: signer.ErrPinMismatch, Status: 499, Code: "rail.ErrPin"},
	}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("%w: x", errRail), 418, "rail.ErrRefused"},
		{fmt.Errorf("%w: x", signer.ErrPinMismatch), 403, signerapi.CodePinMismatch},
		{fmt.Errorf("%w: %w", commitment.ErrMalformed, errRail), 418, "rail.ErrRefused"},
		{errors.New("unclassified"), 500, signerapi.CodeInternal},
	} {
		e := railEnv(t, railHandler{bound: signerapi.MaxRequirementsSize, rules: rules, err: tc.err})
		srv := newAPI(t, e, signer.HTTPOptions{})
		resp, body := post(t, srv, "application/cbor", signerapi.EncodeSignRequest(request(e.decision(signertest.DecisionOpts{}))))
		assert.Equal(t, tc.status, resp.StatusCode, tc.err.Error())
		assert.Equal(t, tc.code, errorCode(t, "application/cbor", body), tc.err.Error())
	}
}
