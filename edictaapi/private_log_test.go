package edictaapi_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

func (e *env) useLogger(l *slog.Logger) {
	e.h = edictaapi.NewHandler(e.gate, e.pub, e.allow, e.quota, e.health, e.cfg, l)
}

func TestPrivateDenyLogsNoReason(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("gate: %w", policy.ErrMinSpacing), 403, "policy.ErrMinSpacing"},
		{policy.ErrAmountAboveMax, 403, "policy.ErrAmountAboveMax"},
		{policy.ErrDecisionAge, 410, "policy.ErrDecisionAge"},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			var buf bytes.Buffer
			e := newEnv(t, nil)
			e.useLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug - 4})))
			e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
				return gate.Result{PolicyVerdict: []byte("verdict"), PrivatePart: []byte("part")}, c.err
			}
			rec := e.post("/v1/authorize", authReq(t))
			requireErr(t, rec, c.status, c.code, false)
			logs := buf.String()
			assert.Contains(t, logs, "private policy deny")
			assert.NotContains(t, logs, c.code)
			assert.NotContains(t, logs, c.err.Error())
		})
	}
}

func TestPublicDenyStillLogsReason(t *testing.T) {
	var buf bytes.Buffer
	e := newEnv(t, nil)
	e.useLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	e.gate.authFn = func(context.Context, []byte, []byte) (gate.Result, error) {
		return gate.Result{PolicyVerdict: []byte("verdict")}, policy.ErrMinSpacing
	}
	rec := e.post("/v1/authorize", authReq(t))
	requireErr(t, rec, 403, "policy.ErrMinSpacing", false)
	assert.Contains(t, buf.String(), "policy.ErrMinSpacing")
}
