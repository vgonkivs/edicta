package edictaapi_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/sdk"
)

func TestRecorderErrorsWrappingADeadlineAreNot504(t *testing.T) {
	sk, pubHex := testKey(1)
	for name, c := range map[string]struct {
		err  error
		code string
	}{
		"submit timeout":    {fmt.Errorf("%w: %w", errRecOutcomeUnk, context.DeadlineExceeded), "recorder.ErrOutcomeUnknown"},
		"head read timeout": {fmt.Errorf("%w: head: %w", errRecNodeUnavail, context.DeadlineExceeded), "recorder.ErrNodeUnavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"agent-a": pubHex})
			e.pub.err = c.err
			requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("a"))), 503, c.code, true)
		})
	}
}

func TestOnlyTheHandlersOwnDeadlineIs504(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	cfg := e.cfg
	cfg.RequestTimeout = time.Nanosecond
	e.pub.fn = func(ctx context.Context, _ []byte) (sdk.Published, error) {
		<-ctx.Done()
		return sdk.Published{}, ctx.Err()
	}
	e.h = edictaapi.NewHandler(e.gate, e.pub, e.allow, e.quota, e.health, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("a"))), 504, "edictaapi.ErrDeadline", true)
}

func TestPublishHasItsOwnDeadline(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	cfg := e.cfg
	cfg.RequestTimeout = time.Nanosecond
	cfg.PublishTimeout = time.Minute
	e.pub.fn = func(ctx context.Context, _ []byte) (sdk.Published, error) {
		<-time.After(20 * time.Millisecond)
		return sdk.Published{}, ctx.Err()
	}
	e.h = edictaapi.NewHandler(e.gate, e.pub, e.allow, e.quota, e.health, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("a")))
	assert.NotEqual(t, 504, rec.Code, "the request deadline does not apply to publish")
}
