package edictad_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/edictaapi"
)

type timeoutSubmitter struct{ *landing }

func (timeoutSubmitter) Submit(context.Context, []byte, []byte) (recorder.SubmitResult, error) {
	return recorder.SubmitResult{}, fmt.Errorf("submit: %w", context.DeadlineExceeded)
}

// slowHeadReader times out Head once armed, after the startup checks passed.
type slowHeadReader struct {
	node.Reader
	armed atomic.Bool
}

func (r *slowHeadReader) Head(ctx context.Context) (node.Header, error) {
	if r.armed.Load() {
		return node.Header{}, fmt.Errorf("head: %w", context.DeadlineExceeded)
	}
	return r.Reader.Head(ctx)
}

func TestPublishTimeoutsOfTheNodeAre503Not504(t *testing.T) {
	for name, c := range map[string]struct {
		prepare func(e *env) func()
		code    string
	}{
		"submit timeout": {func(e *env) func() {
			e.deps.Submitter = timeoutSubmitter{e.sub}
			return func() {}
		}, "recorder.ErrOutcomeUnknown"},
		"head timeout": {func(e *env) func() {
			rd := &slowHeadReader{Reader: e.chain}
			e.deps.Reader = rd
			return func() { rd.armed.Store(true) }
		}, "recorder.ErrNodeUnavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			arm := c.prepare(e)
			e.start()
			arm()
			_, err := e.client("").Publish(bg, []byte("decision payload"))
			var ae *edictaapi.Error
			require.ErrorAs(t, err, &ae)
			assert.Equal(t, 503, ae.Status)
			assert.True(t, ae.Retryable)
			assert.Equal(t, c.code, ae.Code)
		})
	}
}
