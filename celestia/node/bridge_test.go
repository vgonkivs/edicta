package node

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"not found", errors.New("header: not found"), ErrNotFound},
		{"blob not found", errors.New("rpc error: blob: not found"), ErrNotFound},
		{"no blob", errors.New("no blob for commitment"), ErrNotFound},
		{"embedded", errors.New("a: b: not found: c"), ErrNotFound},
		{"deadline", context.DeadlineExceeded, ErrUnavailable},
		{"canceled", fmt.Errorf("call: %w", context.Canceled), ErrUnavailable},
		{"connection", errors.New("dial tcp: connection refused"), ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wrap(tc.err)
			assert.ErrorIs(t, got, tc.want)
			assert.ErrorContains(t, got, tc.err.Error())
		})
	}
}

// Unknown wording must never read as not-found: callers treat not-found as a
// definitive answer, so a miss in the match fails closed as unavailable.
func TestWrapUnknownErrorsFailClosed(t *testing.T) {
	for _, msg := range []string{
		"", "NOT FOUND", "Not Found", "notfound", "not  found", "missing", "does not exist",
		"blob unknown", "internal error", "404", "no such blob", "nothing found",
	} {
		got := wrap(errors.New(msg))
		require.ErrorIs(t, got, ErrUnavailable, msg)
		assert.NotErrorIs(t, got, ErrNotFound, msg)
	}
}

// A timed-out lookup says nothing about chain state, so a context error wins
// over a not-found text.
func TestWrapContextErrorBeatsNotFoundText(t *testing.T) {
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		got := wrap(fmt.Errorf("not found: %w", ctxErr))
		assert.ErrorIs(t, got, ctxErr)
		assert.ErrorIs(t, got, ErrUnavailable)
		assert.NotErrorIs(t, got, ErrNotFound)
	}
}

func TestNewReaderNil(t *testing.T) {
	_, err := NewReader(nil)
	require.Error(t, err)
}
