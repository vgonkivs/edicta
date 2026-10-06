package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

var _ sdk.Publisher = (*recorder.Recorder)(nil)

func cfg() recorder.Config {
	return recorder.Config{Namespace: ns, MaxBlobBytes: 1 << 10, SubmitTimeout: time.Second,
		VisibleTimeout: 50 * time.Millisecond, PollInterval: time.Millisecond, ScanBlocks: 16}
}

// followHead is a clock that reads the time of the reader's head, so a block
// is never older than the Recorder's own clock allows.
func followHead(r node.Reader) func() time.Time {
	return func() time.Time {
		h, err := r.Head(bg)
		if err != nil {
			return t0
		}
		return h.Time
	}
}

func mk(t *testing.T, c recorder.Config, s recorder.Submitter, r node.Reader) *recorder.Recorder {
	t.Helper()
	if c.Now == nil {
		c.Now = followHead(r)
	}
	rec, err := recorder.New(c, s, r)
	require.NoError(t, err)
	return rec
}

func TestPublishBuildsPayloadRef(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	rec := mk(t, cfg(), sub, ch)
	blob := []byte("decision payload")
	orig := bytes.Clone(blob)

	p, err := rec.Publish(bg, blob)
	require.NoError(t, err)
	assert.Equal(t, orig, blob, "blob never modified")
	assert.Equal(t, commitment.DACelestiaBlob, p.Ref.DA)
	assert.Equal(t, ns, p.Ref.Namespace)
	assert.Equal(t, signer, p.Ref.Signer)
	assert.Equal(t, genesis+1, p.Ref.Height)
	assert.Equal(t, realCommitment(t, ns, signer, blob), p.Ref.Commitment)
	assert.EqualValues(t, blockAt(genesis+1).Time.Unix(), p.BlockTime, "floored header time")
	assert.Zero(t, p.RetentionStart)
	_, err = commitment.EncodePayloadRef(p.Ref)
	require.NoError(t, err, "ref valid for the commitment encoder")
	assert.Equal(t, 1, sub.Calls)
}

func TestPublishWaitsForVisibility(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	lr := &lagReader{Reader: ch, hdrMiss: 3, blobMiss: 2}
	rec := mk(t, cfg(), sub, lr)
	p, err := rec.Publish(bg, []byte("x"))
	require.NoError(t, err)
	assert.Equal(t, genesis+1, p.Ref.Height)
	assert.Equal(t, 1, sub.Calls, "waiting never resubmits")
	assert.Greater(t, lr.hdrCalls, 3)
}

func TestPublishNotVisible(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	lr := &lagReader{Reader: ch, hdrMiss: 1 << 30}
	rec := mk(t, cfg(), sub, lr)
	_, err := rec.Publish(bg, []byte("x"))
	require.ErrorIs(t, err, recorder.ErrNotVisible)
	assert.Equal(t, 1, sub.Calls)
}

func TestPublishVerifiesAnchoredBlob(t *testing.T) {
	v0 := uint8(0)
	cases := []struct {
		name string
		bend func(*landing)
		want error
	}{
		{"other signer on chain", func(l *landing) { l.BlobSigner = other }, recorder.ErrSignerMismatch},
		{"share version 0", func(l *landing) { l.ShareV = &v0 }, recorder.ErrSignerMismatch},
		{"data differs", func(l *landing) { l.DataTamper = true }, nil},
		{"lying height, blob absent there", func(l *landing) { l.ClaimOffset = 5 }, nil},
		{"claimed but never landed", func(l *landing) { l.NoLand = true }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			tc.bend(sub)
			rec := mk(t, cfg(), sub, ch)
			_, err := rec.Publish(bg, []byte("payload"))
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			assert.NotErrorIs(t, err, context.Canceled)
		})
	}
}

func TestPublishTooLarge(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	rec := mk(t, cfg(), sub, ch)
	_, err := rec.Publish(bg, make([]byte, 1<<10+1))
	require.ErrorIs(t, err, recorder.ErrTooLarge)
	assert.Zero(t, sub.Calls)
}

func TestNewRefusesBadNamespaceOrSigner(t *testing.T) {
	ch := newChain()
	bad := map[string][]byte{
		"short":      ns[:28],
		"v0 prefix":  append([]byte{1}, ns[1:]...),
		"all zero":   make([]byte, 29),
		"empty":      nil,
		"nonzero id": append([]byte{0, 1}, ns[2:]...),
	}
	for name, n := range bad {
		t.Run(name, func(t *testing.T) {
			c := cfg()
			c.Namespace = n
			_, err := recorder.New(c, newLanding(ch), ch)
			require.Error(t, err)
		})
	}
	t.Run("signer not 20 bytes", func(t *testing.T) {
		sub := newLanding(ch)
		sub.addr = signer[:19]
		rec, err := recorder.New(cfg(), sub, ch)
		if err == nil {
			_, err = rec.Publish(bg, []byte("x"))
		}
		require.Error(t, err)
		assert.Zero(t, sub.Calls)
	})
	t.Run("nil deps", func(t *testing.T) {
		_, err := recorder.New(cfg(), nil, ch)
		require.Error(t, err)
		_, err = recorder.New(cfg(), newLanding(ch), nil)
		require.Error(t, err)
	})
}

func TestAmbiguousSubmitNeverDoubleSubmits(t *testing.T) {
	ambiguous := map[string]error{
		"deadline":    context.DeadlineExceeded,
		"unavailable": node.ErrUnavailable,
		"unknown":     errBoom,
	}
	for name, e := range ambiguous {
		t.Run(name+" landed", func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			sub.Err, sub.ErrAfterLand = e, true
			rec := mk(t, cfg(), sub, ch)
			blob := []byte("same bytes")
			p, err := rec.Publish(bg, blob)
			if err != nil {
				require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
				require.NotErrorIs(t, err, node.ErrNotFound)
				sub.Err = nil // the endpoint recovered
				p, err = rec.Publish(bg, blob)
				require.NoError(t, err)
			}
			assert.Equal(t, 1, sub.Calls, "found in recent blocks: no second submit")
			assert.Equal(t, genesis+1, p.Ref.Height)
		})
		t.Run(name+" not landed", func(t *testing.T) {
			// A scan miss is not proof the first tx is gone.
			ch := newChain()
			sub := newLanding(ch)
			sub.Err, sub.NoLand = e, true
			rec := mk(t, cfg(), sub, ch)
			blob := []byte("same bytes")
			_, err := rec.Publish(bg, blob)
			require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
			sub.Err, sub.NoLand = nil, false
			for i := 0; i < 3; i++ {
				_, err = rec.Publish(bg, blob)
				require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "retry %d", i)
			}
			assert.Equal(t, 1, sub.Calls, "a scan miss never resubmits")
		})
	}
}

func TestSubmitErrorClassified(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"unsupported passes through", node.ErrUnsupported, node.ErrUnsupported},
		{"unavailable is outcome unknown", node.ErrUnavailable, recorder.ErrOutcomeUnknown},
		{"deadline is outcome unknown", context.DeadlineExceeded, recorder.ErrOutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			sub.Err, sub.NoLand = tc.err, true
			_, err := mk(t, cfg(), sub, ch).Publish(bg, []byte("x"))
			require.ErrorIs(t, err, tc.want)
			assert.NotErrorIs(t, err, node.ErrNotFound)
			assert.NotErrorIs(t, err, recorder.ErrNotVisible)
		})
	}
}

func TestContextCancellation(t *testing.T) {
	t.Run("cancelled before", func(t *testing.T) {
		ch := newChain()
		sub := newLanding(ch)
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_, err := mk(t, cfg(), sub, ch).Publish(ctx, []byte("x"))
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, recorder.ErrNotVisible)
		assert.NotErrorIs(t, err, node.ErrNotFound)
	})
	t.Run("submitter returns the context error", func(t *testing.T) {
		ch := newChain()
		sub := newLanding(ch)
		sub.Err, sub.NoLand = context.Canceled, true
		_, err := mk(t, cfg(), sub, ch).Publish(bg, []byte("x"))
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, node.ErrNotFound)
	})
	t.Run("cancelled while waiting for the header", func(t *testing.T) {
		ch := newChain()
		sub := newLanding(ch)
		ctx, cancel := context.WithCancel(bg)
		lr := &lagReader{Reader: ch, hdrMiss: 1 << 30, onCall: cancel}
		c := cfg()
		c.VisibleTimeout = time.Minute // only the cancel may end the wait
		_, err := mk(t, c, sub, lr).Publish(ctx, []byte("x"))
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, recorder.ErrNotVisible)
		assert.NotErrorIs(t, err, node.ErrNotFound)
	})
	t.Run("reader returns context error", func(t *testing.T) {
		ch := newChain()
		sub := newLanding(ch)
		lr := &lagReader{Reader: ch, hdrMiss: 1 << 30, err: context.DeadlineExceeded}
		_, err := mk(t, cfg(), sub, lr).Publish(bg, []byte("x"))
		require.Error(t, err)
		assert.False(t, errors.Is(err, node.ErrNotFound))
	})
}

func TestConcurrentPublishDistinctBlobs(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	rec := mk(t, cfg(), sub, ch)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { _, err := rec.Publish(bg, []byte{byte(i), 1}); done <- err }()
	}
	for i := 0; i < 8; i++ {
		require.NoError(t, <-done)
	}
}
