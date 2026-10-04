package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk"
)

// shortWait is a publication deadline that a hanging fake reaches without any
// sleep in the test itself.
const shortWait = 25 * time.Millisecond

// scripted decides per call (0-based) whether the publisher hangs until its
// context ends, fails, or delegates to the recorder.
type scripted struct {
	mu    sync.Mutex
	inner *recorder
	n     int
	blobs [][]byte
	step  func(n int) (hang bool, err error)
}

func (s *scripted) Publish(ctx context.Context, b []byte) (sdk.Published, error) {
	s.mu.Lock()
	n := s.n
	s.n++
	s.blobs = append(s.blobs, bytes.Clone(b))
	s.mu.Unlock()
	hang, err := s.step(n)
	if hang {
		<-ctx.Done()
		return sdk.Published{}, ctx.Err()
	}
	if err != nil {
		return sdk.Published{}, err
	}
	return s.inner.Publish(ctx, b)
}

func (s *scripted) calls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

func (s *scripted) blob(i int) []byte { s.mu.Lock(); defer s.mu.Unlock(); return s.blobs[i] }

func (r *rig) withPublisher(p sdk.Publisher) *sdk.Builder {
	r.t.Helper()
	d := r.deps
	d.Publisher, d.Signer, d.Clock = p, r.signer, r.clock
	b, err := sdk.New(r.cfg, d)
	require.NoError(r.t, err)
	return b
}

func waitCfg(reissues int) func(*rig) {
	return func(r *rig) { r.cfg.MaxPublishWait, r.cfg.MaxReissues = shortWait, reissues }
}

func TestSlowPublisherReissuesWithNewBlob(t *testing.T) {
	r := newRig(t, waitCfg(2))
	p := &scripted{inner: r.rec, step: func(n int) (bool, error) { return n == 0, nil }}
	res, err := r.withPublisher(p).Commit(bg, r.payload())
	require.NoError(t, err)
	require.Equal(t, 2, p.calls())
	assert.NotEqual(t, p.blob(0), p.blob(1), "a re-issue is a new seal: new salt, key and nonce")
	assert.Equal(t, p.blob(1), res.Blob)
	assert.Equal(t, 1, r.signer.calls(), "only the confirmed payload is signed")

	dropped, err := sharev1.Commitment(testNS, []byte("0123456789abcdefghij"), p.blob(0))
	require.NoError(t, err)
	assert.NotEqual(t, dropped, res.Commitment.PayloadRef.Commitment, "no commitment refers to the dropped blob")
	droppedHash := sha256.Sum256(p.blob(0))
	assert.NotEqual(t, droppedHash[:], res.Commitment.CiphertextHash)
	requireValidAtGate(t, res, now)
}

func TestPublicationDeadlineGivesTimeoutAndNoSignature(t *testing.T) {
	for _, reissues := range []int{1, 2, 3} {
		r := newRig(t, waitCfg(reissues))
		p := &scripted{inner: r.rec, step: func(int) (bool, error) { return true, nil }}
		res, err := r.withPublisher(p).Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrPublishTimeout)
		assert.Nil(t, res)
		assert.Equal(t, 1+reissues, p.calls(), "the first attempt plus MaxReissues")
		assert.Zero(t, r.signer.calls())
		for i := 1; i < p.calls(); i++ {
			for j := 0; j < i; j++ {
				assert.NotEqual(t, p.blob(j), p.blob(i), "no attempt reuses an earlier blob")
			}
		}
	}
}

func TestEveryAttemptIsASeparateSeal(t *testing.T) {
	r := newRig(t, waitCfg(2))
	p := &scripted{inner: r.rec, step: func(n int) (bool, error) { return n < 2, nil }}
	res, err := r.withPublisher(p).Commit(bg, r.payload())
	require.NoError(t, err)
	require.Equal(t, 3, p.calls())
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		h := sha256.Sum256(p.blob(i))
		assert.False(t, seen[string(h[:])])
		seen[string(h[:])] = true
	}
	assert.Equal(t, 1, r.signer.calls())
	assert.Equal(t, p.blob(2), res.Blob)
}

func TestAmbiguousPublisherErrorReissues(t *testing.T) {
	boom := errors.New("connection reset after send")
	r := newRig(t, waitCfg(2))
	p := &scripted{inner: r.rec, step: func(n int) (bool, error) {
		if n == 0 {
			return false, boom
		}
		return false, nil
	}}
	res, err := r.withPublisher(p).Commit(bg, r.payload())
	require.NoError(t, err)
	assert.Equal(t, 2, p.calls())
	assert.NotEqual(t, p.blob(0), res.Blob)
	assert.Equal(t, 1, r.signer.calls())
}

func TestPersistentPublisherErrorKeepsItsCause(t *testing.T) {
	boom := errors.New("fibre unavailable")
	r := newRig(t, waitCfg(1))
	p := &scripted{inner: r.rec, step: func(int) (bool, error) { return false, boom }}
	res, err := r.withPublisher(p).Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrPublishTimeout)
	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)
	assert.Equal(t, 2, p.calls())
	assert.Zero(t, r.signer.calls())
}

func TestUnverifiedInclusionReissues(t *testing.T) {
	r := newRig(t, waitCfg(2))
	var mu sync.Mutex
	n := 0
	r.deps.Inclusion = &verifierFn{fn: func(context.Context, commitment.PayloadRef) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if n == 1 {
			return 0, sdk.ErrInclusionUnverified
		}
		return now - 100, nil
	}}
	res, err := r.builder().Commit(bg, r.payload())
	require.NoError(t, err)
	assert.Equal(t, 2, r.rec.calls())
	assert.Equal(t, 1, r.signer.calls())
	assert.Equal(t, r.rec.lastBlob(t), res.Blob)
}

func TestVerifierNeverConfirmsGivesTimeout(t *testing.T) {
	r := newRig(t, waitCfg(2))
	v := &verifierFn{fn: func(context.Context, commitment.PayloadRef) (uint64, error) {
		return 0, sdk.ErrInclusionUnverified
	}}
	r.deps.Inclusion = v
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrPublishTimeout)
	assert.Nil(t, res)
	assert.Equal(t, 3, v.count())
	assert.Zero(t, r.signer.calls())
}

// The wait covers the verification too, not only the publisher.
func TestSlowVerifierIsBoundedByTheDeadline(t *testing.T) {
	r := newRig(t, waitCfg(1), func(r *rig) { r.cfg.CallTimeout = time.Minute })
	v := &verifierFn{fn: func(ctx context.Context, _ commitment.PayloadRef) (uint64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	r.deps.Inclusion = v
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrPublishTimeout)
	assert.Nil(t, res)
	assert.Equal(t, 2, v.count())
	assert.Zero(t, r.signer.calls())
}

// A recorder that anchors other bytes is not a delay: no retry, no signature.
func TestDACommitmentMismatchIsNotRetried(t *testing.T) {
	r := newRig(t, waitCfg(2))
	r.rec.other = []byte("a different blob")
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
	assert.Nil(t, res)
	assert.Equal(t, 1, r.rec.calls())
	assert.Zero(t, r.signer.calls())
}

func TestCallerCancellationStopsTheReissueLoop(t *testing.T) {
	r := newRig(t, waitCfg(5))
	ctx, cancel := context.WithCancel(bg)
	p := &scripted{inner: r.rec, step: func(int) (bool, error) {
		cancel()
		return true, nil
	}}
	res, err := r.withPublisher(p).Commit(ctx, r.payload())
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, res)
	assert.Equal(t, 1, p.calls())
	assert.Zero(t, r.signer.calls())
}

func TestPublishWaitConfigIsValidated(t *testing.T) {
	for name, mod := range map[string]func(*rig){
		"negative wait":     func(r *rig) { r.cfg.MaxPublishWait = -time.Second },
		"negative reissues": func(r *rig) { r.cfg.MaxReissues = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newRig(t, mod).tryNew()
			require.ErrorIs(t, err, sdk.ErrInvalidConfig)
		})
	}
}
