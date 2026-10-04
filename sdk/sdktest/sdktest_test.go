package sdktest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/sdktest"
)

var bg = context.Background()

func TestInclusionVerifierConfirmsWhatThePublisherAnchored(t *testing.T) {
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	p.SetBlockTime(1_700_000_123)
	v := sdktest.NewInclusionVerifier(p)
	var _ sdk.InclusionVerifier = v
	var _ sdk.IndependenceReporter = v

	pub, err := p.Publish(bg, []byte("blob"))
	require.NoError(t, err)
	tm, err := v.VerifyInclusion(bg, pub.Ref)
	require.NoError(t, err)
	assert.Equal(t, pub.BlockTime, tm)
	assert.Equal(t, 1, v.Calls())
	assert.True(t, v.Independent(), "independent by default")
	v.SetIndependent(false)
	assert.False(t, v.Independent())

	other := pub.Ref
	other.Height++
	_, err = v.VerifyInclusion(bg, other)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified, "a reference nobody published")
}

func TestInclusionVerifierFaults(t *testing.T) {
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	pub, err := p.Publish(bg, []byte("blob"))
	require.NoError(t, err)

	t.Run("lying time", func(t *testing.T) {
		v := sdktest.NewInclusionVerifier(p)
		v.SetBlockTime(pub.BlockTime + 60)
		tm, err := v.VerifyInclusion(bg, pub.Ref)
		require.NoError(t, err)
		assert.Equal(t, pub.BlockTime+60, tm)
	})
	t.Run("fail", func(t *testing.T) {
		boom := errors.New("provider down")
		v := sdktest.NewInclusionVerifier(p)
		v.Fail(boom)
		_, err := v.VerifyInclusion(bg, pub.Ref)
		require.ErrorIs(t, err, boom)
	})
	t.Run("panic", func(t *testing.T) {
		v := sdktest.NewInclusionVerifier(p)
		v.Panic()
		assert.Panics(t, func() { _, _ = v.VerifyInclusion(bg, pub.Ref) })
	})
	t.Run("hang ends with the context", func(t *testing.T) {
		v := sdktest.NewInclusionVerifier(p)
		v.Hang()
		ctx, cancel := context.WithTimeout(bg, 10*time.Millisecond)
		defer cancel()
		_, err := v.VerifyInclusion(ctx, pub.Ref)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestPublisherNamespaceSignerAndHangNext(t *testing.T) {
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	ns, signer := p.Namespace(), p.Signer()
	require.Len(t, ns, 29)
	require.Len(t, signer, 20)
	pub, err := p.Publish(bg, []byte("a"))
	require.NoError(t, err)
	assert.Equal(t, ns, pub.Ref.Namespace)
	assert.Equal(t, signer, pub.Ref.Signer)

	newNS := append(make([]byte, 19), []byte("sdktest-02")...)
	newSigner := []byte("another-fake-account")
	p.SetNamespace(newNS)
	p.SetSigner(newSigner)
	pub, err = p.Publish(bg, []byte("a"))
	require.NoError(t, err)
	assert.Equal(t, newNS, pub.Ref.Namespace)
	assert.Equal(t, newSigner, pub.Ref.Signer)

	p.HangNext(1)
	ctx, cancel := context.WithTimeout(bg, 10*time.Millisecond)
	defer cancel()
	_, err = p.Publish(ctx, []byte("b"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	_, err = p.Publish(bg, []byte("c"))
	require.NoError(t, err, "only the next publish hangs")
	assert.Len(t, p.Blobs(), 4, "a hanging publish is still recorded")
}
