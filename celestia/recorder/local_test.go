package recorder_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

func TestLocalSubmitterOverNodeSeam(t *testing.T) {
	ch := newChain()
	var s recorder.Submitter = recorder.NewLocalSubmitter(ch)

	addr, err := s.Signer(bg)
	require.NoError(t, err)
	assert.Equal(t, signer, addr)
	addr[0] ^= 0xff
	again, _ := s.Signer(bg)
	assert.Equal(t, signer, again, "returned address is a copy")

	res, err := s.Submit(bg, ns, []byte("data"))
	require.NoError(t, err)
	assert.Equal(t, genesis+1, res.Height)
	assert.Equal(t, 1, ch.Submitted)
}

func TestLocalSubmitterReportsClaimedHeightUnverified(t *testing.T) {
	ch := newChain()
	ch.SubmitHeight = 777
	res, err := recorder.NewLocalSubmitter(ch).Submit(bg, ns, []byte("d"))
	require.NoError(t, err)
	assert.EqualValues(t, 777, res.Height, "claim passed through; the Recorder verifies")
}

func TestLocalSubmitterErrorsAndContext(t *testing.T) {
	ch := newChain()
	ch.Fail = nodefake.ErrInjected
	s := recorder.NewLocalSubmitter(ch)
	_, err := s.Signer(bg)
	require.ErrorIs(t, err, nodefake.ErrInjected)
	_, err = s.Submit(bg, ns, []byte("d"))
	require.ErrorIs(t, err, nodefake.ErrInjected)
	assert.Zero(t, ch.Submitted)

	ch.Fail = context.Canceled
	_, err = s.Submit(bg, ns, []byte("d"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestRecorderWithLocalSubmitterRefusesStandInCommitment(t *testing.T) {
	// nodefake.SubmitBlob stores a stand-in commitment, not the real share
	// commitment, so the Recorder's byte-exact check must not find its blob.
	ch := newChain()
	rec := mk(t, cfg(), recorder.NewLocalSubmitter(ch), ch)
	_, err := rec.Publish(bg, []byte("x"))
	require.Error(t, err)
}
