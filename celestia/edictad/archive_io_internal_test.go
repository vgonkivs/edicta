package edictad

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/gate"
)

// blockingStore blocks every Put until released.
type blockingStore struct {
	archive.Store
	entered chan struct{}
	release chan struct{}
}

func (b *blockingStore) Put(context.Context, archive.Record) (archive.Outcome, error) {
	b.entered <- struct{}{}
	<-b.release
	return archive.Written, nil
}

func TestArchiveIOInFlightLimit(t *testing.T) {
	st := &blockingStore{entered: make(chan struct{}, maxArchiveCalls+1), release: make(chan struct{})}
	io := newArchiveIO(st)
	done := make(chan error, maxArchiveCalls)
	for range maxArchiveCalls {
		go func() {
			_, err := io.put(context.Background(), &archive.DecisionRecord{})
			done <- err
		}()
	}
	for range maxArchiveCalls {
		<-st.entered
	}

	_, err := io.put(context.Background(), &archive.DecisionRecord{})
	require.ErrorIs(t, err, errArchiveBusy)

	// The archive stage reports a full limit as a fault of the archive.
	a := &archiver{io: io}
	err = a.Put(context.Background(), gate.DecisionRecord{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errArchive)

	close(st.release)
	for range maxArchiveCalls {
		require.NoError(t, <-done)
	}
	_, err = io.put(context.Background(), &archive.DecisionRecord{})
	assert.NoError(t, err, "the slots are free again")
}

func TestArchiveIOReturnsAtTheCallersContextAndFreesTheSlotLater(t *testing.T) {
	st := &blockingStore{entered: make(chan struct{}, 4), release: make(chan struct{})}
	io := newArchiveIO(st)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := io.put(ctx, &archive.DecisionRecord{})
		errc <- err
	}()
	<-st.entered
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled, "the caller does not wait for the disk")
	assert.Len(t, io.sem, 1, "the stuck call still holds its slot")
	close(st.release)
	require.Eventually(t, func() bool { return len(io.sem) == 0 }, 5e9, 1e6)
}

func TestArchiveFaultKeepsOnlyTheTextOfItsCause(t *testing.T) {
	cause := gate.ErrNonceUsed
	err := archiveFault("put decision: %v", cause)
	require.ErrorIs(t, err, errArchive)
	assert.NotErrorIs(t, err, cause, "a verdict sentinel inside would be read as a refusal of the decision")
	assert.False(t, errors.Is(err, context.DeadlineExceeded))
}
