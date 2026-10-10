package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// hookUploader runs hook before the honest upload; a hook error is the
// upload's error.
type hookUploader struct {
	*liveUploader
	hook func(ctx context.Context, blob []byte) error
}

func (u *hookUploader) Upload(ctx context.Context, ns, blob []byte) (node.FibreUpload, error) {
	if u.hook != nil {
		if err := u.hook(ctx, blob); err != nil {
			u.calls.Add(1)
			return node.FibreUpload{}, err
		}
	}
	return u.liveUploader.Upload(ctx, ns, blob)
}

func (f *fibreFast) recWith(st archive.Store, up node.FibreUploader) *recorder.FibreRecorder {
	f.t.Helper()
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: up}
	r, err := recorder.NewFibre(f.cfg(st), d)
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r
}

// sameSize is a blob other than the live one with its upload cost.
func (f *fibreFast) sameSize(tag byte) []byte {
	b := bytes.Repeat([]byte{tag}, len(f.blob))
	require.NotEqual(f.t, f.blob, b)
	return b
}

func (f *fibreFast) cost() uint64 { return recorder.FibreCostUtia(f.us) }

// landNow lands the live PayForFibre at h0 + 3 and lets the node report the
// archived tx as committed there.
func (f *fibreFast) landNow() {
	h := f.h0 + 3
	f.fibreFx.node.Land(*f.pff(h))
	f.truth.Store(h)
	f.node.setTx(f.l.PFFTx, node.TxStatus{Found: true, Height: h})
}

func (f *fibreFast) evidence() bool {
	_, err := f.st.Evidence(bg, commitment.DAFibre, f.comm[:])
	return err == nil
}

func TestFastFibreReservesTheEscrowBeforeTheUpload(t *testing.T) {
	f := newFibreFast(t)
	f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
	up := &hookUploader{liveUploader: f.up}
	r := f.recWith(f.st, up)
	other := f.sameSize(0x66)
	var during error
	up.hook = func(_ context.Context, blob []byte) error {
		if bytes.Equal(blob, f.blob) {
			_, during = r.Publish(bg, other)
		}
		return nil
	}
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	var short *recorder.EscrowShortfall
	require.ErrorAs(t, during, &short, "the cost is reserved before the shards leave")
	assert.EqualValues(t, 1, up.calls.Load(), "the second blob is never uploaded")
}

// An expired promise can still be charged by its timeout settlement, so its
// cost stays reserved after the expiry.
func TestFastFibreKeepsTheEscrowOfAnExpiredPromiseThroughItsSettlement(t *testing.T) {
	f := newFibreFast(t)
	f.fibreFx.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 3600})
	f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
	r := f.rec()
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())

	f.skew.Store(int64(2 * time.Hour))
	require.Eventually(t, func() bool {
		_, err := r.Publish(bg, f.blob)
		return errors.Is(err, recorder.ErrAnchorExpired)
	}, 5*time.Second, time.Millisecond)
	f.skew.Store(0)

	_, err = r.Publish(bg, f.sameSize(0x66))
	var short *recorder.EscrowShortfall
	require.ErrorAs(t, err, &short, "the expired promise's cost is still reserved")
	assert.False(t, f.evidence())
}

// The escrow of an anchor that lands is given back exactly once: with two
// more uploads in flight the third one past the escrow is still refused.
func TestFastFibreReleasesTheEscrowOfALandedAnchorOnce(t *testing.T) {
	f := newFibreFast(t)
	f.sub.EscrowVal = node.Escrow{AvailableUtia: 2 * f.cost()}
	up := &hookUploader{liveUploader: f.up}
	gate := make(chan struct{})
	blocked := make(chan struct{}, 4)
	// The blocked uploads ignore their context: the upload timeout would
	// otherwise end them, and release their cost, while the test still runs.
	up.hook = func(_ context.Context, blob []byte) error {
		if bytes.Equal(blob, f.blob) {
			return nil
		}
		blocked <- struct{}{}
		<-gate
		return errTransport
	}
	r := f.recWith(f.st, up)
	var wg sync.WaitGroup
	t.Cleanup(func() { close(gate); wg.Wait() })
	inFlight := func(tag byte) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Publish(bg, f.sameSize(tag))
		}()
		<-blocked
	}

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())
	inFlight(0x61)

	f.landNow()
	for i := 0; i < 20; i++ {
		_, _ = r.Publish(bg, f.blob)
	}
	require.Eventually(t, f.evidence, 5*time.Second, time.Millisecond)
	again, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	require.False(t, again.Ref.Pending())

	inFlight(0x62)
	_, err = r.Publish(bg, f.sameSize(0x63))
	var short *recorder.EscrowShortfall
	require.ErrorAs(t, err, &short, "two uploads are in flight; a release counted twice would let a third through")
}

func TestFastFibreAlreadyProcessedPromiseIsFoundByScanning(t *testing.T) {
	f := newFibreFast(t)
	f.node.script(fmt.Errorf("%w: payment promise has already been processed", node.ErrRejected))
	r := f.rec()
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "a promise the chain settled under another tx is not a refusal")
	require.True(t, pub.Ref.Pending())

	h := f.h0 + 3
	f.fibreFx.node.Land(*f.pff(h))
	f.truth.Store(h)
	require.Eventually(t, f.evidence, 5*time.Second, time.Millisecond, "the loop finds the anchor by height")
	again, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, h, again.Ref.Height)
	assert.Len(t, f.node.sends(), 1)
}

func TestFastFibreRestartRebroadcastsTheArchivedTxOnly(t *testing.T) {
	f := newFibreFast(t)
	st := newStepStore(f.st.(*fsarchive.Store))
	st.crash[archive.KindAnchorIntent] = crashAfter
	_, err := f.recWith(st, f.up).Publish(bg, f.blob)
	require.Error(t, err)
	assert.Empty(t, f.node.sends())

	st.crash = map[archive.Kind]crashMode{}
	f.grow(f.h0 + 4)
	pub, err := f.recWith(st, f.up).Publish(bg, f.blob)
	require.NoError(t, err)
	assert.True(t, pub.Ref.Pending())
	assert.Equal(t, f.h0, pub.Ref.Height)
	assert.EqualValues(t, 1, f.up.calls.Load(), "the restart does not upload again")
	assert.Equal(t, 1, st.count(archive.KindAnchorIntent))
	sent := f.node.sends()
	require.Len(t, sent, 1)
	assert.Equal(t, f.l.PFFTx, sent[0])
}
