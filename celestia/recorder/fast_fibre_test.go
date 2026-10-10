package recorder_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// liveUploader returns the certificate of the live PayForFibre for every
// upload, as an honest uploader would for the live blob.
type liveUploader struct {
	f     *fibreFx
	calls atomic.Int32
}

func (u *liveUploader) Upload(context.Context, []byte, []byte) (node.FibreUpload, error) {
	u.calls.Add(1)
	msg, err := node.PFFMessage(u.f.l.PFFTx)
	if err != nil {
		return node.FibreUpload{}, err
	}
	return node.FibreUpload{Msg: msg, PromiseHeight: u.f.l.PromiseHeight, Created: u.f.l.Created}, nil
}

func (u *liveUploader) Endpoint() string            { return fibreEndpoint }
func (u *liveUploader) Close(context.Context) error { return nil }

// liveSigner signs every PayForFibre as the live tx, so the hash the node
// reports for the landed anchor is the one the Recorder sent.
type liveSigner struct{ f *fibreFx }

func (s liveSigner) Address(context.Context) ([]byte, error) { return make([]byte, 20), nil }
func (s liveSigner) SignPFB(context.Context, []byte, []byte, node.TxParams) ([]byte, error) {
	return nil, node.ErrUnsupported
}
func (s liveSigner) SignPFF(context.Context, []byte, node.TxParams) ([]byte, error) {
	return bytes.Clone(s.f.l.PFFTx), nil
}

type fibreFast struct {
	*fibreFx
	st   archive.Store
	up   *liveUploader
	node *anchorNode
	h0   uint64
}

func newFibreFast(t *testing.T) *fibreFast {
	f := &fibreFast{fibreFx: newFibreFx(t), node: newAnchorNode()}
	f.st = f.openArchive(t.TempDir())
	f.up = &liveUploader{f: f.fibreFx}
	f.h0 = f.l.PromiseHeight
	f.fibreFx.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 3600})
	f.grow(f.h0 + 2)
	return f
}

func (f *fibreFast) rec() *recorder.FibreRecorder {
	f.t.Helper()
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: f.up}
	r, err := recorder.NewFibre(f.cfg(f.st), d)
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r
}

// land makes an accepted PayForFibre land at h0 + 3.
func (f *fibreFast) land() {
	f.node.onAccept = func(raw []byte) {
		h := f.h0 + 3
		f.fibreFx.node.Land(*f.pff(h))
		f.truth.Store(h)
		f.node.setTx(raw, node.TxStatus{Found: true, Height: h})
	}
}

func TestFastFibreUploadsWithoutPayingAndArchivesTheCertificateFirst(t *testing.T) {
	f := newFibreFast(t)
	f.land()
	seen := 0
	f.node.before = func(raw []byte) {
		seen++
		rec, err := f.st.(archive.IntentReader).Intent(bg, commitment.DAFibre, f.comm[:], f.h0)
		require.NoError(t, err, "the intent is archived before the broadcast")
		assert.Equal(t, rec.Tx, raw)
	}
	r := f.rec()
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, 1, seen)
	assert.EqualValues(t, 1, f.up.calls.Load())
	assert.Zero(t, f.sub.Calls(), "the paying submit path is never used")

	assert.True(t, pub.Ref.Pending())
	assert.Equal(t, f.h0, pub.Ref.Height, "h0 is the promise height")
	assert.Equal(t, uint64(f.timeAt(f.h0).Unix()), pub.BlockTime, "T_ref is the header time at h0")
	assert.Equal(t, uint64(f.l.Created.Unix()), pub.RetentionStart, "retention starts at the promise creation")
	assert.Nil(t, pub.Ref.Signer)

	rec, err := f.st.(archive.IntentReader).Intent(bg, commitment.DAFibre, f.comm[:], f.h0)
	require.NoError(t, err)
	assert.Equal(t, uint64(f.l.Created.Unix()), rec.CreatedAt, "created_at is the floored promise creation")
	assert.Equal(t, f.l.PFFTx, rec.Tx)

	require.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DAFibre, f.comm[:])
		return err == nil
	}, 5*time.Second, time.Millisecond, "the confirmation loop writes the evidence")
	again, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.False(t, again.Ref.Pending())
	assert.Equal(t, f.h0+3, again.Ref.Height)
}

func TestFastFibreRefusesACertificateForAnotherBlob(t *testing.T) {
	f := newFibreFast(t)
	other := []byte{0x66}
	_, err := f.rec().Publish(bg, other)
	require.ErrorIs(t, err, recorder.ErrSubmitMismatch)
	assert.Empty(t, f.node.sends(), "nothing is broadcast")
	_, err = f.rec().Publish(bg, other)
	require.Error(t, err)
}

func TestFastFibreReservesTheEscrowUntilTheAnchorLands(t *testing.T) {
	f := newFibreFast(t)
	us := f.us
	f.sub.EscrowVal = node.Escrow{AvailableUtia: recorder.FibreCostUtia(us) + 10}
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)

	_, err = r.Publish(bg, []byte{0x66})
	var short *recorder.EscrowShortfall
	require.ErrorAs(t, err, &short, "the first upload's cost is still reserved")
	assert.EqualValues(t, 1, f.up.calls.Load(), "the second blob is not uploaded")
}

func TestFastFibreRefusesAnUploaderOnAnotherNode(t *testing.T) {
	f := newFibreFast(t)
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: otherNodeUploader{f.up}}
	_, err := recorder.NewFibre(f.cfg(f.st), d)
	require.Error(t, err)
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node}
	_, err = recorder.NewFibre(f.cfg(f.st), d)
	require.Error(t, err, "no uploader")
}

type otherNodeUploader struct{ *liveUploader }

func (otherNodeUploader) Endpoint() string { return "elsewhere.example:9090" }
