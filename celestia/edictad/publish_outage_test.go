package edictad_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/edictaapi"
)

// A node outage seen by the Recorder is answered 503 with retryable = 1,
// never a 500.

type outageReader struct {
	node.Reader
	failHead, failHeader atomic.Bool
}

var errConnRefused = errors.New("dial tcp 127.0.0.1:26658: connect: connection refused")

func (r *outageReader) Head(ctx context.Context) (node.Header, error) {
	if r.failHead.Load() {
		return node.Header{}, errConnRefused
	}
	return r.Reader.Head(ctx)
}

func (r *outageReader) HeaderAt(ctx context.Context, h uint64) (node.Header, error) {
	if r.failHeader.Load() {
		return node.Header{}, errConnRefused
	}
	return r.Reader.HeaderAt(ctx, h)
}

func TestPublishNodeOutageIs503Retryable(t *testing.T) {
	for name, set := range map[string]func(*outageReader){
		"head fails":        func(r *outageReader) { r.failHead.Store(true) },
		"header read fails": func(r *outageReader) { r.failHeader.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			rd := &outageReader{Reader: e.chain}
			e.deps.Reader = rd
			e.start()
			set(rd) // after startup checks passed
			_, err := e.client("").Publish(bg, []byte("decision payload"))
			var ae *edictaapi.Error
			require.ErrorAs(t, err, &ae)
			assert.Equal(t, 503, ae.Status, "a node outage is not an internal error")
			assert.True(t, ae.Retryable)
			assert.NotEqual(t, "edictaapi.ErrInternal", ae.Code)
		})
	}
}

// da = blob never needs x/fibre. The consensus fake reports the module
// absent (FibreParams = ErrNotFound) and Start must still serve.
func TestStartInBlobModeOnAChainWithoutFibre(t *testing.T) {
	e := newEnv(t)
	e.cons.Fibre = nil
	_, err := e.cons.FibreParams(bg)
	require.ErrorIs(t, err, node.ErrNotFound)
	srv := e.start()
	require.NotEmpty(t, srv.Addr())
	pub, err := e.client("").Publish(bg, []byte("blob mode needs no fibre"))
	require.NoError(t, err)
	assert.Equal(t, nsBytes, pub.Ref.Namespace)
}
