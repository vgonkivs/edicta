package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/header"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// The signed header of an untrusted bridge goes through the capped header
// client: an endless answer is cut near the limit, not read whole.
func TestFibreBridgeSignedHeaderIsCapped(t *testing.T) {
	fb := startBridge(t, func(w http.ResponseWriter, id json.RawMessage, fb *fakeBridge) {
		fb.stream(w, id, `{"header":{"chain_id":"`, `"}}`)
	})
	b := fb.bridge(t, BridgeLimits{NamespaceDataBytes: 1 << 20})
	raw, err := b.SignedHeader(tctx(t), 50)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Nil(t, raw)
	assert.Positive(t, fb.calls.Load())
	assert.Less(t, fb.written.Load(), int64(headerAnswerBytes+32<<20), "the server was not drained")
	assert.Less(t, fb.written.Load(), int64(serverCap), "the stream was cut by the client")
}

func TestFibreBridgeSignedHeader(t *testing.T) {
	var fb FibreBridge
	fb.header.Internal.GetByHeight = func(_ context.Context, h uint64) (*header.ExtendedHeader, error) {
		return signedExtHeader(h), nil
	}
	raw, err := fb.SignedHeader(tctx(t), 77)
	require.NoError(t, err)
	var got cmtproto.SignedHeader
	require.NoError(t, got.Unmarshal(raw))
	require.NotNil(t, got.Header)
	require.NotNil(t, got.Commit)
	assert.Equal(t, int64(77), got.Header.Height)
	assert.Equal(t, int64(77), got.Commit.Height)

	for name, tc := range map[string]struct {
		get  func(context.Context, uint64) (*header.ExtendedHeader, error)
		want error
	}{
		"other height": {func(context.Context, uint64) (*header.ExtendedHeader, error) { return signedExtHeader(78), nil }, heightcheck.ErrHeightIgnored},
		"nil header":   {func(context.Context, uint64) (*header.ExtendedHeader, error) { return nil, nil }, ErrUnavailable},
		"no commit":    {func(_ context.Context, h uint64) (*header.ExtendedHeader, error) { return extHeader(h), nil }, ErrUnavailable},
		"error": {func(context.Context, uint64) (*header.ExtendedHeader, error) {
			return nil, fmt.Errorf("%w: down", ErrUnavailable)
		}, ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			var fb FibreBridge
			fb.header.Internal.GetByHeight = tc.get
			raw, err := fb.SignedHeader(tctx(t), 77)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, raw)
		})
	}
}
