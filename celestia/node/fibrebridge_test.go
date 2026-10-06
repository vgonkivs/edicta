package node

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/header"
	headerapi "github.com/celestiaorg/celestia-node/nodebuilder/header"
	libshare "github.com/celestiaorg/go-square/v4/share"
)

// serverCap stops a runaway stream; a client that bounds its reads never gets
// near it.
const serverCap = 256 << 20

type rpcReq struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

// fakeBridge answers every JSON-RPC call with reply. A reply that is a stream
// of filler of n bytes counts what it wrote.
type fakeBridge struct {
	srv     *httptest.Server
	written atomic.Int64
	calls   atomic.Int64
}

func startBridge(t *testing.T, reply func(w http.ResponseWriter, id json.RawMessage, fb *fakeBridge)) *fakeBridge {
	t.Helper()
	fb := &fakeBridge{}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q rpcReq
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fb.calls.Add(1)
		reply(w, q.ID, fb)
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

// stream writes a JSON-RPC answer whose result is a string of filler, without
// a content length, until the client stops reading or the cap is reached.
func (fb *fakeBridge) stream(w http.ResponseWriter, id json.RawMessage, prefix, suffix string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	head := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s`, id, prefix)
	n, err := w.Write([]byte(head))
	fb.written.Add(int64(n))
	if err != nil {
		return
	}
	chunk := []byte(strings.Repeat("A", 64<<10))
	for fb.written.Load() < serverCap {
		n, err := w.Write(chunk)
		fb.written.Add(int64(n))
		if err != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	_, _ = w.Write([]byte(suffix))
}

func (fb *fakeBridge) bridge(t *testing.T, lim BridgeLimits) *FibreBridge {
	t.Helper()
	b, err := NewFibreBridge(tctx(t), BridgeConfig{Addr: fb.srv.URL}, lim)
	require.NoError(t, err)
	t.Cleanup(b.Close)
	return b
}

func TestFibreBridgeBoundsOversizeAnswers(t *testing.T) {
	ns := libshare.PayForFibreNamespace
	cases := []struct {
		name   string
		prefix string
		suffix string
		limit  int64
		call   func(t *testing.T, b *FibreBridge) error
	}{
		{
			name: "dah", prefix: `{"dah":{"row_roots":["`, suffix: `"]}}`, limit: headerAnswerBytes,
			call: func(t *testing.T, b *FibreBridge) error { _, err := b.DAH(tctx(t), 50); return err },
		},
		{
			name: "namespace data", prefix: `["`, suffix: `"]`, limit: int64(wireSize(1 << 20)),
			call: func(t *testing.T, b *FibreBridge) error {
				_, err := b.NamespaceData(tctx(t), 50, ns)
				return err
			},
		},
		{
			name: "download", prefix: `{"data":"`, suffix: `"}`, limit: int64(wireSize(1 << 20)),
			call: func(t *testing.T, b *FibreBridge) error {
				_, err := b.Downloader().Download(tctx(t), [33]byte{}, 1, 1<<20)
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fb := startBridge(t, func(w http.ResponseWriter, id json.RawMessage, fb *fakeBridge) {
				fb.stream(w, id, tc.prefix, tc.suffix)
			})
			b := fb.bridge(t, BridgeLimits{NamespaceDataBytes: 1 << 20})
			err := tc.call(t, b)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrUnavailable)
			assert.NotErrorIs(t, err, ErrNotFound)
			assert.Positive(t, fb.calls.Load())
			// The client stops reading shortly after the limit; the rest of
			// the written bytes sit in socket buffers.
			assert.Less(t, fb.written.Load(), tc.limit+32<<20, "the server was not drained")
			assert.Less(t, fb.written.Load(), int64(serverCap), "the stream was cut by the client")
		})
	}
}

func TestFibreBridgeDownloadEnforcesMaxSize(t *testing.T) {
	data := make([]byte, 100)
	fb := startBridge(t, func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge) {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"data":%q}}`, id, base64.StdEncoding.EncodeToString(data))
	})
	d := fb.bridge(t, BridgeLimits{}).Downloader()

	got, err := d.Download(tctx(t), [33]byte{}, 1, 100)
	require.NoError(t, err)
	assert.Equal(t, data, got)

	_, err = d.Download(tctx(t), [33]byte{}, 1, 99)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.ErrorIs(t, err, ErrUnavailable, "a bridge answer is never settled by size alone")
}

func TestFibreBridgeNullResults(t *testing.T) {
	fb := startBridge(t, func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge) {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":null}`, id)
	})
	b := fb.bridge(t, BridgeLimits{})

	_, err := b.DAH(tctx(t), 50)
	require.ErrorIs(t, err, ErrUnavailable)
	assert.NotErrorIs(t, err, ErrNotFound)

	_, err = b.Downloader().Download(tctx(t), [33]byte{}, 1, 10)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestBridgeReaderNilHeader(t *testing.T) {
	var h headerapi.API
	h.Internal.NetworkHead = func(context.Context) (*header.ExtendedHeader, error) { return nil, nil }
	h.Internal.GetByHeight = func(context.Context, uint64) (*header.ExtendedHeader, error) { return nil, nil }
	r := bridge{rc: &client.ReadClient{Header: &h}}

	require.NotPanics(t, func() {
		_, err := r.Head(tctx(t))
		require.ErrorIs(t, err, ErrUnavailable)
		_, err = r.HeaderAt(tctx(t), 50)
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func TestNewFibreBridgeConnectionFailureIsUnavailable(t *testing.T) {
	_, err := NewFibreBridge(tctx(t), BridgeConfig{Addr: "ftp://x"}, BridgeLimits{})
	require.Error(t, err)
}

func TestWireSize(t *testing.T) {
	assert.GreaterOrEqual(t, wireSize(3000), uint64(4000), "base64 growth is covered")
	assert.Greater(t, wireSize(0), uint64(0))
}

type stopCounter struct {
	state.Client
	stops    int
	err      error
	startErr error
}

func (s *stopCounter) Stop(context.Context) error  { s.stops++; return s.err }
func (s *stopCounter) Start(context.Context) error { return s.startErr }
func (s *stopCounter) ChainID() string             { return "test-chain" }

func TestFibreDirectClosesTheStateClientOnConstructorErrors(t *testing.T) {
	t.Run("the dial fails", func(t *testing.T) {
		old := dialStateClient
		t.Cleanup(func() { dialStateClient = old })
		dialStateClient = func(string, bool, string) (state.Client, error) { return nil, errors.New("dial") }
		_, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
		require.Error(t, err)
	})
	t.Run("start fails after the dial", func(t *testing.T) {
		old := dialStateClient
		t.Cleanup(func() { dialStateClient = old })
		sc := &stopCounter{startErr: errors.New("start")}
		dialStateClient = func(string, bool, string) (state.Client, error) { return sc, nil }
		_, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
		require.Error(t, err)
		assert.GreaterOrEqual(t, sc.stops, 1, "the consensus connection is not leaked")
	})
}

func TestFibreDirectCloseStopsTheStateClient(t *testing.T) {
	old := dialStateClient
	t.Cleanup(func() { dialStateClient = old })
	sc := &stopCounter{}
	dialStateClient = func(string, bool, string) (state.Client, error) { return sc, nil }
	d, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
	require.NoError(t, err)
	assert.Zero(t, sc.stops)
	require.NoError(t, d.Close(tctx(t)))
	assert.GreaterOrEqual(t, sc.stops, 1)
}

func TestFibreDirectClosePropagatesTheStateStopError(t *testing.T) {
	old := dialStateClient
	t.Cleanup(func() { dialStateClient = old })
	errStop := errors.New("stop failed")
	dialStateClient = func(string, bool, string) (state.Client, error) { return &stopCounter{err: errStop}, nil }
	d, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
	require.NoError(t, err)
	require.ErrorIs(t, d.Close(tctx(t)), errStop)
}
