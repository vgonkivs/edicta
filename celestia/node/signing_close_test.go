package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
	blobapi "github.com/celestiaorg/celestia-node/nodebuilder/blob"
	stateapi "github.com/celestiaorg/celestia-node/nodebuilder/state"
)

type atomicStop struct {
	state.Client
	stops atomic.Int32
	err   error
}

func (s *atomicStop) Stop(context.Context) error  { s.stops.Add(1); return s.err }
func (s *atomicStop) Start(context.Context) error { return nil }
func (s *atomicStop) ChainID() string             { return "test-chain" }

// setCloser sets the unexported close hook of a library client built by hand.
func setCloser(t *testing.T, v any, fn func() error) {
	t.Helper()
	f := reflect.ValueOf(v).Elem().FieldByName("closer")
	require.True(t, f.IsValid())
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(fn))
}

// fakeClient is a library client whose Close counts and returns err.
func fakeClient(t *testing.T, withSubmit bool, closes *atomic.Int32, err error) *client.Client {
	t.Helper()
	c := &client.Client{}
	fn := func() error { closes.Add(1); return err }
	setCloser(t, &c.ReadClient, fn)
	setCloser(t, c, func() error { return nil })
	if withSubmit {
		c.State = struct{ stateapi.Module }{}
		c.Blob = struct{ blobapi.Module }{}
	}
	return c
}

type signingSeams struct {
	got    client.Config
	states []*atomicStop
}

// installSigningSeams replaces both seams; newClient builds the client handed back.
func installSigningSeams(t *testing.T, newClient func() (*client.Client, error)) *signingSeams {
	t.Helper()
	s := &signingSeams{}
	oldNew, oldDial := newClientFn, dialStateClient
	t.Cleanup(func() { newClientFn, dialStateClient = oldNew, oldDial })
	newClientFn = func(_ context.Context, cfg client.Config, _ keyring.Keyring) (*client.Client, error) {
		s.got = cfg
		return newClient()
	}
	dialStateClient = func(GRPCConfig) (state.Client, error) {
		sc := &atomicStop{}
		s.states = append(s.states, sc)
		return sc, nil
	}
	return s
}

func signIn(t *testing.T, g GRPCConfig) (interface{ Close() error }, error) {
	t.Helper()
	c, _, _, err := NewSigning(tctx(t), BridgeConfig{Addr: "http://bn.invalid:26658"}, g,
		keyring.NewInMemory(nil), "k", "mocha-4")
	return c, err
}

func dialTwice(t *testing.T, s *signingSeams) {
	t.Helper()
	fn := s.got.SubmitConfig.Fibre.StateClientFn
	require.NotNil(t, fn)
	for range 2 {
		_, err := fn()
		require.NoError(t, err)
	}
	require.Len(t, s.states, 2)
}

func TestNewSigningStopsStateClientsOnFailurePaths(t *testing.T) {
	g := GRPCConfig{Addr: "127.0.0.1:9090"}

	t.Run("client construction fails", func(t *testing.T) {
		errNew := errors.New("new client")
		s := installSigningSeams(t, func() (*client.Client, error) { return nil, errNew })
		// The library dials the state client while it builds the client.
		oldFn := newClientFn
		newClientFn = func(ctx context.Context, cfg client.Config, kr keyring.Keyring) (*client.Client, error) {
			_, err := cfg.SubmitConfig.Fibre.StateClientFn()
			require.NoError(t, err)
			return oldFn(ctx, cfg, kr)
		}
		c, err := signIn(t, g)
		require.ErrorIs(t, err, ErrUnavailable)
		assert.Contains(t, err.Error(), errNew.Error())
		assert.Nil(t, c)
		require.Len(t, s.states, 1)
		assert.EqualValues(t, 1, s.states[0].stops.Load())
	})

	t.Run("submitter fails", func(t *testing.T) {
		var closes atomic.Int32
		s := installSigningSeams(t, func() (*client.Client, error) { return fakeClient(t, false, &closes, nil), nil })
		oldFn := newClientFn
		newClientFn = func(ctx context.Context, cfg client.Config, kr keyring.Keyring) (*client.Client, error) {
			_, err := cfg.SubmitConfig.Fibre.StateClientFn()
			require.NoError(t, err)
			return oldFn(ctx, cfg, kr)
		}
		c, err := signIn(t, g)
		require.Error(t, err)
		assert.Nil(t, c)
		assert.EqualValues(t, 1, closes.Load(), "the client is closed")
		require.Len(t, s.states, 1)
		assert.EqualValues(t, 1, s.states[0].stops.Load())
	})
}

func TestNewSigningDisablesEscrowAutoFund(t *testing.T) {
	var closes atomic.Int32
	s := installSigningSeams(t, func() (*client.Client, error) { return fakeClient(t, true, &closes, nil), nil })
	c, err := signIn(t, GRPCConfig{Addr: "127.0.0.1:9090"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NotNil(t, s.got.SubmitConfig.Fibre)
	assert.False(t, s.got.SubmitConfig.Fibre.Escrow.AutoFund)
}

func TestNewSigningCloserStopsEveryClientOnce(t *testing.T) {
	var closes atomic.Int32
	errClose := errors.New("close")
	s := installSigningSeams(t, func() (*client.Client, error) { return fakeClient(t, true, &closes, errClose), nil })
	c, err := signIn(t, GRPCConfig{Addr: "127.0.0.1:9090"})
	require.NoError(t, err)
	dialTwice(t, s)

	const n = 16
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = c.Close() }()
	}
	wg.Wait()

	assert.EqualValues(t, 1, closes.Load())
	for _, sc := range s.states {
		assert.EqualValues(t, 1, sc.stops.Load())
	}
	for _, e := range errs {
		require.ErrorIs(t, e, errClose)
		assert.Equal(t, errs[0], e, "every call returns the first result")
	}
}

func TestFibreDirectCloseRunsOnce(t *testing.T) {
	old := dialStateClient
	t.Cleanup(func() { dialStateClient = old })
	errStop := errors.New("stop failed")
	sc := &atomicStop{err: errStop}
	dialStateClient = func(GRPCConfig) (state.Client, error) { return sc, nil }
	d, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
	require.NoError(t, err)

	first := d.Close(tctx(t))
	require.ErrorIs(t, first, errStop)
	assert.Equal(t, first, d.Close(tctx(t)))
	assert.EqualValues(t, 1, sc.stops.Load())
}

func TestFibreDirectCloseConcurrent(t *testing.T) {
	old := dialStateClient
	t.Cleanup(func() { dialStateClient = old })
	sc := &atomicStop{}
	dialStateClient = func(GRPCConfig) (state.Client, error) { return sc, nil }
	d, err := NewFibreDirect(tctx(t), GRPCConfig{Addr: "127.0.0.1:1"})
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); assert.NoError(t, d.Close(tctx(t))) }()
	}
	wg.Wait()
	assert.EqualValues(t, 1, sc.stops.Load())
}

func TestDefaultDialStateClientTokenRule(t *testing.T) {
	t.Run("token without TLS is refused before any dial", func(t *testing.T) {
		sc, err := defaultDialStateClient(GRPCConfig{Addr: "127.0.0.1:9090", Token: "tok"})
		require.Error(t, err)
		assert.Nil(t, sc)
		assert.Contains(t, err.Error(), "token")
	})
	t.Run("token without TLS on a remote address is refused", func(t *testing.T) {
		_, err := defaultDialStateClient(GRPCConfig{Addr: "grpc.example.invalid:9090", Token: "tok"})
		require.Error(t, err)
	})
	t.Run("loopback with the caller's opt-in is accepted", func(t *testing.T) {
		sc, err := defaultDialStateClient(GRPCConfig{Addr: "127.0.0.1:9090", Token: "tok", AllowInsecureToken: true})
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.NoError(t, sc.Stop(tctx(t)))
	})
}

func TestFibreBridgeLimits(t *testing.T) {
	fb := startBridge(t, func(http.ResponseWriter, json.RawMessage, *fakeBridge) {})
	for _, tc := range []struct {
		name string
		in   uint64
		want uint64
	}{
		{"zero takes the default", 0, DefaultBridgeNamespaceDataBytes},
		{"non-zero is kept", 1 << 20, 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := NewFibreBridge(tctx(t), BridgeConfig{Addr: fb.srv.URL}, BridgeLimits{NamespaceDataBytes: tc.in})
			require.NoError(t, err)
			t.Cleanup(b.Close)
			assert.Equal(t, BridgeLimits{NamespaceDataBytes: tc.want}, b.Limits())
		})
	}
}
