package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-node/fibre"
	nodefibre "github.com/celestiaorg/celestia-node/nodebuilder/fibre"
	"github.com/celestiaorg/celestia-node/state/txclient"
	libshare "github.com/celestiaorg/go-square/v4/share"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFibreModule is the part of the Fibre module the adapter calls.
type fakeFibreModule struct {
	res *nodefibre.SubmitResult
	err error

	esc    *fibre.EscrowAccount
	escErr error

	submits   int
	gotCfg    *txclient.TxConfig
	gotNS     libshare.Namespace
	gotData   []byte
	gotSigner string
}

func (f *fakeFibreModule) Submit(_ context.Context, ns libshare.Namespace, data []byte, cfg *txclient.TxConfig) (*nodefibre.SubmitResult, error) {
	f.submits++
	f.gotCfg, f.gotNS, f.gotData = cfg, ns, bytes.Clone(data)
	return f.res, f.err
}

func (f *fakeFibreModule) QueryEscrowAccount(_ context.Context, signer string) (*fibre.EscrowAccount, error) {
	f.gotSigner = signer
	return f.esc, f.escErr
}

var (
	fibreAddr  = bytes.Repeat([]byte{7}, 20)
	fibreTxRaw = bytes.Repeat([]byte{0xab}, 32)
)

func newAdapter(m *fakeFibreModule) FibreSubmitter {
	return newFibreSubmitter(m, func(context.Context) ([]byte, error) { return fibreAddr, nil }, "consensus.example:9090")
}

func goodSubmitResult(ns libshare.Namespace) *nodefibre.SubmitResult {
	var c appfibre.Commitment
	copy(c[:], bytes.Repeat([]byte{3}, 32))
	return &nodefibre.SubmitResult{
		UploadResult: nodefibre.UploadResult{
			BlobID: appfibre.NewBlobID(0, c),
			PaymentPromise: &nodefibre.PaymentPromise{
				ChainID: "mocha-5", Namespace: ns, BlobSize: 262144, Commitment: c,
				ValsetHeight: 1402813, CreationTimestamp: time.Unix(1791196769, 0),
			},
		},
		Height: 1402819,
		TxHash: hex.EncodeToString(fibreTxRaw),
	}
}

func TestSubmitFibreMapsTheResultAndUsesTheDefaultKey(t *testing.T) {
	ns, err := libshare.NewNamespaceFromBytes(testNS())
	require.NoError(t, err)
	m := &fakeFibreModule{res: goodSubmitResult(ns)}
	s := newAdapter(m)

	res, err := s.SubmitFibre(context.Background(), testNS(), []byte("payload"))
	require.NoError(t, err)
	assert.Equal(t, 1, m.submits)
	assert.Nil(t, m.gotCfg, "a nil TxConfig: the promise signer, the PFF signer and Address are the client's default key")
	assert.Equal(t, testNS(), m.gotNS.Bytes())
	assert.Equal(t, []byte("payload"), m.gotData)

	assert.Equal(t, [33]byte(appfibre.NewBlobID(0, appfibre.Commitment(bytes.Repeat([]byte{3}, 32)))), res.BlobID)
	assert.EqualValues(t, 1402819, res.Height)
	assert.Equal(t, [32]byte(fibreTxRaw), res.TxHash)
	assert.EqualValues(t, 1402813, res.PromiseHeight)
	assert.Equal(t, testNS(), res.Namespace)
	assert.Equal(t, bytes.Repeat([]byte{3}, 32), res.Commitment[:])
	assert.EqualValues(t, 262144, res.BlobSize)
}

func TestSubmitFibreErrorMapping(t *testing.T) {
	ns, err := libshare.NewNamespaceFromBytes(testNS())
	require.NoError(t, err)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		m    func() *fakeFibreModule
		want error
	}{
		{"transport failure", context.Background(), func() *fakeFibreModule { return &fakeFibreModule{err: errors.New("connection refused")} }, ErrUnavailable},
		{"ctx ended", canceled, func() *fakeFibreModule { return &fakeFibreModule{err: context.Canceled} }, ErrUnavailable},
		{"deadline", context.Background(), func() *fakeFibreModule { return &fakeFibreModule{err: context.DeadlineExceeded} }, ErrUnavailable},
		{"nil result without an error", context.Background(), func() *fakeFibreModule { return &fakeFibreModule{} }, ErrUnsupported},
		{"blob id of 32 bytes", context.Background(), func() *fakeFibreModule {
			r := goodSubmitResult(ns)
			r.BlobID = r.BlobID[:32]
			return &fakeFibreModule{res: r}
		}, ErrUnsupported},
		{"empty blob id", context.Background(), func() *fakeFibreModule {
			r := goodSubmitResult(ns)
			r.BlobID = nil
			return &fakeFibreModule{res: r}
		}, ErrUnsupported},
		{"tx hash not hex", context.Background(), func() *fakeFibreModule {
			r := goodSubmitResult(ns)
			r.TxHash = strings.Repeat("zz", 32)
			return &fakeFibreModule{res: r}
		}, ErrUnsupported},
		{"tx hash too short", context.Background(), func() *fakeFibreModule {
			r := goodSubmitResult(ns)
			r.TxHash = hex.EncodeToString(fibreTxRaw[:31])
			return &fakeFibreModule{res: r}
		}, ErrUnsupported},
		{"no payment promise", context.Background(), func() *fakeFibreModule {
			r := goodSubmitResult(ns)
			r.PaymentPromise = nil
			return &fakeFibreModule{res: r}
		}, ErrUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newAdapter(tc.m()).SubmitFibre(tc.ctx, testNS(), []byte("payload"))
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestSubmitFibreRefusesABadNamespaceBeforeTheModule(t *testing.T) {
	m := &fakeFibreModule{}
	_, err := newAdapter(m).SubmitFibre(context.Background(), testNS()[:28], []byte("payload"))
	require.Error(t, err)
	assert.Zero(t, m.submits)
}

func TestFibreSubmitterAddressAndEndpoint(t *testing.T) {
	s := newAdapter(&fakeFibreModule{})
	a, err := s.Address(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fibreAddr, a)
	assert.Equal(t, "consensus.example:9090", s.Endpoint())

	short := newFibreSubmitter(&fakeFibreModule{}, func(context.Context) ([]byte, error) { return fibreAddr[:19], nil }, "x:1")
	_, err = short.Address(context.Background())
	require.ErrorIs(t, err, ErrUnsupported)

	broken := newFibreSubmitter(&fakeFibreModule{}, func(context.Context) ([]byte, error) { return nil, errors.New("no key") }, "x:1")
	_, err = broken.Address(context.Background())
	require.ErrorIs(t, err, ErrUnavailable)
}

func coin(amount int64, denom string) sdk.Coin { return sdk.NewInt64Coin(denom, amount) }

func TestFibreSubmitterEscrow(t *testing.T) {
	t.Run("available excludes pending withdrawals", func(t *testing.T) {
		m := &fakeFibreModule{esc: &fibre.EscrowAccount{Balance: coin(100, "utia"), AvailableBalance: coin(70, "utia")}}
		e, err := newAdapter(m).Escrow(context.Background())
		require.NoError(t, err)
		assert.EqualValues(t, 70, e.AvailableUtia)
		assert.EqualValues(t, 30, e.PendingWithdrawalUtia)
		assert.NotEmpty(t, m.gotSigner, "the query names the signer of the client's key")
	})
	t.Run("another denom is not utia", func(t *testing.T) {
		m := &fakeFibreModule{esc: &fibre.EscrowAccount{Balance: coin(100, "uother"), AvailableBalance: coin(100, "uother")}}
		_, err := newAdapter(m).Escrow(context.Background())
		require.ErrorIs(t, err, ErrUnsupported)
	})
	t.Run("an account that does not exist holds nothing", func(t *testing.T) {
		m := &fakeFibreModule{escErr: errors.New("querying escrow account: escrow account not found for signer:celestia1xyz")}
		e, err := newAdapter(m).Escrow(context.Background())
		require.NoError(t, err)
		assert.Equal(t, Escrow{}, e)
	})
	t.Run("any other failure is unavailable", func(t *testing.T) {
		m := &fakeFibreModule{escErr: errors.New("connection refused")}
		_, err := newAdapter(m).Escrow(context.Background())
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("a nil account without an error is unsupported", func(t *testing.T) {
		_, err := newAdapter(&fakeFibreModule{}).Escrow(context.Background())
		require.Error(t, err)
	})
	t.Run("the signer string follows the key", func(t *testing.T) {
		m1, m2 := &fakeFibreModule{escErr: errors.New("x")}, &fakeFibreModule{escErr: errors.New("x")}
		_, _ = newAdapter(m1).Escrow(context.Background())
		other := newFibreSubmitter(m2, func(context.Context) ([]byte, error) { return bytes.Repeat([]byte{8}, 20), nil }, "x:1")
		_, _ = other.Escrow(context.Background())
		assert.NotEqual(t, m1.gotSigner, m2.gotSigner)
	})
}

// The Recorder never moves funds: neither the interface it sees nor the part
// of the module the adapter uses can reach a deposit or a withdrawal.
func TestFibreSurfaceHasNoDepositOrWithdraw(t *testing.T) {
	names := func(typ reflect.Type) []string {
		var out []string
		for i := 0; i < typ.NumMethod(); i++ {
			out = append(out, typ.Method(i).Name)
		}
		sort.Strings(out)
		return out
	}
	assert.Equal(t, []string{"Address", "Endpoint", "Escrow", "SubmitFibre"}, names(reflect.TypeOf((*FibreSubmitter)(nil)).Elem()))
	assert.Equal(t, []string{"QueryEscrowAccount", "Submit"}, names(reflect.TypeOf((*fibreModule)(nil)).Elem()),
		"Upload sends the PFF from a goroutine nobody can cancel; Deposit and Withdraw move funds")
}

var fundMoves = regexp.MustCompile(`MsgDepositToEscrow|MsgRequestWithdrawal|\.Withdraw\(`)

// Escrow is funded by the operator: no production code builds a deposit or a
// withdrawal message.
func TestNoEscrowFundsMovementInProductionCode(t *testing.T) {
	require.NoError(t, filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(p)
		require.NoError(t, rerr)
		assert.False(t, fundMoves.Match(src), "%s moves escrow funds", p)
		return nil
	}))
}
