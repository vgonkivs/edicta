package gatechain_test

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// fibreEnv is the gate over the real da = 1 read path: anchors and blobs from
// the fake node, the real committer. The commitment names the live Mocha blob,
// so the only thing a test changes is what the chain says.
func fibreEnv(t *testing.T, l live, r node.FibreAnchorReader) (*gatefix.Env, *commitment.Commitment, []byte) {
	t.Helper()
	created := uint64(l.created.Unix())
	c := gatefix.FibreTemplate(t)
	c.PayloadRef = l.ref()
	sum := sha256.Sum256(l.payload)
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(l.payload))
	c = gatefix.Times(c, created+120, created+120+900)
	anchors := anchorsOver(r, mochaID)
	blobs := gatechain.NewFibreBlobs(anchors, &fakeDL{data: l.payload}, nil, committer(t))
	e := gatefix.New(t, gatefix.WithNow(created+130), gatefix.WithDeps(func(d *gate.Deps) {
		d.Anchors = anchors
		d.DA = blobs
		d.Committers = map[commitment.DA]gate.DACommitter{commitment.DAFibre: committer(t), commitment.DACelestiaBlob: blobv1.New()}
	}))
	e.Headers.Set(l.pffHeight, created+30)
	b, _ := gatefix.Sign(t, "agent1", c)
	return e, c, b
}

func TestFibreGateAuthorizesTheLivePFF(t *testing.T) {
	l := loadLive(t)
	e, c, b := fibreEnv(t, l, liveBlock(t).chain(t, l))
	res, err := e.Authorize(b)
	require.NoError(t, err)
	assert.NotEmpty(t, res.Authorization)
	_, err = e.Entry(c)
	require.NoError(t, err, "the nonce is marked once the authorization is issued")
}

func requireNeverAuthorized(t *testing.T, e *gatefix.Env, c *commitment.Commitment, b []byte) error {
	t.Helper()
	res, err := e.Authorize(b)
	require.Error(t, err)
	assert.Empty(t, res.Authorization)
	assert.True(t, errors.Is(err, gate.ErrAnchorNotFound) || errors.Is(err, gate.ErrChainUnavailable), "unexpected rejection: %v", err)
	e.RequireUntouched(c)
	return err
}

func parsedSigs(t *testing.T, l live) [][]byte {
	t.Helper()
	f, ok, err := fibrecert.ParsePFF(l.pff)
	require.NoError(t, err)
	require.True(t, ok)
	return f.Signatures
}

// signedIndexes are the positions of the first n non-empty signatures of the
// live certificate.
func signedIndexes(t *testing.T, l live, n int) []int {
	t.Helper()
	var idx []int
	for i, s := range parsedSigs(t, l) {
		if len(s) > 0 {
			idx = append(idx, i)
		}
		if len(idx) == n {
			return idx
		}
	}
	require.FailNow(t, "too few signatures in the live certificate")
	return nil
}

// A certificate that reuses one validator's valid signature under several list
// positions, or reorders the list, must not stand in for the network quorum.
func TestFibreForgedCertificateNeverAuthorizes(t *testing.T) {
	l := loadLive(t)
	hi := parseHist(t, l.hist)
	sigs := parsedSigs(t, l)
	idx := signedIndexes(t, l, 3)
	a, b, c := idx[0], idx[1], idx[2]

	forge := func(vals []stakingtypes.Validator, list [][]byte) (histRaw, tx []byte) {
		h := hi
		h.Valset = vals
		tx = l.pff
		if list != nil {
			tx = mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.ValidatorSignatures = list })
		}
		return marshalHist(t, h), tx
	}
	cases := []struct {
		name string
		make func() (hist, tx []byte)
	}{
		{"[A,A,A,A,B,C] with the valid signature of A repeated", func() ([]byte, []byte) {
			v := hi.Valset
			return forge([]stakingtypes.Validator{v[a], v[a], v[a], v[a], v[b], v[c]},
				[][]byte{sigs[a], sigs[a], sigs[a], sigs[a], sigs[b], sigs[c]})
		}},
		{"[A,A,A,A,B,C] list over the unchanged signatures", func() ([]byte, []byte) {
			v := hi.Valset
			return forge([]stakingtypes.Validator{v[a], v[a], v[a], v[a], v[b], v[c]}, nil)
		}},
		{"list permuted, signatures as they were", func() ([]byte, []byte) {
			v := append([]stakingtypes.Validator(nil), hi.Valset...)
			v[0], v[1] = v[1], v[0]
			return forge(v, nil)
		}},
		{"list and signatures permuted together", func() ([]byte, []byte) {
			v := append([]stakingtypes.Validator(nil), hi.Valset...)
			s := append([][]byte(nil), sigs...)
			v[0], v[1] = v[1], v[0]
			s[0], s[1] = s[1], s[0]
			return forge(v, s)
		}},
		{"list reversed with reversed signatures", func() ([]byte, []byte) {
			n := len(hi.Valset)
			v := make([]stakingtypes.Validator, n)
			s := make([][]byte, n)
			for i := range v {
				v[i], s[i] = hi.Valset[n-1-i], sigs[n-1-i]
			}
			return forge(v, s)
		}},
		{"one validator holding all the power", func() ([]byte, []byte) {
			v := append([]stakingtypes.Validator(nil), hi.Valset...)
			v[a].Tokens = v[a].Tokens.MulRaw(1000)
			return forge(v, nil)
		}},
		{"signatures truncated below the network rule", func() ([]byte, []byte) {
			return l.hist, mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
				for i := 5; i < len(m.ValidatorSignatures); i++ {
					m.ValidatorSignatures[i] = nil
				}
			})
		}},
		{"every signature truncated by one byte", func() ([]byte, []byte) {
			return l.hist, mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
				for i, s := range m.ValidatorSignatures {
					if len(s) > 0 {
						m.ValidatorSignatures[i] = s[:len(s)-1]
					}
				}
			})
		}},
		{"signature list longer than the validator set", func() ([]byte, []byte) {
			return l.hist, mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
				m.ValidatorSignatures = append(m.ValidatorSignatures, sigs[a], sigs[b])
			})
		}},
		{"no signatures", func() ([]byte, []byte) {
			return l.hist, mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.ValidatorSignatures = nil })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hist, tx := tc.make()
			ch := buildBlock(t, l.pffHeight, tx).chain(t, l)
			ch.SetHistoricalInfo(l.promiseH, hist)
			e, cm, b := fibreEnv(t, l, ch)
			requireNeverAuthorized(t, e, cm, b)
		})
	}
}

// Every mutation of the live proof inputs is refused by the gate, and the
// nonce stays untouched.
func TestFibreMutatedBlockNeverAuthorizes(t *testing.T) {
	l := loadLive(t)
	v := loadAnchorVector(t)
	base := liveBlock(t)
	for _, m := range v.Mutations {
		t.Run(m.ID, func(t *testing.T) {
			mut, ok := applyOp(t, base, m.Op)
			if !ok {
				t.Skip("acts on the encoded stream or the checked namespace")
			}
			e, c, b := fibreEnv(t, l, mut.chain(t, l))
			err := requireNeverAuthorized(t, e, c, b)
			assert.ErrorIs(t, err, gate.ErrChainUnavailable, "an unprovable block is the endpoint's failure")
		})
	}
}

// A chain that has no valid PFF for the commitment never authorizes, however
// the lookup fails.
func TestFibreGateNeverAuthorizesWithoutAnAnchor(t *testing.T) {
	l := loadLive(t)
	t.Run("PFF of another chain", func(t *testing.T) {
		tx := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.ChainId = "mocha-4" })
		e, c, b := fibreEnv(t, l, buildBlock(t, l.pffHeight, tx).chain(t, l))
		requireNeverAuthorized(t, e, c, b)
	})
	t.Run("PFF that failed in execution", func(t *testing.T) {
		ch := liveBlock(t).chain(t, l)
		ch.SetTxCode(l.pffHeight, txHash(l.pff), 11)
		e, c, b := fibreEnv(t, l, ch)
		err := requireNeverAuthorized(t, e, c, b)
		assert.ErrorIs(t, err, gate.ErrAnchorNotFound)
	})
	t.Run("block without the PFF", func(t *testing.T) {
		e, c, b := fibreEnv(t, l, buildBlock(t, l.pffHeight, []byte("other")).chain(t, l))
		err := requireNeverAuthorized(t, e, c, b)
		assert.ErrorIs(t, err, gate.ErrAnchorNotFound)
	})
	t.Run("height-ignoring endpoint", func(t *testing.T) {
		ch := liveBlock(t).chain(t, l)
		ch.AddHeader(l.pffHeight+1, []byte{1}, headerTime)
		ch.IgnoreHeights(l.pffHeight + 1)
		e, c, b := fibreEnv(t, l, ch)
		err := requireNeverAuthorized(t, e, c, b)
		assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
	})
	t.Run("bridge down", func(t *testing.T) {
		ch := liveBlock(t).chain(t, l)
		ch.FailBridge = nodefake.ErrInjected
		e, c, b := fibreEnv(t, l, ch)
		err := requireNeverAuthorized(t, e, c, b)
		assert.ErrorIs(t, err, gate.ErrChainUnavailable)
	})
	t.Run("result code unreadable", func(t *testing.T) {
		h := &hooks{FibreAnchorReader: liveBlock(t).chain(t, l),
			txCode: func(uint64, [32]byte) (uint32, error) { return 0, node.ErrNotFound }}
		e, c, b := fibreEnv(t, l, h)
		err := requireNeverAuthorized(t, e, c, b)
		assert.ErrorIs(t, err, gate.ErrChainUnavailable)
	})
	t.Run("a PFF in the namespace that is not the committed one", func(t *testing.T) {
		tx := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment[1] ^= 1 })
		e, c, b := fibreEnv(t, l, buildBlock(t, l.pffHeight, tx).chain(t, l))
		requireNeverAuthorized(t, e, c, b)
	})
	t.Run("proof shares of the wrong namespace", func(t *testing.T) {
		shares := splitTxs(t, l.pff)
		wrong := libshare.NewCompactShareSplitter(libshare.PayForBlobNamespace, libshare.ShareVersionZero)
		require.NoError(t, wrong.WriteTx(l.pff))
		other, err := wrong.Export()
		require.NoError(t, err)
		require.Len(t, other, len(shares))
		e, c, b := fibreEnv(t, l, buildBlockFromShares(t, l.pffHeight, other).chain(t, l))
		requireNeverAuthorized(t, e, c, b)
	})
}

// Two concurrent requests with the same nonce: one Authorization.
func TestFibreGateDoubleSpendIssuesOneAuthorization(t *testing.T) {
	l := loadLive(t)
	e, _, b := fibreEnv(t, l, liveBlock(t).chain(t, l))
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	issued := 0
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.Authorize(b)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && len(res.Authorization) > 0 {
				issued++
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, issued)
}
