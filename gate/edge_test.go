package gate_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// A signature with S replaced by S+L verifies in a lax implementation and
// would give a second valid envelope for the same decision.
func TestMalleableSignatureIsRejected(t *testing.T) {
	e, c, _, _ := happy(t)
	s, _, err := commitment.Sign(gatefix.Key(t, "agent1"), c)
	require.NoError(t, err)
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	le := func(b []byte) *big.Int {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	sv := le(s.Signature[32:])
	sv.Add(sv, l)
	buf := sv.FillBytes(make([]byte, 32))
	mal := append([]byte(nil), s.Signature[:32]...)
	for i := 31; i >= 0; i-- {
		mal = append(mal, buf[i])
	}
	b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: s.Commitment, Signature: mal})
	require.NoError(t, err)
	_, err = e.Authorize(b)
	e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
}

// Many different envelopes that all use one (agent, nonce): one wins.
func TestConcurrentSameNonceDifferentOrders(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c0, _, _ := happy(t, gatefix.WithRegistry(open(t)))
			const n = 32
			var wg sync.WaitGroup
			var ok, used atomic.Int32
			var leaked atomic.Int32
			for i := 0; i < n; i++ {
				c := gatefix.Variant(t, c0, i)
				e.StageDA(c, gatefix.Blob(t))
				b, _ := gatefix.Sign(t, "agent1", c)
				action := gatefix.OtherAction(t, i)
				wg.Add(1)
				go func() {
					defer wg.Done()
					res, err := e.AuthorizeWith(b, action)
					switch {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, gate.ErrNonceUsed):
						used.Add(1)
						if res.Authorization != nil {
							leaked.Add(1)
						}
					default:
						assert.NoError(t, err)
					}
				}()
			}
			wg.Wait()
			require.EqualValues(t, 1, ok.Load())
			require.EqualValues(t, n-1, used.Load())
			require.Zero(t, leaked.Load(), "a loser with another commitment got the stored Authorization")
		})
	}
}

func TestFetchBudgetSmallerThanPayloadStillAdmits(t *testing.T) {
	e, _, b, _ := happy(t, gatefix.WithConfig(func(c *gate.Config) { c.MaxFetchBytes = 10 }))
	_, err := e.Authorize(b)
	require.NoError(t, err)
}

func TestCancelDuringFetchWritesNothing(t *testing.T) {
	e, c, b, _ := happy(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.DA.OnFetch(cancel)
	_, err := e.Gate.Authorize(ctx, b, gatefix.Action(t))
	e.RequireRejected(c, err, context.Canceled)
}

func TestBothSourcesHangUntilTheirTimeouts(t *testing.T) {
	e, c, b, _ := happy(t, gatefix.WithConfig(func(cfg *gate.Config) {
		cfg.DATimeout = 20 * time.Millisecond
		cfg.ArchiveTimeout = 20 * time.Millisecond
	}))
	e.DA.Hang()
	e.Archive.Hang()
	_, err := e.Authorize(b)
	e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
}
