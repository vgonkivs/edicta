package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func authorized(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
	t.Helper()
	e, c, b, h := happy(t, opts...)
	_, err := e.Authorize(b)
	require.NoError(t, err)
	return e, c, b, h
}

func TestRecordSignsAndStoresTheReceipt(t *testing.T) {
	e, c, b, h := authorized(t)
	e.Clock.Advance(7 * time.Second)
	r, err := e.Record(b, "order-42")
	require.NoError(t, err)
	gatefix.CheckReceipt(t, r, h, "order-42", gatefix.GateID, gatefix.Pub(t, "gate1"), gatefix.Now+7)
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, r, ent.Receipt)

	sr, rh, err := commitment.VerifyReceipt(r)
	require.NoError(t, err)
	require.True(t, verifyUnder(sr, commitment.ReceiptSigningMessage(rh)), "not signed under the receipt tag")
	_, _, err = commitment.VerifyAuthorization(r, commitment.AuthorizationCheck{
		GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: c.Action.Type,
		Action: gatefix.Action(t), Now: gatefix.Now, SkewS: 30,
	})
	require.Error(t, err, "a receipt must not pass as an Authorization")
}

func verifyUnder(sr *commitment.SignedReceipt, msg []byte) bool {
	return ed25519Verify(sr.Receipt.GatePubKey, msg, sr.Signature)
}

func TestRecordRequiresAPriorAuthorization(t *testing.T) {
	t.Run("never authorized", func(t *testing.T) {
		e, c, b, _ := happy(t)
		r, err := e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrNotAuthorized)
		require.Nil(t, r)
		_, gerr := e.Entry(c)
		require.ErrorIs(t, gerr, registry.ErrNotFound, "Record must not create an entry")
	})
	t.Run("the nonce is held by another commitment", func(t *testing.T) {
		e, _, _, _ := authorized(t)
		c2 := gatefix.Variant(t, gatefix.Template(t), 1)
		b2, _ := gatefix.Sign(t, "agent1", c2)
		r, err := e.Record(b2, "ref-1")
		require.ErrorIs(t, err, gate.ErrNotAuthorized)
		require.Nil(t, r)
	})
	t.Run("after the entry was pruned", func(t *testing.T) {
		e, _, b, _ := authorized(t)
		later := uint64(1791000900 + 3600 + 100)
		e.Clock.Set(later)
		cc := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 3), later-10, later+890)
		e.StageDA(cc, gatefix.Blob(t))
		bc, _ := gatefix.Sign(t, "agent1", cc)
		_, err := e.Authorize(bc)
		require.NoError(t, err)
		n, err := e.Gate.Prune(context.Background())
		require.NoError(t, err)
		require.EqualValues(t, 1, n)
		_, err = e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrNotAuthorized)
	})
	t.Run("not an envelope", func(t *testing.T) {
		e, _, _, _ := authorized(t)
		for _, b := range [][]byte{nil, {}, {0xa0}, []byte("junk")} {
			r, err := e.Gate.Record(context.Background(), b, "ref-1", gatefix.ExecutorPub(t, "executor1"), make([]byte, 64))
			require.Error(t, err)
			require.NotErrorIs(t, err, gate.ErrNotAuthorized)
			require.Nil(t, r)
		}
	})
}

func TestRecordNeedsNoTimeOrChainChecks(t *testing.T) {
	e, _, b, h := authorized(t)
	e.Clock.Set(gatefix.Now + 1000) // past valid_until
	e.Anchors.Fail(errors.New("down"))
	r, err := e.Record(b, "late-ref")
	require.NoError(t, err)
	gatefix.CheckReceipt(t, r, h, "late-ref", gatefix.GateID, gatefix.Pub(t, "gate1"), gatefix.Now+1000)
}

func TestRecordAtMostOneReceipt(t *testing.T) {
	e, c, b, _ := authorized(t)
	first, err := e.Record(b, "ref-1")
	require.NoError(t, err)
	e.Clock.Advance(time.Minute)
	again, err := e.Record(b, "ref-2")
	require.ErrorIs(t, err, gate.ErrReceiptExists)
	require.Equal(t, first, again, "the stored receipt is returned")
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, first, ent.Receipt)
}

func TestRecordConcurrently(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := authorized(t, gatefix.WithRegistry(open(t)))
			const n = 32
			var wg sync.WaitGroup
			var start sync.WaitGroup
			start.Add(1)
			var ok, exists atomic.Int32
			out := make([][]byte, n)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					start.Wait()
					r, err := e.Record(b, "ref-"+strings.Repeat("x", i%5+1))
					out[i] = r
					switch {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, gate.ErrReceiptExists):
						exists.Add(1)
					default:
						assert.Fail(t, "unexpected error", "%v", err)
					}
				}()
			}
			start.Done()
			wg.Wait()
			require.EqualValues(t, 1, ok.Load())
			require.EqualValues(t, n-1, exists.Load())
			ent, err := e.Entry(c)
			require.NoError(t, err)
			for _, r := range out {
				require.Equal(t, ent.Receipt, r)
			}
		})
	}
}

func TestRecordRailRefValidation(t *testing.T) {
	bad := map[string]string{
		"empty":     "",
		"space":     "a b",
		"newline":   "a\nb",
		"too long":  strings.Repeat("a", 129),
		"non-ascii": "café",
	}
	for name, ref := range bad {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := authorized(t)
			r, err := e.Record(b, ref)
			require.Error(t, err)
			require.True(t, errors.Is(err, commitment.ErrFieldSize) || errors.Is(err, commitment.ErrInvalidString), "%v", err)
			require.Nil(t, r)
			ent, gerr := e.Entry(c)
			require.NoError(t, gerr)
			require.Nil(t, ent.Receipt, "an invalid reference was stored")
			_, err = e.Record(b, "ok-ref")
			require.NoError(t, err, "a refused Record must not use up the receipt")
		})
	}
	t.Run("longest valid reference", func(t *testing.T) {
		e, _, b, _ := authorized(t)
		_, err := e.Record(b, strings.Repeat("a", 128))
		require.NoError(t, err)
	})
	t.Run("the reference is opaque", func(t *testing.T) {
		e, _, b, h := authorized(t)
		ref := "0x" + strings.Repeat("ab", 20)
		r, err := e.Record(b, ref)
		require.NoError(t, err)
		gatefix.CheckReceipt(t, r, h, ref, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
	})
}

func TestRecordFailures(t *testing.T) {
	t.Run("signer fails: no receipt, retry works", func(t *testing.T) {
		inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
		require.NoError(t, err)
		s := &flakySigner{inner: inner}
		e, c, b, _ := authorized(t, gatefix.WithSigner(s))
		s.fail.Store(true)
		r, err := e.Record(b, "ref-1")
		require.Error(t, err)
		require.Nil(t, r)
		ent, _ := e.Entry(c)
		require.Nil(t, ent.Receipt)
		s.fail.Store(false)
		_, err = e.Record(b, "ref-1")
		require.NoError(t, err)
	})
	t.Run("broken signers", func(t *testing.T) {
		for name, mode := range map[string]signerMode{"panic": signPanic, "bad signature": signZero} {
			s := newModalSigner(t, signOK)
			e, c, b, _ := authorized(t, gatefix.WithSigner(s))
			s.mode.Store(int32(mode))
			require.NotPanics(t, func() {
				r, err := e.Record(b, "ref-1")
				require.Errorf(t, err, name)
				require.Nil(t, r)
			})
			ent, _ := e.Entry(c)
			require.Nil(t, ent.Receipt, name)
		}
	})
	t.Run("attach fails: a retry signs again and only the stored receipt is returned", func(t *testing.T) {
		e, c, b, _ := authorized(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("AttachReceipt", errors.New("disk full"))
		r, err := e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrRegistryUnavailable)
		require.Nil(t, r)
		ent, _ := e.Entry(c)
		require.Nil(t, ent.Receipt)
		got, err := e.Record(b, "ref-1")
		require.NoError(t, err)
		ent, _ = e.Entry(c)
		require.Equal(t, got, ent.Receipt)
	})
	t.Run("lookup fails", func(t *testing.T) {
		e, _, b, _ := authorized(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Get", errors.New("io"))
		_, err := e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrRegistryUnavailable)
	})
}

func ed25519Verify(pub, msg, sig []byte) bool { return ed25519.Verify(pub, msg, sig) }
