package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
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

func TestAuthorizeHappyPathDA(t *testing.T) {
	e, c, b, h := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.Equal(t, registry.PathDA, res.Path)
	require.Equal(t, h, res.CommitmentHash)
	require.Equal(t, string(c.Action.Hash), string(res.ActionHash[:]))
	sa := gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, gatefix.Now+300, gatefix.Now)
	require.Equal(t, commitment.PathDA, sa.Authorization.Path)

	require.EqualValues(t, 1, e.DA.Fetches())
	require.EqualValues(t, 0, e.Archive.Fetches())

	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, h, ent.CommitmentHash)
	require.Equal(t, string(c.Action.Hash), string(ent.ActionHash[:]))
	require.Equal(t, registry.PathDA, ent.Path)
	require.Equal(t, c.ValidUntil, ent.ValidUntil)
	require.EqualValues(t, gatefix.Now, ent.AuthorizedAt)
	require.Equal(t, res.Authorization, ent.Authorization)
	require.Nil(t, ent.Receipt, "no receipt until Record")

	ev := e.Metrics.Events()
	require.Len(t, ev, 1)
	require.NoError(t, ev[0].Err)
	require.True(t, ev[0].Authorized)
	require.Equal(t, registry.PathDA, ev[0].Path)
	require.Equal(t, commitment.DACelestiaBlob, ev[0].DA)
	require.Equal(t, h, ev[0].CommitmentHash)
}

func TestAuthorizeHappyPathFibre(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.Equal(t, registry.PathDA, res.Path)
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
}

func TestAuthorizePathRecorded(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.Template(t)
	routeArchive(e, c)
	e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.Equal(t, registry.PathArchive, res.Path)
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathArchive, 0, gatefix.Now)
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, registry.PathArchive, ent.Path)
}

// The Authorization bytes are rebuilt here from the wire definition, not with
// the gate's code path.
func TestAuthorizationBytesMatchTheWireFormat(t *testing.T) {
	e, c, b, h := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)

	a := commitment.Authorization{
		Version: 0, CommitmentHash: h[:], ActionHash: c.Action.Hash,
		GateID: gatefix.GateID, Expires: gatefix.Now + 300, Path: commitment.PathDA,
	}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	ah := commitment.HashAuthorization(canon)
	msg := commitment.AuthorizationSigningMessage(ah)
	require.Len(t, msg, 60)
	sig := ed25519.Sign(gatefix.Key(t, "gate1"), msg)
	want, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	require.Equal(t, want, res.Authorization)
	require.LessOrEqual(t, len(res.Authorization), commitment.MaxAuthorizationSize)

	sa, _, err := commitment.DecodeSignedAuthorization(res.Authorization)
	require.NoError(t, err)
	pub := gatefix.Pub(t, "gate1")
	require.False(t, ed25519.Verify(pub, commitment.SigningMessage(h), sa.Signature), "verifies as a commitment signature")
	require.False(t, ed25519.Verify(pub, commitment.ReceiptSigningMessage(ah), sa.Signature), "verifies as a receipt signature")
	require.False(t, ed25519.Verify(gatefix.Pub(t, "agent1"), msg, sa.Signature), "verifies under the agent key")
	require.Equal(t, pub, []byte(e.Gate.PublicKey()))
}

func TestAuthorizationBindsTheActionType(t *testing.T) {
	e, c, b, _ := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	_, _, err = commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
		GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: "application/json",
		Action: gatefix.Action(t), Now: gatefix.Now, SkewS: 30,
	})
	require.ErrorIs(t, err, commitment.ErrActionMismatch)
	_, _, err = commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
		GatePubKey: gatefix.Pub(t, "gate1"), GateID: "gate-paper-2", ActionType: c.Action.Type,
		Action: gatefix.Action(t), Now: gatefix.Now, SkewS: 30,
	})
	require.ErrorIs(t, err, commitment.ErrScopeMismatch)
}

func TestAuthorizationExpires(t *testing.T) {
	const validUntil = uint64(1791000900)
	rows := []struct {
		name    string
		now     uint64
		ttl     uint64
		advance time.Duration
		want    uint64
	}{
		{"now plus the default ttl", gatefix.Now, 0, 0, gatefix.Now + 300},
		{"valid_until when it is nearer", validUntil - 31, 0, 0, validUntil},
		{"a smaller configured ttl", gatefix.Now, 60, 0, gatefix.Now + 60},
		{"ttl just reaching valid_until", validUntil - 31 - 100, 131, 0, validUntil},
		{"measured at the second clock reading, after the fetch", gatefix.Now, 0, 100 * time.Second, gatefix.Now + 100 + 300},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e, c, b, h := happy(t, gatefix.WithNow(r.now), gatefix.WithConfig(func(cfg *gate.Config) {
				if r.ttl != 0 {
					cfg.MaxAuthorizationTTL = r.ttl
				}
			}))
			if r.advance != 0 {
				e.DA.OnFetch(func() { e.Clock.Advance(r.advance) })
			}
			res, err := e.Authorize(b)
			require.NoError(t, err)
			sa, _, err := commitment.DecodeSignedAuthorization(res.Authorization)
			require.NoError(t, err)
			require.Equal(t, r.want, sa.Authorization.Expires)
			require.LessOrEqual(t, sa.Authorization.Expires, c.ValidUntil)
			require.Equal(t, h, res.CommitmentHash)
		})
	}
}

func TestAuthorizeConfigValidation(t *testing.T) {
	t.Run("ttl not above skew", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.MaxAuthorizationTTL = c.SkewS }))
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("sign timeout not positive", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.SignTimeout = 0 }))
		require.ErrorIs(t, err, gate.ErrInvalidConfig)
	})
	t.Run("defaults", func(t *testing.T) {
		cfg := gate.DefaultConfig()
		require.EqualValues(t, 300, cfg.MaxAuthorizationTTL)
		require.Positive(t, cfg.SignTimeout)
	})
}

func TestAuthorizeAllowsEveryConfiguredActionType(t *testing.T) {
	const jsonType = "application/json"
	e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{
		GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, jsonType},
	}))
	for i, typ := range []string{gatefix.ActionType, jsonType} {
		action := []byte(`{"to":"a"}`)
		c := gatefix.Fresh(gatefix.WithAction(t, gatefix.Template(t), typ, action), byte(i+1))
		c = gatefix.WithAction(t, c, typ, action)
		e.StageDA(c, gatefix.Blob(t))
		b, h := gatefix.Sign(t, "agent1", c)
		res, err := e.AuthorizeWith(b, action)
		require.NoErrorf(t, err, "type %s", typ)
		gatefix.CheckAuthorization(t, res.Authorization, action, c, h, commitment.PathDA, 0, gatefix.Now)
	}
}

func TestAuthorizeEnvelopeBytesOnly(t *testing.T) {
	e := gatefix.New(t)
	for _, b := range [][]byte{nil, {}, {0xa0}} {
		res, err := e.Authorize(b)
		require.Errorf(t, err, "authorized %x", b)
		require.Nil(t, res.Authorization)
	}
}

func TestReplayAcrossAgentsAndNonces(t *testing.T) {
	t.Run("same nonce, other agent key is a different registry key", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		c2 := gatefix.WithKey(t, gatefix.Template(t), "agent2")
		c2.AgentID = "dca-agent-2"
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent2", c2)
		res, err := e.Authorize(b2)
		require.NoError(t, err, "second agent with the same nonce")
		require.NotEmpty(t, res.Authorization)
	})
	t.Run("same nonce, different action, same agent", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		c2 := gatefix.Variant(t, gatefix.Template(t), 1)
		e.StageDA(c2, gatefix.Blob(t))
		b2, h2 := gatefix.Sign(t, "agent1", c2)
		res, err := e.AuthorizeWith(b2, gatefix.OtherAction(t, 1))
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, h2, res.CommitmentHash)
		require.Zero(t, res.Path, "nothing of another decision's entry may be reported")
		require.Nil(t, res.Authorization)
	})
}

// A used nonce: the stored Authorization is returned only to the holder of the
// committed bytes of the same commitment.
func TestRetryRule(t *testing.T) {
	t.Run("same envelope and bytes get the stored bytes with ErrNonceUsed", func(t *testing.T) {
		e, _, b, h := happy(t)
		first, err := e.Authorize(b)
		require.NoError(t, err)
		for range 3 {
			again, err := e.Authorize(b)
			require.ErrorIs(t, err, gate.ErrNonceUsed)
			require.Equal(t, first.Authorization, again.Authorization)
			require.Equal(t, first.Path, again.Path)
			require.Equal(t, h, again.CommitmentHash)
		}
	})
	t.Run("the retry needs no payload or chain", func(t *testing.T) {
		e, _, b, _ := happy(t)
		first, err := e.Authorize(b)
		require.NoError(t, err)
		e.Anchors.Fail(errors.New("down"))
		again, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, first.Authorization, again.Authorization)
	})
	t.Run("other bytes of the same commitment get ErrActionMismatch and nothing stored", func(t *testing.T) {
		e, c, b, _ := happy(t)
		first, err := e.Authorize(b)
		require.NoError(t, err)
		before, err := e.Entry(c)
		require.NoError(t, err)
		other := gatefix.Action(t)
		other[0] ^= 1
		res, err := e.AuthorizeWith(b, other)
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		require.NotErrorIs(t, err, gate.ErrNonceUsed)
		require.Nil(t, res.Authorization)
		require.Zero(t, res.Path)
		after, err := e.Entry(c)
		require.NoError(t, err)
		require.Equal(t, before, after)
		again, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, first.Authorization, again.Authorization)
	})
	t.Run("empty bytes on a used nonce", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		res, err := e.AuthorizeWith(b, nil)
		require.ErrorIs(t, err, commitment.ErrActionSize)
		require.Nil(t, res.Authorization)
	})
	t.Run("another commitment on the nonce never gets the stored Authorization", func(t *testing.T) {
		for name, action := range map[string][]byte{
			"its own bytes":       gatefix.OtherAction(t, 1),
			"the first one bytes": nil,
		} {
			e, _, b, h := happy(t)
			_, err := e.Authorize(b)
			require.NoError(t, err)
			c2 := gatefix.Variant(t, gatefix.Template(t), 1)
			e.StageDA(c2, gatefix.Blob(t))
			b2, h2 := gatefix.Sign(t, "agent1", c2)
			if action == nil {
				action = gatefix.Action(t)
			}
			res, err := e.AuthorizeWith(b2, action)
			require.Error(t, err, name)
			require.True(t, errors.Is(err, gate.ErrNonceUsed) || errors.Is(err, commitment.ErrActionMismatch), "%s: %v", name, err)
			require.Nil(t, res.Authorization, name)
			require.Zero(t, res.Path, name)
			require.NotEqual(t, h, h2)
			require.NotContains(t, err.Error(), string(h[:]))
		}
	})
	t.Run("a lost consume race is answered under the same rule", func(t *testing.T) {
		e, c, b, h := happy(t, gatefix.WithFaultyRegistry())
		stored := signedToken(t, h[:], c.Action.Hash, c.ValidUntil)
		e.Faulty.Before("Consume", func() {
			require.NoError(t, e.Reg.Consume(context.Background(), registry.Entry{
				Key: gatefix.KeyOf(c), CommitmentHash: h, ActionHash: commitment.Hash(c.Action.Hash),
				Path: registry.PathArchive, AuthorizedAt: gatefix.Now, ValidUntil: c.ValidUntil, Authorization: stored,
			}, 60))
		})
		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, stored, res.Authorization)
		require.Equal(t, registry.PathArchive, res.Path)
	})
	t.Run("a lost consume race against another commitment reports nothing", func(t *testing.T) {
		e, c, b, h := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.Before("Consume", func() {
			require.NoError(t, e.Reg.Consume(context.Background(), registry.Entry{
				Key: gatefix.KeyOf(c), CommitmentHash: commitment.Hash{9}, ActionHash: commitment.Hash{8},
				Path: registry.PathArchive, AuthorizedAt: gatefix.Now, ValidUntil: c.ValidUntil, Authorization: []byte("other"),
			}, 60))
		})
		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Nil(t, res.Authorization)
		require.Zero(t, res.Path)
		require.Equal(t, h, res.CommitmentHash)
	})
}

// A stored action hash that differs while the commitment's own check passes
// is a gate bug or a damaged registry: refuse, tell the operator, return
// nothing of the entry.
func TestStoredActionHashMismatch(t *testing.T) {
	corrupt := func(c *commitment.Commitment, h commitment.Hash) registry.Entry {
		bad := commitment.Hash(c.Action.Hash)
		bad[0] ^= 0xff
		return registry.Entry{
			Key: gatefix.KeyOf(c), CommitmentHash: h, ActionHash: bad, Path: registry.PathDA,
			AuthorizedAt: gatefix.Now, ValidUntil: c.ValidUntil,
			Authorization: signedToken(t, h[:], bad[:], c.ValidUntil),
		}
	}
	undecodable := func(c *commitment.Commitment, h commitment.Hash) registry.Entry {
		return registry.Entry{
			Key: gatefix.KeyOf(c), CommitmentHash: h, ActionHash: commitment.Hash(c.Action.Hash), Path: registry.PathDA,
			AuthorizedAt: gatefix.Now, ValidUntil: c.ValidUntil, Authorization: []byte("older gate output"),
		}
	}
	check := func(t *testing.T, e *gatefix.Env, h commitment.Hash, res gate.Result, err error) {
		t.Helper()
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		require.Nil(t, res.Authorization)
		require.Zero(t, res.Path)
		recs := e.Logs.Records(slog.LevelError)
		require.NotEmpty(t, recs, "no error-level log")
		require.Contains(t, e.Metrics.Mismatches(), h, "no metric event")
	}
	t.Run("seen by the first nonce read", func(t *testing.T) {
		e, c, b, h := happy(t)
		require.NoError(t, e.Reg.Consume(context.Background(), corrupt(c, h), 60))
		res, err := e.Authorize(b)
		check(t, e, h, res, err)
	})
	t.Run("seen after losing the consume race", func(t *testing.T) {
		e, c, b, h := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.Before("Consume", func() {
			require.NoError(t, e.Reg.Consume(context.Background(), corrupt(c, h), 60))
		})
		res, err := e.Authorize(b)
		check(t, e, h, res, err)
	})
	t.Run("undecodable stored token fails closed", func(t *testing.T) {
		for name, tok := range map[string][]byte{
			"text":      []byte("older gate output"),
			"truncated": signedToken(t, make([]byte, 32), make([]byte, 32), 1)[:20],
		} {
			t.Run(name, func(t *testing.T) {
				e, c, b, h := happy(t)
				en := undecodable(c, h)
				en.Authorization = tok
				require.NoError(t, e.Reg.Consume(context.Background(), en, 60))
				res, err := e.Authorize(b)
				require.Error(t, err)
				require.NotErrorIs(t, err, gate.ErrNonceUsed)
				require.Nil(t, res.Authorization)
				require.Zero(t, res.Path)
				require.NotEmpty(t, e.Logs.Records(slog.LevelError))
			})
		}
	})
	t.Run("a healthy entry logs nothing at error level", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		_, err = e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Empty(t, e.Logs.Records(slog.LevelError))
		require.Empty(t, e.Metrics.Mismatches())
	})
	t.Run("Record does not hand out the entry either", func(t *testing.T) {
		e, c, b, h := happy(t)
		require.NoError(t, e.Reg.Consume(context.Background(), corrupt(c, h), 60))
		_, err := e.Record(b, "ref-1")
		require.NoError(t, err, "the receipt depends on the commitment hash only")
	})
}

func TestNonceConsumedOnceConcurrently(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, _, b, _ := happy(t, gatefix.WithRegistry(open(t)))
			const n = 64
			var wg sync.WaitGroup
			var start sync.WaitGroup
			start.Add(1)
			var ok, used atomic.Int32
			results := make([][]byte, n)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					start.Wait()
					res, err := e.Authorize(append([]byte(nil), b...))
					results[i] = res.Authorization
					switch {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, gate.ErrNonceUsed):
						used.Add(1)
					default:
						assert.Fail(t, "unexpected error", "%v", err)
					}
				}()
			}
			start.Done()
			wg.Wait()
			require.EqualValues(t, 1, ok.Load())
			require.EqualValues(t, n-1, used.Load())
			for i := range results {
				require.NotEmpty(t, results[i])
				require.Equal(t, results[0], results[i], "every caller sees the same Authorization bytes")
			}
		})
	}
}

func TestConcurrentDistinctNoncesAllAuthorized(t *testing.T) {
	e, _, _, _ := happy(t)
	const n = 16
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := range n {
		c := gatefix.Fresh(gatefix.Template(t), byte(i))
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.Authorize(b)
			if assert.NoError(t, err) && len(res.Authorization) > 0 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, n, ok.Load())
}

// Many authorizers, pruners and retries together keep every invariant.
func TestAuthorizeAndPruneTogether(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c0, _, _ := happy(t, gatefix.WithRegistry(open(t)))
			stop := make(chan struct{})
			var bg sync.WaitGroup
			bg.Add(1)
			go func() {
				defer bg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_, _ = e.Gate.Prune(context.Background())
					}
				}
			}()
			var wg sync.WaitGroup
			for i := range 24 {
				c := gatefix.Fresh(c0, byte(i+1))
				e.StageDA(c, gatefix.Blob(t))
				b, _ := gatefix.Sign(t, "agent1", c)
				wg.Add(1)
				go func() {
					defer wg.Done()
					first, err := e.Authorize(b)
					assert.NoError(t, err)
					again, err := e.Authorize(b)
					assert.ErrorIs(t, err, gate.ErrNonceUsed)
					assert.Equal(t, first.Authorization, again.Authorization)
				}()
			}
			wg.Wait()
			close(stop)
			bg.Wait()
		})
	}
}

func TestPrune(t *testing.T) {
	e, a, ba, _ := happy(t)
	_, err := e.Authorize(ba)
	require.NoError(t, err)

	n, err := e.Gate.Prune(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "early prune")

	later := uint64(1791000900 + 3600 + 100)
	e.Clock.Set(later)
	cc := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 3), later-10, later+890)
	e.StageDA(cc, gatefix.Blob(t))
	bc, _ := gatefix.Sign(t, "agent1", cc)
	_, err = e.Authorize(bc)
	require.NoError(t, err)
	n, err = e.Gate.Prune(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "every entry is prunable once its decision cannot pass the time check")
	_, err = e.Entry(a)
	require.ErrorIs(t, err, registry.ErrNotFound)
	_, err = e.Authorize(ba)
	require.ErrorIs(t, err, commitment.ErrExpired, "replay after prune")
}

func TestRegistryFailures(t *testing.T) {
	t.Run("consume fails: nothing leaves, nonce free, retry gets a fresh Authorization", func(t *testing.T) {
		cause := errors.New("disk full")
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Consume", cause)
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrRegistryUnavailable)
		require.ErrorIs(t, err, cause)
		require.Nil(t, res.Authorization, "an Authorization left the gate before the mark was durable")
		res, err = e.Authorize(b)
		require.NoError(t, err, "retry")
		require.NotEmpty(t, res.Authorization)
	})
	t.Run("nonce read fails", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Get", errors.New("io"))
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrRegistryUnavailable)
		require.Nil(t, res.Authorization)
	})
	t.Run("below the watermark inside the transaction", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Consume", registry.ErrBelowWatermark)
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrClockRegression)
		require.Nil(t, res.Authorization)
	})
	t.Run("pruned window inside the transaction", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Consume", registry.ErrPrunedWindow)
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrClockRegression)
		require.Nil(t, res.Authorization)
	})
}

// A broken signer consumes nothing: the Authorization is signed before the
// nonce is marked.
func TestBrokenSignerConsumesNothing(t *testing.T) {
	for name, mode := range map[string]signerMode{"panic": signPanic, "hang": signHang, "bad signature": signZero} {
		t.Run(name, func(t *testing.T) {
			s := newModalSigner(t, mode)
			e, c, b, _ := happy(t, gatefix.WithSigner(s), gatefix.WithConfig(func(cfg *gate.Config) {
				cfg.SignTimeout = 20 * time.Millisecond
			}))
			res, err := authorizeWithin(t, e, b, 30*time.Second, s)
			require.Error(t, err)
			require.Nil(t, res.Authorization)
			e.RequireUntouched(c)

			s.mode.Store(int32(signOK))
			res, err = e.Authorize(b)
			require.NoError(t, err, "a working signer must be able to authorize the same decision")
			require.NotEmpty(t, res.Authorization)
		})
	}
	t.Run("signer error", func(t *testing.T) {
		inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
		require.NoError(t, err)
		bad := &flakySigner{inner: inner}
		bad.fail.Store(true)
		e, c, b, _ := happy(t, gatefix.WithSigner(bad))
		_, err = e.Authorize(b)
		require.Error(t, err)
		e.RequireUntouched(c)
		bad.fail.Store(false)
		_, err = e.Authorize(b)
		require.NoError(t, err)
	})
}

type flakySigner struct {
	inner gate.Signer
	fail  atomic.Bool
}

func (s *flakySigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *flakySigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("hsm unavailable")
	}
	return s.inner.Sign(ctx, msg)
}

// spyRegistry reports what the gate hands to the registry and when.
type spyRegistry struct {
	registry.Registry
	onConsume func(registry.Entry)
}

func (s *spyRegistry) Claim() (func(), error) {
	if c, ok := s.Registry.(registry.Claimer); ok {
		return c.Claim()
	}
	return func() {}, nil
}

func (s *spyRegistry) Consume(ctx context.Context, e registry.Entry, tol uint64) error {
	if s.onConsume != nil {
		s.onConsume(e)
	}
	return s.Registry.Consume(ctx, e, tol)
}

func TestSignBeforeConsume(t *testing.T) {
	var signed atomic.Int32
	inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
	require.NoError(t, err)
	counting := &countingSigner{inner: inner, n: &signed}
	spy := &spyRegistry{Registry: gatefix.MemReg(t, gatefix.Epoch)}
	var got registry.Entry
	spy.onConsume = func(e registry.Entry) {
		require.EqualValues(t, 1, signed.Load(), "the nonce was marked before the Authorization was signed")
		got = e
	}
	e, c, b, h := happy(t, gatefix.WithSigner(counting), gatefix.WithRegistry(spy))
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.Equal(t, res.Authorization, got.Authorization, "the stored bytes are the returned bytes")
	require.Equal(t, h, got.CommitmentHash)
	require.Equal(t, string(c.Action.Hash), string(got.ActionHash[:]))
	gatefix.CheckAuthorization(t, got.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
	require.EqualValues(t, 1, signed.Load(), "one signature per decision")
	_, err = e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.EqualValues(t, 1, signed.Load(), "the retry reuses the stored Authorization")
}

type countingSigner struct {
	inner gate.Signer
	n     *atomic.Int32
}

func (s *countingSigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *countingSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	s.n.Add(1)
	return s.inner.Sign(ctx, msg)
}

func TestAuthorizeMetricsOnRejection(t *testing.T) {
	e, _, b, h := happy(t)
	e.Anchors.Fail(errors.New("down"))
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	ev := e.Metrics.Events()
	require.Len(t, ev, 1)
	require.False(t, ev[0].Authorized)
	require.ErrorIs(t, ev[0].Err, gate.ErrChainUnavailable)
	require.Equal(t, h, ev[0].CommitmentHash)
}

// The gate authorizes and never executes: the old entry points and the
// state-machine operations are gone.
func TestExecutionSurfaceIsGone(t *testing.T) {
	e := gatefix.New(t)
	var g any = e.Gate
	_, ok := g.(interface {
		Admit(context.Context, []byte, []byte) (gate.Result, error)
	})
	require.False(t, ok, "Admit")
	_, ok = g.(interface {
		Reconcile(context.Context) (struct{ Executed, Rejected, StillUnknown int }, error)
	})
	require.False(t, ok, "Reconcile")
	_, ok = g.(interface {
		Authorize(context.Context, []byte, []byte) (gate.Result, error)
	})
	require.True(t, ok, "Authorize")
	_, ok = g.(interface {
		Record(context.Context, []byte, string, ed25519.PublicKey, []byte) ([]byte, error)
	})
	require.True(t, ok, "Record")
}
