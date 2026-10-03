package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// happy builds an environment where the template commitment passes every
// stage with the payload on the DA path.
func happy(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
	t.Helper()
	e := gatefix.New(t, opts...)
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, h := gatefix.Sign(t, "agent1", c)
	return e, c, b, h
}

func TestAdmitHappyPathDA(t *testing.T) {
	e, c, b, h := happy(t)
	res, err := e.Admit(b)
	require.NoError(t, err, "Admit")
	require.Equalf(t, registry.StateExecuted, res.State, "result %+v", res)
	require.Equalf(t, registry.PathDA, res.Path, "result %+v", res)
	require.Equalf(t, h, res.CommitmentHash, "result %+v", res)
	gatefix.CheckReceipt(t, res, h, gatefix.RailRef, commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), gatefix.Now)
	require.EqualValuesf(t, 1, e.Exec.Calls(), "calls exec=%d da=%d archive=%d", e.Exec.Calls(), e.DA.Fetches(), e.Archive.Fetches())
	require.EqualValuesf(t, 1, e.DA.Fetches(), "calls exec=%d da=%d archive=%d", e.Exec.Calls(), e.DA.Fetches(), e.Archive.Fetches())
	require.EqualValuesf(t, 0, e.Archive.Fetches(), "calls exec=%d da=%d archive=%d", e.Exec.Calls(), e.DA.Fetches(), e.Archive.Fetches())
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, registry.StateExecuted, ent.State)
	require.Equal(t, registry.PathDA, ent.Path)
	require.Equal(t, gatefix.RailRef, ent.RailRef)
	require.Equal(t, h, ent.CommitmentHash)
	require.Equal(t, c.ValidUntil, ent.ValidUntil)
	require.EqualValues(t, gatefix.Now, ent.ReservedAt)
	require.Equal(t, res.Receipt, ent.Receipt)
	require.Len(t, ent.History, 1)
	require.Equal(t, registry.Resolution{Source: registry.SourceRail, By: "gate", At: gatefix.Now, PrevState: registry.StateReserved}, ent.History[0])
	ev := e.Metrics.Events()
	require.Len(t, ev, 1)
	require.NoError(t, ev[0].Err)
	require.Equal(t, registry.PathDA, ev[0].Path)
	require.Equal(t, registry.StateExecuted, ev[0].State)
	require.Equal(t, commitment.DACelestiaBlob, ev[0].DA)
}

func TestAdmitHappyPathFibre(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Admit(b)
	require.NoError(t, err, "Admit")
	require.Equalf(t, registry.StateExecuted, res.State, "result %+v", res)
	require.Equalf(t, registry.PathDA, res.Path, "result %+v", res)
	gatefix.CheckReceipt(t, res, h, gatefix.RailRef, commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
}

func TestExecRequestFields(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline *uint64
		notAfter uint64
	}{
		{"valid_until", nil, 1791000900 - 30},
		{"deadline", ptr(uint64(1791000600)), 1791000600 - 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			c.Constraints.Deadline = tc.deadline
			e.StageDA(c, gatefix.Blob(t))
			b, h := gatefix.Sign(t, "agent1", c)
			_, err := e.Admit(b)
			require.NoError(t, err)
			reqs := e.Exec.Requests()
			require.Lenf(t, reqs, 1, "%d requests", len(reqs))
			r := reqs[0]
			wantID, err := commitment.ClientOrderID(commitment.RailIBKR, h)
			require.NoError(t, err)
			require.Equalf(t, h, r.CommitmentHash, "hash/client order id: %x %q", r.CommitmentHash, r.ClientOrderID)
			require.Equalf(t, wantID, r.ClientOrderID, "hash/client order id: %x %q", r.CommitmentHash, r.ClientOrderID)
			require.Equal(t, *c.Action.IBKROrder, r.Order)
			require.True(t, r.NotAfter.Equal(time.Unix(int64(tc.notAfter), 0)))
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestInvariantRejections: every row breaks exactly one check and must give
// its sentinel, with zero executor calls and an untouched nonce.
func TestInvariantRejections(t *testing.T) {
	forged := func(t *testing.T, c *commitment.Commitment, signer string) []byte {
		h, err := commitment.HashOf(c)
		require.NoError(t, err)
		sig := ed25519.Sign(gatefix.Key(t, signer), commitment.SigningMessage(h))
		b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: sig})
		require.NoError(t, err)
		return b
	}
	type row struct {
		name  string
		want  error
		build func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte)
	}
	mutateOrder := func(f func(o *commitment.IBKROrderV0)) func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
		return func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t)
			e.Gate.SetMutateOrder(f)
			return e, c, b
		}
	}
	signedVariant := func(f func(c *commitment.Commitment)) func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
		return func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			c := gatefix.Template(t)
			f(c)
			e := gatefix.New(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}
	}
	rows := []row{
		// Agent signature and key roles.
		{"inv1 signature by another key", commitment.ErrSignatureInvalid, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, _, _ := happy(t)
			return e, c, forged(t, c, "agent2")
		}},
		{"inv1 zero signature", commitment.ErrSignatureInvalid, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, _, _ := happy(t)
			b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
			require.NoError(t, err)
			return e, c, b
		}},
		{"inv1 small-order agent key", commitment.ErrInvalidPublicKey, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, _, _ := happy(t)
			c.AgentPubKey = append([]byte{1}, make([]byte, 31)...)
			b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
			require.NoError(t, err)
			return e, c, b
		}},
		{"inv1 agent not in allowlist", gate.ErrAgentNotAllowed, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"someone-else": gatefix.Pub(t, "agent2")}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv1 allowlist maps id to another key", gate.ErrAgentKeyMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"dca-agent-1": gatefix.Pub(t, "agent2")}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv1 agent key is the gate signer key", gate.ErrAgentKeyIsGateKey, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.WithKey(t, gatefix.Template(t), "gate1")
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "gate1", c)
			return e, c, b
		}},
		{"inv1 agent key is another configured gate key", gate.ErrAgentKeyIsGateKey, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			var k [32]byte
			copy(k[:], gatefix.Pub(t, "agent2"))
			e := gatefix.New(t,
				gatefix.WithAllowlist(map[string][]byte{"dca-agent-1": gatefix.Pub(t, "agent1")}),
				gatefix.WithConfig(func(c *gate.Config) { c.OtherGateKeys = [][32]byte{k} }))
			c := gatefix.WithKey(t, gatefix.Template(t), "agent2")
			c.AgentID = "dca-agent-2"
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent2", c)
			return e, c, b
		}},
		// Payload availability and integrity.
		{"inv2 no anchor", gate.ErrAnchorNotFound, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 payload in neither DA nor archive", gate.ErrPayloadUnavailable, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 payload swapped after the fact", commitment.ErrPayloadHashMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.BlobY(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 truncated payload", commitment.ErrPayloadSizeMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t)[:100])
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 oversized payload", commitment.ErrPayloadSizeMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			e.StageDA(c, append(gatefix.Blob(t), 0))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 anchor X, sign hash of Y, archive path", gate.ErrDACommitmentMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			y := gatefix.BlobY(t)
			sum := sha256sum(y)
			c.CiphertextHash = sum[:]
			routeArchive(e, c)
			e.Archive.Put(c.PayloadRef, y)
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv2 fibre payload only in archive", gate.ErrArchiveRecomputeUnsupported, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.FibreTemplate(t)
			routeArchive(e, c)
			e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		// Action within the committed action and constraints.
		{"inv3 qty differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.Qty++ })},
		{"inv3 price differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { p := *o.LimitPrice + 1; o.LimitPrice = &p })},
		{"inv3 side differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.Side = commitment.SideSell })},
		{"inv3 account differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.Account = "DU7654321" })},
		{"inv3 asset differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.ConID++ })},
		{"inv3 currency differs", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.Currency = "EUR" })},
		{"inv3 market instead of limit", commitment.ErrActionMismatch, mutateOrder(func(o *commitment.IBKROrderV0) { o.OrderType = commitment.OrderMarket; o.LimitPrice = nil })},
		{"inv3 notional above max_notional", commitment.ErrNotionalExceeded, signedVariant(func(c *commitment.Commitment) { c.Action.IBKROrder.Qty *= 2 })},
		{"inv3 price outside price_bound", commitment.ErrPriceBound, signedVariant(func(c *commitment.Commitment) {
			c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice - 1)
		})},
		{"inv3 order account differs from scope account", commitment.ErrAccountMismatch, signedVariant(func(c *commitment.Commitment) { c.Action.IBKROrder.Account = "DU7654321" })},
		// Validity window and retention.
		{"inv4 expired", commitment.ErrExpired, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t, gatefix.WithNow(1791000900))
			return e, c, b
		}},
		{"inv4 expiry minus skew reached", commitment.ErrExpired, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t, gatefix.WithNow(1791000900-30))
			return e, c, b
		}},
		{"inv4 not yet valid", commitment.ErrNotYetValid, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t, gatefix.WithNow(1791000000-31))
			return e, c, b
		}},
		{"inv4 deadline passed", commitment.ErrExpired, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			c := gatefix.Template(t)
			c.Constraints.Deadline = ptr(uint64(1791000100))
			e := gatefix.New(t, gatefix.WithNow(1791000100))
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv4 ttl above maximum", commitment.ErrTTLTooLong, signedVariant(func(c *commitment.Commitment) { c.ValidUntil = c.IssuedAt + 3601 })},
		{"inv4 expires while the payload is fetched", commitment.ErrExpired, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t)
			e.DA.OnFetch(func() { e.Clock.Advance(time.Hour) })
			return e, c, b
		}},
		{"inv4 signed before the anchor", commitment.ErrIssuedBeforeAnchor, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.Template(t)
			e.StageChain(c, c.IssuedAt+31, c.IssuedAt+31)
			e.DA.Put(c.PayloadRef, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		{"inv4 retention at anchor height unreadable", gate.ErrRetentionUnavailable, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			e.Chain.FailHistorical(errors.New("pruned state"))
			c := gatefix.FibreTemplate(t)
			e.StageDA(c, gatefix.FibreBlob())
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
		// Nonce and registry creation time.
		{"inv5 commitment older than the registry", gate.ErrBeforeRegistryEpoch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(gatefix.MemReg(t, 1791000000-10)))
			return e, c, b
		}},
		// Canonical encoding; the hash is not a field.
		{"inv6 trailing byte", commitment.ErrTrailingData, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, b, _ := happy(t)
			return e, c, append(b, 0)
		}},
		{"inv6 not CBOR", commitment.ErrMalformed, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e, c, _, _ := happy(t)
			return e, c, []byte{0xff, 0xff}
		}},
		{"inv6 foreign gate", commitment.ErrScopeMismatch, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{GateID: "gate-paper-2", Rail: commitment.RailIBKR, Account: gatefix.Account}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e, c, b := r.build(t)
			_, err := e.Admit(b)
			e.RequireRejected(c, err, r.want)
		})
	}
}

// TestStageOrder: an earlier stage's sentinel must win over a later one.
func TestStageOrder(t *testing.T) {
	t.Run("signature before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
		require.NoError(t, err)
		_, err = e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("registry epoch before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithRegistry(gatefix.MemReg(t, 1791000000-10)), gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrBeforeRegistryEpoch)
	})
	t.Run("gate key role before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.WithKey(t, gatefix.Template(t), "gate1")
		b, _ := gatefix.Sign(t, "gate1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAgentKeyIsGateKey)
	})
	t.Run("allowlist before anchor", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAgentNotAllowed)
	})
	t.Run("nonce peek before anchor lookup", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		e.Anchors.Fail(errors.New("down"))
		_, err = e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
	})
	t.Run("anchor before payload", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		e.DA.Put(c.PayloadRef, gatefix.BlobY(t))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAnchorNotFound)
		require.EqualValues(t, 0, e.DA.Fetches(), "payload fetched before the anchor was found")
	})
	t.Run("signed-before-anchor before payload", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.StageChain(c, c.IssuedAt+31, c.IssuedAt+31)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrIssuedBeforeAnchor)
		require.EqualValues(t, 0, e.DA.Fetches()+e.Archive.Fetches(), "payload fetched after the anchor time check failed")
	})
	t.Run("order check before nonce peek", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		e.Gate.SetMutateOrder(func(o *commitment.IBKROrderV0) { o.Qty++ })
		_, err = e.Admit(b)
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
	})
}

func TestBoundaryExpiryAccepted(t *testing.T) {
	for name, now := range map[string]uint64{
		"one second before expiry minus skew": 1791000900 - 31,
		"issued_at minus skew":                1791000000 - 30,
	} {
		t.Run(name, func(t *testing.T) {
			e, _, b, _ := happy(t, gatefix.WithNow(now))
			_, err := e.Admit(b)
			require.NoErrorf(t, err, "Admit at %d", now)
		})
	}
}

func TestClockAndChainErrors(t *testing.T) {
	t.Run("clock stepped back beyond tolerance", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		c2 := gatefix.Fresh(gatefix.Template(t), 2)
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent1", c2)
		e.Clock.Set(gatefix.Now - 61)
		_, err = e.Admit(b2)
		require.ErrorIs(t, err, gate.ErrClockRegression)
		_, gerr := e.Entry(c2)
		require.ErrorIs(t, gerr, registry.ErrNotFound, "nonce touched")
		e.Clock.Set(gatefix.Now - 60)
		_, err = e.Admit(b2)
		require.NoError(t, err, "within tolerance")
	})
	t.Run("clock reads zero", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Clock.Set(0)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrClockRegression)
	})
	t.Run("latest retention unreadable", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Chain.FailLatest(errors.New("node down"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("latest retention zero is invalid params", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Chain.SetLatest(0)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrInvalidParams)
	})
	t.Run("header source error", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Headers.Fail(errors.New("node down"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("anchor source error", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Anchors.Fail(errors.New("node down"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("no header for the height", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.Anchors.Set(c.PayloadRef, gate.Anchor{Height: c.PayloadRef.Height})
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAnchorNotFound)
	})
	t.Run("cancelled context writes nothing", func(t *testing.T) {
		e, c, b, _ := happy(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.Gate.Admit(ctx, b)
		e.RequireRejected(c, err, context.Canceled)
	})
}

func TestAdmitEnvelopeBytesOnly(t *testing.T) {
	// The only admission method takes bytes. Calling it with nil must fail
	// closed, not panic.
	e := gatefix.New(t)
	for _, b := range [][]byte{nil, {}, {0xa0}} {
		_, err := e.Admit(b)
		require.Errorf(t, err, "admitted %x", b)
	}
	require.EqualValues(t, 0, e.Exec.Calls(), "executor called")
}

func TestNewValidation(t *testing.T) {
	t.Run("executor rail differs from scope rail", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithDeps(func(d *gate.Deps) {
			d.Executor = gatetest.NewExecutor(2)
		}))
		require.Error(t, err, "New accepted a rail mismatch")
	})
	t.Run("gate key in the allowlist", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithAllowlist(map[string][]byte{"gate": gatefix.Pub(t, "gate1")}))
		require.ErrorIs(t, err, gate.ErrAgentKeyIsGateKey)
	})
	t.Run("other gate key in the allowlist", func(t *testing.T) {
		var k [32]byte
		copy(k[:], gatefix.Pub(t, "agent1"))
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.OtherGateKeys = [][32]byte{k} }))
		require.ErrorIs(t, err, gate.ErrAgentKeyIsGateKey)
	})
	t.Run("small-order gate key", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) {
			c.OtherGateKeys = [][32]byte{{1}}
		}))
		require.ErrorIs(t, err, commitment.ErrInvalidPublicKey)
	})
	t.Run("skew above 300", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.SkewS = 301 }))
		require.Error(t, err, "accepted skew 301")
	})
	t.Run("prune grace not above clock tolerance", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.PruneGrace = c.ClockTolerance }))
		require.Error(t, err, "accepted prune grace equal to clock tolerance")
	})
}

func TestReplayAcrossAgentsAndNonces(t *testing.T) {
	t.Run("same nonce, other agent key is a different registry key", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		c2 := gatefix.WithKey(t, gatefix.Template(t), "agent2")
		c2.AgentID = "dca-agent-2"
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent2", c2)
		_, err = e.Admit(b2)
		require.NoError(t, err, "second agent with the same nonce")
		require.EqualValuesf(t, 2, e.Exec.Calls(), "exec calls %d", e.Exec.Calls())
	})
	t.Run("same nonce, different action, same agent", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		c2 := gatefix.Template(t)
		c2.Action.IBKROrder.Qty--
		e.StageDA(c2, gatefix.Blob(t))
		b2, h2 := gatefix.Sign(t, "agent1", c2)
		res, err := e.Admit(b2)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, 1, e.Exec.Calls())
		require.Equal(t, h2, res.CommitmentHash)
		require.Zero(t, res.State, "the state of another decision must not be reported as this one's")
		require.Zero(t, res.Path)
		require.Nil(t, res.Receipt)
	})
	t.Run("replay returns the stored receipt with ErrNonceUsed", func(t *testing.T) {
		e, _, b, _ := happy(t)
		first, err := e.Admit(b)
		require.NoError(t, err)
		again, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equalf(t, registry.StateExecuted, again.State, "replay result %+v", again)
		require.Equalf(t, first.Receipt, again.Receipt, "replay result %+v", again)
		require.EqualValuesf(t, 1, e.Exec.Calls(), "exec calls %d", e.Exec.Calls())
	})
}

func TestPrune(t *testing.T) {
	e, a, ba, _ := happy(t)
	_, err := e.Admit(ba)
	require.NoError(t, err)
	// B ends in Unknown and must never be pruned.
	cb := gatefix.Fresh(gatefix.Template(t), 2)
	e.StageDA(cb, gatefix.Blob(t))
	bb, _ := gatefix.Sign(t, "agent1", cb)
	e.Exec.SetError(errors.New("rail down"))
	_, err = e.Admit(bb)
	require.ErrorIs(t, err, gate.ErrExecutionUnknown)
	e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: gatefix.RailRef})

	n, err := e.Gate.Prune(context.Background())
	require.NoErrorf(t, err, "early prune removed %d, err", n)
	require.EqualValuesf(t, 0, n, "early prune removed %d, err %v", n, err)

	later := uint64(1791000900 + 3600 + 100)
	e.Clock.Set(later)
	cc := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 3), later-10, later+890)
	e.StageDA(cc, gatefix.Blob(t))
	bc, _ := gatefix.Sign(t, "agent1", cc)
	_, err = e.Admit(bc)
	require.NoError(t, err, "admit at the later time")
	n, err = e.Gate.Prune(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	_, err = e.Entry(a)
	require.ErrorIs(t, err, registry.ErrNotFound, "executed entry not pruned")
	ent, err := e.Entry(cb)
	require.NoErrorf(t, err, "unknown entry must stay: %+v", ent)
	require.Equalf(t, registry.StateUnknown, ent.State, "unknown entry must stay: %+v %v", ent, err)
	_, err = e.Admit(ba)
	require.ErrorIs(t, err, commitment.ErrExpired, "replay after prune")
	require.EqualValuesf(t, 3, e.Exec.Calls(), "exec calls %d", e.Exec.Calls())
}
