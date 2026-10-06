package gate_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
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

// TestInvariantRejections: every row breaks exactly one check and must give
// its sentinel, and an untouched nonce.
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
		// The committed action type must be one the gate is configured for.
		{"inv3 action type not configured", commitment.ErrActionTypeNotAllowed, func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
			e := gatefix.New(t)
			c := gatefix.WithAction(t, gatefix.Template(t), "application/json", gatefix.Action(t))
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
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
			e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{GateID: "gate-paper-2", ActionTypes: []string{gatefix.ActionType}}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e, c, b := r.build(t)
			res, err := e.Authorize(b)
			e.RequireRejected(c, err, r.want)
			require.Nil(t, res.Authorization, "a rejection must not carry an Authorization")
		})
	}
}

// TestActionBytesRejections: the bytes presented with the envelope must be
// exactly the committed ones. Each row presents other bytes for a commitment
// that is otherwise valid; nothing is authorized and the nonce stays free.
func TestActionBytesRejections(t *testing.T) {
	flip := func(i int) func([]byte) []byte {
		return func(a []byte) []byte {
			b := bytes.Clone(a)
			if i < 0 {
				i = len(b) + i
			}
			b[i] ^= 1
			return b
		}
	}
	rows := []struct {
		name   string
		want   error
		action func(committed []byte) []byte
	}{
		{"first byte flipped", commitment.ErrActionMismatch, flip(0)},
		{"last byte flipped", commitment.ErrActionMismatch, flip(-1)},
		{"truncated by one byte", commitment.ErrActionMismatch, func(a []byte) []byte { return a[:len(a)-1] }},
		{"one byte appended", commitment.ErrActionMismatch, func(a []byte) []byte { return append(bytes.Clone(a), 0) }},
		{"a single zero byte", commitment.ErrActionMismatch, func([]byte) []byte { return []byte{0} }},
		{"empty", commitment.ErrActionSize, func([]byte) []byte { return nil }},
		{"empty non-nil", commitment.ErrActionSize, func([]byte) []byte { return []byte{} }},
		{"above the size limit", commitment.ErrActionSize, func([]byte) []byte { return make([]byte, commitment.MaxActionSize+1) }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e, c, b, _ := happy(t)
			res, err := e.AuthorizeWith(b, r.action(gatefix.Action(t)))
			e.RequireRejected(c, err, r.want)
			require.Nil(t, res.Authorization, "a rejection must not carry an Authorization")
		})
	}
	t.Run("the committed bytes are admitted", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.NoError(t, err)
	})
	t.Run("the same bytes committed under another allowed type", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{
			GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, "application/json"},
		}))
		c := gatefix.WithAction(t, gatefix.Template(t), "application/json", gatefix.Action(t))
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.NoError(t, err, "the type is part of the commitment, and it matches")
	})
	t.Run("bytes committed under the other type are another action", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{
			GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, "application/json"},
		}))
		c := gatefix.Template(t)
		c.Action.Type = "application/json" // the hash was computed under another type
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.AuthorizeWith(b, gatefix.Action(t))
		e.RequireRejected(c, err, commitment.ErrActionMismatch)
	})
}

// TestStageOrder: an earlier stage's sentinel must win over a later one.
func TestStageOrder(t *testing.T) {
	t.Run("signature before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
		require.NoError(t, err)
		_, err = e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("registry epoch before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithRegistry(gatefix.MemReg(t, 1791000000-10)), gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrBeforeRegistryEpoch)
	})
	t.Run("gate key role before allowlist", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.WithKey(t, gatefix.Template(t), "gate1")
		b, _ := gatefix.Sign(t, "gate1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrAgentKeyIsGateKey)
	})
	t.Run("allowlist before anchor", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"x": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrAgentNotAllowed)
	})
	t.Run("nonce peek before anchor lookup", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		e.Anchors.Fail(errors.New("down"))
		_, err = e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
	})
	t.Run("anchor before payload", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		b, _ := gatefix.Sign(t, "agent1", c)
		e.DA.Put(c.PayloadRef, gatefix.BlobY(t))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrAnchorNotFound)
		require.EqualValues(t, 0, e.DA.Fetches(), "payload fetched before the anchor was found")
	})
	t.Run("signed-before-anchor before payload", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.StageChain(c, c.IssuedAt+31, c.IssuedAt+31)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrIssuedBeforeAnchor)
		require.EqualValues(t, 0, e.DA.Fetches()+e.Archive.Fetches(), "payload fetched after the anchor time check failed")
	})
	t.Run("action check before nonce peek", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		changed := gatefix.Action(t)
		changed[0] ^= 1
		_, err = e.AuthorizeWith(b, changed)
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
			_, err := e.Authorize(b)
			require.NoErrorf(t, err, "Authorize at %d", now)
		})
	}
}

func TestClockAndChainErrors(t *testing.T) {
	t.Run("clock stepped back beyond tolerance", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		c2 := gatefix.Fresh(gatefix.Template(t), 2)
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent1", c2)
		e.Clock.Set(gatefix.Now - 61)
		_, err = e.Authorize(b2)
		require.ErrorIs(t, err, gate.ErrClockRegression)
		_, gerr := e.Entry(c2)
		require.ErrorIs(t, gerr, registry.ErrNotFound, "nonce touched")
		e.Clock.Set(gatefix.Now - 60)
		_, err = e.Authorize(b2)
		require.NoError(t, err, "within tolerance")
	})
	t.Run("clock reads zero", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Clock.Set(0)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrClockRegression)
	})
	t.Run("latest retention unreadable", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Chain.FailLatest(errors.New("node down"))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("latest retention zero is invalid params", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Chain.SetLatest(0)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrInvalidParams)
	})
	t.Run("header source error", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Headers.Fail(errors.New("node down"))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("anchor source error", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Anchors.Fail(errors.New("node down"))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("no header for the height", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.Anchors.Set(c.PayloadRef, gate.Anchor{Height: c.PayloadRef.Height})
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
	})
	t.Run("cancelled context writes nothing", func(t *testing.T) {
		e, c, b, _ := happy(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.Gate.Authorize(ctx, b, gatefix.Action(t))
		e.RequireRejected(c, err, context.Canceled)
	})
}

func TestNewValidation(t *testing.T) {
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

func TestGateWithoutActionTypesIsRefusedAtNew(t *testing.T) {
	_, err := gatefix.TryNew(t, gatefix.WithScope(commitment.GateScope{GateID: gatefix.GateID}))
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
}
