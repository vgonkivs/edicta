package attacks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// countingArchiver counts decision records; the v1 attacks below require
// that refusals before the archive stage leave nothing behind.
type countingArchiver struct {
	mu sync.Mutex
	n  int
}

func (a *countingArchiver) Put(context.Context, gate.DecisionRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	return nil
}

func (a *countingArchiver) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

func withArchiver(a gate.Archiver) gatefix.Option {
	return gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = a })
}

// requireNothingWritten is the "refused before any write" check: no
// Authorization, no verdict, no decision record, untouched nonce.
func requireNothingWritten(t *testing.T, e *gatefix.Env, arch *countingArchiver, before int, c *commitment.Commitment, res gate.Result) {
	t.Helper()
	assert.Empty(t, res.Authorization, "no Authorization")
	assert.Empty(t, res.PolicyVerdict, "no verdict")
	assert.False(t, res.DecisionArchived)
	assert.Equal(t, before, arch.count(), "no decision record")
	e.RequireUntouched(c)
}

func otherSalt(t *testing.T, b byte) []byte {
	s := bytes.Repeat([]byte{b}, commitment.ActionSaltSize)
	require.NotEqual(t, gatefix.Salt(t), s)
	return s
}

// withSalt commits c to the template action under another salt.
func withSalt(t *testing.T, c *commitment.Commitment, salt []byte) *commitment.Commitment {
	h, err := commitment.ActionHash(gatefix.ActionType, salt, gatefix.Action(t))
	require.NoError(t, err)
	d := gatefix.Clone(c)
	d.Action.Hash = h[:]
	return d
}

func taggedMsg(tag string, parts ...[]byte) []byte {
	m := append([]byte{byte(len(tag))}, tag...)
	for _, p := range parts {
		m = append(m, p...)
	}
	return m
}

func taggedHash(tag string, parts ...[]byte) []byte {
	s := sha256.Sum256(taggedMsg(tag, parts...))
	return s[:]
}

// v0Tag derives the tag of the superseded drafts from its v1 successor.
func v0Tag(v1 string) string { return strings.Replace(v1, "/v1/", "/v0/", 1) }

// The salt travels next to the action bytes. Every way to present the bytes
// without the committed salt is refused at stage A, before the archive and
// the registry are touched.
func TestV1AttackActionSalt(t *testing.T) {
	salt := gatefix.Salt(t)
	action := gatefix.Action(t)
	flipped := bytes.Clone(salt)
	flipped[31] ^= 0x80
	for _, tc := range []struct {
		name         string
		action, salt []byte
		want         error
	}{
		{"missing salt", action, nil, commitment.ErrMissingField},
		{"empty salt", action, []byte{}, commitment.ErrMissingField},
		{"wrong salt", action, flipped, commitment.ErrActionMismatch},
		{"all-zero salt", action, make([]byte, 32), commitment.ErrActionMismatch},
		// tag || type || salt || bytes is one byte string: moving the boundary
		// keeps the preimage, only the fixed salt width refuses it.
		{"boundary shifted into the salt", action[1:], append(bytes.Clone(salt), action[0]), commitment.ErrFieldSize},
		{"boundary shifted into the bytes", append([]byte{salt[31]}, action...), salt[:31], commitment.ErrFieldSize},
		{"salt carried inside the bytes", append(bytes.Clone(salt), action...), nil, commitment.ErrMissingField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch := &countingArchiver{}
			e, c, b := armed(t, withArchiver(arch))
			res, err := e.AuthorizeWithSalt(b, tc.action, tc.salt)
			require.ErrorIs(t, err, tc.want)
			requireNothingWritten(t, e, arch, 0, c, res)

			_, err = e.Authorize(b)
			require.NoError(t, err, "the refusal consumed nothing")
		})
	}
}

// Two decisions of the same agent with the same action bytes have different
// salts; the salt of one does not open the other.
func TestV1AttackSaltFromAnotherDecision(t *testing.T) {
	arch := &countingArchiver{}
	e := gatefix.New(t, withArchiver(arch))
	a := gatefix.Template(t)
	bDec := withSalt(t, gatefix.Fresh(a, 9), otherSalt(t, 0x5a))
	e.StageDA(a, gatefix.Blob(t))
	e.StageDA(bDec, gatefix.Blob(t))
	envA, _ := gatefix.Sign(t, "agent1", a)
	envB, _ := gatefix.Sign(t, "agent1", bDec)

	resA, err := e.Authorize(envA)
	require.NoError(t, err)
	before := arch.count()

	res, err := e.AuthorizeWithSalt(envB, gatefix.Action(t), gatefix.Salt(t))
	require.ErrorIs(t, err, commitment.ErrActionMismatch, "decision A's salt presented for decision B")
	requireNothingWritten(t, e, arch, before, bDec, res)

	_, err = e.AuthorizeWithSalt(envB, gatefix.Action(t), otherSalt(t, 0x5a))
	require.NoError(t, err, "control: B with its own salt")

	t.Run("executor refuses A's Authorization with B's salt", func(t *testing.T) {
		_, _, err := commitment.VerifyAuthorization(resA.Authorization, commitment.AuthorizationCheck{
			GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: gatefix.ActionType,
			Action: gatefix.Action(t), ActionSalt: otherSalt(t, 0x5a), Now: gatefix.Now, SkewS: 30,
		})
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
	})
}

// A commitment whose action hash was computed without the salt (the v0
// preimage, or the v1 tag with no salt) never matches, whatever salt is shown.
func TestV1AttackActionHashedWithoutSalt(t *testing.T) {
	typ := append([]byte{byte(len(gatefix.ActionType))}, gatefix.ActionType...)
	for name, h := range map[string][]byte{
		"v0 action tag, no salt":       taggedHash(v0Tag(commitment.TagAction), typ, gatefix.Action(t)),
		"v1 action tag, no salt":       taggedHash(commitment.TagAction, typ, gatefix.Action(t)),
		"v1 tag, salt after the bytes": taggedHash(commitment.TagAction, typ, gatefix.Action(t), gatefix.Salt(t)),
	} {
		t.Run(name, func(t *testing.T) {
			arch := &countingArchiver{}
			e := gatefix.New(t, withArchiver(arch))
			c := gatefix.Clone(gatefix.Template(t))
			c.Action.Hash = h
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			for _, salt := range [][]byte{gatefix.Salt(t), make([]byte, 32)} {
				res, err := e.AuthorizeWithSalt(b, gatefix.Action(t), salt)
				require.ErrorIs(t, err, commitment.ErrActionMismatch)
				requireNothingWritten(t, e, arch, 0, c, res)
			}
			res, err := e.AuthorizeWithSalt(b, gatefix.Action(t), nil)
			require.ErrorIs(t, err, commitment.ErrMissingField)
			requireNothingWritten(t, e, arch, 0, c, res)
		})
	}
}

// The executor side of the salt: an Authorization verifies only with the
// exact action bytes and the exact salt.
func TestV1AttackExecutorSalt(t *testing.T) {
	e, _, b := armed(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	salt := gatefix.Salt(t)
	action := gatefix.Action(t)
	for _, tc := range []struct {
		name         string
		action, salt []byte
		want         error
	}{
		{"missing salt", action, nil, commitment.ErrMissingField},
		{"wrong salt", action, otherSalt(t, 1), commitment.ErrActionMismatch},
		{"boundary shifted", action[1:], append(bytes.Clone(salt), action[0]), commitment.ErrFieldSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
				GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: gatefix.ActionType,
				Action: tc.action, ActionSalt: tc.salt, Now: gatefix.Now, SkewS: 30,
			})
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// lastByteExtractor reads the amount from the last action byte.
type lastByteExtractor struct{}

func (lastByteExtractor) ID() string         { return "test/last-byte/v1" }
func (lastByteExtractor) ActionType() string { return gatefix.ActionType }
func (lastByteExtractor) Extract(a []byte) (policy.Facts, error) {
	if len(a) == 0 {
		return policy.Facts{}, errors.New("unreadable action")
	}
	return policy.Facts{Kind: "transfer", Asset: "x:a", Amount: policy.AmountFromUint64(uint64(a[len(a)-1])), Recipient: "bob"}, nil
}

func principal() ed25519.PrivateKey {
	s := sha256.Sum256([]byte("attack suite principal"))
	return ed25519.NewKeyFromSeed(s[:])
}

func mandate(t *testing.T, version uint64, id byte) *policy.Mandate {
	return &policy.Mandate{
		Format: 1, Principal: principal().Public().(ed25519.PublicKey), GateID: gatefix.GateID,
		Agents:    [][]byte{gatefix.Pub(t, "agent2"), gatefix.Pub(t, "agent1")},
		NotBefore: 1, NotAfter: 1 << 35, MandateID: bytes.Repeat([]byte{id}, 16), Version: version,
		Assets: []policy.AssetRule{{Asset: "x:a", PerActionMax: []byte{200},
			Periods: []policy.PeriodLimit{{Hours: 1, Max: []byte{250}}}}},
	}
}

func signMandate(t *testing.T, m *policy.Mandate) ([]byte, []byte) {
	b, h, err := policy.SignMandate(principal(), m)
	require.NoError(t, err)
	return b, h[:]
}

func mandateGate(t *testing.T, m *policy.Mandate, arch *countingArchiver) *gatefix.Env {
	x, err := policy.NewExtractors(lastByteExtractor{})
	require.NoError(t, err)
	b, _ := signMandate(t, m)
	return gatefix.New(t,
		gatefix.WithConfig(func(c *gate.Config) { c.Mandate = b }),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }),
		withArchiver(arch))
}

func decisionWithRef(t *testing.T, e *gatefix.Env, tag byte, ref []byte) (*commitment.Commitment, []byte) {
	c := gatefix.Fresh(gatefix.Template(t), tag)
	c.MandateRef = ref
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	return c, b
}

// A commitment that names a mandate at a gate that has none is refused
// before anything is written: no decision record, no verdict, no nonce.
func TestV1AttackMandateRefAtGateWithoutMandate(t *testing.T) {
	_, ref := signMandate(t, mandate(t, 1, 1))
	arch := &countingArchiver{}
	e := gatefix.New(t, withArchiver(arch))
	c, b := decisionWithRef(t, e, 1, ref)
	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrMandateMismatch)
	requireNothingWritten(t, e, arch, 0, c, res)

	res, err = e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrMandateMismatch, "a retry is refused the same way")
	requireNothingWritten(t, e, arch, 0, c, res)
}

// A commitment naming another mandate than the one in force is refused at
// the reference stage: no deny verdict, no decision record, no nonce.
func TestV1AttackMandateMismatch(t *testing.T) {
	_, otherRef := signMandate(t, mandate(t, 1, 2))
	t.Run("another mandate of the same principal", func(t *testing.T) {
		arch := &countingArchiver{}
		e := mandateGate(t, mandate(t, 1, 1), arch)
		// 250 is above the per-action maximum: a 4p deny would sign a verdict.
		c := gatefix.WithAction(t, gatefix.Fresh(gatefix.Template(t), 1), gatefix.ActionType, gatefix.OtherAction(t, 250))
		c.MandateRef = otherRef
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.AuthorizeWith(b, gatefix.OtherAction(t, 250))
		require.ErrorIs(t, err, gate.ErrMandateMismatch)
		require.NotErrorIs(t, err, policy.ErrDenied)
		requireNothingWritten(t, e, arch, 0, c, res)
	})
	t.Run("previous version after a bump", func(t *testing.T) {
		arch := &countingArchiver{}
		v1 := mandate(t, 1, 1)
		e := mandateGate(t, v1, arch)
		_, ref1 := signMandate(t, v1)
		_, b := decisionWithRef(t, e, 1, ref1)
		_, err := e.Authorize(b)
		require.NoError(t, err, "control under version 1")

		v2 := mandate(t, 2, 1)
		e.Cfg.Mandate, _ = signMandate(t, v2)
		require.NoError(t, e.Restart())
		before := arch.count()
		c, b2 := decisionWithRef(t, e, 2, ref1)
		res, err := e.Authorize(b2)
		require.ErrorIs(t, err, gate.ErrMandateMismatch)
		requireNothingWritten(t, e, arch, before, c, res)
	})
	t.Run("missing reference at a mandate gate", func(t *testing.T) {
		arch := &countingArchiver{}
		e := mandateGate(t, mandate(t, 1, 1), arch)
		c, b := decisionWithRef(t, e, 1, nil)
		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrMandateRefMissing)
		assert.Empty(t, res.Authorization)
		assert.Empty(t, res.PolicyVerdict)
		e.RequireUntouched(c)
	})
}

// Kind 3 was the decision record of the v0 drafts; in format 1 it is
// unassigned, so neither the codec nor a store read accepts it, and a
// format 0 record is corrupt too.
func TestV1AttackKind3Record(t *testing.T) {
	var vf struct {
		Reject []struct {
			ID  string `json:"id"`
			Hex string `json:"record_cbor_hex"`
		} `json:"reject"`
	}
	gatefix.ReadVector(t, "archive.json", &vf)
	records := map[string][]byte{}
	for _, r := range vf.Reject {
		records[r.ID] = gatefix.MustHex(t, r.Hex)
	}
	for _, id := range []string{"kind_3_unassigned", "format_0_decision"} {
		t.Run(id, func(t *testing.T) {
			rec, ok := records[id]
			require.True(t, ok, "vector %s", id)
			_, err := archive.Decode(rec)
			require.ErrorIs(t, err, archive.ErrCorrupt)

			// The same bytes planted at the decision path of a store.
			env, err := commitment.EnvelopeCommitment(gatefix.MustHex(t, validEnvelopeHex(t)))
			require.NoError(t, err)
			h := commitment.HashCanonical(env)
			dir := t.TempDir()
			path := filepath.Join(dir, filepath.FromSlash(archive.HashPath(archive.KindDecision, h)))
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, rec, 0o644))
			st, err := fsarchive.OpenReadOnly(dir, nil)
			require.NoError(t, err)
			_, err = st.Decision(context.Background(), h)
			require.ErrorIs(t, err, archive.ErrCorrupt)
		})
	}
}

func validEnvelopeHex(t *testing.T) string {
	var vf struct {
		Cases []struct {
			ID  string `json:"id"`
			Hex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "valid.json", &vf)
	for _, c := range vf.Cases {
		if c.ID == "minimal_lmt" {
			return c.Hex
		}
	}
	require.FailNow(t, "no minimal_lmt")
	return ""
}

// Objects hashed or signed under the edicta/v0 tags never verify as v1.
func TestV1AttackV0TaggedObjects(t *testing.T) {
	t.Run("commitment", func(t *testing.T) {
		c := gatefix.Template(t)
		canon, err := commitment.Encode(c)
		require.NoError(t, err)
		v1h, err := commitment.HashOf(c)
		require.NoError(t, err)
		v0h := taggedHash(v0Tag(commitment.TagCommitment), canon)
		agent := gatefix.Key(t, "agent1")
		for name, msg := range map[string][]byte{
			"v1 hash under the v0 sig tag": taggedMsg(v0Tag(commitment.TagSig), v1h[:]),
			"v0 hash under the v0 sig tag": taggedMsg(v0Tag(commitment.TagSig), v0h),
			"v0 hash under the v1 sig tag": commitment.SigningMessage(commitment.Hash(v0h)),
		} {
			t.Run(name, func(t *testing.T) {
				e := gatefix.New(t)
				e.StageDA(c, gatefix.Blob(t))
				b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: ed25519.Sign(agent, msg)})
				require.NoError(t, err)
				_, err = e.Authorize(b)
				e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
			})
		}
	})
	t.Run("version 0 envelope", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		c.Version = 0
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrUnsupportedVersion)
	})

	e, _, b := armed(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	gk := gatefix.Key(t, "gate1")
	t.Run("authorization", func(t *testing.T) {
		sa, _, err := commitment.DecodeSignedAuthorization(res.Authorization)
		require.NoError(t, err)
		canon, err := commitment.EncodeAuthorization(&sa.Authorization)
		require.NoError(t, err)
		v1h := commitment.HashAuthorization(canon)
		v0h := taggedHash(v0Tag(commitment.TagAuthorization), canon)
		v0sig := v0Tag(commitment.TagAuthorizationSig)
		for name, msg := range map[string][]byte{
			"v1 hash under the v0 sig tag": taggedMsg(v0sig, v1h[:]),
			"v0 hash under the v0 sig tag": taggedMsg(v0sig, v0h),
			"v0 hash under the v1 sig tag": commitment.AuthorizationSigningMessage(commitment.Hash(v0h)),
		} {
			t.Run(name, func(t *testing.T) {
				forged := &commitment.SignedAuthorization{Authorization: sa.Authorization, Signature: ed25519.Sign(gk, msg)}
				fb, err := commitment.EncodeSignedAuthorization(forged)
				require.NoError(t, err)
				_, _, err = commitment.VerifyAuthorization(fb, commitment.AuthorizationCheck{
					GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: gatefix.ActionType,
					Action: gatefix.Action(t), ActionSalt: gatefix.Salt(t), Now: gatefix.Now, SkewS: 30,
				})
				require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
			})
		}
	})
	t.Run("receipt", func(t *testing.T) {
		rb, err := e.Record(b, gatefix.RailRef)
		require.NoError(t, err)
		sr, _, err := commitment.DecodeSignedReceipt(rb)
		require.NoError(t, err)
		canon, err := commitment.EncodeReceipt(&sr.Receipt)
		require.NoError(t, err)
		v1h := commitment.HashReceipt(canon)
		v0sig := v0Tag(commitment.TagReceiptSig)
		msg := taggedMsg(v0sig, v1h[:])
		fb, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: sr.Receipt, Signature: ed25519.Sign(gk, msg)})
		require.NoError(t, err)
		_, _, err = commitment.VerifyReceipt(fb)
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	})
	t.Run("record request", func(t *testing.T) {
		h, err := commitment.HashOf(gatefix.Template(t))
		require.NoError(t, err)
		v0tag := v0Tag(commitment.TagRecordRequest)
		v1msg, err := commitment.RecordRequestMessage(h, gatefix.GateID, gatefix.RailRef)
		require.NoError(t, err)
		v0msg := append([]byte{byte(len(v0tag))}, v0tag...)
		v0msg = append(v0msg, v1msg[1+len(commitment.TagRecordRequest):]...)
		ek := gatefix.ExecutorKey(t, "executor1")
		err = commitment.VerifyRecordRequest(h, gatefix.GateID, gatefix.RailRef, gatefix.ExecutorPub(t, "executor1"), ed25519.Sign(ek, v0msg))
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	})
}

// Fast mode issues an Authorization before the anchor exists, so it needs
// the principal's consent: a gate without a mandate does not start in fast
// mode, and with FastMode off a pending reference is refused.
func TestV1AttackFastModeWithoutMandate(t *testing.T) {
	ns := gatefix.MustHex(t, "000000000000000000000000000000000000006564696374612f643031")
	_, err := gatefix.TryNew(t, withArchiver(&countingArchiver{}), gatefix.WithConfig(func(c *gate.Config) {
		c.FastMode = true
		c.PendingNamespaces = [][]byte{ns}
	}))
	require.ErrorIs(t, err, gate.ErrInvalidConfig)
	require.ErrorContains(t, err, gate.CauseFastModeWithoutMandate)

	t.Run("pending reference at a strict gate", func(t *testing.T) {
		arch := &countingArchiver{}
		e := gatefix.New(t, withArchiver(arch))
		c := gatefix.Template(t)
		c.PayloadRef.Anchor = commitment.AnchorPending
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrAnchorPending)
		assert.Empty(t, res.Authorization)
		e.RequireUntouched(c)
	})
}

// Until stage K-fast exists, a gate with FastMode on still refuses every
// pending reference, and the refusal writes nothing.
func TestV1AttackPendingAtFastModeGateWritesNothing(t *testing.T) {
	arch := &countingArchiver{}
	tmpl := gatefix.Template(t)
	x, err := policy.NewExtractors(lastByteExtractor{})
	require.NoError(t, err)
	mb, ref := signMandate(t, mandate(t, 1, 1))
	e := gatefix.New(t,
		gatefix.WithConfig(func(c *gate.Config) {
			c.Mandate = mb
			c.FastMode = true
			c.PendingNamespaces = [][]byte{tmpl.PayloadRef.Namespace}
		}),
		gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }),
		withArchiver(arch))
	c := gatefix.Clone(tmpl)
	c.MandateRef = ref
	c.PayloadRef.Anchor = commitment.AnchorPending
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrAnchorPending)
	requireNothingWritten(t, e, arch, 0, c, res)

	// Red until the gate wraps the sentinel with the interim reason.
	t.Run("message names the missing fast-mode path", func(t *testing.T) {
		require.ErrorContains(t, err, "fast-mode authorization not implemented")
	})
}
