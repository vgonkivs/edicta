package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

type authorizationInput struct {
	Version        string `json:"version"`
	CommitmentHash string `json:"commitment_hash"`
	ActionHash     string `json:"action_hash"`
	GateID         string `json:"gate_id"`
	Expires        string `json:"expires"`
	Path           string `json:"path"`
	Mode           string `json:"mode"`
	AnchorDeadline string `json:"anchor_deadline"`
}

type authorizationCheck struct {
	GatePubKeyHex string `json:"gate_pubkey_hex"`
	GateID        string `json:"gate_id"`
	ActionType    string `json:"action_type"`
	Now           string `json:"now"`
	SkewS         string `json:"skew_s"`
	actionSpec
}

type authorizationFile struct {
	MaxTTLS string `json:"max_authorization_ttl_s"`
	Cases   []struct {
		ID                     string             `json:"id"`
		CommitmentRef          string             `json:"commitment_ref"`
		AuthorizedAt           string             `json:"authorized_at"`
		Signer                 string             `json:"signer"`
		Input                  authorizationInput `json:"input"`
		AuthorizationCBORHex   string             `json:"authorization_cbor_hex"`
		AuthorizationHashHex   string             `json:"authorization_hash_hex"`
		SignedMessageHex       string             `json:"signed_message_hex"`
		SignatureHex           string             `json:"signature_hex"`
		SignedAuthorizationHex string             `json:"signed_authorization_hex"`
		Check                  authorizationCheck `json:"check"`
	} `json:"cases"`
	Reject []struct {
		ID                     string             `json:"id"`
		Stage                  string             `json:"stage"`
		SignedAuthorizationHex string             `json:"signed_authorization_hex"`
		Check                  authorizationCheck `json:"check"`
		ExpectError            string             `json:"expect_error"`
	} `json:"reject"`
}

func toAuthorization(t testing.TB, in authorizationInput) *commitment.Authorization {
	a := &commitment.Authorization{
		Version:        u64(t, in.Version),
		CommitmentHash: mustHex(t, in.CommitmentHash),
		ActionHash:     mustHex(t, in.ActionHash),
		GateID:         in.GateID,
		Expires:        u64(t, in.Expires),
		Path:           commitment.PayloadPath(u64(t, in.Path)),
	}
	if in.Mode != "" {
		a.Mode = u64(t, in.Mode)
	}
	if in.AnchorDeadline != "" {
		a.AnchorDeadline = u64(t, in.AnchorDeadline)
	}
	return a
}

func toAuthorizationCheck(t testing.TB, c authorizationCheck) commitment.AuthorizationCheck {
	return commitment.AuthorizationCheck{
		GatePubKey: mustHex(t, c.GatePubKeyHex),
		GateID:     c.GateID,
		ActionType: c.ActionType,
		Action:     actionBytes(t, c.actionSpec),
		ActionSalt: actionSalt(t, c.actionSpec),
		Now:        u64(t, c.Now),
		SkewS:      u64(t, c.SkewS),
	}
}

func TestAuthorizationValidVectors(t *testing.T) {
	var af authorizationFile
	loadJSON(t, "authorization.json", &af)
	vf := loadValid(t)
	gate1 := loadKey(t, "gate1")
	maxTTL := u64(t, af.MaxTTLS)
	require.GreaterOrEqual(t, len(af.Cases), 7)

	for _, ac := range af.Cases {
		t.Run(ac.ID, func(t *testing.T) {
			a := toAuthorization(t, ac.Input)
			wantCanon := mustHex(t, ac.AuthorizationCBORHex)
			wantHash := mustHex(t, ac.AuthorizationHashHex)
			wantMsg := mustHex(t, ac.SignedMessageHex)
			wantSig := mustHex(t, ac.SignatureHex)
			wantSigned := mustHex(t, ac.SignedAuthorizationHex)
			require.Equal(t, "gate1", ac.Signer)

			t.Run("encode", func(t *testing.T) {
				canon, err := commitment.EncodeAuthorization(a)
				require.NoError(t, err)
				require.Equal(t, hex.EncodeToString(wantCanon), hex.EncodeToString(canon))
			})

			t.Run("hash and signature", func(t *testing.T) {
				h := commitment.HashAuthorization(wantCanon)
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
				msg := commitment.AuthorizationSigningMessage(h)
				require.Equal(t, hex.EncodeToString(wantMsg), hex.EncodeToString(msg))
				require.Len(t, msg, 60)
				sig := ed25519.Sign(gate1, msg)
				require.Equal(t, hex.EncodeToString(wantSig), hex.EncodeToString(sig))
			})

			t.Run("signed encode and decode", func(t *testing.T) {
				signed, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: *a, Signature: wantSig})
				require.NoError(t, err)
				require.Equal(t, hex.EncodeToString(wantSigned), hex.EncodeToString(signed))
				require.LessOrEqual(t, len(signed), commitment.MaxAuthorizationSize)

				sa, h, err := commitment.DecodeSignedAuthorization(wantSigned)
				require.NoError(t, err)
				require.Equal(t, a, &sa.Authorization)
				require.Equal(t, hex.EncodeToString(wantSig), hex.EncodeToString(sa.Signature))
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
			})

			t.Run("verify", func(t *testing.T) {
				if ac.Check.GateID == "" {
					t.Skip("encoding and signature only")
				}
				sa, h, err := commitment.VerifyAuthorization(wantSigned, toAuthorizationCheck(t, ac.Check))
				require.NoError(t, err)
				require.Equal(t, a, &sa.Authorization)
				require.Equal(t, hex.EncodeToString(wantHash), hex.EncodeToString(h[:]))
			})

			t.Run("agrees with its commitment", func(t *testing.T) {
				if ac.CommitmentRef == "" {
					t.Skip("stand-in hashes")
				}
				vc := validCaseByID(t, vf, ac.CommitmentRef)
				c := toCommitment(t, vc.Input)
				assert.Equal(t, vc.CommitmentHashHex, ac.Input.CommitmentHash, "commitment_hash")
				assert.Equal(t, hex.EncodeToString(c.Action.Hash), ac.Input.ActionHash, "action_hash")
				assert.Equal(t, c.Scope.GateID, ac.Input.GateID, "gate_id")
				want := min(c.ValidUntil, u64(t, ac.AuthorizedAt)+maxTTL)
				assert.Equal(t, want, a.Expires, "expires = min(valid_until, authorized_at + ttl)")
				assert.LessOrEqual(t, a.Expires, c.ValidUntil, "expires never outlives the decision")
				assert.Equal(t, vc.ActionType, ac.Check.ActionType)
				wantMode := uint64(commitment.ModeStrict)
				if vc.Pending {
					wantMode = commitment.ModeFast
				}
				assert.Equal(t, wantMode, a.Mode, "mode follows the reference form")
			})
		})
	}
}

func TestAuthorizationRejectVectors(t *testing.T) {
	var af authorizationFile
	loadJSON(t, "authorization.json", &af)
	require.GreaterOrEqual(t, len(af.Reject), 42)
	for _, rc := range af.Reject {
		t.Run(rc.ID, func(t *testing.T) {
			b := mustHex(t, rc.SignedAuthorizationHex)
			_, _, err := commitment.VerifyAuthorization(b, toAuthorizationCheck(t, rc.Check))
			assertSentinel(t, err, rc.ExpectError)

			_, _, derr := commitment.DecodeSignedAuthorization(b)
			if rc.Stage == "D" {
				assertSentinel(t, derr, rc.ExpectError)
				return
			}
			require.NoError(t, derr, "decoding must pass for a stage %s vector", rc.Stage)
		})
	}
}

func authFixture(t *testing.T) (signed []byte, chk commitment.AuthorizationCheck, a commitment.Authorization) {
	var af authorizationFile
	loadJSON(t, "authorization.json", &af)
	ac := af.Cases[0]
	return mustHex(t, ac.SignedAuthorizationHex), toAuthorizationCheck(t, ac.Check), *toAuthorization(t, ac.Input)
}

func signAuthorization(t *testing.T, key ed25519.PrivateKey, a commitment.Authorization) []byte {
	t.Helper()
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	h := commitment.HashAuthorization(canon)
	sig := ed25519.Sign(key, commitment.AuthorizationSigningMessage(h))
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return b
}

func TestMaxAuthorizationSize(t *testing.T) {
	require.EqualValues(t, 256, commitment.MaxAuthorizationSize)
	_, chk, _ := authFixture(t)
	_, _, err := commitment.VerifyAuthorization(make([]byte, commitment.MaxAuthorizationSize+1), chk)
	assertSentinel(t, err, "ErrTooLarge")
	_, _, err = commitment.DecodeSignedAuthorization(make([]byte, commitment.MaxAuthorizationSize+1))
	assertSentinel(t, err, "ErrTooLarge")
}

// The executor clock: valid while now + skew < expires.
func TestVerifyAuthorizationExpiryBoundary(t *testing.T) {
	signed, chk, a := authFixture(t)
	tests := []struct {
		name string
		now  uint64
		skew uint64
		want string
	}{
		{"well before", a.Expires - 100, 30, ""},
		{"last valid second", a.Expires - 31, 30, ""},
		{"now+skew equals expires", a.Expires - 30, 30, "ErrExpired"},
		{"zero skew last valid second", a.Expires - 1, 0, ""},
		{"zero skew now equals expires", a.Expires, 0, "ErrExpired"},
		{"max skew", a.Expires - 301, 300, ""},
		{"max skew boundary", a.Expires - 300, 300, "ErrExpired"},
		{"far after", a.Expires + 100000, 30, "ErrExpired"},
		{"now max uint64", ^uint64(0), 30, "ErrExpired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chk
			c.Now, c.SkewS = tt.now, tt.skew
			_, _, err := commitment.VerifyAuthorization(signed, c)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

// The executor holds the pinned key, id, type and bytes. Anything else it is
// handed is refused, with the order of the stages fixed.
func TestVerifyAuthorizationBindsEverythingTheExecutorKnows(t *testing.T) {
	signed, chk, _ := authFixture(t)
	_, _, err := commitment.VerifyAuthorization(signed, chk)
	require.NoError(t, err, "control")

	tests := []struct {
		name   string
		mutate func(c *commitment.AuthorizationCheck)
		want   string
	}{
		{"other pinned key", func(c *commitment.AuthorizationCheck) {
			c.GatePubKey = loadKey(t, "agent2").Public().(ed25519.PublicKey)
		}, "ErrSignatureInvalid"},
		{"agent key pinned", func(c *commitment.AuthorizationCheck) {
			c.GatePubKey = loadKey(t, "agent1").Public().(ed25519.PublicKey)
		}, "ErrSignatureInvalid"},
		{"small order pinned key", func(c *commitment.AuthorizationCheck) { c.GatePubKey = mustHex(t, badPublicKeys[0].hex) }, "ErrInvalidPublicKey"},
		{"short pinned key", func(c *commitment.AuthorizationCheck) { c.GatePubKey = c.GatePubKey[:31] }, "ErrInvalidPublicKey"},
		{"nil pinned key", func(c *commitment.AuthorizationCheck) { c.GatePubKey = nil }, "ErrInvalidPublicKey"},
		{"other gate id", func(c *commitment.AuthorizationCheck) { c.GateID = "gate-paper-2" }, "ErrScopeMismatch"},
		{"other action type", func(c *commitment.AuthorizationCheck) { c.ActionType = "application/json" }, "ErrActionMismatch"},
		{"first action byte flipped", func(c *commitment.AuthorizationCheck) { c.Action = bytes.Clone(c.Action); c.Action[0] ^= 1 }, "ErrActionMismatch"},
		{"action truncated", func(c *commitment.AuthorizationCheck) { c.Action = c.Action[:len(c.Action)-1] }, "ErrActionMismatch"},
		{"action extended", func(c *commitment.AuthorizationCheck) { c.Action = append(bytes.Clone(c.Action), 0) }, "ErrActionMismatch"},
		{"action empty", func(c *commitment.AuthorizationCheck) { c.Action = nil }, "ErrActionSize"},
		{"action too large", func(c *commitment.AuthorizationCheck) { c.Action = make([]byte, commitment.MaxActionSize+1) }, "ErrActionSize"},
		{"salt missing", func(c *commitment.AuthorizationCheck) { c.ActionSalt = nil }, "ErrMissingField"},
		{"salt 31 bytes", func(c *commitment.AuthorizationCheck) { c.ActionSalt = c.ActionSalt[:31] }, "ErrFieldSize"},
		{"salt flipped", func(c *commitment.AuthorizationCheck) {
			c.ActionSalt = bytes.Clone(c.ActionSalt)
			c.ActionSalt[0] ^= 1
		}, "ErrActionMismatch"},
		{"expired", func(c *commitment.AuthorizationCheck) { c.Now += 1000 }, "ErrExpired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chk
			tt.mutate(&c)
			_, _, err := commitment.VerifyAuthorization(signed, c)
			assertSentinel(t, err, tt.want)
		})
	}

	t.Run("signature before gate id", func(t *testing.T) {
		c := chk
		c.GatePubKey = loadKey(t, "agent2").Public().(ed25519.PublicKey)
		c.GateID = "gate-paper-2"
		_, _, err := commitment.VerifyAuthorization(signed, c)
		assertSentinel(t, err, "ErrSignatureInvalid")
	})
	t.Run("gate id before action", func(t *testing.T) {
		c := chk
		c.GateID = "gate-paper-2"
		c.Action = []byte{1}
		_, _, err := commitment.VerifyAuthorization(signed, c)
		assertSentinel(t, err, "ErrScopeMismatch")
	})
	t.Run("action size before salt", func(t *testing.T) {
		c := chk
		c.Action = nil
		c.ActionSalt = nil
		_, _, err := commitment.VerifyAuthorization(signed, c)
		assertSentinel(t, err, "ErrActionSize")
	})
	t.Run("salt before hash", func(t *testing.T) {
		c := chk
		c.Action = []byte{1}
		c.ActionSalt = nil
		_, _, err := commitment.VerifyAuthorization(signed, c)
		assertSentinel(t, err, "ErrMissingField")
	})
	t.Run("action before expiry", func(t *testing.T) {
		c := chk
		c.Action = []byte{1}
		c.Now += 1000
		_, _, err := commitment.VerifyAuthorization(signed, c)
		assertSentinel(t, err, "ErrActionMismatch")
	})
}

// A fresh, correctly signed Authorization whose fields are inconsistent with
// the schema is still refused.
func TestVerifyAuthorizationSignedGarbage(t *testing.T) {
	_, chk, base := authFixture(t)
	gate1 := loadKey(t, "gate1")
	tests := []struct {
		name   string
		mutate func(a *commitment.Authorization)
		want   string
	}{
		{"version 0", func(a *commitment.Authorization) { a.Version = 0 }, "ErrUnsupportedVersion"},
		{"version 2", func(a *commitment.Authorization) { a.Version = 2 }, "ErrUnsupportedVersion"},
		{"mode zero", func(a *commitment.Authorization) { a.Mode = 0 }, "ErrInvalidEnum"},
		{"mode three", func(a *commitment.Authorization) { a.Mode = 3 }, "ErrInvalidEnum"},
		{"expires zero", func(a *commitment.Authorization) { a.Expires = 0 }, "ErrZeroValue"},
		{"expires 2^63", func(a *commitment.Authorization) { a.Expires = 1 << 63 }, "ErrIntRange"},
		{"path zero", func(a *commitment.Authorization) { a.Path = 0 }, "ErrInvalidEnum"},
		{"path three", func(a *commitment.Authorization) { a.Path = 3 }, "ErrInvalidEnum"},
		{"short commitment hash", func(a *commitment.Authorization) { a.CommitmentHash = a.CommitmentHash[:31] }, "ErrFieldSize"},
		{"long action hash", func(a *commitment.Authorization) { a.ActionHash = append(bytes.Clone(a.ActionHash), 0) }, "ErrFieldSize"},
		{"unicode gate id", func(a *commitment.Authorization) { a.GateID = "gate-é" }, "ErrInvalidString"},
		{"other action hash", func(a *commitment.Authorization) {
			a.ActionHash = bytes.Clone(a.ActionHash)
			a.ActionHash[0] ^= 1
		}, "ErrActionMismatch"},
		{"path archive is fine", func(a *commitment.Authorization) { a.Path = commitment.PathArchive }, ""},
		{"path da is fine", func(a *commitment.Authorization) { a.Path = commitment.PathDA }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := base
			tt.mutate(&a)
			b := signAuthorization(t, gate1, a)
			_, _, err := commitment.VerifyAuthorization(b, chk)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

// A signature of one role must not verify as another: commitment, receipt
// and Authorization signing messages are all distinct.
func TestAuthorizationDomainSeparation(t *testing.T) {
	signed, chk, base := authFixture(t)
	gate1 := loadKey(t, "gate1")
	canon, err := commitment.EncodeAuthorization(&base)
	require.NoError(t, err)
	h := commitment.HashAuthorization(canon)

	sa, _, err := commitment.DecodeSignedAuthorization(signed)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(gate1.Public().(ed25519.PublicKey), commitment.AuthorizationSigningMessage(h), sa.Signature), "control")
	for name, msg := range map[string][]byte{
		"commitment tag": commitment.SigningMessage(h),
		"receipt tag":    commitment.ReceiptSigningMessage(h),
		"bare hash":      h[:],
		"raw cbor":       canon,
	} {
		t.Run(name, func(t *testing.T) {
			bad := signAuthorizationWith(t, base, ed25519.Sign(gate1, msg))
			_, _, err := commitment.VerifyAuthorization(bad, chk)
			assertSentinel(t, err, "ErrSignatureInvalid")
		})
	}
	t.Run("hash is under its own tag", func(t *testing.T) {
		assert.NotEqual(t, h, commitment.HashReceipt(canon))
		assert.NotEqual(t, h, commitment.HashCanonical(canon))
	})
	t.Run("agent envelope is not an authorization", func(t *testing.T) {
		vf := loadValid(t)
		_, _, err := commitment.VerifyAuthorization(mustHex(t, vf.Cases[0].EnvelopeHex), chk)
		require.Error(t, err)
	})
	t.Run("authorization is not an envelope", func(t *testing.T) {
		vf := loadValid(t)
		_, _, err := commitment.VerifyForGate(signed, edgeNow, toGate(t, vf.Gate), toParams(t, vf.Params))
		require.Error(t, err)
	})
	t.Run("receipt is not an authorization", func(t *testing.T) {
		var rf receiptFile
		loadJSON(t, "receipt.json", &rf)
		_, _, err := commitment.VerifyAuthorization(mustHex(t, rf.Cases[0].SignedReceiptHex), chk)
		require.Error(t, err)
	})
	t.Run("authorization is not a receipt", func(t *testing.T) {
		_, _, err := commitment.VerifyReceipt(signed)
		require.Error(t, err)
	})
}

func signAuthorizationWith(t *testing.T, a commitment.Authorization, sig []byte) []byte {
	t.Helper()
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return b
}

// Every single-bit change of a signed Authorization must be refused.
func TestEveryBitFlipOfAnAuthorizationIsRejected(t *testing.T) {
	good, chk, _ := authFixture(t)
	_, _, err := commitment.VerifyAuthorization(good, chk)
	require.NoError(t, err)
	for i := range good {
		for bit := 0; bit < 8; bit++ {
			b := bytes.Clone(good)
			b[i] ^= 1 << bit
			_, _, err := commitment.VerifyAuthorization(b, chk)
			require.Errorf(t, err, "flip of byte %d bit %d accepted", i, bit)
		}
	}
}

func TestAuthorizationNilAndEmptyInput(t *testing.T) {
	_, chk, _ := authFixture(t)
	for name, b := range map[string][]byte{"nil": nil, "empty": {}, "one byte": {0xa0}} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, err := commitment.VerifyAuthorization(b, chk)
				require.Error(t, err)
				assert.True(t, matchesAnySentinel(err), "no sentinel: %v", err)
			})
		})
	}
	_, err := commitment.EncodeAuthorization(nil)
	require.Error(t, err)
	_, err = commitment.EncodeSignedAuthorization(nil)
	require.Error(t, err)
}

// An Authorization carries a bound, not a tx hash or rail reference
// (the receipt carries the reference).
func TestAuthorizationWireHasNoTypeAndNoRailReference(t *testing.T) {
	signed, _, _ := authFixture(t)
	sa, _, err := commitment.DecodeSignedAuthorization(signed)
	require.NoError(t, err)
	canon, err := commitment.EncodeAuthorization(&sa.Authorization)
	require.NoError(t, err)
	assert.Len(t, canon, 97, "version, two hashes, gate id, expires, path, mode only")
	assert.False(t, bytes.Contains(canon, []byte("application/")), "action type leaked into the Authorization")
}
