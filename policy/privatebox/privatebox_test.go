package privatebox_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
	"github.com/vgonkivs/edicta/sdk/blob"
)

type auditorKey struct {
	IKM         string `json:"ikm_hex"`
	SK          string `json:"sk_hex"`
	PK          string `json:"pk_hex"`
	Kid         string `json:"kid_hex"`
	Fingerprint string `json:"fingerprint"`
}

type envelopeCase struct {
	ID         string `json:"id"`
	Kind       string `json:"plaintext_kind"`
	Plaintext  string `json:"plaintext_cbor_hex"`
	Hash       string `json:"hash_hex"`
	PlainHash  string `json:"plaintext_hash_hex"`
	StateSalt  string `json:"state_salt_hex"`
	Salt       string `json:"salt_hex"`
	DEK        string `json:"dek_hex"`
	Nonce      string `json:"aead_nonce_hex"`
	ActionType string `json:"action_type"`
	ActionSalt string `json:"action_salt_hex"`
	Action     string `json:"action_hex"`
	Recipients []struct {
		Kid     string `json:"kid_hex"`
		IKME    string `json:"ikme_hex"`
		Enc     string `json:"enc_hex"`
		Wrapped string `json:"wrapped_dek_hex"`
	} `json:"recipients"`
	Envelope string `json:"envelope_hex"`
}

type doc struct {
	Cap        string                `json:"cap"`
	ActionCap  string                `json:"action_cap"`
	Keys       map[string]auditorKey `json:"auditor_keys"`
	Envelopes  []envelopeCase        `json:"envelopes"`
	Reject     []rejectCase          `json:"reject"`
	Derivation map[string]string     `json:"derivation"`
}

type rejectCase struct {
	ID       string   `json:"id"`
	Kind     string   `json:"plaintext_kind"`
	Hash     string   `json:"hash_hex"`
	Keys     []string `json:"auditor_keys"`
	Size     string   `json:"envelope_size"`
	Envelope string   `json:"envelope_hex"`
	Expect   string   `json:"expect"`
}

func load(t testing.TB) doc {
	raw, err := os.ReadFile("../../spec/vectors/policy/private.json")
	require.NoError(t, err)
	var d doc
	require.NoError(t, json.Unmarshal(raw, &d))
	return d
}

func hx(t testing.TB, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func kindOf(t testing.TB, s string) policy.PrivateKind {
	n, err := strconv.Atoi(s)
	require.NoError(t, err)
	return policy.PrivateKind(n)
}

func privKey(t testing.TB, sk string) *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(hx(t, sk))
	require.NoError(t, err)
	return k
}

func deriveSK(t testing.TB, ikm []byte) []byte {
	k, err := hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(ikm)
	require.NoError(t, err)
	b, err := k.Bytes()
	require.NoError(t, err)
	return b
}

func TestCaps(t *testing.T) {
	d := load(t)
	assert.Equal(t, strconv.Itoa(policy.MaxPrivateEnvelope), d.Cap)
	assert.Equal(t, strconv.Itoa(policy.MaxPrivateActionEnvelope), d.ActionCap)
	for k := policy.PrivateMandate; k <= policy.PrivatePartKind; k++ {
		assert.Equal(t, policy.MaxPrivateEnvelope, privatebox.Suite(k).MaxSize)
	}
	assert.Equal(t, policy.MaxPrivateActionEnvelope, privatebox.Suite(policy.PrivateAction).MaxSize)
}

func TestAuditorKeys(t *testing.T) {
	d := load(t)
	require.Len(t, d.Keys, 3)
	for name, k := range d.Keys {
		t.Run(name, func(t *testing.T) {
			// The stdlib returns the scalar clamped; RFC 9180 keeps it raw.
			want := hx(t, k.SK)
			want[0] &= 248
			want[31] = want[31]&127 | 64
			assert.Equal(t, want, deriveSK(t, hx(t, k.IKM)))
			assert.Equal(t, hx(t, k.PK), privKey(t, k.SK).PublicKey().Bytes())
			assert.Equal(t, hx(t, k.Kid), policy.AuditorKid(hx(t, k.PK)))
			assert.Equal(t, k.Fingerprint, policy.Fingerprint(hx(t, k.Kid)))
		})
	}
}

// Every envelope opens with every listed auditor key to the vector's
// plaintext, and its bytes follow from the labelled randomness: the
// ephemeral keys give the encs, every wrap opens to the DEK, and the
// ciphertext is the AEAD of salt || plaintext under that DEK and nonce.
func TestEnvelopeVectors(t *testing.T) {
	d := load(t)
	require.Len(t, d.Envelopes, 5)
	byKid := map[string]auditorKey{}
	for _, k := range d.Keys {
		byKid[k.Kid] = k
	}
	for _, e := range d.Envelopes {
		t.Run(e.ID, func(t *testing.T) {
			kind := kindOf(t, e.Kind)
			env := hx(t, e.Envelope)
			b, err := blob.Decode(env)
			require.NoError(t, err)
			require.Len(t, b.Recipients, len(e.Recipients))
			assert.Equal(t, hx(t, e.Nonce), b.AEADNonce[:])

			plain := hx(t, e.Plaintext)
			if kind == policy.PrivateAction {
				assert.Equal(t, append(hx(t, e.ActionSalt), hx(t, e.Action)...), plain)
			}
			aead, err := chacha20poly1305.New(hx(t, e.DEK))
			require.NoError(t, err)
			aad := append([]byte{byte(len(policy.TagPrivateAEAD))}, policy.TagPrivateAEAD...)
			want := aead.Seal(nil, hx(t, e.Nonce), append(hx(t, e.Salt), plain...), aad)
			assert.Equal(t, want, b.Ciphertext)

			for i, r := range e.Recipients {
				assert.Equal(t, hx(t, r.Kid), b.Recipients[i].KID)
				assert.Equal(t, hx(t, r.Enc), b.Recipients[i].Enc[:])
				assert.Equal(t, hx(t, r.Wrapped), b.Recipients[i].WrappedDEK[:])
				skE := privKey(t, hex.EncodeToString(deriveSK(t, hx(t, r.IKME))))
				assert.Equal(t, hx(t, r.Enc), skE.PublicKey().Bytes(), "enc from the labelled ephemeral key")

				k, ok := byKid[r.Kid]
				require.True(t, ok)
				o, err := privatebox.NewOpener(privKey(t, k.SK))
				require.NoError(t, err)
				pt, kid, err := o.Open(kind, env)
				require.NoError(t, err)
				assert.Equal(t, plain, pt)
				assert.Equal(t, hx(t, r.Kid), kid, "the reader's own entry opens first")
			}

			h, err := policy.PlaintextHash(kind, plain, e.ActionType)
			require.NoError(t, err)
			key := h
			if e.StateSalt != "" {
				assert.Equal(t, hx(t, e.PlainHash), h[:])
				key = policy.NewSaltHasher(hx(t, e.StateSalt)).BlobKey(kind, h)
			}
			assert.Equal(t, hx(t, e.Hash), key[:])
		})
	}
}

func TestEnvelopeRejects(t *testing.T) {
	d := load(t)
	require.Len(t, d.Reject, 5)
	for _, r := range d.Reject {
		t.Run(r.ID, func(t *testing.T) {
			env := hx(t, r.Envelope)
			assert.Equal(t, r.Size, strconv.Itoa(len(env)))
			var keys []*ecdh.PrivateKey
			for _, n := range r.Keys {
				keys = append(keys, privKey(t, d.Keys[n].SK))
			}
			o, err := privatebox.NewOpener(keys...)
			require.NoError(t, err)
			pt, _, err := o.Open(kindOf(t, r.Kind), env)
			switch r.Expect {
			case "policy_private":
				require.ErrorIs(t, err, policy.ErrPrivateUnopened)
			case "source_corrupt":
				if err == nil {
					h, herr := policy.PlaintextHash(kindOf(t, r.Kind), pt, "")
					require.True(t, herr != nil || !bytes.Equal(h[:], hx(t, r.Hash)), "opens to bytes of another hash")
					return
				}
				require.ErrorIs(t, err, policy.ErrPrivateCorrupt)
			default:
				require.FailNow(t, "unknown expectation "+r.Expect)
			}
		})
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	a := privKey(t, hex.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	b := privKey(t, hex.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	auditors := []policy.Auditor{
		{Kid: policy.AuditorKid(a.PublicKey().Bytes()), Pubkey: a.PublicKey().Bytes(), Label: "A"},
		{Kid: policy.AuditorKid(b.PublicKey().Bytes()), Pubkey: b.PublicKey().Bytes(), Label: "B"},
	}
	env, err := privatebox.Sealer{}.Seal(policy.PrivatePartKind, []byte("plaintext"), auditors)
	require.NoError(t, err)
	again, err := privatebox.Sealer{}.Seal(policy.PrivatePartKind, []byte("plaintext"), auditors)
	require.NoError(t, err)
	assert.NotEqual(t, env, again, "fresh randomness per envelope")
	for _, k := range []*ecdh.PrivateKey{a, b} {
		o, err := privatebox.NewOpener(k)
		require.NoError(t, err)
		pt, kid, err := o.Open(policy.PrivatePartKind, env)
		require.NoError(t, err)
		assert.Equal(t, []byte("plaintext"), pt)
		assert.Equal(t, policy.AuditorKid(k.PublicKey().Bytes()), kid)
	}
	other := privKey(t, hex.EncodeToString(bytes.Repeat([]byte{5}, 32)))
	o, err := privatebox.NewOpener(other)
	require.NoError(t, err)
	_, _, err = o.Open(policy.PrivatePartKind, env)
	require.ErrorIs(t, err, policy.ErrPrivateUnopened)

	// A payload blob is not a private envelope: the tags differ.
	rk, err := blob.NewRecipientKey(a)
	require.NoError(t, err)
	_, _, err = blob.Open(env, rk)
	require.Error(t, err)

	big := make([]byte, policy.MaxPrivateEnvelope)
	_, err = privatebox.Sealer{}.Seal(policy.PrivatePartKind, big, auditors)
	require.ErrorIs(t, err, blob.ErrTooLarge)
	_, err = privatebox.Sealer{}.Seal(policy.PrivateKind(6), []byte{1}, auditors)
	require.Error(t, err)
}

func TestOpenerNeverPrintsKeys(t *testing.T) {
	sk := bytes.Repeat([]byte{7}, 32)
	o, err := privatebox.NewOpener(privKey(t, hex.EncodeToString(sk)))
	require.NoError(t, err)
	for _, s := range []string{hex.EncodeToString(sk), string(sk)} {
		assert.NotContains(t, sprint(o), s)
	}
}

func sprint(v any) string { return fmt.Sprintf("%v %+v %#v %s", v, v, v, v) }

// FuzzOpen feeds arbitrary bytes to the opener: it never panics, and what it
// opens it opens to a plaintext under the suite's cap.
func FuzzOpen(f *testing.F) {
	d := load(f)
	for _, e := range d.Envelopes {
		f.Add(uint8(kindOf(f, e.Kind)), hx(f, e.Envelope))
	}
	for _, r := range d.Reject {
		if len(r.Envelope) < 4096 {
			f.Add(uint8(kindOf(f, r.Kind)), hx(f, r.Envelope))
		}
	}
	o, err := privatebox.NewOpener(privKey(f, d.Keys["auditor-1"].SK), privKey(f, d.Keys["auditor-2"].SK))
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, kind uint8, env []byte) {
		pt, kid, err := o.Open(policy.PrivateKind(kind), env)
		if err != nil {
			require.True(t, errors.Is(err, policy.ErrPrivateCorrupt) || errors.Is(err, policy.ErrPrivateUnopened), "%v", err)
			return
		}
		require.Len(t, kid, 16)
		require.Less(t, len(pt), policy.PrivateKind(kind).EnvelopeCap())
	})
}
