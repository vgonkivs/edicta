// Package blob is the published payload: a canonical CBOR container holding
// the payload encrypted once under a random DEK, with the DEK wrapped for each
// recipient by HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305).
package blob

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	Version           = 1
	MinRecipients     = 1
	MaxRecipients     = 16
	MaxKIDSize        = 32
	EncSize           = 32
	WrappedDEKSize    = 48
	NonceSize         = 12
	SaltSize          = 32
	MinCiphertextSize = SaltSize + 1 + 16
	MaxDecodeSize     = commitment.MaxPayloadSize
	MaxSealSize       = commitment.MaxPayloadSize - 5

	TagPayloadAEAD = "edicta/v1/payload"
	TagPayloadDEK  = "edicta/v1/payload-dek"

	dekSize = chacha20poly1305.KeySize
)

var (
	ErrTooLarge     = errors.New("blob: too large")
	ErrMalformed    = errors.New("blob: malformed")
	ErrVersion      = errors.New("blob: unsupported version")
	ErrRecipients   = errors.New("blob: recipient count out of range")
	ErrDuplicateKID = errors.New("blob: duplicate recipient kid")
	ErrNoRecipient  = errors.New("blob: no entry for this key")
	ErrUnwrap       = errors.New("blob: DEK unwrap failed")
	ErrDecrypt      = errors.New("blob: payload decryption failed")
	ErrRecipientKey = errors.New("blob: invalid recipient key")
)

// Recipient is a public X25519 key and the public label that selects its entry.
// Labels are written in cleartext into the blob.
type Recipient struct {
	KID       []byte
	PublicKey *ecdh.PublicKey
}

// RecipientKey is a private X25519 key. An empty KID makes Open try every
// entry. Build one with NewRecipientKey; a zero value is not usable.
//
// The key sits behind a pointer to an unexported struct that itself holds a
// pointer: fmt prints the pointee of a pointer it cannot format, and that
// pointee must show only an address, never key bytes.
type RecipientKey struct {
	KID []byte
	key *keyHolder
}

type keyHolder struct{ pk *ecdh.PrivateKey }

// NewRecipientKey wraps an X25519 private key.
func NewRecipientKey(pk *ecdh.PrivateKey) (RecipientKey, error) {
	if pk == nil || pk.Curve() != ecdh.X25519() {
		return RecipientKey{}, fmt.Errorf("%w: not an X25519 private key", ErrRecipientKey)
	}
	return RecipientKey{key: &keyHolder{pk: pk}}, nil
}

// String shows the label only; the private key is never printed.
func (k RecipientKey) String() string {
	return "RecipientKey(kid=" + hex.EncodeToString(k.KID) + ", key redacted)"
}

// Format makes every fmt verb print the redacted form.
func (k RecipientKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

func (k RecipientKey) GoString() string { return k.String() }

func (k RecipientKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

func (k RecipientKey) MarshalJSON() ([]byte, error) { return nil, errNoMarshal }
func (k RecipientKey) MarshalText() ([]byte, error) { return nil, errNoMarshal }

var errNoMarshal = errors.New("blob: a recipient key has no serialized form")

type Entry struct {
	KID        []byte
	Enc        [EncSize]byte
	WrappedDEK [WrappedDEKSize]byte
}

type Blob struct {
	Version    uint64
	Recipients []Entry
	AEADNonce  [NonceSize]byte
	Ciphertext []byte // includes the 16-byte Poly1305 tag
}

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

func entryAAD(kid []byte) []byte {
	return append([]byte{byte(len(kid))}, kid...)
}

// Seal draws a fresh salt, encrypts salt || plaintext once under a fresh DEK,
// wraps the DEK for every recipient and returns the canonical blob and the
// salt. Randomness comes from crypto/rand only; a caller cannot supply any.
func Seal(plaintext []byte, rs []Recipient) (raw []byte, salt [SaltSize]byte, err error) {
	raw, err = seal(&salt, plaintext, rs, payloadSuite, MaxSealSize)
	if err != nil {
		return nil, [SaltSize]byte{}, err
	}
	return raw, salt, nil
}

// Suite is the domain of one envelope family: the tag used as the AEAD aad,
// the tag used as the HPKE info of the DEK wraps, and the cap of the encoded
// envelope. The payload and the policy's private records share the layout
// and differ only here.
type Suite struct {
	AEADTag string
	DEKTag  string
	MaxSize int
}

func (s Suite) aad() []byte  { return append([]byte{byte(len(s.AEADTag))}, s.AEADTag...) }
func (s Suite) info() []byte { return append([]byte{byte(len(s.DEKTag))}, s.DEKTag...) }

func (s Suite) valid() bool {
	return s.AEADTag != "" && s.DEKTag != "" && len(s.AEADTag) < 256 && len(s.DEKTag) < 256 &&
		s.MaxSize > 0 && s.MaxSize <= MaxDecodeSize
}

var payloadSuite = Suite{AEADTag: TagPayloadAEAD, DEKTag: TagPayloadDEK, MaxSize: MaxDecodeSize}

// SealWith seals plaintext under the suite's tags. The envelope salt is drawn
// as for a payload and discarded: the suite's readers do not use it.
func SealWith(s Suite, plaintext []byte, rs []Recipient) ([]byte, error) {
	if !s.valid() {
		return nil, fmt.Errorf("%w: invalid suite", ErrMalformed)
	}
	var salt [SaltSize]byte
	return seal(&salt, plaintext, rs, s, s.MaxSize)
}

func seal(salt *[SaltSize]byte, plaintext []byte, rs []Recipient, s Suite, maxSize int) ([]byte, error) {
	if len(rs) < MinRecipients || len(rs) > MaxRecipients {
		return nil, fmt.Errorf("%w: %d", ErrRecipients, len(rs))
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrMalformed)
	}
	kids := make([][]byte, len(rs))
	for i, r := range rs {
		kids[i] = r.KID
		if r.PublicKey == nil || r.PublicKey.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: recipient %d is not an X25519 public key", ErrRecipientKey, i)
		}
	}
	if err := checkKIDs(kids); err != nil {
		return nil, err
	}
	ctLen := SaltSize + len(plaintext) + chacha20poly1305.Overhead
	if size := encodedSize(kids, ctLen); size > maxSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, size)
	}

	rand.Read(salt[:])
	kdf, aead := suite()
	dek := make([]byte, dekSize)
	rand.Read(dek)
	defer clear(dek)

	b := &Blob{Version: Version, Recipients: make([]Entry, len(rs))}
	for i, r := range rs {
		pk, err := hpke.NewDHKEMPublicKey(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrRecipientKey, i, err)
		}
		enc, sender, err := hpke.NewSender(pk, kdf, aead, s.info())
		if err != nil {
			return nil, fmt.Errorf("blob: hpke sender for recipient %d: %w", i, err)
		}
		wrapped, err := sender.Seal(entryAAD(r.KID), dek)
		if err != nil {
			return nil, fmt.Errorf("blob: wrap for recipient %d: %w", i, err)
		}
		e := &b.Recipients[i]
		e.KID = bytes.Clone(r.KID)
		if copy(e.Enc[:], enc) != EncSize || len(wrapped) != WrappedDEKSize {
			return nil, fmt.Errorf("blob: unexpected hpke output sizes %d, %d", len(enc), len(wrapped))
		}
		copy(e.WrappedDEK[:], wrapped)
	}

	rand.Read(b.AEADNonce[:])
	cipher, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, fmt.Errorf("blob: aead: %w", err)
	}
	msg := make([]byte, 0, SaltSize+len(plaintext))
	msg = append(msg, salt[:]...)
	msg = append(msg, plaintext...)
	b.Ciphertext = cipher.Seal(nil, b.AEADNonce[:], msg, s.aad())
	clear(msg)
	return Encode(b)
}

func checkKIDs(kids [][]byte) error {
	seen := make(map[string]struct{}, len(kids))
	for i, kid := range kids {
		if len(kid) < 1 || len(kid) > MaxKIDSize {
			return fmt.Errorf("%w: recipient %d kid of %d bytes", ErrMalformed, i, len(kid))
		}
		if _, dup := seen[string(kid)]; dup {
			return fmt.Errorf("%w: recipient %d", ErrDuplicateKID, i)
		}
		seen[string(kid)] = struct{}{}
	}
	return nil
}

// headLen is the size of a CBOR head carrying n in shortest form.
func headLen(n uint64) int {
	switch {
	case n < 24:
		return 1
	case n < 1<<8:
		return 2
	case n < 1<<16:
		return 3
	case n < 1<<32:
		return 5
	}
	return 9
}

func encodedSize(kids [][]byte, ctLen int) int {
	n := 1 + 2 + 1 + headLen(uint64(len(kids)))
	for _, kid := range kids {
		n += 1 + 1 + headLen(uint64(len(kid))) + len(kid) + 1 + headLen(EncSize) + EncSize + 1 + headLen(WrappedDEKSize) + WrappedDEKSize
	}
	n += 1 + headLen(NonceSize) + NonceSize + 1 + headLen(uint64(ctLen)) + ctLen
	return n
}

func appendHead(dst []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(dst, m|byte(n))
	case n < 1<<8:
		return append(dst, m|24, byte(n))
	case n < 1<<16:
		return append(dst, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(dst, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(dst, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendBytes(dst, b []byte) []byte {
	return append(appendHead(dst, 2, uint64(len(b))), b...)
}

// Encode returns the canonical encoding of b after the checks of Decode.
func Encode(b *Blob) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: nil blob", ErrMalformed)
	}
	if b.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, b.Version)
	}
	if len(b.Recipients) < MinRecipients || len(b.Recipients) > MaxRecipients {
		return nil, fmt.Errorf("%w: %d", ErrRecipients, len(b.Recipients))
	}
	kids := make([][]byte, len(b.Recipients))
	for i, e := range b.Recipients {
		kids[i] = e.KID
	}
	if err := checkKIDs(kids); err != nil {
		return nil, err
	}
	if len(b.Ciphertext) < MinCiphertextSize {
		return nil, fmt.Errorf("%w: ciphertext of %d bytes", ErrMalformed, len(b.Ciphertext))
	}
	size := encodedSize(kids, len(b.Ciphertext))
	if size > MaxDecodeSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, size)
	}
	out := make([]byte, 0, size)
	out = append(out, 0xa4, 0x01, Version, 0x02)
	out = appendHead(out, 4, uint64(len(b.Recipients)))
	for i := range b.Recipients {
		e := &b.Recipients[i]
		out = append(out, 0xa3, 0x01)
		out = appendBytes(out, e.KID)
		out = append(out, 0x02)
		out = appendBytes(out, e.Enc[:])
		out = append(out, 0x03)
		out = appendBytes(out, e.WrappedDEK[:])
	}
	out = append(out, 0x03)
	out = appendBytes(out, b.AEADNonce[:])
	out = append(out, 0x04)
	out = appendBytes(out, b.Ciphertext)
	return out, nil
}

type parser struct {
	b   []byte
	off int
}

func (p *parser) malformed(what string) error {
	return fmt.Errorf("%w: %s at byte %d", ErrMalformed, what, p.off)
}

// head reads one CBOR head in shortest, definite form.
func (p *parser) head() (major byte, arg uint64, err error) {
	if p.off >= len(p.b) {
		return 0, 0, p.malformed("truncated")
	}
	ib := p.b[p.off]
	major, ai := ib>>5, ib&0x1f
	var n int
	switch {
	case ai < 24:
		p.off++
		return major, uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	default:
		return 0, 0, p.malformed("indefinite or reserved head")
	}
	if len(p.b)-p.off-1 < n {
		return 0, 0, p.malformed("truncated")
	}
	for _, c := range p.b[p.off+1 : p.off+1+n] {
		arg = arg<<8 | uint64(c)
	}
	min := [...]uint64{1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]
	if arg < min {
		return 0, 0, p.malformed("head not in shortest form")
	}
	p.off += 1 + n
	return major, arg, nil
}

func (p *parser) expect(major byte, arg uint64, what string) error {
	m, a, err := p.head()
	if err != nil {
		return err
	}
	if m != major || a != arg {
		return p.malformed(what)
	}
	return nil
}

func (p *parser) key(k byte) error {
	if p.off >= len(p.b) || p.b[p.off] != k {
		return p.malformed(fmt.Sprintf("expected key %d", k))
	}
	p.off++
	return nil
}

// bstr reads a byte string whose length is within [min, max].
func (p *parser) bstr(min, max uint64, what string) ([]byte, error) {
	m, n, err := p.head()
	if err != nil {
		return nil, err
	}
	if m != 2 {
		return nil, p.malformed(what + " is not a byte string")
	}
	if n < min || n > max {
		return nil, p.malformed(fmt.Sprintf("%s of %d bytes", what, n))
	}
	if uint64(len(p.b)-p.off) < n {
		return nil, p.malformed("truncated")
	}
	s := p.b[p.off : p.off+int(n)]
	p.off += int(n)
	return s, nil
}

// Decode accepts exactly the canonical encodings of the blob layout.
func Decode(raw []byte) (*Blob, error) {
	if len(raw) > MaxDecodeSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	p := &parser{b: raw}
	if p.off >= len(raw) || raw[0] != 0xa4 {
		return nil, p.malformed("top item is not a map of 4 pairs")
	}
	p.off++
	if err := p.key(1); err != nil {
		return nil, err
	}
	m, v, err := p.head()
	if err != nil {
		return nil, err
	}
	if m != 0 {
		return nil, p.malformed("version is not a uint")
	}
	if v != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, v)
	}
	if err := p.key(2); err != nil {
		return nil, err
	}
	m, n, err := p.head()
	if err != nil {
		return nil, err
	}
	if m != 4 {
		return nil, p.malformed("recipients is not an array")
	}
	if n < MinRecipients || n > MaxRecipients {
		return nil, fmt.Errorf("%w: %d", ErrRecipients, n)
	}
	b := &Blob{Version: Version, Recipients: make([]Entry, n)}
	seen := make(map[string]struct{}, n)
	for i := range b.Recipients {
		e := &b.Recipients[i]
		if err := p.expect(5, 3, "entry is not a map of 3 pairs"); err != nil {
			return nil, err
		}
		if err := p.key(1); err != nil {
			return nil, err
		}
		kid, err := p.bstr(1, MaxKIDSize, "kid")
		if err != nil {
			return nil, err
		}
		if _, dup := seen[string(kid)]; dup {
			return nil, fmt.Errorf("%w: entry %d", ErrDuplicateKID, i)
		}
		seen[string(kid)] = struct{}{}
		e.KID = bytes.Clone(kid)
		if err := p.key(2); err != nil {
			return nil, err
		}
		enc, err := p.bstr(EncSize, EncSize, "enc")
		if err != nil {
			return nil, err
		}
		copy(e.Enc[:], enc)
		if err := p.key(3); err != nil {
			return nil, err
		}
		w, err := p.bstr(WrappedDEKSize, WrappedDEKSize, "wrapped_dek")
		if err != nil {
			return nil, err
		}
		copy(e.WrappedDEK[:], w)
	}
	if err := p.key(3); err != nil {
		return nil, err
	}
	nonce, err := p.bstr(NonceSize, NonceSize, "aead_nonce")
	if err != nil {
		return nil, err
	}
	copy(b.AEADNonce[:], nonce)
	if err := p.key(4); err != nil {
		return nil, err
	}
	ct, err := p.bstr(MinCiphertextSize, MaxDecodeSize, "ciphertext")
	if err != nil {
		return nil, err
	}
	b.Ciphertext = bytes.Clone(ct)
	if p.off != len(raw) {
		return nil, p.malformed("trailing bytes")
	}
	return b, nil
}

// Open returns the AEAD plaintext split into salt and plaintext for the entry
// of k. The result is NOT bound to any commitment: two recipients of one blob
// can be made to open different plaintexts, because ChaCha20-Poly1305 does not
// commit to its key. Callers that need the committed decision use
// sdk.OpenPayload, which compares the plaintext hash before parsing.
func Open(raw []byte, k RecipientKey) (salt [SaltSize]byte, plaintext []byte, err error) {
	salt, plaintext, _, err = open(raw, k, payloadSuite, false)
	return salt, plaintext, err
}

// OpenWith opens an envelope of the suite. It tries the entry whose kid is
// k.KID first and then every other entry, and returns the plaintext without
// the envelope salt and the kid of the entry that opened. The binding caveat
// of Open applies: the caller compares the plaintext's hash.
func OpenWith(s Suite, raw []byte, k RecipientKey) (plaintext, kid []byte, err error) {
	if !s.valid() {
		return nil, nil, fmt.Errorf("%w: invalid suite", ErrMalformed)
	}
	if len(raw) > s.MaxSize {
		return nil, nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	_, plaintext, kid, err = open(raw, k, s, true)
	return plaintext, kid, err
}

// open tries the entries of k.KID first and, with others set, every other
// entry after them. The first unwrap that succeeds decides: an AEAD failure
// then is ErrDecrypt, never a reason to try another entry.
func open(raw []byte, k RecipientKey, s Suite, others bool) (salt [SaltSize]byte, plaintext, kid []byte, err error) {
	if k.key == nil || k.key.pk == nil || k.key.pk.Curve() != ecdh.X25519() {
		return salt, nil, nil, fmt.Errorf("%w: not an X25519 private key", ErrRecipientKey)
	}
	b, err := Decode(raw)
	if err != nil {
		return salt, nil, nil, err
	}
	var candidates, rest []*Entry
	for i := range b.Recipients {
		if len(k.KID) == 0 || bytes.Equal(b.Recipients[i].KID, k.KID) {
			candidates = append(candidates, &b.Recipients[i])
		} else if others {
			rest = append(rest, &b.Recipients[i])
		}
	}
	candidates = append(candidates, rest...)
	if len(candidates) == 0 {
		return salt, nil, nil, ErrNoRecipient
	}
	kdf, aead := suite()
	sk, err := hpke.NewDHKEMPrivateKey(k.key.pk)
	if err != nil {
		return salt, nil, nil, fmt.Errorf("%w: %v", ErrRecipientKey, err)
	}
	for _, e := range candidates {
		dek, ok := unwrap(e, sk, kdf, aead, s.info())
		if !ok {
			continue
		}
		defer clear(dek)
		cipher, err := chacha20poly1305.New(dek)
		if err != nil {
			return salt, nil, nil, fmt.Errorf("blob: aead: %w", err)
		}
		msg, err := cipher.Open(nil, b.AEADNonce[:], b.Ciphertext, s.aad())
		if err != nil {
			return salt, nil, nil, ErrDecrypt
		}
		defer clear(msg)
		copy(salt[:], msg)
		return salt, bytes.Clone(msg[SaltSize:]), bytes.Clone(e.KID), nil
	}
	return salt, nil, nil, ErrUnwrap
}

func unwrap(e *Entry, sk hpke.PrivateKey, kdf hpke.KDF, aead hpke.AEAD, info []byte) ([]byte, bool) {
	r, err := hpke.NewRecipient(e.Enc[:], sk, kdf, aead, info)
	if err != nil {
		return nil, false
	}
	dek, err := r.Open(entryAAD(e.KID), e.WrappedDEK[:])
	if err != nil || len(dek) != dekSize {
		return nil, false
	}
	return dek, true
}
