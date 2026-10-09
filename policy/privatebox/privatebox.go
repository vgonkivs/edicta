// Package privatebox seals and opens the private records of a mandate with
// auditors: the payload blob layout under the policy's own tags and caps.
package privatebox

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk/blob"
)

// Suite is the envelope suite of a plaintext kind.
func Suite(kind policy.PrivateKind) blob.Suite {
	return blob.Suite{AEADTag: policy.TagPrivateAEAD, DEKTag: policy.TagPrivateDEK, MaxSize: kind.EnvelopeCap()}
}

// Sealer encrypts with fresh randomness from crypto/rand.
type Sealer struct{}

var _ policy.Sealer = Sealer{}

// Seal encrypts plaintext to every auditor, in mandate order, under the
// auditor's derived kid.
func (Sealer) Seal(kind policy.PrivateKind, plaintext []byte, auditors []policy.Auditor) ([]byte, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("privatebox: plaintext kind %d", kind)
	}
	if len(auditors) == 0 {
		return nil, errors.New("privatebox: no auditors")
	}
	rs := make([]blob.Recipient, len(auditors))
	for i, a := range auditors {
		pk, err := ecdh.X25519().NewPublicKey(a.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("privatebox: auditor %d key: %w", i, err)
		}
		rs[i] = blob.Recipient{KID: policy.AuditorKid(a.Pubkey), PublicKey: pk}
	}
	env, err := blob.SealWith(Suite(kind), plaintext, rs)
	if err != nil {
		return nil, fmt.Errorf("privatebox: seal: %w", err)
	}
	return env, nil
}

// Opener holds auditor private keys. It never prints them.
type Opener struct{ keys []blob.RecipientKey }

var _ policy.Opener = (*Opener)(nil)

// NewOpener wraps X25519 private keys; each tries its own derived kid first.
func NewOpener(keys ...*ecdh.PrivateKey) (*Opener, error) {
	o := &Opener{}
	for i, k := range keys {
		rk, err := blob.NewRecipientKey(k)
		if err != nil {
			return nil, fmt.Errorf("privatebox: key %d: %w", i, err)
		}
		rk.KID = policy.AuditorKid(k.PublicKey().Bytes())
		o.keys = append(o.keys, rk)
	}
	return o, nil
}

// NewOpenerFromKeys is NewOpener for keys held as recipient keys; their
// kids are replaced by the derived ones.
func NewOpenerFromKeys(keys ...blob.RecipientKey) (*Opener, error) {
	o := &Opener{}
	for i, k := range keys {
		pub := k.PublicKey()
		if pub == nil {
			return nil, fmt.Errorf("privatebox: key %d is not an X25519 private key", i)
		}
		k.KID = policy.AuditorKid(pub.Bytes())
		o.keys = append(o.keys, k)
	}
	return o, nil
}

// Kids are the derived kids of the opener's keys, in order.
func (o *Opener) Kids() [][]byte {
	out := make([][]byte, len(o.keys))
	for i, k := range o.keys {
		out[i] = append([]byte(nil), k.KID...)
	}
	return out
}

// Open decrypts with the first key that unwraps an entry. An envelope that
// does not decode, or whose AEAD fails after an unwrap, is corrupt; one no
// key unwraps is ErrPrivateUnopened.
func (o *Opener) Open(kind policy.PrivateKind, envelope []byte) (plaintext, kid []byte, err error) {
	if !kind.Valid() {
		return nil, nil, fmt.Errorf("%w: plaintext kind %d", policy.ErrPrivateCorrupt, kind)
	}
	if len(envelope) > kind.EnvelopeCap() {
		return nil, nil, fmt.Errorf("%w: envelope of %d bytes", policy.ErrPrivateCorrupt, len(envelope))
	}
	if _, err := blob.Decode(envelope); err != nil {
		return nil, nil, fmt.Errorf("%w: envelope: %v", policy.ErrPrivateCorrupt, err)
	}
	for _, k := range o.keys {
		pt, kid, err := blob.OpenWith(Suite(kind), envelope, k)
		switch {
		case err == nil:
			return pt, kid, nil
		case errors.Is(err, blob.ErrUnwrap), errors.Is(err, blob.ErrNoRecipient):
			continue
		}
		return nil, nil, fmt.Errorf("%w: %v", policy.ErrPrivateCorrupt, err)
	}
	return nil, nil, policy.ErrPrivateUnopened
}
