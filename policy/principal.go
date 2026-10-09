package policy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/principalsig"
)

// ErrPrincipalPin: a trusted principal identity does not parse.
var ErrPrincipalPin = errors.New("policy: invalid principal identity")

// ParsePrincipal parses a trusted principal identity: "ed25519:<hex>",
// "cosmos:<bech32 address>", "eth:0x<hex20>", or a bare 32-byte hex key,
// which is Ed25519.
func ParsePrincipal(s string) (PrincipalID, error) {
	scheme, val, ok := strings.Cut(s, ":")
	if !ok {
		scheme, val = "ed25519", s
	}
	switch scheme {
	case "ed25519":
		b, err := hex.DecodeString(val)
		if err != nil {
			return PrincipalID{}, fmt.Errorf("%w: ed25519 key: %v", ErrPrincipalPin, err)
		}
		id := PrincipalID{Principal: b}
		return id, id.Validate()
	case "cosmos":
		id := PrincipalID{SigType: uint8(SigTypeADR036), Principal: []byte(val)}
		if err := id.Validate(); err != nil {
			return PrincipalID{}, err
		}
		id.Principal = []byte(strings.ToLower(val))
		return id, nil
	case "eth":
		b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(val), "0x"))
		if err != nil {
			return PrincipalID{}, fmt.Errorf("%w: eth address: %v", ErrPrincipalPin, err)
		}
		id := PrincipalID{SigType: uint8(SigTypeEIP712), Principal: b}
		return id, id.Validate()
	}
	return PrincipalID{}, fmt.Errorf("%w: unknown scheme %q", ErrPrincipalPin, scheme)
}

// Validate checks a trusted principal identity (a pin, see PrincipalID).
func (id PrincipalID) Validate() error {
	switch uint64(id.SigType) {
	case 0:
		if err := commitment.CheckPublicKey(id.Principal); err != nil {
			return fmt.Errorf("%w: %w", ErrPrincipalPin, err)
		}
	case SigTypeADR036:
		if _, _, err := principalsig.ParseCosmosAddress(string(id.Principal)); err != nil {
			return fmt.Errorf("%w: %w", ErrPrincipalPin, err)
		}
	case SigTypeEIP712:
		if len(id.Principal) != 20 {
			return fmt.Errorf("%w: eth address has %d bytes", ErrPrincipalPin, len(id.Principal))
		}
	default:
		return fmt.Errorf("%w: sig_type %d", ErrPrincipalPin, id.SigType)
	}
	return nil
}

// Pins reports whether the trusted identity names the mandate's principal,
// compared per scheme: a key or an address of another scheme never matches.
func (id PrincipalID) Pins(m *Mandate) bool {
	if uint64(id.SigType) != m.SigType {
		return false
	}
	if m.SigType == SigTypeADR036 {
		addr, err := principalsig.CosmosAddress(m.Principal, m.PrincipalHRP)
		return err == nil && addr == strings.ToLower(string(id.Principal))
	}
	return bytes.Equal(id.Principal, m.Principal)
}

// String is the parseable text form of the identity.
func (id PrincipalID) String() string {
	switch uint64(id.SigType) {
	case 0:
		return "ed25519:" + hex.EncodeToString(id.Principal)
	case SigTypeADR036:
		return "cosmos:" + string(id.Principal)
	case SigTypeEIP712:
		return "eth:0x" + hex.EncodeToString(id.Principal)
	}
	return fmt.Sprintf("sig_type%d:%x", id.SigType, id.Principal)
}
