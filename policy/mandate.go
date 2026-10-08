package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/commitment"
)

const maxNotAfter = uint64(253402300799)

type PeriodLimit struct {
	Hours uint64 `cbor:"1,keyasint"`
	Max   []byte `cbor:"2,keyasint"`
}

type CountLimit struct {
	Hours    uint64 `cbor:"1,keyasint"`
	MaxCount uint64 `cbor:"2,keyasint"`
}

type AssetRule struct {
	Asset        string        `cbor:"1,keyasint"`
	Scale        uint64        `cbor:"2,keyasint"`
	PerActionMax []byte        `cbor:"3,keyasint,omitempty"`
	Periods      []PeriodLimit `cbor:"4,keyasint,omitempty"`
	Recipients   []string      `cbor:"5,keyasint,omitempty"`
}

type Mandate struct {
	Format         uint64       `cbor:"1,keyasint"`
	Principal      []byte       `cbor:"2,keyasint"`
	GateID         string       `cbor:"3,keyasint"`
	Agents         [][]byte     `cbor:"4,keyasint"`
	NotBefore      uint64       `cbor:"5,keyasint"`
	NotAfter       uint64       `cbor:"6,keyasint"`
	Assets         []AssetRule  `cbor:"7,keyasint"`
	CountLimits    []CountLimit `cbor:"8,keyasint,omitempty"`
	MandateID      []byte       `cbor:"9,keyasint"`
	Version        uint64       `cbor:"10,keyasint"`
	MaxDecisionAge uint64       `cbor:"11,keyasint,omitempty"`
	MinSpacing     uint64       `cbor:"12,keyasint,omitempty"`
	Kinds          []string     `cbor:"13,keyasint,omitempty"`
}

type SignedMandate struct {
	Mandate   Mandate `cbor:"1,keyasint"`
	Signature []byte  `cbor:"2,keyasint"`
}

func validGateID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-') {
			return false
		}
	}
	return true
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMandateInvalid, fmt.Sprintf(format, a...))
}

// ValidateBasic checks every stateless rule of the mandate.
func (m *Mandate) ValidateBasic() error {
	if m == nil {
		return errNil
	}
	if m.Format != 1 {
		return fmt.Errorf("%w: format %d: %w", ErrMandateInvalid, m.Format, commitment.ErrUnsupportedVersion)
	}
	for name, v := range map[string]uint64{"not_before": m.NotBefore, "not_after": m.NotAfter, "version": m.Version,
		"max_decision_age": m.MaxDecisionAge, "min_spacing": m.MinSpacing} {
		if v > maxInt {
			return fmt.Errorf("%w: %s: %w", ErrMandateInvalid, name, commitment.ErrIntRange)
		}
	}
	if err := commitment.CheckPublicKey(m.Principal); err != nil {
		return fmt.Errorf("%w: principal: %w", ErrMandateInvalid, err)
	}
	if !validGateID(m.GateID) {
		return bad("gate_id")
	}
	if n := len(m.Agents); n < 1 || n > 64 {
		return bad("%d agents", n)
	}
	for i, a := range m.Agents {
		if err := commitment.CheckPublicKey(a); err != nil {
			return fmt.Errorf("%w: agent %d: %w", ErrMandateInvalid, i, err)
		}
		if i > 0 && bytes.Compare(m.Agents[i-1], a) >= 0 {
			return bad("agents not strictly ascending")
		}
		if bytes.Equal(a, m.Principal) {
			return fmt.Errorf("%w: %w: principal listed as agent", ErrMandateInvalid, commitment.ErrKeyRole)
		}
	}
	switch {
	case m.NotBefore < 1:
		return bad("not_before is zero")
	case m.NotAfter <= m.NotBefore || m.NotAfter > maxNotAfter:
		return bad("not_after %d", m.NotAfter)
	case len(m.MandateID) != 16:
		return bad("mandate_id has %d bytes", len(m.MandateID))
	case m.Version < 1:
		return bad("version is zero")
	case m.MaxDecisionAge > 86400:
		return bad("max_decision_age %d", m.MaxDecisionAge)
	case m.MinSpacing > 2678400:
		return bad("min_spacing %d", m.MinSpacing)
	}
	if n := len(m.Kinds); n > 8 {
		return bad("%d kinds", n)
	}
	for i, k := range m.Kinds {
		if !validKind(k) {
			return bad("kind %q", k)
		}
		if i > 0 && m.Kinds[i-1] >= k {
			return bad("kinds not strictly ascending")
		}
	}
	if n := len(m.Assets); n < 1 || n > 16 {
		return bad("%d assets", n)
	}
	for i := range m.Assets {
		if i > 0 && m.Assets[i-1].Asset >= m.Assets[i].Asset {
			return bad("assets not strictly ascending")
		}
		if err := m.Assets[i].validate(); err != nil {
			return fmt.Errorf("%w: asset %d: %w", ErrMandateInvalid, i, err)
		}
	}
	if n := len(m.CountLimits); n > 4 {
		return bad("%d count limits", n)
	}
	for i, c := range m.CountLimits {
		if c.Hours < 1 || c.Hours > 744 || c.MaxCount < 1 || c.MaxCount > 1<<32 {
			return bad("count limit %d", i)
		}
		if i > 0 && m.CountLimits[i-1].Hours >= c.Hours {
			return bad("count limits not strictly ascending")
		}
	}
	return nil
}

func (r *AssetRule) validate() error {
	if !isPrintable(r.Asset, 1, 128) {
		return errors.New("asset outside its charset")
	}
	if r.Scale > 255 {
		return errors.New("scale above 255")
	}
	if r.PerActionMax == nil && len(r.Periods) == 0 {
		return fmt.Errorf("%w: neither per_action_max nor periods", commitment.ErrMissingField)
	}
	if r.PerActionMax != nil {
		if err := checkPositive(r.PerActionMax); err != nil {
			return fmt.Errorf("per_action_max: %w", err)
		}
	}
	if len(r.Periods) > 4 {
		return errors.New("more than 4 periods")
	}
	for i, p := range r.Periods {
		if p.Hours < 1 || p.Hours > 744 {
			return fmt.Errorf("period hours %d", p.Hours)
		}
		if err := checkPositive(p.Max); err != nil {
			return fmt.Errorf("period max: %w", err)
		}
		if i > 0 && r.Periods[i-1].Hours >= p.Hours {
			return errors.New("periods not strictly ascending")
		}
	}
	if r.Recipients != nil {
		if n := len(r.Recipients); n < 1 || n > 256 {
			return fmt.Errorf("%d recipients", n)
		}
		for i, s := range r.Recipients {
			if !isPrintable(s, 1, 128) {
				return errors.New("recipient outside its charset")
			}
			if i > 0 && r.Recipients[i-1] >= s {
				return errors.New("recipients not strictly ascending")
			}
		}
	}
	return nil
}

func checkPositive(b []byte) error {
	if err := checkAmount(b); err != nil {
		return err
	}
	if len(b) == 1 && b[0] == 0 {
		return fmt.Errorf("%w: zero", commitment.ErrZeroValue)
	}
	return nil
}

// Covers reports whether the agent key is one of the mandate's agents.
func (m *Mandate) Covers(agentPub []byte) bool {
	for _, a := range m.Agents {
		if bytes.Equal(a, agentPub) {
			return true
		}
	}
	return false
}

// CounterKey is the registry key of the mandate's counter.
func (m *Mandate) CounterKey() [32]byte {
	return sha256.Sum256(tagged(TagCounter, m.Principal, m.MandateID))
}

// AssetRuleFor returns the index of the rule for an asset, or -1.
func (m *Mandate) AssetRuleFor(asset string) int {
	return slices.IndexFunc(m.Assets, func(r AssetRule) bool { return r.Asset == asset })
}

// EncodeMandate returns the canonical bytes of a validated mandate.
func EncodeMandate(m *Mandate) ([]byte, error) {
	if err := m.ValidateBasic(); err != nil {
		return nil, err
	}
	return marshal(m)
}

func HashMandate(canon []byte) commitment.Hash { return hashTagged(TagMandate, canon) }

func MandateSigningMessage(h commitment.Hash) []byte { return signingMessage(TagMandateSig, h) }

// SignMandate signs the mandate with the principal key and returns the
// canonical SignedMandate and the mandate hash.
func SignMandate(priv ed25519.PrivateKey, m *Mandate) ([]byte, commitment.Hash, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, commitment.Hash{}, fmt.Errorf("policy: private key has %d bytes", len(priv))
	}
	canon, err := EncodeMandate(m)
	if err != nil {
		return nil, commitment.Hash{}, err
	}
	if pub, ok := priv.Public().(ed25519.PublicKey); !ok || !bytes.Equal(pub, m.Principal) {
		return nil, commitment.Hash{}, fmt.Errorf("%w: private key is not the principal", ErrMandateSignature)
	}
	h := HashMandate(canon)
	sm := SignedMandate{Mandate: *m, Signature: ed25519.Sign(priv, MandateSigningMessage(h))}
	b, err := marshal(&sm)
	return b, h, err
}

// DecodeSignedMandate strictly decodes a SignedMandate without checking the
// signature.
func DecodeSignedMandate(b []byte) (*SignedMandate, commitment.Hash, error) {
	var sm SignedMandate
	if err := decodeStrict(b, maxSignedSize, &sm, ErrMandateInvalid); err != nil {
		return nil, commitment.Hash{}, err
	}
	if len(sm.Signature) != 64 {
		return nil, commitment.Hash{}, fmt.Errorf("%w: signature has %d bytes: %w", ErrMandateInvalid, len(sm.Signature), commitment.ErrFieldSize)
	}
	if err := sm.Mandate.ValidateBasic(); err != nil {
		return nil, commitment.Hash{}, err
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(&sm) }, ErrMandateInvalid); err != nil {
		return nil, commitment.Hash{}, err
	}
	canon, err := marshal(&sm.Mandate)
	if err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("%w: %v", ErrMandateInvalid, err)
	}
	return &sm, HashMandate(canon), nil
}

// VerifyMandate decodes and checks the principal signature.
func VerifyMandate(b []byte) (*SignedMandate, commitment.Hash, error) {
	sm, h, err := DecodeSignedMandate(b)
	if err != nil {
		return nil, commitment.Hash{}, err
	}
	if !ed25519.Verify(sm.Mandate.Principal, MandateSigningMessage(h), sm.Signature) {
		return nil, commitment.Hash{}, ErrMandateSignature
	}
	return sm, h, nil
}
