package commitment

import (
	"fmt"
	"math/bits"
	"slices"
)

// ValidateStatic runs static validation in the normative order.
func ValidateStatic(c *Commitment, p Params) error {
	if c == nil {
		return errNilCommitment
	}
	ref := &c.PayloadRef

	if c.Version != 0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, c.Version)
	}

	for _, u := range []struct {
		name string
		v    uint64
	}{
		{"version", c.Version}, {"issued_at", c.IssuedAt}, {"valid_until", c.ValidUntil},
		{"da", uint64(ref.DA)}, {"height", ref.Height}, {"payload_size", c.PayloadSize},
	} {
		if u.v > maxUint63 {
			return fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}

	if ref.DA != DAFibre && ref.DA != DACelestiaBlob {
		return fmt.Errorf("%w: da %d", ErrInvalidEnum, ref.DA)
	}

	for _, z := range []struct {
		name string
		v    uint64
	}{
		{"issued_at", c.IssuedAt}, {"height", ref.Height}, {"payload_size", c.PayloadSize},
	} {
		if z.v == 0 {
			return fmt.Errorf("%w: %s", ErrZeroValue, z.name)
		}
	}

	if c.PayloadSize > MaxPayloadSize {
		return fmt.Errorf("%w: %d", ErrPayloadTooLarge, c.PayloadSize)
	}
	if !validNamespace(ref.Namespace) {
		return ErrInvalidNamespace
	}
	if c.ValidUntil <= c.IssuedAt {
		return fmt.Errorf("%w: valid_until %d, issued_at %d", ErrTimeOrder, c.ValidUntil, c.IssuedAt)
	}
	if ttl, max := c.ValidUntil-c.IssuedAt, p.MaxTTL(ref.DA); ttl > max {
		return fmt.Errorf("%w: ttl %d, max %d", ErrTTLTooLong, ttl, max)
	}
	return nil
}

// validNamespace reports whether ns is an acceptable blob namespace.
func validNamespace(ns []byte) bool {
	if len(ns) != 29 || ns[0] != 0 {
		return false
	}
	for _, b := range ns[1:19] {
		if b != 0 {
			return false
		}
	}
	for _, b := range ns[19:28] {
		if b != 0 {
			return true
		}
	}
	return false
}

// CheckTime checks the start and expiry of validity. Skew only ever shortens validity at the end.
func CheckTime(c *Commitment, now uint64, p Params) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrExpired)
	}
	horizon, carry := bits.Add64(now, p.SkewS, 0)
	if carry != 0 {
		horizon = ^uint64(0)
	}
	if c.IssuedAt > horizon {
		return fmt.Errorf("%w: issued_at %d, now %d", ErrNotYetValid, c.IssuedAt, now)
	}
	if horizon >= c.ValidUntil {
		return fmt.Errorf("%w: valid_until %d, now %d", ErrExpired, c.ValidUntil, now)
	}
	return nil
}

// CheckScope requires the commitment to name this gate and an action type the
// gate is configured for.
func CheckScope(c *Commitment, g GateScope) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrScopeMismatch)
	}
	if c.Scope.GateID != g.GateID {
		return ErrScopeMismatch
	}
	if !slices.Contains(g.ActionTypes, c.Action.Type) {
		return fmt.Errorf("%w: %q", ErrActionTypeNotAllowed, c.Action.Type)
	}
	return nil
}

// VerifyForGate is the normative pipeline D, S, G, T, C.
func VerifyForGate(b []byte, now uint64, g GateScope, p Params) (*SignedCommitment, Hash, error) {
	if err := p.Validate(); err != nil {
		return nil, Hash{}, err
	}
	s, err := DecodeSigned(b)
	if err != nil {
		return nil, Hash{}, err
	}
	if err := ValidateStatic(&s.Commitment, p); err != nil {
		return nil, Hash{}, err
	}
	h, err := Verify(s)
	if err != nil {
		return nil, Hash{}, err
	}
	if err := CheckTime(&s.Commitment, now, p); err != nil {
		return nil, Hash{}, err
	}
	if err := CheckScope(&s.Commitment, g); err != nil {
		return nil, Hash{}, err
	}
	return s, h, nil
}
