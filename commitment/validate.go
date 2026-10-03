package commitment

import (
	"fmt"
	"math/bits"
)

// ValidateStatic runs stage S in the normative order.
func ValidateStatic(c *Commitment, p Params) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrUnsupportedActionKind)
	}
	o := c.Action.IBKROrder
	if c.Action.Kind != KindIBKROrderV0 || o == nil {
		return fmt.Errorf("%w: %q", ErrUnsupportedActionKind, c.Action.Kind)
	}
	ref := &c.PayloadRef

	if c.Version != 0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, c.Version)
	}

	uints := []struct {
		name string
		v    uint64
	}{
		{"version", c.Version}, {"issued_at", c.IssuedAt}, {"valid_until", c.ValidUntil},
		{"rail", uint64(c.Scope.Rail)}, {"conid", o.ConID}, {"side", uint64(o.Side)},
		{"qty", o.Qty}, {"order_type", uint64(o.OrderType)}, {"tif", uint64(o.TIF)},
		{"max_notional", c.Constraints.MaxNotional}, {"da", uint64(ref.DA)},
		{"height", ref.Height}, {"payload_size", c.PayloadSize},
	}
	for _, f := range []struct {
		name string
		v    *uint64
	}{
		{"limit_price", o.LimitPrice}, {"price_bound", c.Constraints.PriceBound},
		{"deadline", c.Constraints.Deadline},
	} {
		if f.v != nil {
			uints = append(uints, struct {
				name string
				v    uint64
			}{f.name, *f.v})
		}
	}
	for _, u := range uints {
		if u.v > maxUint63 {
			return fmt.Errorf("%w: %s", ErrIntRange, u.name)
		}
	}

	switch {
	case o.Side != SideBuy && o.Side != SideSell:
		return fmt.Errorf("%w: side %d", ErrInvalidEnum, o.Side)
	case o.OrderType != OrderLimit && o.OrderType != OrderMarket:
		return fmt.Errorf("%w: order_type %d", ErrInvalidEnum, o.OrderType)
	case o.TIF < 1 || o.TIF > 3:
		return fmt.Errorf("%w: tif %d", ErrInvalidEnum, o.TIF)
	case ref.DA != DAFibre && ref.DA != DACelestiaBlob:
		return fmt.Errorf("%w: da %d", ErrInvalidEnum, ref.DA)
	case c.Scope.Rail == 0:
		return fmt.Errorf("%w: rail 0", ErrInvalidEnum)
	}

	if c.Scope.Rail != RailIBKR {
		return fmt.Errorf("%w: %d", ErrUnsupportedRail, c.Scope.Rail)
	}
	if o.OrderType == OrderMarket {
		return ErrUnsupportedOrderType
	}

	zero := func(name string, v uint64) error {
		if v == 0 {
			return fmt.Errorf("%w: %s", ErrZeroValue, name)
		}
		return nil
	}
	for _, z := range []struct {
		name string
		v    uint64
	}{
		{"issued_at", c.IssuedAt}, {"conid", o.ConID}, {"qty", o.Qty},
	} {
		if err := zero(z.name, z.v); err != nil {
			return err
		}
	}
	if o.LimitPrice != nil {
		if err := zero("limit_price", *o.LimitPrice); err != nil {
			return err
		}
	}
	if err := zero("max_notional", c.Constraints.MaxNotional); err != nil {
		return err
	}
	if c.Constraints.PriceBound != nil {
		if err := zero("price_bound", *c.Constraints.PriceBound); err != nil {
			return err
		}
	}
	if err := zero("height", ref.Height); err != nil {
		return err
	}
	if err := zero("payload_size", c.PayloadSize); err != nil {
		return err
	}

	if c.PayloadSize > MaxPayloadSize {
		return fmt.Errorf("%w: %d", ErrPayloadTooLarge, c.PayloadSize)
	}
	if !validNamespace(ref.Namespace) {
		return ErrInvalidNamespace
	}
	if o.OrderType == OrderLimit && o.LimitPrice == nil {
		return fmt.Errorf("%w: LMT without limit_price", ErrLimitPrice)
	}
	if c.Scope.Account != o.Account {
		return ErrAccountMismatch
	}
	if c.Scope.ChainID != nil {
		return ErrChainIDRule
	}
	if c.ValidUntil <= c.IssuedAt {
		return fmt.Errorf("%w: valid_until %d, issued_at %d", ErrTimeOrder, c.ValidUntil, c.IssuedAt)
	}
	if d := c.Constraints.Deadline; d != nil && (*d <= c.IssuedAt || *d > c.ValidUntil) {
		return fmt.Errorf("%w: deadline %d", ErrDeadlineRange, *d)
	}
	if ttl, max := c.ValidUntil-c.IssuedAt, p.MaxTTL(ref.DA); ttl > max {
		return fmt.Errorf("%w: ttl %d, max %d", ErrTTLTooLong, ttl, max)
	}

	if pb := c.Constraints.PriceBound; pb != nil {
		if o.Side == SideBuy && *o.LimitPrice > *pb || o.Side == SideSell && *o.LimitPrice < *pb {
			return ErrPriceBound
		}
	}

	// Both products are below 2^127, so 128-bit arithmetic is exact.
	lh, ll := bits.Mul64(o.Qty, *o.LimitPrice)
	bh, bl := bits.Mul64(c.Constraints.MaxNotional, QtyScale)
	if lh > bh || lh == bh && ll > bl {
		return ErrNotionalExceeded
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

// CheckTime implements T1 and T2. Skew only ever shortens validity at the end.
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
	expiry := c.ValidUntil
	if c.Constraints.Deadline != nil {
		expiry = *c.Constraints.Deadline
	}
	if horizon >= expiry {
		return fmt.Errorf("%w: expiry %d, now %d", ErrExpired, expiry, now)
	}
	return nil
}

func CheckScope(c *Commitment, g GateScope) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrScopeMismatch)
	}
	s := c.Scope
	same := s.GateID == g.GateID && s.Rail == g.Rail && s.Account == g.Account &&
		(s.ChainID == nil) == (g.ChainID == nil) &&
		(s.ChainID == nil || *s.ChainID == *g.ChainID)
	if !same {
		return ErrScopeMismatch
	}
	return nil
}

// CheckAction matches the order about to be placed against the committed
// params. Symbol is informational and ignored (rule A1).
func CheckAction(c *Commitment, req IBKROrderV0) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrActionMismatch)
	}
	o := c.Action.IBKROrder
	if o == nil {
		return fmt.Errorf("%w: commitment has no order params", ErrActionMismatch)
	}
	same := o.Account == req.Account && o.ConID == req.ConID && o.Side == req.Side &&
		o.Qty == req.Qty && o.OrderType == req.OrderType && o.Currency == req.Currency &&
		o.TIF == req.TIF &&
		(o.LimitPrice == nil) == (req.LimitPrice == nil) &&
		(o.LimitPrice == nil || *o.LimitPrice == *req.LimitPrice)
	if !same {
		return ErrActionMismatch
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
