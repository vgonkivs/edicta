package commitment

import (
	"fmt"
	"math/bits"
)

const marginCap = 600

func satAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return s
}

// CheckAnchorTime requires issued_at + skew_s >= blockTime, so a decision
// signed before its payload was public is refused.
func CheckAnchorTime(c *Commitment, blockTime uint64, p Params) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrIssuedBeforeAnchor)
	}
	if satAdd(c.IssuedAt, p.SkewS) < blockTime {
		return fmt.Errorf("%w: issued_at %d, block time %d", ErrIssuedBeforeAnchor, c.IssuedAt, blockTime)
	}
	return nil
}

// RetentionMargin is min(600, floor(retention / 8)).
func RetentionMargin(retention uint64) uint64 {
	return min(marginCap, retention/8)
}

// WithinRetention reports valid_until + margin <= start + retention, with
// saturating sums. A nil commitment is never within the window.
func WithinRetention(c *Commitment, start, retention uint64) bool {
	if c == nil {
		return false
	}
	return satAdd(c.ValidUntil, RetentionMargin(retention)) <= satAdd(start, retention)
}
