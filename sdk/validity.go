package sdk

import (
	"fmt"
	"math/bits"

	"github.com/vgonkivs/edicta/commitment"
)

// Window is everything ChooseValidity needs; all times are Unix seconds.
type Window struct {
	Now, BlockTime, RetentionStart            uint64
	DA                                        commitment.DA
	FibreLatestS, FibreAtHeightS              uint64 // da = 1 only
	BlobRetentionS, SkewS, TTLS, MinValidityS uint64
	Deadline                                  *uint64
}

// Validity reports what ChooseValidity decided.
type Validity struct {
	IssuedAt       uint64
	ValidUntil     uint64 // effective value, as signed
	RequestedUntil uint64 // deadline if set, else issued_at + TTLS
	Clamped        bool   // ValidUntil < RequestedUntil
	ClampedBy      string // "", "max_ttl" or "retention"
	Expiry         uint64 // deadline if set, else ValidUntil
}

const (
	clampMaxTTL    = "max_ttl"
	clampRetention = "retention"
)

func satAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return s
}

// ChooseValidity picks issued_at and valid_until. valid_until is only ever cut
// down from what was asked for, never raised; a window that leaves less than
// MinValidityS before the expiry is refused.
func ChooseValidity(w Window) (Validity, error) {
	if w.DA != commitment.DAFibre && w.DA != commitment.DACelestiaBlob {
		return Validity{}, fmt.Errorf("%w: da %d", ErrPublishResult, w.DA)
	}
	if w.BlockTime == 0 {
		return Validity{}, fmt.Errorf("%w: no block time", ErrPublishResult)
	}
	if w.DA == commitment.DAFibre && w.RetentionStart == 0 {
		return Validity{}, fmt.Errorf("%w: no payment promise time for da 1", ErrPublishResult)
	}
	if w.BlockTime > satAdd(w.Now, w.SkewS) {
		return Validity{}, fmt.Errorf("%w: block time %d, now %d", ErrClockBehindAnchor, w.BlockTime, w.Now)
	}
	issued := max(w.Now, w.BlockTime)

	retention, start := w.BlobRetentionS, w.BlockTime
	if w.DA == commitment.DAFibre {
		retention, start = min(w.FibreLatestS, w.FibreAtHeightS), min(w.BlockTime, w.RetentionStart)
	}
	margin := commitment.RetentionMargin(retention)
	window := satAdd(start, retention)
	if window < margin {
		return Validity{}, fmt.Errorf("%w: retention already used up", ErrValidityWindow)
	}
	k2max := window - margin
	p := commitment.Params{FibreRetentionS: w.FibreLatestS, BlobRetentionS: w.BlobRetentionS}
	ttlmax := satAdd(issued, p.MaxTTL(w.DA))

	requested := satAdd(issued, w.TTLS)
	if w.Deadline != nil {
		requested = *w.Deadline
	}
	until := min(requested, ttlmax, k2max)
	v := Validity{IssuedAt: issued, ValidUntil: until, RequestedUntil: requested, Expiry: until}
	if until < requested {
		v.Clamped = true
		v.ClampedBy = clampRetention
		if ttlmax <= k2max {
			v.ClampedBy = clampMaxTTL
		}
	}
	if w.Deadline != nil {
		if until < *w.Deadline {
			return Validity{}, fmt.Errorf("%w: deadline %d is beyond valid_until %d", ErrValidityWindow, *w.Deadline, until)
		}
		v.Expiry = *w.Deadline
	}
	if until <= issued {
		return Validity{}, fmt.Errorf("%w: valid_until %d not after issued_at %d", ErrValidityWindow, until, issued)
	}
	if sum, carry := bits.Add64(w.Now, w.MinValidityS, 0); carry != 0 || v.Expiry < sum {
		return Validity{}, fmt.Errorf("%w: less than %d s left until %d", ErrValidityWindow, w.MinValidityS, v.Expiry)
	}
	if v.Expiry <= satAdd(w.Now, w.SkewS) {
		return Validity{}, fmt.Errorf("%w: expiry %d is inside the clock skew", ErrValidityWindow, v.Expiry)
	}
	return v, nil
}
