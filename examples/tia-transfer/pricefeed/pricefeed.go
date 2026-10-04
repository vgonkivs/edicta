// Package pricefeed reads a price from a public source into integers scaled
// by 1e8. Prices never pass through a float.
package pricefeed

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"sync"
)

// ErrPrice means a price text is not a positive decimal within range.
var ErrPrice = errors.New("pricefeed: bad price")

// ErrExhausted means a Fake has no scripted answer left.
var ErrExhausted = errors.New("pricefeed: no scripted observation left")

const (
	scale       = 100_000_000
	scaleDigits = 8
)

// Observation is one price reading. Price is scaled by 1e8, times are Unix
// seconds.
type Observation struct {
	Source, AssetID, Quote string
	Price                  uint64
	ObservedAt, FetchedAt  uint64
}

// Feed returns the current price.
type Feed interface {
	Observe(ctx context.Context) (Observation, error)
}

// ParseDecimal converts a plain decimal such as "4.12345678" to a price
// scaled by 1e8. It accepts digits with an optional fraction and nothing
// else; more than 8 decimals, zero and overflow are errors, never rounded.
func ParseDecimal(s string) (uint64, error) {
	bad := func(why string) (uint64, error) { return 0, fmt.Errorf("%w: %s", ErrPrice, why) }
	intPart, frac := s, ""
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			intPart, frac = s[:i], s[i+1:]
			if len(frac) == 0 {
				return bad("empty fraction")
			}
			break
		}
	}
	if len(intPart) == 0 {
		return bad("empty integer part")
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return bad("leading zero")
	}
	if len(frac) > scaleDigits {
		return bad("more than 8 decimals")
	}
	var v uint64
	for i := 0; i < len(intPart); i++ {
		c := intPart[i]
		if c < '0' || c > '9' {
			return bad("not a decimal number")
		}
		hi, lo := bits.Mul64(v, 10)
		var carry uint64
		lo, carry = bits.Add64(lo, uint64(c-'0'), 0)
		if hi != 0 || carry != 0 {
			return bad("out of range")
		}
		v = lo
	}
	hi, v := bits.Mul64(v, scale)
	if hi != 0 {
		return bad("out of range")
	}
	var f uint64
	for i := 0; i < scaleDigits; i++ {
		f *= 10
		if i < len(frac) {
			c := frac[i]
			if c < '0' || c > '9' {
				return bad("not a decimal number")
			}
			f += uint64(c - '0')
		}
	}
	v, carry := bits.Add64(v, f, 0)
	if carry != 0 {
		return bad("out of range")
	}
	if v == 0 {
		return bad("zero")
	}
	return v, nil
}

// Fake replays a script of answers in order. It is for tests and never makes
// up a price: an empty script is an error.
type Fake struct {
	mu     sync.Mutex
	script []step
	calls  int
}

type step struct {
	obs Observation
	err error
}

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{} }

// Push queues an observation.
func (f *Fake) Push(o Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = append(f.script, step{obs: o})
}

// PushErr queues a failure.
func (f *Fake) PushErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = append(f.script, step{err: err})
}

// Calls is the number of Observe calls so far.
func (f *Fake) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *Fake) Observe(ctx context.Context) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.script) == 0 {
		return Observation{}, ErrExhausted
	}
	s := f.script[0]
	f.script = f.script[1:]
	return s.obs, s.err
}
