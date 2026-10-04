// Package dca implements the body of the media type
// application/vnd.edicta.dca.v0+cbor, the context of the dollar-cost-averaging
// agent.
package dca

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// ErrMalformed covers every violation of the encoding or the field table.
var ErrMalformed = errors.New("dca: malformed")

type Schedule struct {
	PeriodS     uint64 `cbor:"1,keyasint"`
	PeriodStart uint64 `cbor:"2,keyasint"`
}

type Budget struct {
	Currency  string `cbor:"1,keyasint"`
	PerPeriod uint64 `cbor:"2,keyasint"`
	Spent     uint64 `cbor:"3,keyasint"`
}

type Price struct {
	Source     string `cbor:"1,keyasint"`
	ConID      uint64 `cbor:"2,keyasint"`
	Price      uint64 `cbor:"3,keyasint"`
	ObservedAt uint64 `cbor:"4,keyasint"`
}

type Fill struct {
	FilledAt uint64 `cbor:"1,keyasint"`
	Side     uint64 `cbor:"2,keyasint"`
	Qty      uint64 `cbor:"3,keyasint"`
	Price    uint64 `cbor:"4,keyasint"`
}

type Order struct {
	Side       uint64 `cbor:"1,keyasint"`
	Qty        uint64 `cbor:"2,keyasint"`
	LimitPrice uint64 `cbor:"3,keyasint"`
}

type Context struct {
	StrategyID string   `cbor:"1,keyasint"`
	Schedule   Schedule `cbor:"2,keyasint"`
	Budget     Budget   `cbor:"3,keyasint"`
	Price      Price    `cbor:"4,keyasint"`
	LastFills  []Fill   `cbor:"5,keyasint,omitempty"`
	Order      Order    `cbor:"6,keyasint"`
}

var encMode, encModeErr = func() (cbor.EncMode, error) {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	o.NilContainers = cbor.NilContainerAsEmpty
	return o.EncMode()
}()

var decMode, decModeErr = cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	IndefLength:       cbor.IndefLengthForbidden,
	TagsMd:            cbor.TagsForbidden,
	UTF8:              cbor.UTF8RejectInvalid,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	MaxNestedLevels:   4,
	MaxArrayElements:  16,
	MaxMapPairs:       16,
}.DecMode()

// Encode returns the canonical CBOR of c after the checks of Decode.
func Encode(c *Context) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil context", ErrMalformed)
	}
	if err := validate(c); err != nil {
		return nil, err
	}
	if encModeErr != nil {
		return nil, fmt.Errorf("dca: encoder: %w", encModeErr)
	}
	b, err := encMode.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMalformed, err)
	}
	return b, nil
}

// Decode accepts exactly the canonical encodings of a valid Context.
func Decode(b []byte) (*Context, error) {
	if decModeErr != nil || encModeErr != nil {
		return nil, fmt.Errorf("dca: codec: %w", errors.Join(decModeErr, encModeErr))
	}
	var c Context
	if err := decMode.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := validate(&c); err != nil {
		return nil, err
	}
	again, err := encMode.Marshal(&c)
	if err != nil || !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: not the canonical encoding", ErrMalformed)
	}
	return &c, nil
}

func validate(c *Context) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrMalformed, what) }
	if !idText(c.StrategyID) {
		return bad("strategy_id")
	}
	if c.Schedule.PeriodS == 0 || c.Schedule.PeriodStart == 0 {
		return bad("schedule")
	}
	if len(c.Budget.Currency) != 3 || !upper(c.Budget.Currency) {
		return bad("budget.currency")
	}
	if c.Budget.PerPeriod == 0 {
		return bad("budget.per_period")
	}
	if !idText(c.Price.Source) {
		return bad("price.source")
	}
	if c.Price.ConID == 0 || c.Price.Price == 0 || c.Price.ObservedAt == 0 {
		return bad("price")
	}
	if len(c.LastFills) > 8 || c.LastFills != nil && len(c.LastFills) == 0 {
		return bad("last_fills count")
	}
	for _, f := range c.LastFills {
		if f.FilledAt == 0 || !side(f.Side) || f.Qty == 0 || f.Price == 0 {
			return bad("last_fills entry")
		}
	}
	if !side(c.Order.Side) || c.Order.Qty == 0 || c.Order.LimitPrice == 0 {
		return bad("order")
	}
	for _, u := range []uint64{
		c.Schedule.PeriodS, c.Schedule.PeriodStart, c.Budget.PerPeriod, c.Budget.Spent,
		c.Price.ConID, c.Price.Price, c.Price.ObservedAt, c.Order.Qty, c.Order.LimitPrice,
	} {
		if u > math.MaxInt64 {
			return bad("uint above 2^63-1")
		}
	}
	for _, f := range c.LastFills {
		if f.FilledAt > math.MaxInt64 || f.Qty > math.MaxInt64 || f.Price > math.MaxInt64 {
			return bad("uint above 2^63-1")
		}
	}
	return nil
}

func side(s uint64) bool { return s == 1 || s == 2 }

func upper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// idText is 1..64 bytes of the ID charset of the commitment.
func idText(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}
