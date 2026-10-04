// Package ibkrorder is the action format of the IBKR order profile: a strict
// canonical CBOR body that carries the account it is for, so the order bytes
// identify their own domain.
package ibkrorder

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// ActionType is the action_type under which these bodies are committed.
const ActionType = "application/vnd.edicta.ibkr.order.v0+cbor"

const (
	SideBuy  = 1
	SideSell = 2

	TypeLimit  = 1
	TypeMarket = 2

	TIFDay = 1
	TIFGTC = 2
	TIFIOC = 3
)

var (
	// ErrMalformed covers every violation of the encoding or the field table.
	ErrMalformed = errors.New("ibkrorder: malformed")
	// ErrInvalid is a canonical body that breaks a value rule.
	ErrInvalid = errors.New("ibkrorder: invalid")
)

// Order is the body. Qty has scale 1e4, LimitPrice 1e8. LimitPrice is nil
// when absent.
type Order struct {
	Account    string  `cbor:"1,keyasint"`
	ConID      uint64  `cbor:"2,keyasint"`
	Symbol     string  `cbor:"3,keyasint,omitempty"`
	Side       uint64  `cbor:"4,keyasint"`
	Qty        uint64  `cbor:"5,keyasint"`
	OrderType  uint64  `cbor:"6,keyasint"`
	LimitPrice *uint64 `cbor:"7,keyasint,omitempty"`
	Currency   string  `cbor:"8,keyasint"`
	TIF        uint64  `cbor:"9,keyasint"`
}

var encMode, encModeErr = func() (cbor.EncMode, error) {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
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

// Encode returns the canonical CBOR of o. It checks the schema only; value
// rules are Validate's job.
func Encode(o *Order) ([]byte, error) {
	if o == nil {
		return nil, fmt.Errorf("%w: nil order", ErrMalformed)
	}
	if err := schema(o); err != nil {
		return nil, err
	}
	if encModeErr != nil {
		return nil, fmt.Errorf("ibkrorder: encoder: %w", encModeErr)
	}
	b, err := encMode.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMalformed, err)
	}
	return b, nil
}

// Decode accepts exactly the canonical encodings of a schema-valid order, so
// the bytes have one meaning. A missing required key shows up as a
// re-encoding mismatch.
func Decode(b []byte) (*Order, error) {
	if decModeErr != nil || encModeErr != nil {
		return nil, fmt.Errorf("ibkrorder: codec: %w", errors.Join(decModeErr, encModeErr))
	}
	var o Order
	if err := decMode.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := schema(&o); err != nil {
		return nil, err
	}
	again, err := encMode.Marshal(&o)
	if err != nil || !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: not the canonical encoding", ErrMalformed)
	}
	return &o, nil
}

func schema(o *Order) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrMalformed, what) }
	if !idText(o.Account, 32) {
		return bad("account")
	}
	if o.Symbol != "" && !printable(o.Symbol, 32) {
		return bad("symbol")
	}
	if len(o.Currency) != 3 {
		return bad("currency")
	}
	for i := 0; i < 3; i++ {
		if o.Currency[i] < 'A' || o.Currency[i] > 'Z' {
			return bad("currency")
		}
	}
	return nil
}

// Validate applies the value rules to a decoded order.
func Validate(o *Order) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalid, what) }
	if o == nil {
		return bad("nil order")
	}
	ints := []uint64{o.ConID, o.Qty, o.Side, o.OrderType, o.TIF}
	if o.LimitPrice != nil {
		ints = append(ints, *o.LimitPrice)
	}
	for _, u := range ints {
		if u > math.MaxInt64 {
			return bad("uint above 2^63-1")
		}
	}
	if o.Side != SideBuy && o.Side != SideSell {
		return bad("side")
	}
	if o.OrderType != TypeLimit && o.OrderType != TypeMarket {
		return bad("order_type")
	}
	if o.TIF != TIFDay && o.TIF != TIFGTC && o.TIF != TIFIOC {
		return bad("tif")
	}
	if o.OrderType == TypeMarket {
		return bad("market orders are refused")
	}
	if o.ConID == 0 || o.Qty == 0 || o.LimitPrice != nil && *o.LimitPrice == 0 {
		return bad("zero conid, qty or limit_price")
	}
	if (o.OrderType == TypeLimit) != (o.LimitPrice != nil) {
		return bad("limit_price must be present exactly for limit orders")
	}
	return nil
}

// FormatQty writes qty (scale 1e4) as exact decimal text.
func FormatQty(qty uint64) string { return decimal(qty, 4) }

// FormatPrice writes a price (scale 1e8) as exact decimal text.
func FormatPrice(p uint64) string { return decimal(p, 8) }

func decimal(v uint64, scale int) string {
	s := strconv.FormatUint(v, 10)
	if len(s) <= scale {
		s = strings.Repeat("0", scale-len(s)+1) + s
	}
	whole, frac := s[:len(s)-scale], strings.TrimRight(s[len(s)-scale:], "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// NotionalAtMost reports qty*price <= limit*1e4 exactly; a zero limit admits
// nothing.
func NotionalAtMost(qty, price, limit uint64) bool {
	if limit == 0 {
		return false
	}
	lhsHi, lhsLo := bits.Mul64(qty, price)
	rhsHi, rhsLo := bits.Mul64(limit, 10000)
	if lhsHi != rhsHi {
		return lhsHi < rhsHi
	}
	return lhsLo <= rhsLo
}

func printable(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func idText(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
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
