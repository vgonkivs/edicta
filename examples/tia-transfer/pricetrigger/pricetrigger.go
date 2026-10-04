// Package pricetrigger is the context format of an agent that moves funds
// when a price leaves a band around a baseline, and the replay checks a
// reader runs on it. The checks only compare the agent's statements with each
// other and with the transfer; they never judge the prices or the decision.
package pricetrigger

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
)

// MediaType is the payload context media type of these bodies.
const MediaType = "application/vnd.edicta.price-trigger.v0+cbor"

const maxUint = math.MaxInt64

var ErrMalformed = errors.New("pricetrigger: malformed")

type Asset struct {
	Feed    string `cbor:"1,keyasint"`
	AssetID string `cbor:"2,keyasint"`
	Quote   string `cbor:"3,keyasint"`
}

type Observation struct {
	Source     string `cbor:"1,keyasint"`
	Price      uint64 `cbor:"2,keyasint"`
	ObservedAt uint64 `cbor:"3,keyasint"`
	FetchedAt  uint64 `cbor:"4,keyasint"`
}

type Baseline struct {
	Price uint64 `cbor:"1,keyasint"`
	SetAt uint64 `cbor:"2,keyasint"`
}

type Branch struct {
	Name      string `cbor:"1,keyasint"`
	ToAddress string `cbor:"2,keyasint"`
	Amount    uint64 `cbor:"3,keyasint"`
	Denom     string `cbor:"4,keyasint"`
}

// Payload prices are scaled by 1e8, times are Unix seconds. Observations are
// newest first.
type Payload struct {
	StrategyID   string        `cbor:"1,keyasint"`
	Asset        Asset         `cbor:"2,keyasint"`
	Observations []Observation `cbor:"3,keyasint"`
	Baseline     Baseline      `cbor:"4,keyasint"`
	ThresholdBP  uint64        `cbor:"5,keyasint"`
	Direction    uint64        `cbor:"6,keyasint"`
	MoveBP       uint64        `cbor:"7,keyasint"`
	Branch       Branch        `cbor:"8,keyasint"`
	Reason       string        `cbor:"9,keyasint,omitempty"`
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

func bad(what string) error { return fmt.Errorf("%w: %s", ErrMalformed, what) }

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

func schema(p *Payload) error {
	if !idText(p.StrategyID, 64) || !idText(p.Asset.Feed, 64) || !idText(p.Asset.AssetID, 64) {
		return bad("identifier")
	}
	if len(p.Asset.Quote) != 3 {
		return bad("quote")
	}
	for i := 0; i < 3; i++ {
		if c := p.Asset.Quote[i]; c < 'A' || c > 'Z' {
			return bad("quote")
		}
	}
	if n := len(p.Observations); n < 1 || n > 8 {
		return bad("observations count")
	}
	for i, o := range p.Observations {
		if !idText(o.Source, 64) {
			return bad("source")
		}
		for _, u := range []uint64{o.Price, o.ObservedAt, o.FetchedAt} {
			if u == 0 || u > maxUint {
				return bad("observation value")
			}
		}
		if i > 0 && o.ObservedAt > p.Observations[i-1].ObservedAt {
			return bad("observations not newest first")
		}
	}
	for _, u := range []uint64{p.Baseline.Price, p.Baseline.SetAt, p.Branch.Amount} {
		if u == 0 || u > maxUint {
			return bad("baseline or amount")
		}
	}
	if p.ThresholdBP < 1 || p.ThresholdBP > 10000 {
		return bad("threshold_bp")
	}
	if p.Direction != 1 && p.Direction != 2 {
		return bad("direction")
	}
	if p.MoveBP > maxUint {
		return bad("move_bp")
	}
	if !idText(p.Branch.Name, 64) {
		return bad("branch name")
	}
	if n := len(p.Branch.ToAddress); n < 1 || n > 90 {
		return bad("branch to_address")
	}
	for i := 0; i < len(p.Branch.ToAddress); i++ {
		if c := p.Branch.ToAddress[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return bad("branch to_address")
		}
	}
	if !bankmsg.ValidDenom(p.Branch.Denom) {
		return bad("branch denom")
	}
	if p.Reason != "" && (len(p.Reason) > 1024 || !utf8.ValidString(p.Reason)) {
		return bad("reason")
	}
	return nil
}

// Encode returns the canonical CBOR of p.
func Encode(p *Payload) ([]byte, error) {
	if p == nil {
		return nil, bad("nil payload")
	}
	if err := schema(p); err != nil {
		return nil, err
	}
	if encModeErr != nil {
		return nil, fmt.Errorf("pricetrigger: encoder: %w", encModeErr)
	}
	b, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMalformed, err)
	}
	return b, nil
}

// Decode accepts exactly the canonical encodings of a schema-valid payload.
// A missing key or an empty reason shows up as a re-encoding mismatch.
func Decode(b []byte) (*Payload, error) {
	if decModeErr != nil || encModeErr != nil {
		return nil, fmt.Errorf("pricetrigger: codec: %w", errors.Join(decModeErr, encModeErr))
	}
	var p Payload
	if err := decMode.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := schema(&p); err != nil {
		return nil, err
	}
	again, err := encMode.Marshal(&p)
	if err != nil || !bytes.Equal(again, b) {
		return nil, bad("not the canonical encoding")
	}
	return &p, nil
}

// MoveBP returns floor(abs(p-b)*10000/b) in exact integer arithmetic. ok is
// false when b is zero or the result does not fit in 63 bits.
func MoveBP(p, b uint64) (uint64, bool) {
	if b == 0 {
		return 0, false
	}
	d := p - b
	if b > p {
		d = b - p
	}
	hi, lo := bits.Mul64(d, 10000)
	if hi >= b {
		return 0, false
	}
	q, _ := bits.Div64(hi, lo, b)
	if q > maxUint {
		return 0, false
	}
	return q, true
}

// Check names one replay check.
type Check string

const (
	CheckMove               Check = "PT1"
	CheckDirection          Check = "PT2"
	CheckThreshold          Check = "PT3"
	CheckBranch             Check = "PT4"
	CheckFetchedBeforeIssue Check = "PT5"
)

// Verify returns the checks that fail, in order; the slice is empty when all
// pass. m is the authorized transfer and issuedAt the commitment's issue time.
func Verify(p *Payload, m bankmsg.MsgSend, issuedAt uint64) []Check {
	failed := []Check{}
	if len(p.Observations) == 0 {
		return append(failed, CheckMove, CheckDirection, CheckThreshold, CheckBranch, CheckFetchedBeforeIssue)
	}
	obs := p.Observations[0]
	b := p.Baseline.Price
	if got, ok := MoveBP(obs.Price, b); !ok || got != p.MoveBP {
		failed = append(failed, CheckMove)
	}
	if !(obs.Price > b && p.Direction == 1 || obs.Price < b && p.Direction == 2) {
		failed = append(failed, CheckDirection)
	}
	if p.MoveBP < p.ThresholdBP {
		failed = append(failed, CheckThreshold)
	}
	if p.Branch.ToAddress != m.To || p.Branch.Amount != m.Amount || p.Branch.Denom != m.Denom {
		failed = append(failed, CheckBranch)
	}
	if obs.FetchedAt > issuedAt {
		failed = append(failed, CheckFetchedBeforeIssue)
	}
	return failed
}
