// Package bankaction is the action format of the bank-send profile: a strict
// canonical CBOR body naming the chain and carrying one protobuf MsgSend
// verbatim, plus the byte-exact transaction body, the timeout height and the
// pure checks an executor runs before it signs.
package bankaction

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/fxamacker/cbor/v2"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
)

// ActionType is the action_type under which these bodies are committed.
const ActionType = "application/vnd.edicta.cosmos.bank-send.v0+cbor"

const (
	maxChainIDLen = 50
	maxMsgLen     = 1024
	// MaxTimeoutBlocks is the upper bound of the configurable block cap.
	MaxTimeoutBlocks = 10000
	maxHeight        = math.MaxInt64
	msgSendTypeURL   = "/cosmos.bank.v1beta1.MsgSend"
)

var (
	ErrMalformed      = errors.New("bankaction: malformed")
	ErrBodyMismatch   = errors.New("bankaction: body does not match the authorized action")
	ErrHeaders        = errors.New("bankaction: unusable block headers")
	ErrExpired        = errors.New("bankaction: authorization expired or no block fits")
	ErrChainMismatch  = errors.New("bankaction: chain id mismatch")
	ErrSenderMismatch = errors.New("bankaction: sender mismatch")
	ErrDenomMismatch  = errors.New("bankaction: denom mismatch")
	ErrDestination    = errors.New("bankaction: destination not allowed")
	ErrRiskLimit      = errors.New("bankaction: amount above the limit")
)

// Action is the committed body: the chain the transaction is signed for and
// the exact MsgSend bytes.
type Action struct {
	ChainID string `cbor:"1,keyasint"`
	Msg     []byte `cbor:"2,keyasint"`
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

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

func schema(a Action) error {
	if n := len(a.ChainID); n < 1 || n > maxChainIDLen {
		return malformed("chain_id length")
	}
	for i := 0; i < len(a.ChainID); i++ {
		c := a.ChainID[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return malformed("chain_id character")
		}
	}
	if n := len(a.Msg); n < 1 || n > maxMsgLen {
		return malformed("msg length")
	}
	return nil
}

// Encode returns the canonical CBOR of a.
func Encode(a Action) ([]byte, error) {
	if err := schema(a); err != nil {
		return nil, err
	}
	if encModeErr != nil {
		return nil, fmt.Errorf("bankaction: encoder: %w", encModeErr)
	}
	b, err := encMode.Marshal(a)
	if err != nil {
		return nil, malformed("encode: %v", err)
	}
	return b, nil
}

// Decode accepts exactly the canonical encodings of a schema-valid action.
// msg is not parsed here: that needs the chain's address prefix.
func Decode(b []byte) (Action, error) {
	if decModeErr != nil || encModeErr != nil {
		return Action{}, fmt.Errorf("bankaction: codec: %w", errors.Join(decModeErr, encModeErr))
	}
	var a Action
	if err := decMode.Unmarshal(b, &a); err != nil {
		return Action{}, malformed("%v", err)
	}
	if err := schema(a); err != nil {
		return Action{}, err
	}
	again, err := encMode.Marshal(a)
	if err != nil || !bytes.Equal(again, b) {
		return Action{}, malformed("not the canonical encoding")
	}
	return a, nil
}

func appendUvarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// Body returns the TxBody bytes for msg, with the commitment hash as memo and
// timeout_height. msg is copied in verbatim.
func Body(msg []byte, h commitment.Hash, timeoutHeight uint64) ([]byte, error) {
	if len(msg) == 0 || len(msg) > maxMsgLen {
		return nil, malformed("msg length")
	}
	if timeoutHeight == 0 || timeoutHeight > maxHeight {
		return nil, fmt.Errorf("bankaction: timeout_height %d out of range", timeoutHeight)
	}
	any := []byte{0x0a, byte(len(msgSendTypeURL))}
	any = append(any, msgSendTypeURL...)
	any = append(any, 0x12)
	any = appendUvarint(any, uint64(len(msg)))
	any = append(any, msg...)

	const hexdigits = "0123456789abcdef"
	body := []byte{0x0a}
	body = appendUvarint(body, uint64(len(any)))
	body = append(body, any...)
	body = append(body, 0x12, 0x40)
	for _, c := range h {
		body = append(body, hexdigits[c>>4], hexdigits[c&15])
	}
	body = append(body, 0x18)
	return appendUvarint(body, timeoutHeight), nil
}

// CheckBody verifies that body is exactly Body(a.Msg, h, timeout_height) for
// some timeout height and returns that height.
func CheckBody(a Action, h commitment.Hash, body []byte) (uint64, error) {
	mismatch := func(why string) (uint64, error) {
		return 0, fmt.Errorf("%w: %s", ErrBodyMismatch, why)
	}
	ref, err := Body(a.Msg, h, 1)
	if err != nil {
		return mismatch(err.Error())
	}
	prefix := ref[:len(ref)-2]
	if !bytes.HasPrefix(body, prefix) {
		return mismatch("prefix differs")
	}
	rest := body[len(prefix):]
	if len(rest) < 2 || rest[0] != 0x18 {
		return mismatch("timeout_height missing")
	}
	var th uint64
	n := 0
	for i, c := range rest[1:] {
		if i >= 9 || i == 9 && c > 1 {
			return mismatch("timeout_height varint")
		}
		th |= uint64(c&0x7f) << uint(7*i)
		n = i + 1
		if c < 0x80 {
			break
		}
	}
	if n != len(rest)-1 {
		return mismatch("trailing bytes")
	}
	want, err := Body(a.Msg, h, th)
	if err != nil || !bytes.Equal(want, body) {
		return mismatch("not the canonical body")
	}
	return th, nil
}

// Header is the height and time of one block.
type Header struct {
	Height uint64
	TimeNs uint64
}

// BlockIntervalMs returns the largest interval between neighbouring headers,
// rounded up to whole milliseconds and at least 1. Headers must have
// consecutive heights and non-decreasing times.
func BlockIntervalMs(hs []Header) (uint64, error) {
	if len(hs) < 2 {
		return 0, fmt.Errorf("%w: need at least 2 headers", ErrHeaders)
	}
	var maxNs uint64
	for i := 1; i < len(hs); i++ {
		p, c := hs[i-1], hs[i]
		if p.Height == math.MaxUint64 || c.Height != p.Height+1 {
			return 0, fmt.Errorf("%w: heights not consecutive", ErrHeaders)
		}
		if c.TimeNs < p.TimeNs {
			return 0, fmt.Errorf("%w: time goes back", ErrHeaders)
		}
		maxNs = max(maxNs, c.TimeNs-p.TimeNs)
	}
	ms := maxNs / 1_000_000
	if maxNs%1_000_000 != 0 {
		ms++
	}
	return max(ms, 1), nil
}

// TimeoutInput is what TimeoutHeight needs. HeadTime, Expires, SkewS and Now
// are Unix seconds.
type TimeoutInput struct {
	HeadHeight uint64
	HeadTime   uint64
	TauMs      uint64
	Expires    uint64
	SkewS      uint64
	MaxBlocks  uint64
	Now        uint64
}

// TimeoutHeight returns the last block that may include the transaction. The
// budget assumes blocks twice as slow as the slowest recent one, so the
// height falls before expires-skew unless the chain slows down further.
func TimeoutHeight(in TimeoutInput) (uint64, error) {
	if in.TauMs == 0 {
		return 0, errors.New("bankaction: block interval is zero")
	}
	if in.MaxBlocks < 1 || in.MaxBlocks > MaxTimeoutBlocks {
		return 0, fmt.Errorf("bankaction: max blocks %d outside 1..%d", in.MaxBlocks, MaxTimeoutBlocks)
	}
	if in.HeadHeight > maxHeight {
		return 0, errors.New("bankaction: head height out of range")
	}
	if in.Expires < in.SkewS || in.Now >= in.Expires-in.SkewS {
		return 0, ErrExpired
	}
	end := in.Expires - in.SkewS
	if end <= in.HeadTime {
		return 0, ErrExpired
	}
	num := new(big.Int).SetUint64(end - in.HeadTime)
	num.Mul(num, big.NewInt(1000))
	den := new(big.Int).SetUint64(in.TauMs)
	den.Lsh(den, 1)
	num.Quo(num, den)
	n := in.MaxBlocks
	if num.IsUint64() {
		n = min(n, num.Uint64())
	}
	if n == 0 {
		return 0, ErrExpired
	}
	if in.HeadHeight+n > maxHeight {
		return 0, errors.New("bankaction: timeout height overflows")
	}
	return in.HeadHeight + n, nil
}

// Domain is the executor's own view of the chain and its key.
type Domain struct {
	ChainID string
	Denom   string
	HRP     string
	Sender  string
}

// Limits are the operator's optional restrictions. An empty Destinations or a
// zero MaxAmount disables that check.
type Limits struct {
	Destinations []string
	MaxAmount    uint64
}

// CheckExecution decodes the authorized action bytes and checks them against
// the domain and limits, in a fixed order: encoding, chain, message, sender,
// denom, destination, amount. It returns the decoded action and message.
func CheckExecution(raw []byte, d Domain, lim Limits) (Action, bankmsg.MsgSend, error) {
	a, err := Decode(raw)
	if err != nil {
		return Action{}, bankmsg.MsgSend{}, err
	}
	if a.ChainID != d.ChainID {
		return Action{}, bankmsg.MsgSend{}, fmt.Errorf("%w: %q", ErrChainMismatch, a.ChainID)
	}
	m, err := bankmsg.Decode(a.Msg, d.HRP)
	if err != nil {
		return Action{}, bankmsg.MsgSend{}, err
	}
	if m.From != d.Sender {
		return Action{}, bankmsg.MsgSend{}, fmt.Errorf("%w: %s", ErrSenderMismatch, m.From)
	}
	if m.Denom != d.Denom {
		return Action{}, bankmsg.MsgSend{}, fmt.Errorf("%w: %s", ErrDenomMismatch, m.Denom)
	}
	if len(lim.Destinations) > 0 && !slices.Contains(lim.Destinations, m.To) {
		return Action{}, bankmsg.MsgSend{}, fmt.Errorf("%w: %s", ErrDestination, m.To)
	}
	if lim.MaxAmount != 0 && m.Amount > lim.MaxAmount {
		return Action{}, bankmsg.MsgSend{}, fmt.Errorf("%w: %d > %d", ErrRiskLimit, m.Amount, lim.MaxAmount)
	}
	return a, m, nil
}
