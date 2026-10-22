// Package bankmsg is the strict canonical codec of cosmos.bank.v1beta1.MsgSend
// with one coin. The decoder accepts only the bytes the encoder emits, so one
// byte string cannot be read as two different transfers.
package bankmsg

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// ErrMalformed is every violation of the encoding or the field rules.
var ErrMalformed = errors.New("bankmsg: malformed")

// MaxAmount is the largest accepted amount, 2^63-1.
const MaxAmount = 1<<63 - 1

// MsgSend is a transfer of Amount base units of Denom.
type MsgSend struct {
	From   string
	To     string
	Denom  string
	Amount uint64
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// ValidDenom reports whether d matches the Cosmos SDK denom grammar.
func ValidDenom(d string) bool {
	if len(d) < 3 || len(d) > 128 {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 {
			if !alpha {
				return false
			}
			continue
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '/' && c != ':' && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func validate(m MsgSend, hrp string) error {
	if _, err := DecodeAddress(hrp, m.From); err != nil {
		return bad("from_address: %v", err)
	}
	if _, err := DecodeAddress(hrp, m.To); err != nil {
		return bad("to_address: %v", err)
	}
	if m.From == m.To {
		return bad("from_address equals to_address")
	}
	if !ValidDenom(m.Denom) {
		return bad("denom")
	}
	if m.Amount == 0 || m.Amount > MaxAmount {
		return bad("amount out of range")
	}
	return nil
}

func putField(dst []byte, tag byte, v []byte) []byte {
	dst = append(dst, tag)
	dst = appendUvarint(dst, uint64(len(v)))
	return append(dst, v...)
}

func appendUvarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// Encode returns the canonical protobuf bytes of m for the given prefix.
func Encode(m MsgSend, hrp string) ([]byte, error) {
	if err := validate(m, hrp); err != nil {
		return nil, err
	}
	coin := putField(nil, 0x0a, []byte(m.Denom))
	coin = putField(coin, 0x12, []byte(strconv.FormatUint(m.Amount, 10)))
	out := putField(nil, 0x0a, []byte(m.From))
	out = putField(out, 0x12, []byte(m.To))
	return putField(out, 0x1a, coin), nil
}

// reader walks length-delimited fields and rejects non-minimal varints.
type reader struct {
	b []byte
}

func (r *reader) uvarint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if i >= len(r.b) {
			return 0, bad("truncated varint")
		}
		c := r.b[i]
		if i == 9 && c > 1 {
			return 0, bad("varint overflow")
		}
		v |= uint64(c&0x7f) << uint(7*i)
		if c < 0x80 {
			if c == 0 && i > 0 {
				return 0, bad("non-minimal varint")
			}
			r.b = r.b[i+1:]
			return v, nil
		}
	}
	return 0, bad("varint too long")
}

// field reads the next field, which must have the given single-byte tag
// (field number below 16, wire type 2).
func (r *reader) field(tag byte) ([]byte, error) {
	if len(r.b) == 0 || r.b[0] != tag {
		return nil, bad("expected field tag %#x", tag)
	}
	r.b = r.b[1:]
	n, err := r.uvarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)) {
		return nil, bad("length exceeds input")
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

// Decode parses msg strictly and checks every field rule.
func Decode(msg []byte, hrp string) (MsgSend, error) {
	r := &reader{b: msg}
	from, err := r.field(0x0a)
	if err != nil {
		return MsgSend{}, err
	}
	to, err := r.field(0x12)
	if err != nil {
		return MsgSend{}, err
	}
	coinBytes, err := r.field(0x1a)
	if err != nil {
		return MsgSend{}, err
	}
	if len(r.b) != 0 {
		return MsgSend{}, bad("trailing bytes")
	}
	cr := &reader{b: coinBytes}
	denom, err := cr.field(0x0a)
	if err != nil {
		return MsgSend{}, err
	}
	amt, err := cr.field(0x12)
	if err != nil {
		return MsgSend{}, err
	}
	if len(cr.b) != 0 {
		return MsgSend{}, bad("trailing bytes in coin")
	}
	if len(amt) == 0 || len(amt) > 19 || amt[0] < '1' || amt[0] > '9' {
		return MsgSend{}, bad("amount")
	}
	for _, c := range amt {
		if c < '0' || c > '9' {
			return MsgSend{}, bad("amount")
		}
	}
	n, err := strconv.ParseUint(string(amt), 10, 64)
	if err != nil {
		return MsgSend{}, bad("amount")
	}
	m := MsgSend{From: string(from), To: string(to), Denom: string(denom), Amount: n}
	if err := validate(m, hrp); err != nil {
		return MsgSend{}, err
	}
	again, err := Encode(m, hrp)
	if err != nil || !bytes.Equal(again, msg) {
		return MsgSend{}, bad("not the canonical encoding")
	}
	return m, nil
}
