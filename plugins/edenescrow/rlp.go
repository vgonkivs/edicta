// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"errors"
	"fmt"
)

var errRLP = errors.New("rlp")

// rlpItem is one canonical RLP item. payload and raw alias the input, so a
// length prefix never causes an allocation.
type rlpItem struct {
	list    bool
	payload []byte
	raw     []byte
}

// rlpNext reads the canonical item at the start of b and returns the rest.
// Every length prefix is in its shortest form and a single byte below 0x80
// encodes itself.
func rlpNext(b []byte) (rlpItem, []byte, error) {
	if len(b) == 0 {
		return rlpItem{}, nil, fmt.Errorf("%w: truncated item", errRLP)
	}
	c := b[0]
	var (
		list  bool
		short bool
		hdr   int
		n     uint64
	)
	switch {
	case c < 0x80:
		return rlpItem{payload: b[:1], raw: b[:1]}, b[1:], nil
	case c <= 0xb7:
		hdr, n, short = 1, uint64(c-0x80), true
	case c <= 0xbf:
		ll := int(c - 0xb7)
		v, err := rlpLongLength(b, ll)
		if err != nil {
			return rlpItem{}, nil, err
		}
		hdr, n = 1+ll, v
	case c <= 0xf7:
		list, hdr, n, short = true, 1, uint64(c-0xc0), true
	default:
		ll := int(c - 0xf7)
		v, err := rlpLongLength(b, ll)
		if err != nil {
			return rlpItem{}, nil, err
		}
		list, hdr, n = true, 1+ll, v
	}
	if n > uint64(len(b)-hdr) {
		return rlpItem{}, nil, fmt.Errorf("%w: item extends past its input", errRLP)
	}
	end := hdr + int(n)
	if short && !list && n == 1 && b[1] < 0x80 {
		return rlpItem{}, nil, fmt.Errorf("%w: a single byte below 0x80 must encode itself", errRLP)
	}
	return rlpItem{list: list, payload: b[hdr:end], raw: b[:end]}, b[end:], nil
}

// rlpLongLength reads the big-endian length of a long form; ll is 1 to 8.
func rlpLongLength(b []byte, ll int) (uint64, error) {
	if ll > len(b)-1 {
		return 0, fmt.Errorf("%w: truncated length", errRLP)
	}
	lb := b[1 : 1+ll]
	if lb[0] == 0 {
		return 0, fmt.Errorf("%w: length with a leading zero byte", errRLP)
	}
	var n uint64
	for _, x := range lb {
		n = n<<8 | uint64(x)
	}
	if n <= 55 {
		return 0, fmt.Errorf("%w: long form for %d bytes", errRLP, n)
	}
	return n, nil
}

// maxNesting bounds list depth inside the access list. A valid access list
// is two levels deep; the bound keeps the check's memory constant.
const maxNesting = 16

// rlpCheckNested checks that every item inside a list payload, at any depth
// up to maxNesting, is canonical and ends inside its enclosing list.
func rlpCheckNested(payload []byte) error {
	var buf [maxNesting + 1][]byte
	stack := append(buf[:0], payload)
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if len(top) == 0 {
			stack = stack[:len(stack)-1]
			continue
		}
		it, rest, err := rlpNext(top)
		if err != nil {
			return err
		}
		stack[len(stack)-1] = rest
		if it.list {
			if len(stack) > maxNesting {
				return fmt.Errorf("%w: lists nested deeper than %d", errRLP, maxNesting)
			}
			stack = append(stack, it.payload)
		}
	}
	return nil
}

// rlpListHeader is the canonical header of a list whose payload has n bytes.
func rlpListHeader(n int) []byte {
	if n <= 55 {
		return []byte{0xc0 + byte(n)}
	}
	var lb []byte
	for v := n; v > 0; v >>= 8 {
		lb = append([]byte{byte(v)}, lb...)
	}
	return append([]byte{0xf7 + byte(len(lb))}, lb...)
}

// rlpString is the canonical encoding of the byte string b.
func rlpString(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	if len(b) <= 55 {
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	var lb []byte
	for v := len(b); v > 0; v >>= 8 {
		lb = append([]byte{byte(v)}, lb...)
	}
	out := append([]byte{0xb7 + byte(len(lb))}, lb...)
	return append(out, b...)
}
