// SPDX-License-Identifier: Apache-2.0

// Package rlp encodes canonical RLP and reads it strictly: every length in
// its shortest form, a single byte below 0x80 encoding itself, so one value
// has exactly one encoding.
package rlp

import (
	"errors"
	"fmt"
)

// Both sentinels read "rlp" so that a wrapped error reads "rlp: <reason>".
var (
	// ErrTruncated: the input ends inside an item or its length.
	ErrTruncated = errors.New("rlp")
	// ErrNonCanonical: the item has a shorter encoding.
	ErrNonCanonical = errors.New("rlp")
)

// Item is one RLP item. Payload and Raw alias the input; Raw is the whole
// encoding, header included.
type Item struct {
	List    bool
	Payload []byte
	Raw     []byte
}

// AppendString appends the encoding of the byte string b.
func AppendString(dst, b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return append(dst, b[0])
	}
	return append(appendHeader(dst, 0x80, len(b)), b...)
}

// AppendUint64 appends the encoding of v: its big-endian bytes without
// leading zeros, so 0 is the empty string.
func AppendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	i := len(b)
	for ; v > 0; v >>= 8 {
		i--
		b[i] = byte(v)
	}
	return AppendString(dst, b[i:])
}

// AppendList appends a list whose items are already encoded.
func AppendList(dst []byte, items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	dst = appendHeader(dst, 0xc0, n)
	for _, it := range items {
		dst = append(dst, it...)
	}
	return dst
}

// appendHeader appends the short or long header with base 0x80 (string) or
// 0xc0 (list) for a payload of n bytes.
func appendHeader(dst []byte, base byte, n int) []byte {
	if n <= 55 {
		return append(dst, base+byte(n))
	}
	var lb [8]byte
	i := len(lb)
	for v := uint64(n); v > 0; v >>= 8 {
		i--
		lb[i] = byte(v)
	}
	dst = append(dst, base+55+byte(len(lb)-i))
	return append(dst, lb[i:]...)
}

// Next reads the canonical item at the start of b and returns the rest.
func Next(b []byte) (Item, []byte, error) {
	if len(b) == 0 {
		return Item{}, nil, fmt.Errorf("%w: truncated item", ErrTruncated)
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
		return Item{Payload: b[:1], Raw: b[:1]}, b[1:], nil
	case c <= 0xb7:
		hdr, n, short = 1, uint64(c-0x80), true
	case c <= 0xbf:
		ll := int(c - 0xb7)
		v, err := longLength(b, ll)
		if err != nil {
			return Item{}, nil, err
		}
		hdr, n = 1+ll, v
	case c <= 0xf7:
		list, hdr, n, short = true, 1, uint64(c-0xc0), true
	default:
		ll := int(c - 0xf7)
		v, err := longLength(b, ll)
		if err != nil {
			return Item{}, nil, err
		}
		list, hdr, n = true, 1+ll, v
	}
	if n > uint64(len(b)-hdr) {
		return Item{}, nil, fmt.Errorf("%w: item extends past its input", ErrTruncated)
	}
	end := hdr + int(n)
	if short && !list && n == 1 && b[1] < 0x80 {
		return Item{}, nil, fmt.Errorf("%w: a single byte below 0x80 must encode itself", ErrNonCanonical)
	}
	return Item{List: list, Payload: b[hdr:end], Raw: b[:end]}, b[end:], nil
}

// longLength reads the big-endian length of a long form; ll is 1 to 8.
func longLength(b []byte, ll int) (uint64, error) {
	if ll > len(b)-1 {
		return 0, fmt.Errorf("%w: truncated length", ErrTruncated)
	}
	lb := b[1 : 1+ll]
	if lb[0] == 0 {
		return 0, fmt.Errorf("%w: length with a leading zero byte", ErrNonCanonical)
	}
	var n uint64
	for _, x := range lb {
		n = n<<8 | uint64(x)
	}
	if n <= 55 {
		return 0, fmt.Errorf("%w: long form for %d bytes", ErrNonCanonical, n)
	}
	return n, nil
}
