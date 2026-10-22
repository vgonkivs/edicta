// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	majorUint  = 0
	majorBytes = 2
	majorText  = 3
	majorArray = 4
	majorMap   = 5

	maxDepth   = 4
	maxEntries = 16
)

var errCBOR = errors.New("cbor")

// cborHead reads the head at off: major type, argument and the offset of
// what follows it. Indefinite lengths, reserved additional info, tags,
// floats, simple values and non-shortest arguments are refused.
func cborHead(b []byte, off int) (major byte, arg uint64, next int, err error) {
	if off >= len(b) {
		return 0, 0, 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	ib := b[off]
	major, info := ib>>5, ib&0x1f
	switch {
	case info >= 28 && info <= 30:
		return 0, 0, 0, fmt.Errorf("%w: reserved additional info %d", errCBOR, info)
	case info == 31:
		return 0, 0, 0, fmt.Errorf("%w: indefinite length or break", errCBOR)
	case major == 7:
		return 0, 0, 0, fmt.Errorf("%w: float or simple value", errCBOR)
	case major == 6:
		return 0, 0, 0, fmt.Errorf("%w: tag", errCBOR)
	}
	off++
	if info < 24 {
		return major, uint64(info), off, nil
	}
	n := 1 << (info - 24)
	if n > len(b)-off {
		return 0, 0, 0, fmt.Errorf("%w: truncated argument", errCBOR)
	}
	for _, c := range b[off : off+n] {
		arg = arg<<8 | uint64(c)
	}
	var min uint64
	switch n {
	case 1:
		min = 24
	case 2:
		min = 1 << 8
	case 4:
		min = 1 << 16
	case 8:
		min = 1 << 32
	}
	if arg < min {
		return 0, 0, 0, fmt.Errorf("%w: argument not in its shortest form", errCBOR)
	}
	return major, arg, off + n, nil
}

// cborWellFormed checks that b is exactly one well-formed data item of the
// core profile: definite lengths, shortest heads, no floats, simple values or
// tags, uint map keys strictly ascending, valid UTF-8, bounded depth and
// entries, nothing after the item.
func cborWellFormed(b []byte) error {
	end, err := cborItem(b, 0, 1)
	if err != nil {
		return err
	}
	if end != len(b) {
		return fmt.Errorf("%w: %d bytes after the item", errCBOR, len(b)-end)
	}
	return nil
}

func cborItem(b []byte, off, depth int) (int, error) {
	major, arg, off, err := cborHead(b, off)
	if err != nil {
		return 0, err
	}
	switch major {
	case majorUint, 1:
		return off, nil
	case majorBytes, majorText:
		if arg > uint64(len(b)-off) {
			return 0, fmt.Errorf("%w: string extends past the input", errCBOR)
		}
		end := off + int(arg)
		if major == majorText && !utf8.Valid(b[off:end]) {
			return 0, fmt.Errorf("%w: text string is not UTF-8", errCBOR)
		}
		return end, nil
	}
	// Array or map.
	if depth > maxDepth {
		return 0, fmt.Errorf("%w: nested deeper than %d", errCBOR, maxDepth)
	}
	if arg > maxEntries {
		return 0, fmt.Errorf("%w: %d entries", errCBOR, arg)
	}
	per := 1
	if major == majorMap {
		per = 2
	}
	if arg*uint64(per) > uint64(len(b)-off) {
		return 0, fmt.Errorf("%w: container extends past the input", errCBOR)
	}
	var prev uint64
	for i := uint64(0); i < arg; i++ {
		if major == majorMap {
			km, k, next, err := cborHead(b, off)
			if err != nil {
				return 0, err
			}
			switch {
			case km != majorUint:
				return 0, fmt.Errorf("%w: map key is not a uint", errCBOR)
			case i > 0 && k == prev:
				return 0, fmt.Errorf("%w: duplicate map key %d", errCBOR, k)
			case i > 0 && k < prev:
				return 0, fmt.Errorf("%w: map keys not ascending", errCBOR)
			}
			prev, off = k, next
		}
		if off, err = cborItem(b, off, depth+1); err != nil {
			return 0, err
		}
	}
	return off, nil
}
