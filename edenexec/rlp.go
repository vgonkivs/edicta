// SPDX-License-Identifier: Apache-2.0

package edenexec

import "golang.org/x/crypto/sha3"

// rlpBytes is the canonical encoding of the byte string b.
func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpHeader(0x80, len(b)), b...)
}

// rlpList is the canonical encoding of a list whose items are already
// encoded.
func rlpList(items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	out := make([]byte, 0, n+9)
	out = append(out, rlpHeader(0xc0, n)...)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// rlpHeader is the short or long form header with base 0x80 (string) or
// 0xc0 (list) for a payload of n bytes.
func rlpHeader(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	var lb []byte
	for v := uint64(n); v > 0; v >>= 8 {
		lb = append([]byte{byte(v)}, lb...)
	}
	return append([]byte{base + 55 + byte(len(lb))}, lb...)
}

// rlpUint64 is the canonical encoding of an integer.
func rlpUint64(v uint64) []byte {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return rlpBytes(b)
}

// rlpQuantity encodes minimal big-endian integer bytes; a leading zero byte
// would make the encoding non-canonical, so it is refused.
func rlpQuantity(b []byte) ([]byte, bool) {
	if len(b) > 0 && b[0] == 0 {
		return nil, false
	}
	return rlpBytes(b), true
}

func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
