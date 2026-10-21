// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
)

// obj is a JSON object that keeps its key order, so the vector files diff
// cleanly and read in the order the profile describes them.
type obj []kv

type kv struct {
	K string
	V any
}

func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(e.K)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(e.V)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func dec(u uint64) string { return strconv.FormatUint(u, 10) }

func label(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Hand-built RLP, so that the reject vectors can hold encodings that
// go-ethereum's encoder would never emit.

func rlpHead(short, long byte, n int) []byte {
	if n <= 55 {
		return []byte{short + byte(n)}
	}
	l := big.NewInt(int64(n)).Bytes()
	return append([]byte{long + byte(len(l))}, l...)
}

func rlpStr(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpHead(0x80, 0xb7, len(b)), b...)
}

func rlpBig(x *big.Int) []byte { return rlpStr(x.Bytes()) }

func rlpUint(u uint64) []byte { return rlpBig(new(big.Int).SetUint64(u)) }

func rlpList(items ...[]byte) []byte {
	p := cat(items...)
	return append(rlpHead(0xc0, 0xf7, len(p)), p...)
}

// Hand-built CBOR in the core profile, for the same reason.

func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 1<<8:
		return []byte{m | 24, byte(n)}
	case n < 1<<16:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		b := []byte{m | 27}
		for i := 7; i >= 0; i-- {
			b = append(b, byte(n>>(8*i)))
		}
		return b
	}
}

func cborUint(n uint64) []byte  { return cborHead(0, n) }
func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

// cborMap writes the pairs in the given order; callers pass canonical order
// unless the vector is about a broken order.
func cborMap(pairs ...[]byte) []byte {
	return append(cborHead(5, uint64(len(pairs)/2)), cat(pairs...)...)
}
