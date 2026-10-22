// SPDX-License-Identifier: Apache-2.0

// Package edenrpc reads Eden through its JSON-RPC: an edenexec.Source over
// eth_* methods and an edenexec.DAStatus over the operator's own ev-node.
// Every answer is read strictly: one JSON value, valid UTF-8, no key twice in
// an object (compared without case, as encoding/json matches field names),
// bounded depth and size, and hex in its canonical form.
package edenrpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrMalformed is an answer that is not strict JSON or not the expected
// shape.
var ErrMalformed = errors.New("edenrpc: malformed answer")

// maxDepth bounds nesting; a block with access lists is about six deep.
const maxDepth = 32

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// checkStrict accepts exactly one JSON value with no duplicate object keys.
func checkStrict(b []byte) error {
	if !utf8.Valid(b) {
		return malformed("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next token of an object is a key
	}
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return malformed("%v", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.key {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 {
					stack[len(stack)-1].key = true
				}
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return malformed("object key is not a string")
			}
			// encoding/json matches field names with Unicode case folding,
			// so a non-ASCII key could alias an ASCII one; the RPC uses
			// ASCII keys only.
			for i := 0; i < len(k); i++ {
				if k[i] >= utf8.RuneSelf {
					return malformed("non-ASCII key %q", k)
				}
			}
			lk := strings.ToLower(k)
			if top.keys[lk] {
				return malformed("key %q appears twice", k)
			}
			top.keys[lk] = true
			top.key = false
			continue
		}
		if len(stack) == 0 {
			values++
			if values > 1 {
				return malformed("more than one value")
			}
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxDepth {
					return malformed("nested deeper than %d", maxDepth)
				}
				stack = append(stack, &frame{object: d == '{', keys: map[string]bool{}, key: d == '{'})
			case ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 {
					stack[len(stack)-1].key = true
				}
			}
			continue
		}
		if top != nil && top.object {
			top.key = true
		}
	}
	if values != 1 || len(stack) != 0 {
		return malformed("not one complete value")
	}
	return nil
}

// quantity reads a JSON-RPC quantity: 0x and minimal hex digits, 0x0 for
// zero. The result is minimal big-endian bytes, empty for zero.
func quantity(s string, maxBytes int) ([]byte, error) {
	digits, ok := strings.CutPrefix(s, "0x")
	switch {
	case !ok || digits == "":
		return nil, malformed("quantity %q", s)
	case digits == "0":
		return []byte{}, nil
	case digits[0] == '0':
		return nil, malformed("quantity %q has a leading zero", s)
	case len(digits) > 2*maxBytes:
		return nil, malformed("quantity %q is longer than %d bytes", s, maxBytes)
	}
	if len(digits)%2 == 1 {
		digits = "0" + digits
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return nil, malformed("quantity %q", s)
	}
	return b, nil
}

func quantity64(s string) (uint64, error) {
	b, err := quantity(s, 8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// data reads 0x and an even number of hex digits.
func data(s string) ([]byte, error) {
	digits, ok := strings.CutPrefix(s, "0x")
	if !ok || len(digits)%2 == 1 {
		return nil, malformed("data %q", trunc(s))
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return nil, malformed("data %q", trunc(s))
	}
	return b, nil
}

func fixed(s string, dst []byte) error {
	b, err := data(s)
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return malformed("%d bytes where %d are expected", len(b), len(dst))
	}
	copy(dst, b)
	return nil
}

func trunc(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
