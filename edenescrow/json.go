// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// The payment server's answers (the /deposit/build body and the
// PAYMENT-REQUIRED document) are read as strict JSON documents: UTF-8
// without a byte order mark, whitespace only space, tab, LF and CR, nothing
// after the value, and no member name twice in any object at any depth,
// compared after unescaping. Two parsers that resolve a repeated name
// differently would read one answer as two deposits.

var errJSON = errors.New("json")

type jsonKind uint8

const (
	jsonObject jsonKind = iota + 1
	jsonArray
	jsonString
	jsonNumber
	jsonLiteral // true, false, null
)

// jsonValue is one parsed value. text is the unescaped string, the number's
// source text or the literal's name.
type jsonValue struct {
	kind    jsonKind
	text    string
	members []jsonMember
	elems   []*jsonValue
}

type jsonMember struct {
	name  string
	value *jsonValue
}

// member returns the value of the named member of an object; names are
// unique, so there is at most one.
func (v *jsonValue) member(name string) *jsonValue {
	if v == nil || v.kind != jsonObject {
		return nil
	}
	for _, m := range v.members {
		if m.name == name {
			return m.value
		}
	}
	return nil
}

func (v *jsonValue) isString() bool { return v != nil && v.kind == jsonString }

type jsonFrame struct {
	v     *jsonValue
	names map[string]struct{}
}

type jsonParser struct {
	b   []byte
	off int
}

// parseJSON reads exactly one strict JSON document. Nesting is kept on an
// explicit stack, so no input depth can exhaust the goroutine stack.
func parseJSON(b []byte) (*jsonValue, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not UTF-8", errJSON)
	}
	p := &jsonParser{b: b}
	var (
		root  *jsonValue
		stack []*jsonFrame
	)
	for {
		p.space()
		var name string
		if n := len(stack); n > 0 && stack[n-1].v.kind == jsonObject {
			nm, err := p.memberName(stack[n-1])
			if err != nil {
				return nil, err
			}
			name = nm
		}
		v, err := p.valueStart()
		if err != nil {
			return nil, err
		}
		if n := len(stack); n == 0 {
			root = v
		} else if top := stack[n-1].v; top.kind == jsonObject {
			top.members = append(top.members, jsonMember{name: name, value: v})
		} else {
			top.elems = append(top.elems, v)
		}
		if v.kind == jsonObject || v.kind == jsonArray {
			f := &jsonFrame{v: v}
			if v.kind == jsonObject {
				f.names = map[string]struct{}{}
			}
			stack = append(stack, f)
			p.space()
			if !p.closes(v.kind) {
				continue
			}
			p.off++
			stack = stack[:len(stack)-1]
		}
		// A value is complete: close containers until a comma asks for the
		// next one.
		for {
			p.space()
			if len(stack) == 0 {
				if p.off != len(p.b) {
					return nil, fmt.Errorf("%w: %d bytes after the document", errJSON, len(p.b)-p.off)
				}
				return root, nil
			}
			if p.off >= len(p.b) {
				return nil, fmt.Errorf("%w: truncated", errJSON)
			}
			top := stack[len(stack)-1].v
			if p.b[p.off] == ',' {
				p.off++
				break
			}
			if !p.closes(top.kind) {
				return nil, fmt.Errorf("%w: unexpected byte 0x%02x at %d", errJSON, p.b[p.off], p.off)
			}
			p.off++
			stack = stack[:len(stack)-1]
		}
	}
}

func (p *jsonParser) space() {
	for p.off < len(p.b) {
		switch p.b[p.off] {
		case ' ', '\t', '\n', '\r':
			p.off++
		default:
			return
		}
	}
}

// closes reports whether the next byte ends a container of kind k.
func (p *jsonParser) closes(k jsonKind) bool {
	if p.off >= len(p.b) {
		return false
	}
	c := p.b[p.off]
	return k == jsonObject && c == '}' || k == jsonArray && c == ']'
}

func (p *jsonParser) memberName(f *jsonFrame) (string, error) {
	if p.off >= len(p.b) || p.b[p.off] != '"' {
		return "", fmt.Errorf("%w: member name expected at %d", errJSON, p.off)
	}
	name, err := p.str()
	if err != nil {
		return "", err
	}
	if _, dup := f.names[name]; dup {
		return "", fmt.Errorf("%w: member %q repeated", errJSON, name)
	}
	f.names[name] = struct{}{}
	p.space()
	if p.off >= len(p.b) || p.b[p.off] != ':' {
		return "", fmt.Errorf("%w: colon expected at %d", errJSON, p.off)
	}
	p.off++
	p.space()
	return name, nil
}

// valueStart reads a scalar or the opening of a container.
func (p *jsonParser) valueStart() (*jsonValue, error) {
	if p.off >= len(p.b) {
		return nil, fmt.Errorf("%w: value expected at the end", errJSON)
	}
	switch c := p.b[p.off]; {
	case c == '{':
		p.off++
		return &jsonValue{kind: jsonObject}, nil
	case c == '[':
		p.off++
		return &jsonValue{kind: jsonArray}, nil
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &jsonValue{kind: jsonString, text: s}, nil
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	}
	for _, lit := range []string{"true", "false", "null"} {
		if len(p.b)-p.off >= len(lit) && string(p.b[p.off:p.off+len(lit)]) == lit {
			p.off += len(lit)
			return &jsonValue{kind: jsonLiteral, text: lit}, nil
		}
	}
	return nil, fmt.Errorf("%w: unexpected byte 0x%02x at %d", errJSON, p.b[p.off], p.off)
}

// number reads the RFC 8259 number grammar and keeps its source text.
func (p *jsonParser) number() (*jsonValue, error) {
	start := p.off
	digits := func() int {
		n := 0
		for p.off < len(p.b) && p.b[p.off] >= '0' && p.b[p.off] <= '9' {
			p.off++
			n++
		}
		return n
	}
	bad := func() (*jsonValue, error) {
		return nil, fmt.Errorf("%w: malformed number at %d", errJSON, start)
	}
	if p.b[p.off] == '-' {
		p.off++
	}
	if p.off < len(p.b) && p.b[p.off] == '0' {
		p.off++
	} else if digits() == 0 {
		return bad()
	}
	if p.off < len(p.b) && p.b[p.off] == '.' {
		p.off++
		if digits() == 0 {
			return bad()
		}
	}
	if p.off < len(p.b) && (p.b[p.off] == 'e' || p.b[p.off] == 'E') {
		p.off++
		if p.off < len(p.b) && (p.b[p.off] == '+' || p.b[p.off] == '-') {
			p.off++
		}
		if digits() == 0 {
			return bad()
		}
	}
	return &jsonValue{kind: jsonNumber, text: string(p.b[start:p.off])}, nil
}

// str reads a string at p.off and returns it unescaped. Raw control
// characters and unpaired surrogates are refused: neither has one agreed
// reading.
func (p *jsonParser) str() (string, error) {
	start := p.off
	p.off++
	var out []byte
	for {
		if p.off >= len(p.b) {
			return "", fmt.Errorf("%w: unterminated string at %d", errJSON, start)
		}
		c := p.b[p.off]
		switch {
		case c == '"':
			p.off++
			return string(out), nil
		case c < 0x20:
			return "", fmt.Errorf("%w: raw control character in a string at %d", errJSON, p.off)
		case c != '\\':
			out = append(out, c)
			p.off++
			continue
		}
		p.off++
		if p.off >= len(p.b) {
			return "", fmt.Errorf("%w: unterminated escape", errJSON)
		}
		e := p.b[p.off]
		p.off++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return "", err
			}
			if utf16.IsSurrogate(r) {
				lo := rune(-1)
				if r < 0xdc00 && len(p.b)-p.off >= 2 && p.b[p.off] == '\\' && p.b[p.off+1] == 'u' {
					p.off += 2
					if lo, err = p.hex4(); err != nil {
						return "", err
					}
				}
				if r = utf16.DecodeRune(r, lo); r == utf8.RuneError {
					return "", fmt.Errorf("%w: unpaired surrogate", errJSON)
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", fmt.Errorf("%w: escape \\%c", errJSON, e)
		}
	}
}

func (p *jsonParser) hex4() (rune, error) {
	if len(p.b)-p.off < 4 {
		return 0, fmt.Errorf("%w: short \\u escape", errJSON)
	}
	v, err := strconv.ParseUint(string(p.b[p.off:p.off+4]), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: \\u escape %q", errJSON, p.b[p.off:p.off+4])
	}
	p.off += 4
	return rune(v), nil
}

// maxSafeInt is 2^53 - 1, the largest integer every JSON implementation
// reads exactly.
const maxSafeInt = 1<<53 - 1

// jsonUint reads a JSON number in integer form: digits only, no sign,
// fraction or exponent, no leading zero, at most 2^53 - 1.
func jsonUint(v *jsonValue) (uint64, bool) {
	if v == nil || v.kind != jsonNumber || !canonicalDecimal(v.text, 16) {
		return 0, false
	}
	n, err := strconv.ParseUint(v.text, 10, 64)
	if err != nil || n > maxSafeInt {
		return 0, false
	}
	return n, true
}

// maxDecimalDigits bounds a decimal string: 2^256 - 1 has 78 digits.
const maxDecimalDigits = 78

// decimalString reads a JSON string of 1 to 78 decimal digits without a
// sign, spaces or a leading zero other than "0" itself.
func decimalString(v *jsonValue) (*big.Int, bool) {
	if !v.isString() || !canonicalDecimal(v.text, maxDecimalDigits) {
		return nil, false
	}
	n, ok := new(big.Int).SetString(v.text, 10)
	return n, ok
}

func canonicalDecimal(s string, maxDigits int) bool {
	if len(s) < 1 || len(s) > maxDigits || len(s) > 1 && s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hexString reads a JSON string of a lower-case "0x" and hex digits of
// either case. n is the number of bytes, or -1 for any even count.
func hexString(v *jsonValue, n int) ([]byte, bool) {
	if !v.isString() || len(v.text) < 2 || v.text[:2] != "0x" {
		return nil, false
	}
	digits := v.text[2:]
	if len(digits)%2 != 0 || n >= 0 && len(digits) != 2*n {
		return nil, false
	}
	out := make([]byte, len(digits)/2)
	for i := range out {
		hi, ok1 := hexNibble(digits[2*i])
		lo, ok2 := hexNibble(digits[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
