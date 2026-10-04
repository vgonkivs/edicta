package edictaapi

import (
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/vgonkivs/edicta/commitment"
)

// A minimal strict decoder and canonical encoder for the wrapper maps of
// section 18 (CBOR profile of section 3, uint keys). Pass 1 (well-formedness)
// completes before pass 2 (schema), as in section 6.

const (
	maxDepth   = 4
	maxEntries = 16
)

const (
	majUint = 0
	majBstr = 2
	majTstr = 3
	majArr  = 4
	majMap  = 5
	majTag  = 6
	majSimp = 7
)

type node struct {
	major   byte
	u       uint64
	b       []byte // aliases the input
	entries []entry
	end     int
}

type entry struct {
	key uint64
	val *node
}

type scanner struct{ in []byte }

func fail(sentinel error, off int, msg string) error {
	return fmt.Errorf("%w: offset %d: %s", sentinel, off, msg)
}

func scanTop(in []byte) (*node, error) {
	s := &scanner{in: in}
	n, err := s.item(0, 1)
	if err != nil {
		return nil, err
	}
	if n.end != len(in) {
		return nil, fail(commitment.ErrTrailingData, n.end, "bytes after the top-level item")
	}
	return n, nil
}

func (s *scanner) item(off, depth int) (*node, error) {
	in := s.in
	if off >= len(in) {
		return nil, fail(commitment.ErrMalformed, off, "truncated")
	}
	major := in[off] >> 5
	info := in[off] & 0x1f
	n := &node{major: major}
	pos := off + 1

	switch {
	case info >= 28 && info <= 30:
		return nil, fail(commitment.ErrMalformed, off, "reserved additional info")
	case info == 31:
		switch major {
		case majBstr, majTstr, majArr, majMap:
			return nil, fail(commitment.ErrIndefiniteLength, off, "indefinite length")
		default:
			return nil, fail(commitment.ErrMalformed, off, "stray break")
		}
	}
	switch major {
	case majSimp:
		if info >= 25 {
			return nil, fail(commitment.ErrFloat, off, "float")
		}
		return nil, fail(commitment.ErrSimpleValue, off, "simple value")
	case majTag:
		return nil, fail(commitment.ErrTag, off, "tag")
	}

	var val uint64
	if info < 24 {
		val = uint64(info)
	} else {
		width := 1 << (info - 24)
		if len(in)-pos < width {
			return nil, fail(commitment.ErrMalformed, off, "truncated head argument")
		}
		for i := 0; i < width; i++ {
			val = val<<8 | uint64(in[pos+i])
		}
		pos += width
		minVal := [4]uint64{24, 1 << 8, 1 << 16, 1 << 32}[info-24]
		if val < minVal {
			return nil, fail(commitment.ErrNonMinimalInt, off, "non-minimal head")
		}
	}
	n.u = val

	switch major {
	case majUint, 1:
		n.end = pos
		return n, nil
	case majBstr, majTstr:
		if val > uint64(len(in)-pos) {
			return nil, fail(commitment.ErrMalformed, off, "string length exceeds input")
		}
		n.b = in[pos : pos+int(val)]
		if major == majTstr && !utf8.Valid(n.b) {
			return nil, fail(commitment.ErrInvalidString, off, "invalid UTF-8")
		}
		n.end = pos + int(val)
		return n, nil
	}

	if depth > maxDepth {
		return nil, fail(commitment.ErrNestingTooDeep, off, "nesting")
	}
	if val > maxEntries {
		return nil, fail(commitment.ErrTooLarge, off, "too many entries")
	}
	need := val
	if major == majMap {
		need = val * 2
	}
	if need > uint64(len(in)-pos) {
		return nil, fail(commitment.ErrMalformed, off, "container exceeds input")
	}
	if major == majArr {
		for i := uint64(0); i < val; i++ {
			c, err := s.item(pos, depth+1)
			if err != nil {
				return nil, err
			}
			n.entries = append(n.entries, entry{val: c})
			pos = c.end
		}
		n.end = pos
		return n, nil
	}
	var prev uint64
	for i := uint64(0); i < val; i++ {
		k, err := s.item(pos, depth+1)
		if err != nil {
			return nil, err
		}
		if k.major != majUint {
			return nil, fail(commitment.ErrKeyType, pos, "map key is not a uint")
		}
		if i > 0 {
			if k.u == prev {
				return nil, fail(commitment.ErrDuplicateKey, pos, "duplicate key")
			}
			if k.u < prev {
				return nil, fail(commitment.ErrUnsortedMap, pos, "keys not ascending")
			}
		}
		prev = k.u
		v, err := s.item(k.end, depth+1)
		if err != nil {
			return nil, err
		}
		n.entries = append(n.entries, entry{key: k.u, val: v})
		pos = v.end
	}
	n.end = pos
	return n, nil
}

type fkind uint8

const (
	fUint fkind = iota
	fBytes
	fText
	fUintArray
)

func (k fkind) major() byte {
	return [...]byte{majUint, majBstr, majTstr, majArr}[k]
}

type fspec struct {
	key      uint64
	name     string
	kind     fkind
	min, max uint64 // length of strings, entries of arrays
	charset  func(byte) bool
	required bool
}

const unbounded = math.MaxInt32

func isID(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isID(s[i]) {
			return false
		}
	}
	return true
}

// decodeFields parses b as one map and applies the schema. Values alias b.
func decodeFields(b []byte, schema []fspec) (map[uint64]*node, error) {
	root, err := scanTop(b)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: top-level item is not a map", commitment.ErrWrongType)
	}
	seen := make(map[uint64]*node, len(root.entries))
	for _, e := range root.entries {
		var f *fspec
		for i := range schema {
			if schema[i].key == e.key {
				f = &schema[i]
				break
			}
		}
		if f == nil {
			return nil, fmt.Errorf("%w: key %d", commitment.ErrUnknownKey, e.key)
		}
		v := e.val
		if v.major != f.kind.major() {
			return nil, fmt.Errorf("%w: %s", commitment.ErrWrongType, f.name)
		}
		switch f.kind {
		case fBytes, fText:
			if uint64(len(v.b)) < f.min || uint64(len(v.b)) > f.max {
				return nil, fmt.Errorf("%w: %s length %d", commitment.ErrFieldSize, f.name, len(v.b))
			}
			if f.charset != nil {
				for _, c := range v.b {
					if !f.charset(c) {
						return nil, fmt.Errorf("%w: %s outside its charset", commitment.ErrInvalidString, f.name)
					}
				}
			}
		case fUintArray:
			if uint64(len(v.entries)) < f.min || uint64(len(v.entries)) > f.max {
				return nil, fmt.Errorf("%w: %s has %d entries", commitment.ErrFieldSize, f.name, len(v.entries))
			}
			for _, el := range v.entries {
				if el.val.major != majUint {
					return nil, fmt.Errorf("%w: %s element", commitment.ErrWrongType, f.name)
				}
			}
		}
		seen[e.key] = v
	}
	for _, f := range schema {
		if f.required && seen[f.key] == nil {
			return nil, fmt.Errorf("%w: %s", commitment.ErrMissingField, f.name)
		}
	}
	return seen, nil
}

// ---- canonical encoder ----

func appendHead(b []byte, major byte, v uint64) []byte {
	m := major << 5
	switch {
	case v < 24:
		return append(b, m|byte(v))
	case v < 1<<8:
		return append(b, m|24, byte(v))
	case v < 1<<16:
		return append(b, m|25, byte(v>>8), byte(v))
	case v < 1<<32:
		return append(b, m|26, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, m|27, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// kv is one map entry; items passed to encodeMap are in ascending key order.
type kv struct {
	key  uint64
	kind fkind
	u    uint64
	b    []byte
	s    string
	arr  []uint64
}

func encodeMap(items ...kv) []byte {
	out := appendHead(nil, majMap, uint64(len(items)))
	for _, it := range items {
		out = appendHead(out, majUint, it.key)
		switch it.kind {
		case fUint:
			out = appendHead(out, majUint, it.u)
		case fBytes:
			out = appendHead(out, majBstr, uint64(len(it.b)))
			out = append(out, it.b...)
		case fText:
			out = appendHead(out, majTstr, uint64(len(it.s)))
			out = append(out, it.s...)
		case fUintArray:
			out = appendHead(out, majArr, uint64(len(it.arr)))
			for _, v := range it.arr {
				out = appendHead(out, majUint, v)
			}
		}
	}
	return out
}
