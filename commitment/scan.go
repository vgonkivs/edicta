package commitment

import (
	"fmt"
	"unicode/utf8"
)

const (
	maxDepth   = 4
	maxEntries = 16
)

// CBOR major types.
const (
	majUint = 0
	majNint = 1
	majBstr = 2
	majTstr = 3
	majArr  = 4
	majMap  = 5
	majTag  = 6
	majSimp = 7
)

type node struct {
	major   byte
	u       uint64 // integer value; for strings, arrays and maps the length
	b       []byte // string content, aliasing the input
	entries []entry
	start   int
	end     int
}

type entry struct {
	key uint64
	val *node
}

// scanner is the pass-1 well-formedness check. It builds a small
// tree so pass 2 never re-parses bytes.
type scanner struct {
	in []byte
	// depth of the outermost container in the input: 1 for an envelope,
	// 2 for a bare commitment.
	baseDepth int
}

func (s *scanner) fail(sentinel error, off int, format string, a ...any) error {
	return fmt.Errorf("%w: offset %d: %s", sentinel, off, fmt.Sprintf(format, a...))
}

// scanTop parses exactly one top-level item and rejects trailing bytes.
func scanTop(in []byte, baseDepth int) (*node, error) {
	s := &scanner{in: in, baseDepth: baseDepth}
	n, err := s.item(0, s.baseDepth)
	if err != nil {
		return nil, err
	}
	if n.end != len(in) {
		return nil, s.fail(ErrTrailingData, n.end, "%d bytes after top-level item", len(in)-n.end)
	}
	return n, nil
}

// item parses the data item at off. depth is the depth this item would have
// if it is a container.
func (s *scanner) item(off, depth int) (*node, error) {
	in := s.in
	if off >= len(in) {
		return nil, s.fail(ErrMalformed, off, "truncated")
	}
	major := in[off] >> 5
	info := in[off] & 0x1f
	n := &node{major: major, start: off}
	pos := off + 1

	switch {
	case info >= 28 && info <= 30:
		return nil, s.fail(ErrMalformed, off, "reserved additional info %d", info)
	case info == 31:
		switch major {
		case majBstr, majTstr, majArr, majMap:
			return nil, s.fail(ErrIndefiniteLength, off, "indefinite length")
		default:
			return nil, s.fail(ErrMalformed, off, "stray break or indefinite head")
		}
	}

	switch major {
	case majSimp:
		if info >= 25 {
			return nil, s.fail(ErrFloat, off, "float")
		}
		return nil, s.fail(ErrSimpleValue, off, "simple value")
	case majTag:
		return nil, s.fail(ErrTag, off, "tag")
	}

	var val uint64
	switch {
	case info < 24:
		val = uint64(info)
	default:
		width := 1 << (info - 24)
		if len(in)-pos < width {
			return nil, s.fail(ErrMalformed, off, "truncated head argument")
		}
		for i := 0; i < width; i++ {
			val = val<<8 | uint64(in[pos+i])
		}
		pos += width
		// Shortest form: the value must not fit in the next smaller head.
		minVal := [4]uint64{24, 1 << 8, 1 << 16, 1 << 32}[info-24]
		if val < minVal {
			return nil, s.fail(ErrNonMinimalInt, off, "value %d in a %d-byte argument", val, width)
		}
	}
	n.u = val

	switch major {
	case majUint, majNint:
		n.end = pos
		return n, nil

	case majBstr, majTstr:
		if val > uint64(len(in)-pos) {
			return nil, s.fail(ErrMalformed, off, "string length %d exceeds input", val)
		}
		n.b = in[pos : pos+int(val)]
		if major == majTstr && !utf8.Valid(n.b) {
			return nil, s.fail(ErrInvalidString, off, "invalid UTF-8")
		}
		n.end = pos + int(val)
		return n, nil
	}

	// Array or map.
	if depth > maxDepth {
		return nil, s.fail(ErrNestingTooDeep, off, "depth %d", depth)
	}
	if val > maxEntries {
		return nil, s.fail(ErrTooLarge, off, "%d entries", val)
	}
	need := val
	if major == majMap {
		need = val * 2
	}
	if need > uint64(len(in)-pos) {
		return nil, s.fail(ErrMalformed, off, "container of %d entries exceeds input", val)
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
			return nil, s.fail(ErrKeyType, pos, "map key of major type %d", k.major)
		}
		if i > 0 {
			if k.u == prev {
				return nil, s.fail(ErrDuplicateKey, pos, "key %d", k.u)
			}
			if k.u < prev {
				return nil, s.fail(ErrUnsortedMap, pos, "key %d after %d", k.u, prev)
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
