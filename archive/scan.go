package archive

import (
	"fmt"
	"unicode/utf8"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	maxDepth = 2
	maxPairs = 24
)

const (
	majUint = 0
	majNint = 1
	majBstr = 2
	majTstr = 3
	majArr  = 4
	majMap  = 5
)

type gitem struct {
	major byte
	u     uint64
	b     []byte // string content, aliasing the input
	pairs []gpair
}

type gpair struct {
	key uint64
	val *gitem
}

type scanner struct {
	in  []byte
	pos int
}

func scanFail(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))
}

// scanTop parses exactly one item under the archive limits: depth 2, 24
// entries per container.
func scanTop(in []byte) (*gitem, error) {
	s := &scanner{in: in}
	it, err := s.item(0)
	if err != nil {
		return nil, err
	}
	if s.pos != len(in) {
		return nil, scanFail(commitment.ErrTrailingData, "%d bytes after the record", len(in)-s.pos)
	}
	return it, nil
}

func (s *scanner) head() (major byte, arg uint64, err error) {
	if s.pos >= len(s.in) {
		return 0, 0, scanFail(commitment.ErrMalformed, "truncated at offset %d", s.pos)
	}
	ib := s.in[s.pos]
	off := s.pos
	s.pos++
	major, ai := ib>>5, ib&0x1f
	switch {
	case ai >= 28 && ai <= 30:
		return 0, 0, scanFail(commitment.ErrMalformed, "reserved additional info %d", ai)
	case ai == 31:
		if major >= majBstr && major <= majMap {
			return 0, 0, scanFail(commitment.ErrIndefiniteLength, "major %d", major)
		}
		return 0, 0, scanFail(commitment.ErrMalformed, "additional info 31 on major %d", major)
	case major == 7:
		if ai >= 25 && ai <= 27 {
			return 0, 0, scanFail(commitment.ErrFloat, "offset %d", off)
		}
		return 0, 0, scanFail(commitment.ErrSimpleValue, "simple value %d", ai)
	case major == 6:
		return 0, 0, scanFail(commitment.ErrTag, "offset %d", off)
	case ai < 24:
		return major, uint64(ai), nil
	}
	n := 1 << (ai - 24)
	if len(s.in)-s.pos < n {
		return 0, 0, scanFail(commitment.ErrMalformed, "truncated at offset %d", s.pos)
	}
	for i := 0; i < n; i++ {
		arg = arg<<8 | uint64(s.in[s.pos+i])
	}
	s.pos += n
	if arg < [4]uint64{24, 1 << 8, 1 << 16, 1 << 32}[ai-24] {
		return 0, 0, scanFail(commitment.ErrNonMinimalInt, "argument %d in %d bytes", arg, n)
	}
	return major, arg, nil
}

func (s *scanner) item(depth int) (*gitem, error) {
	major, arg, err := s.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case majUint, majNint:
		return &gitem{major: major, u: arg}, nil
	case majBstr, majTstr:
		if arg > uint64(len(s.in)-s.pos) {
			return nil, scanFail(commitment.ErrMalformed, "string length exceeds input")
		}
		raw := s.in[s.pos : s.pos+int(arg)]
		s.pos += int(arg)
		if major == majTstr && !utf8.Valid(raw) {
			return nil, scanFail(commitment.ErrInvalidString, "invalid UTF-8")
		}
		return &gitem{major: major, b: raw}, nil
	}
	if depth+1 > maxDepth {
		return nil, scanFail(commitment.ErrNestingTooDeep, "container at depth %d", depth+1)
	}
	if arg > maxPairs {
		return nil, scanFail(commitment.ErrTooLarge, "%d entries exceed %d", arg, maxPairs)
	}
	remaining := uint64(len(s.in) - s.pos)
	if major == majArr {
		if arg > remaining {
			return nil, scanFail(commitment.ErrMalformed, "array length exceeds input")
		}
		for i := uint64(0); i < arg; i++ {
			if _, err := s.item(depth + 1); err != nil {
				return nil, err
			}
		}
		return &gitem{major: majArr, u: arg}, nil
	}
	if 2*arg > remaining {
		return nil, scanFail(commitment.ErrMalformed, "map length exceeds input")
	}
	it := &gitem{major: majMap, u: arg}
	var prev uint64
	for i := uint64(0); i < arg; i++ {
		k, err := s.item(depth + 1)
		if err != nil {
			return nil, err
		}
		if k.major != majUint {
			return nil, scanFail(commitment.ErrKeyType, "map key of major type %d", k.major)
		}
		if i > 0 {
			if k.u == prev {
				return nil, scanFail(commitment.ErrDuplicateKey, "key %d", k.u)
			}
			if k.u < prev {
				return nil, scanFail(commitment.ErrUnsortedMap, "key %d after %d", k.u, prev)
			}
		}
		prev = k.u
		v, err := s.item(depth + 1)
		if err != nil {
			return nil, err
		}
		it.pairs = append(it.pairs, gpair{key: k.u, val: v})
	}
	return it, nil
}
