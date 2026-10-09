package absence

import (
	"fmt"
	"unicode/utf8"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	majUint  = 0
	majNint  = 1
	majBytes = 2
	majText  = 3
	majArray = 4
	majMap   = 5
	majTag   = 6
	majOther = 7

	// The archive's generic limits: two levels of containers, 24 entries.
	maxDepth   = 2
	maxEntries = 24
)

// item is a decoded CBOR value. Only the top-level map keeps its values;
// nested containers are checked for well-formedness and dropped.
type item struct {
	major byte
	u     uint64
	b     []byte
	pairs []pair
}

type pair struct {
	key uint64
	val item
}

type scanner struct {
	in []byte
	at int
}

func scanFail(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))
}

// scanTop runs the generic well-formedness pass of archive records over in.
func scanTop(in []byte) (item, error) {
	s := &scanner{in: in}
	it, err := s.item(0)
	if err != nil {
		return item{}, err
	}
	if s.at != len(in) {
		return item{}, scanFail(commitment.ErrTrailingData, "%d bytes after the record", len(in)-s.at)
	}
	return it, nil
}

func (s *scanner) head() (byte, uint64, error) {
	if s.at >= len(s.in) {
		return 0, 0, scanFail(commitment.ErrMalformed, "truncated at offset %d", s.at)
	}
	ib := s.in[s.at]
	s.at++
	major, ai := ib>>5, ib&0x1f
	switch {
	case ai >= 28 && ai <= 30:
		return 0, 0, scanFail(commitment.ErrMalformed, "reserved additional info %d", ai)
	case ai == 31 && major >= majBytes && major <= majMap:
		return 0, 0, scanFail(commitment.ErrIndefiniteLength, "major %d", major)
	case ai == 31:
		return 0, 0, scanFail(commitment.ErrMalformed, "additional info 31 on major %d", major)
	case major == majOther && ai >= 25 && ai <= 27:
		return 0, 0, scanFail(commitment.ErrFloat, "offset %d", s.at-1)
	case major == majOther:
		return 0, 0, scanFail(commitment.ErrSimpleValue, "simple value %d", ai)
	case major == majTag:
		return 0, 0, scanFail(commitment.ErrTag, "offset %d", s.at-1)
	case ai < 24:
		return major, uint64(ai), nil
	}
	n := 1 << (ai - 24)
	if len(s.in)-s.at < n {
		return 0, 0, scanFail(commitment.ErrMalformed, "truncated at offset %d", s.at)
	}
	var arg uint64
	for _, c := range s.in[s.at : s.at+n] {
		arg = arg<<8 | uint64(c)
	}
	s.at += n
	minimal := uint64(24)
	if n > 1 {
		minimal = 1 << (4 * n)
	}
	if arg < minimal {
		return 0, 0, scanFail(commitment.ErrNonMinimalInt, "argument %d in %d bytes", arg, n)
	}
	return major, arg, nil
}

func (s *scanner) item(depth int) (item, error) {
	major, arg, err := s.head()
	if err != nil {
		return item{}, err
	}
	switch major {
	case majUint, majNint:
		return item{major: major, u: arg}, nil
	case majBytes, majText:
		if arg > uint64(len(s.in)-s.at) {
			return item{}, scanFail(commitment.ErrMalformed, "string length exceeds input")
		}
		raw := s.in[s.at : s.at+int(arg)]
		s.at += int(arg)
		if major == majText && !utf8.Valid(raw) {
			return item{}, scanFail(commitment.ErrInvalidString, "invalid UTF-8")
		}
		return item{major: major, b: raw}, nil
	}
	if depth+1 > maxDepth {
		return item{}, scanFail(commitment.ErrNestingTooDeep, "container at depth %d", depth+1)
	}
	if arg > maxEntries {
		return item{}, scanFail(commitment.ErrTooLarge, "%d entries exceed %d", arg, maxEntries)
	}
	if major == majArray {
		if arg > uint64(len(s.in)-s.at) {
			return item{}, scanFail(commitment.ErrMalformed, "array length exceeds input")
		}
		for range arg {
			if _, err := s.item(depth + 1); err != nil {
				return item{}, err
			}
		}
		return item{major: majArray}, nil
	}
	if 2*arg > uint64(len(s.in)-s.at) {
		return item{}, scanFail(commitment.ErrMalformed, "map length exceeds input")
	}
	out := item{major: majMap, pairs: make([]pair, 0, arg)}
	for i := range arg {
		k, err := s.item(depth + 1)
		if err != nil {
			return item{}, err
		}
		if k.major != majUint {
			return item{}, scanFail(commitment.ErrKeyType, "map key of major type %d", k.major)
		}
		if i > 0 {
			prev := out.pairs[i-1].key
			if k.u == prev {
				return item{}, scanFail(commitment.ErrDuplicateKey, "key %d", k.u)
			}
			if k.u < prev {
				return item{}, scanFail(commitment.ErrUnsortedMap, "key %d after %d", k.u, prev)
			}
		}
		v, err := s.item(depth + 1)
		if err != nil {
			return item{}, err
		}
		out.pairs = append(out.pairs, pair{key: k.u, val: v})
	}
	return out, nil
}

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xff:
		return append(b, m|24, byte(n))
	case n <= 0xffff:
		return append(b, m|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	b = append(b, m|27)
	for i := 7; i >= 0; i-- {
		b = append(b, byte(n>>(8*i)))
	}
	return b
}
