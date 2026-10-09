package principalsig

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ParseEthAddress parses a 20-byte address given as 40 hex digits, with or
// without "0x". All-lowercase and all-uppercase input carries no checksum;
// mixed case is an EIP-55 checksum and must be right, so a mistyped
// checksummed address is refused rather than silently accepted.
func ParseEthAddress(s string) ([]byte, error) {
	digits := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(digits) != 40 {
		return nil, fmt.Errorf("%w: eth address has %d hex digits", ErrPrincipal, len(digits))
	}
	lower := strings.ToLower(digits)
	b, err := hex.DecodeString(lower)
	if err != nil {
		return nil, fmt.Errorf("%w: eth address: %v", ErrPrincipal, err)
	}
	if digits == lower || digits == strings.ToUpper(digits) {
		return b, nil
	}
	if digits != eip55(lower) {
		return nil, fmt.Errorf("%w: eth address checksum does not match", ErrPrincipal)
	}
	return b, nil
}

// eip55 is the checksummed form of 40 lowercase hex digits: a letter is
// uppercased when the matching nibble of keccak256(digits) is 8 or more.
func eip55(lower string) string {
	h := keccak256([]byte(lower))
	out := []byte(lower)
	for i, c := range out {
		nibble := h[i/2] >> 4
		if i%2 == 1 {
			nibble = h[i/2] & 0x0f
		}
		if c >= 'a' && c <= 'f' && nibble >= 8 {
			out[i] = c - 'a' + 'A'
		}
	}
	return string(out)
}
