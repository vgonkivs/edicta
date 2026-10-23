package principalsig

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/internal/evm"
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
	if digits != evm.ChecksumAddress([20]byte(b)) {
		return nil, fmt.Errorf("%w: eth address checksum does not match", ErrPrincipal)
	}
	return b, nil
}
