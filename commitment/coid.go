package commitment

import (
	"encoding/hex"
	"fmt"
)

// ClientOrderID is the id the rail adapter sends with an order, derived from
// the commitment hash alone so that an order of unknown outcome can be found
// by lookup. For the ibkr rail it is the lowercase hex of the hash.
func ClientOrderID(r Rail, h Hash) (string, error) {
	switch r {
	case RailIBKR:
		return hex.EncodeToString(h[:]), nil
	case 0:
		return "", fmt.Errorf("%w: rail 0", ErrInvalidEnum)
	default:
		return "", fmt.Errorf("%w: rail %d", ErrUnsupportedRail, r)
	}
}
