// SPDX-License-Identifier: Apache-2.0

package edenexec

import "github.com/vgonkivs/edicta/internal/evm/rlp"

// rlpQuantity encodes minimal big-endian integer bytes; a leading zero byte
// would make the encoding non-canonical, so it is refused.
func rlpQuantity(b []byte) ([]byte, bool) {
	if len(b) > 0 && b[0] == 0 {
		return nil, false
	}
	return rlp.AppendString(nil, b), true
}
