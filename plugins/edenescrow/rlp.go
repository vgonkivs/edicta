// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/internal/evm/rlp"
)

var errRLP = errors.New("rlp")

// maxNesting bounds list depth inside the access list. A valid access list
// is two levels deep; the bound keeps the check's memory constant.
const maxNesting = 16

// rlpCheckNested checks that every item inside a list payload, at any depth
// up to maxNesting, is canonical and ends inside its enclosing list.
func rlpCheckNested(payload []byte) error {
	var buf [maxNesting + 1][]byte
	stack := append(buf[:0], payload)
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		if len(top) == 0 {
			stack = stack[:len(stack)-1]
			continue
		}
		it, rest, err := rlp.Next(top)
		if err != nil {
			return err
		}
		stack[len(stack)-1] = rest
		if it.List {
			if len(stack) > maxNesting {
				return fmt.Errorf("%w: lists nested deeper than %d", errRLP, maxNesting)
			}
			stack = append(stack, it.Payload)
		}
	}
	return nil
}
