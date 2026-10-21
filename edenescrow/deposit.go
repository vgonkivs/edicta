// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"encoding/binary"
	"math"
)

// depositSelector is the selector of
// deposit(bytes32,address,address,uint256,uint256,uint256).
var depositSelector = [4]byte{0xb7, 0x07, 0xd8, 0x60}

// DepositCallSize is the length of the deposit calldata: the selector and
// six 32-byte words.
const DepositCallSize = 4 + 6*32

// Deposit is the decoded deposit calldata.
type Deposit struct {
	PaymentID   [32]byte
	PayTo       [20]byte
	Facilitator [20]byte
	ExpiresAt   uint64
	RefundAfter uint64
	// TIAPriceUSD is kept as the calldata word and never interpreted.
	TIAPriceUSD [32]byte
}

// DecodeDepositCall accepts exactly the deposit calldata with clean address
// words, non-zero payTo and facilitator, times in 1..2^63-1 with refundAfter
// after expiresAt, and a non-zero tiaPriceUsd. Every failure is ErrMalformed.
// Solidity rejects dirty address words, but other ABI decoders keep the low
// 20 bytes; one byte string must never name two recipients.
func DecodeDepositCall(data []byte) (Deposit, error) {
	if len(data) != DepositCallSize {
		return Deposit{}, malformed("DC1", "deposit calldata of %d bytes", len(data))
	}
	if !bytes.Equal(data[:4], depositSelector[:]) {
		return Deposit{}, malformed("DC2", "selector %x", data[:4])
	}
	word := func(i int) []byte { return data[4+32*i : 4+32*(i+1)] }
	var d Deposit
	copy(d.PaymentID[:], word(0))
	for i, dst := range []*[20]byte{&d.PayTo, &d.Facilitator} {
		w := word(1 + i)
		if !allZero(w[:12]) {
			return Deposit{}, malformed("DC3", "address word %d has non-zero high bytes", 1+i)
		}
		if allZero(w[12:]) {
			return Deposit{}, malformed("DC3", "address word %d is the zero address", 1+i)
		}
		copy(dst[:], w[12:])
	}
	for i, dst := range []*uint64{&d.ExpiresAt, &d.RefundAfter} {
		w := word(3 + i)
		if !allZero(w[:24]) {
			return Deposit{}, malformed("DC4", "time word %d above 64 bits", 3+i)
		}
		v := binary.BigEndian.Uint64(w[24:])
		if v == 0 || v > math.MaxInt64 {
			return Deposit{}, malformed("DC4", "time word %d out of 1..2^63-1", 3+i)
		}
		*dst = v
	}
	if d.RefundAfter <= d.ExpiresAt {
		return Deposit{}, malformed("DC4", "refundAfter %d not after expiresAt %d", d.RefundAfter, d.ExpiresAt)
	}
	if allZero(word(5)) {
		return Deposit{}, malformed("DC5", "tiaPriceUsd is zero")
	}
	copy(d.TIAPriceUSD[:], word(5))
	return d, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
