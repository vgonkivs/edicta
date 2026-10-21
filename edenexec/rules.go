// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/vgonkivs/edicta/edenescrow"
)

// Outcome is what the transaction did, at the level reached.
type Outcome string

const (
	OutcomeExecuted Outcome = "executed"
	OutcomeReverted Outcome = "reverted"
)

// DepositTopic is keccak256 of the NativeEscrowDeposited event signature,
// "NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)".
var DepositTopic = [32]byte{
	0x4e, 0x84, 0x68, 0xb0, 0x36, 0x00, 0x39, 0x85, 0x39, 0x6b, 0xfb, 0x5e, 0x6f, 0xc3, 0x6f, 0x0e,
	0x83, 0x95, 0x14, 0x66, 0x48, 0xe8, 0x29, 0x55, 0x7e, 0xa1, 0xfd, 0x48, 0xd2, 0xb9, 0xa6, 0xff,
}

// ParseRailRef accepts only the receipt form of the profile: 64 lower-case
// hex characters without 0x. Another form may still name the right
// transaction, so it is an unchecked claim, not a proven fault.
func ParseRailRef(s string) ([32]byte, error) {
	h, ok := edenescrow.ParseRailRef(s)
	if !ok {
		return [32]byte{}, ErrMalformedRailRef
	}
	return h, nil
}

// CheckExactTx holds the rebuilt signed bytes to the authorized action: the
// action's 9 items verbatim, then one canonical low-s signature that
// recovers a key. It returns the payer. Every failure is ErrWrongTx: the
// bytes hash to the signed rail_ref, so no source can cause one.
func CheckExactTx(signed []byte, a edenescrow.TxAction) ([20]byte, error) {
	_, payer, err := edenescrow.ParseSigned(a, signed)
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: %w", ErrWrongTx, err)
	}
	return payer, nil
}

// CheckDeposit applies the status and event rules to a receipt whose block
// and index were already compared with the transaction's. With status 1 the
// receipt holds exactly the one deposit log the authorized calldata and value
// determine; with status 0 it holds none.
func CheckDeposit(r ReceiptView, a edenescrow.TxAction, payer, escrow [20]byte) (Outcome, error) {
	switch r.Status {
	case 0:
		if len(r.Logs) != 0 {
			return "", wrapf(ErrLogMismatch, "reverted receipt with %d logs", len(r.Logs))
		}
		return OutcomeReverted, nil
	case 1:
	default:
		return "", wrapf(ErrDisagree, "receipt status %d", r.Status)
	}
	if len(r.Logs) != 1 {
		return "", wrapf(ErrLogMismatch, "%d logs, the deposit emits exactly one", len(r.Logs))
	}
	l := r.Logs[0]
	switch {
	case l.Address != escrow:
		return "", wrapf(ErrLogMismatch, "log emitted by %x, not the escrow", l.Address)
	case l.Removed:
		return "", wrapf(ErrLogMismatch, "log marked removed")
	case l.TxHash != r.TxHash, l.BlockHash != r.BlockHash, l.Index != r.Index:
		return "", wrapf(ErrLogMismatch, "log names another transaction, block or index")
	case len(l.Topics) != 4:
		return "", wrapf(ErrLogMismatch, "%d topics", len(l.Topics))
	case l.Topics[0] != DepositTopic:
		return "", wrapf(ErrLogMismatch, "topic0 is not NativeEscrowDeposited")
	case l.Topics[1] != a.Deposit.PaymentID:
		return "", wrapf(ErrLogMismatch, "paymentId topic differs from the calldata")
	case l.Topics[2] != addressWord(payer):
		return "", wrapf(ErrLogMismatch, "buyer topic is not the payer")
	case l.Topics[3] != addressWord(a.Deposit.PayTo):
		return "", wrapf(ErrLogMismatch, "payTo topic differs from the calldata")
	}
	if want := depositData(a); !bytes.Equal(l.Data, want) {
		return "", wrapf(ErrLogMismatch, "log data differs from the calldata and value")
	}
	return OutcomeExecuted, nil
}

// depositData is facilitator, amount (the tx value), expiresAt, refundAfter
// and tiaPriceUsd, one 32-byte word each.
func depositData(a edenescrow.TxAction) []byte {
	out := make([]byte, 0, 5*32)
	fac := addressWord(a.Deposit.Facilitator)
	out = append(out, fac[:]...)
	var amount [32]byte
	copy(amount[32-len(a.Value):], a.Value)
	out = append(out, amount[:]...)
	for _, v := range []uint64{a.Deposit.ExpiresAt, a.Deposit.RefundAfter} {
		var w [32]byte
		binary.BigEndian.PutUint64(w[24:], v)
		out = append(out, w[:]...)
	}
	return append(out, a.Deposit.TIAPriceUSD[:]...)
}

func addressWord(a [20]byte) [32]byte {
	var w [32]byte
	copy(w[12:], a[:])
	return w
}

// VerifyBlock checks the block's contents against its header: the header
// hashes to blockHash, the transactions rebuild transactionsRoot with signed
// at index, and the receipts rebuild receiptsRoot with receipt at index.
// The header itself is only as good as the sources that served it.
func VerifyBlock(h HeaderView, blockHash [32]byte, txs, receipts [][]byte, index uint64, signed, receipt []byte) error {
	enc, err := HeaderRLP(h)
	if err != nil {
		return wrapf(ErrBlockProof, "%v", err)
	}
	if got := keccak256(enc); got != blockHash {
		return wrapf(ErrBlockProof, "header hashes to %x, not the block hash %x", got, blockHash)
	}
	switch {
	case uint64(len(txs)) <= index:
		return wrapf(ErrBlockProof, "%d transactions, index %d", len(txs), index)
	case len(receipts) != len(txs):
		return wrapf(ErrBlockProof, "%d receipts for %d transactions", len(receipts), len(txs))
	case !bytes.Equal(txs[index], signed):
		return wrapf(ErrBlockProof, "the transaction at index %d is not the claimed one", index)
	case !bytes.Equal(receipts[index], receipt):
		return wrapf(ErrBlockProof, "the receipt at index %d is not the agreed one", index)
	}
	if got := DeriveSha(txs); got != h.TxRoot {
		return wrapf(ErrBlockProof, "transactions rebuild root %x, header %x", got, h.TxRoot)
	}
	if got := DeriveSha(receipts); got != h.ReceiptRoot {
		return wrapf(ErrBlockProof, "receipts rebuild root %x, header %x", got, h.ReceiptRoot)
	}
	return nil
}

// timeWarnings compares the Eden block time with the times of the signed
// objects; the sequencer sets the block time, and no local clock is read.
func timeWarnings(blockTime, expires, tRef uint64) []string {
	var w []string
	if blockTime > expires {
		w = append(w, WarnAfterExpires)
	}
	if tRef != 0 && blockTime < tRef {
		w = append(w, WarnBeforeReference)
	}
	return w
}
