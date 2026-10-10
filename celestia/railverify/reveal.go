package railverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/verifier"
)

// ErrNoBankSend is a transaction whose first message is not exactly the
// MsgSend Any the profile's executor writes, so it gives no action bytes.
var ErrNoBankSend = errors.New("railverify: the transaction does not start with a bank-send message")

var _ verifier.ActionRevealer = (*bankSend)(nil)

// PublicExecution is true: an executed transfer is a public transaction, so
// revealing the action salt hides nothing the chain does not already show.
func (c *bankSend) PublicExecution() bool { return true }

// ActionFromTx reads the transaction named by the receipt's rail_ref from the
// tx sources, keeps the first bytes that hash to it, and rebuilds the action
// with the chain id the checker is configured for. Bytes that hash to the
// reference are the same from every source, so a refusal of them is final.
func (c *bankSend) ActionFromTx(ctx context.Context, in verifier.ExecutionInput) ([]byte, error) {
	ref, ok := parseLowerHex32(in.RailRef)
	if !ok {
		return nil, ErrRailRefMalformed
	}
	var errs []error
	for _, src := range c.candidates {
		tx, err := src.Tx(ctx, ref, false)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			continue
		}
		if sha256.Sum256(tx.Bytes) != ref {
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), ErrTxHashMismatch))
			continue
		}
		return ActionFromTx(tx.Bytes, c.cfg.ChainID)
	}
	return nil, errors.Join(errs...)
}

// ActionFromTx rebuilds the bank-send action from transaction bytes: a strict
// TxRaw whose body starts with the MsgSend Any, the message taken verbatim.
// It checks nothing beyond the message; whether the bytes are the committed
// action is decided by the action hash, and the memo and timeout by the body
// check.
func ActionFromTx(tx []byte, chainID string) ([]byte, error) {
	body, err := bodyOfTxRaw(tx)
	if err != nil {
		return nil, err
	}
	anyMsg, _, err := lengthDelimited(body, 1)
	if err != nil {
		return nil, fmt.Errorf("%w: messages: %w", ErrNoBankSend, err)
	}
	typeURL, rest, err := lengthDelimited(anyMsg, 1)
	if err != nil {
		return nil, fmt.Errorf("%w: type_url: %w", ErrNoBankSend, err)
	}
	if !bytes.Equal(typeURL, []byte(msgSendTypeURL)) {
		return nil, fmt.Errorf("%w: type_url %q", ErrNoBankSend, typeURL)
	}
	msg, rest, err := lengthDelimited(rest, 2)
	if err != nil {
		return nil, fmt.Errorf("%w: value: %w", ErrNoBankSend, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: data after the message value", ErrNoBankSend)
	}
	a, err := bankaction.Encode(bankaction.Action{ChainID: chainID, Msg: bytes.Clone(msg)})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoBankSend, err)
	}
	return a, nil
}

const msgSendTypeURL = "/cosmos.bank.v1beta1.MsgSend"

// lengthDelimited reads one length-delimited field num at the start of b,
// with a one-byte tag and a shortest length varint, and returns its value and
// the bytes after it.
func lengthDelimited(b []byte, num protowire.Number) (v, rest []byte, err error) {
	if len(b) == 0 || b[0] != byte(protowire.EncodeTag(num, protowire.BytesType)) {
		return nil, nil, fmt.Errorf("field %d expected", num)
	}
	l, n := protowire.ConsumeVarint(b[1:])
	if n < 0 {
		return nil, nil, errors.New("truncated length")
	}
	if n != protowire.SizeVarint(l) {
		return nil, nil, errors.New("length is not shortest")
	}
	b = b[1+n:]
	if uint64(len(b)) < l {
		return nil, nil, errors.New("truncated value")
	}
	return b[:l], b[l:], nil
}
