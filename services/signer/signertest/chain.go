// SPDX-License-Identifier: Apache-2.0

package signertest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/evm/rlp"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
)

// EmptyCodeHash is keccak256 of no code.
var EmptyCodeHash = Keccak(nil)

// Keccak is keccak-256.
func Keccak(b []byte) [32]byte { return evm.Keccak256(b) }

// Block is the block a landed transaction is put in.
const Block = 1_000_000

// Chain is a scripted Eden chain: the signer's RPC (eden.Chain) and a
// settlement source (edenexec.Source) at once. A sent transaction lands in
// Block when AutoLand is set, with status 1 unless Revert is set; the head is
// Block + Depth. Code holds the code hash per address; an absent address has
// no code.
type Chain struct {
	mu sync.Mutex

	ID uint64
	// Host names the source; two fakes of one chain need two hosts.
	Host     string
	Code     map[[20]byte][32]byte
	Nonce    uint64
	AutoLand bool
	Revert   bool
	Depth    uint64

	// Latest is the payer's latest nonce.
	Latest uint64

	ChainErr, CodeErr, NonceErr, SendErr, TxErr error

	Sent   [][]byte
	landed map[[32]byte][]byte
}

var _ edenexec.Source = (*Chain)(nil)

// NewChain is chain id with the table's escrow code in place.
func NewChain(id uint64) *Chain {
	c := &Chain{ID: id, Code: map[[20]byte][32]byte{}, AutoLand: true, Depth: edenexec.DefaultConfirmDepth, landed: map[[32]byte][]byte{}}
	if row, ok := edenescrow.Lookup(id); ok {
		c.Code[row.Escrow] = row.CodeHash
	}
	return c
}

// Set changes the chain under its lock.
func (c *Chain) Set(f func(c *Chain)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

// SentCount is the number of sends.
func (c *Chain) SentCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.Sent)
}

// Land puts signed into the chain.
func (c *Chain) Land(signed []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.landed[Keccak(signed)] = append([]byte(nil), signed...)
}

func (c *Chain) Name() string {
	if c.Host != "" {
		return c.Host
	}
	return fmt.Sprintf("fake-eden-%d", c.ID)
}
func (c *Chain) Class() edenexec.SourceClass { return edenexec.ClassOwnNode }

func (c *Chain) ChainID(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ID, c.ChainErr
}

func (c *Chain) CodeHash(_ context.Context, addr [20]byte) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.CodeErr != nil {
		return [32]byte{}, c.CodeErr
	}
	if h, ok := c.Code[addr]; ok {
		return h, nil
	}
	return EmptyCodeHash, nil
}

func (c *Chain) PendingNonce(context.Context, [20]byte) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Nonce, c.NonceErr
}

func (c *Chain) LatestNonce(context.Context, [20]byte) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Latest, c.NonceErr
}

func (c *Chain) SendRawTransaction(_ context.Context, signed []byte) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Sent = append(c.Sent, append([]byte(nil), signed...))
	if c.SendErr != nil {
		return [32]byte{}, c.SendErr
	}
	h := Keccak(signed)
	if c.AutoLand {
		c.landed[h] = append([]byte(nil), signed...)
	}
	return h, nil
}

func (c *Chain) Head(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Block + c.Depth, nil
}

func (c *Chain) blockHash() [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], Block)
	return Keccak(append([]byte("block"), b[:]...))
}

func (c *Chain) Transaction(_ context.Context, h [32]byte) (edenexec.TxView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.TxErr != nil {
		return edenexec.TxView{}, c.TxErr
	}
	signed, ok := c.landed[h]
	if !ok {
		return edenexec.TxView{}, edenexec.ErrNotFound
	}
	tx, err := TxViewOf(signed)
	if err != nil {
		return edenexec.TxView{}, err
	}
	tx.Included, tx.BlockHash, tx.BlockNumber, tx.Index = true, c.blockHash(), Block, 0
	return tx, nil
}

func (c *Chain) Receipt(_ context.Context, h [32]byte) (edenexec.ReceiptView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	signed, ok := c.landed[h]
	if !ok {
		return edenexec.ReceiptView{}, edenexec.ErrNotFound
	}
	rc := edenexec.ReceiptView{
		Type: 2, Status: 1, CumulativeGasUsed: []byte{0x01, 0x00, 0x00}, TxHash: h,
		BlockHash: c.blockHash(), BlockNumber: Block, Index: 0,
	}
	if c.Revert {
		rc.Status = 0
		return rc, nil
	}
	l, err := depositLog(signed)
	if err != nil {
		return edenexec.ReceiptView{}, err
	}
	l.TxHash, l.BlockHash = h, c.blockHash()
	rc.Logs = []edenexec.LogView{l}
	return rc, nil
}

func (c *Chain) Header(_ context.Context, h [32]byte) (edenexec.HeaderView, error) {
	if h != c.blockHash() {
		return edenexec.HeaderView{}, edenexec.ErrNotFound
	}
	return edenexec.HeaderView{Hash: h, Number: Block}, nil
}

func (c *Chain) BlockTransactions(context.Context, [32]byte) ([][]byte, error) {
	return nil, errors.New("signertest: no block bodies")
}

func (c *Chain) BlockReceipts(context.Context, [32]byte) ([][]byte, error) {
	return nil, errors.New("signertest: no block receipts")
}

// TxViewOf is what an RPC serves for signed type 2 bytes with an empty
// access list.
func TxViewOf(signed []byte) (edenexec.TxView, error) {
	if len(signed) < 1 || signed[0] != 2 {
		return edenexec.TxView{}, errors.New("signertest: not type 2")
	}
	it, err := rlpItems(signed[1:])
	if err != nil {
		return edenexec.TxView{}, err
	}
	if len(it) != 12 {
		return edenexec.TxView{}, fmt.Errorf("signertest: %d items", len(it))
	}
	var to [20]byte
	copy(to[:], it[5])
	return edenexec.TxView{
		Type: 2, Hash: Keccak(signed), ChainID: it[0], Nonce: it[1], MaxPriorityFee: it[2], MaxFee: it[3],
		Gas: it[4], To: &to, Value: it[6], Input: it[7], V: it[9], R: it[10], S: it[11],
	}, nil
}

// depositLog is the escrow's log for the deposit signed.
func depositLog(signed []byte) (edenexec.LogView, error) {
	it, err := rlpItems(signed[1:])
	if err != nil {
		return edenexec.LogView{}, err
	}
	var to [20]byte
	copy(to[:], it[5])
	data := it[7]
	tv, err := TxViewOf(signed)
	if err != nil {
		return edenexec.LogView{}, err
	}
	payer, err := recoverPayer(signed, tv)
	if err != nil {
		return edenexec.LogView{}, err
	}
	word := func(i int) [32]byte {
		var w [32]byte
		copy(w[:], data[4+32*i:4+32*(i+1)])
		return w
	}
	var payerWord, amount [32]byte
	copy(payerWord[12:], payer[:])
	copy(amount[32-len(it[6]):], it[6])
	logData := make([]byte, 0, 160)
	for _, w := range [][32]byte{word(2), amount, word(3), word(4), word(5)} {
		logData = append(logData, w[:]...)
	}
	return edenexec.LogView{
		Address: to, Topics: [][32]byte{edenexec.DepositTopic, word(0), payerWord, word(1)}, Data: logData,
	}, nil
}

func recoverPayer(signed []byte, tv edenexec.TxView) ([20]byte, error) {
	var sig edenescrow.Signature
	if len(tv.V) == 1 {
		sig.YParity = tv.V[0]
	}
	copy(sig.R[32-len(tv.R):], tv.R)
	copy(sig.S[32-len(tv.S):], tv.S)
	// The unsigned preimage is the first 9 items under their own header.
	it, err := rlpRaw(signed[1:])
	if err != nil {
		return [20]byte{}, err
	}
	var p []byte
	for _, x := range it[:9] {
		p = append(p, x...)
	}
	unsigned := rlp.AppendList([]byte{0x02}, p)
	return edenescrow.RecoverPayer(Keccak(unsigned), sig)
}

// rlpItems returns the payloads of a list's items; rlpRaw their encodings.
func rlpItems(b []byte) ([][]byte, error) { return rlpSplit(b, false) }
func rlpRaw(b []byte) ([][]byte, error)   { return rlpSplit(b, true) }

func rlpSplit(b []byte, raw bool) ([][]byte, error) {
	payload, rest, err := rlpRead(b)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("signertest: not one list")
	}
	var out [][]byte
	for len(payload) > 0 {
		p, r, err := rlpRead(payload)
		if err != nil {
			return nil, err
		}
		if raw {
			out = append(out, payload[:len(payload)-len(r)])
		} else {
			out = append(out, p)
		}
		payload = r
	}
	return out, nil
}

func rlpRead(b []byte) (payload, rest []byte, err error) {
	if len(b) == 0 {
		return nil, nil, errors.New("signertest: empty")
	}
	c := b[0]
	n, off := 0, 1
	switch {
	case c < 0x80:
		return b[:1], b[1:], nil
	case c <= 0xb7:
		n = int(c - 0x80)
	case c <= 0xbf:
		ll := int(c - 0xb7)
		for _, x := range b[1 : 1+ll] {
			n = n<<8 | int(x)
		}
		off += ll
	case c <= 0xf7:
		n = int(c - 0xc0)
	default:
		ll := int(c - 0xf7)
		for _, x := range b[1 : 1+ll] {
			n = n<<8 | int(x)
		}
		off += ll
	}
	if off+n > len(b) {
		return nil, nil, errors.New("signertest: truncated")
	}
	return b[off : off+n], b[off+n:], nil
}

// Relay is a scripted payment-server relay: it records every send and lands
// the bytes on Chain when Forward is set, as a relay that broadcasts them.
type Relay struct {
	mu      sync.Mutex
	Chain   *Chain
	Forward bool
	Err     error
	Sent    []RelaySend
}

// RelaySend is one call of the relay.
type RelaySend struct {
	Signed    []byte
	RailRef   string
	PaymentID [32]byte
}

func (r *Relay) Send(_ context.Context, signed []byte, railRef string, paymentID [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sent = append(r.Sent, RelaySend{Signed: append([]byte(nil), signed...), RailRef: railRef, PaymentID: paymentID})
	if r.Err != nil {
		return r.Err
	}
	if r.Forward && r.Chain != nil {
		r.Chain.Land(signed)
	}
	return nil
}

// Calls is the number of sends.
func (r *Relay) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Sent)
}

// Set changes the relay under its lock.
func (r *Relay) Set(f func(r *Relay)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r)
}
