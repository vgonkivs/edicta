// SPDX-License-Identifier: Apache-2.0

// Package edenescrow is the eden-escrow profile's form T action: an unsigned
// EIP-1559 transaction that calls deposit on the NativeEscrow contract on
// Eden, wrapped with the x402 purpose binding. It holds the strict decoder
// that gate, signer and verifier share, the compiled escrow table, the
// policy extractor and the pure signature helpers. Everything here is pure.
package edenescrow

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"strconv"

	"golang.org/x/crypto/sha3"
)

const (
	// ActionType is the action_type of a form T deposit.
	ActionType = "application/vnd.edicta.eden.escrow-deposit-tx.v1+cbor"
	// ExtractorID is the policy extractor of ActionType in production
	// builds.
	ExtractorID = "eden/escrow-deposit-tx/v1"
	// DevExtractorID is the policy extractor of ActionType in edictadev
	// builds; its table adds the dev chain.
	DevExtractorID = "eden/escrow-deposit-tx-dev/v1"
	// RequirementsTag is the hash tag of the PaymentRequirements bytes.
	RequirementsTag = "edicta/eden-escrow/v1/requirements"

	MaxActionSize   = 4096
	MaxTxSize       = 512
	MaxResourceSize = 2048

	// Kind and Scale are the facts constants of both extractor IDs.
	Kind  = "x402-payment"
	Scale = 18

	actionVersion = 1
	txType        = 0x02
	txItems       = 9
	maxIntBytes   = 32
	maxSmallBytes = 8
)

// TxAction is a decoded form T action. Byte fields are copies, never
// aliases of the input.
type TxAction struct {
	ChainID  uint64
	Nonce    uint64
	GasLimit uint64
	// MaxPriorityFee, MaxFeePerGas and Value are big-endian without leading
	// zeros; zero is empty. Value is never empty in a decoded action.
	MaxPriorityFee []byte
	MaxFeePerGas   []byte
	To             [20]byte
	Value          []byte
	Deposit        Deposit
	// Unsigned is the action's tx field verbatim: 0x02 || rlp(9 items), the
	// EIP-1559 signing preimage.
	Unsigned         []byte
	Resource         string
	RequirementsHash [32]byte
	// Row is the table row of ChainID.
	Row Row

	// items is the payload of the RLP list in Unsigned: the 9 item
	// encodings, verbatim. The signed transaction starts with it.
	items []byte
}

// DecodeTxAction decodes a form T action with this build's table.
func DecodeTxAction(b []byte) (TxAction, error) { return builtTable.decode(b) }

// decode runs the profile's rules in their fixed order; the first failure
// decides, and every format rule comes before the table.
func (t table) decode(b []byte) (TxAction, error) {
	if len(b) < 1 || len(b) > MaxActionSize {
		return TxAction{}, malformed("EA1", "action of %d bytes", len(b))
	}
	if err := cborWellFormed(b); err != nil {
		return TxAction{}, malformed("EA2", "%v", err)
	}
	a, err := actionSchema(b)
	if err != nil {
		return TxAction{}, err
	}
	if err := parseTx(&a); err != nil {
		return TxAction{}, err
	}
	row, ok := t.lookup(a.ChainID)
	if !ok {
		return TxAction{}, unknownDomain("chain %d is not a row of %s", a.ChainID, t.id)
	}
	if a.To != row.Escrow {
		return TxAction{}, unknownDomain("to %x is not the escrow of chain %d", a.To, a.ChainID)
	}
	a.Row = row
	return a, nil
}

// keyMajor is the major type of each action key's value.
var keyMajor = [5]byte{1: majorUint, 2: majorBytes, 3: majorText, 4: majorBytes}

// actionSchema reads the four keys of a well-formed item: per key in
// encoded order an unknown key, a wrong major type, then the value rule;
// then any missing key.
func actionSchema(b []byte) (TxAction, error) {
	major, n, off, err := cborHead(b, 0)
	if err != nil || major != majorMap {
		return TxAction{}, malformed("EA3", "the action is not a map")
	}
	var (
		a    TxAction
		seen [5]bool
	)
	for range n {
		_, key, next, _ := cborHead(b, off)
		if key < 1 || key > 4 {
			return TxAction{}, malformed("EA3", "unknown key %d", key)
		}
		vm, arg, vstart, err := cborHead(b, next)
		if err != nil {
			return TxAction{}, malformed("EA3", "key %d: %v", key, err)
		}
		if vm != keyMajor[key] {
			return TxAction{}, malformed("EA3", "key %d has major type %d", key, vm)
		}
		off = vstart
		var val []byte
		if vm != majorUint {
			val = b[vstart : vstart+int(arg)]
			off += int(arg)
		}
		switch key {
		case 1:
			if arg != actionVersion {
				return TxAction{}, malformed("EA3", "version %d", arg)
			}
		case 2:
			if len(val) < 1 || len(val) > MaxTxSize {
				return TxAction{}, malformed("EA3", "tx of %d bytes", len(val))
			}
			a.Unsigned = bytes.Clone(val)
		case 3:
			if len(val) < 1 || len(val) > MaxResourceSize {
				return TxAction{}, malformed("EA3", "resource of %d bytes", len(val))
			}
			for _, c := range val {
				if c < 0x21 || c > 0x7e {
					return TxAction{}, malformed("EA3", "resource byte 0x%02x", c)
				}
			}
			a.Resource = string(val)
		case 4:
			if len(val) != 32 {
				return TxAction{}, malformed("EA3", "requirements_hash of %d bytes", len(val))
			}
			copy(a.RequirementsHash[:], val)
		}
		seen[key] = true
	}
	for k := 1; k <= 4; k++ {
		if !seen[k] {
			return TxAction{}, malformed("EA3", "key %d is missing", k)
		}
	}
	return a, nil
}

// parseTx applies the transaction rules to a.Unsigned and fills a.
func parseTx(a *TxAction) error {
	tx := a.Unsigned
	if tx[0] != txType {
		return malformed("ET1", "transaction type 0x%02x", tx[0])
	}
	top, rest, err := rlpNext(tx[1:])
	switch {
	case err != nil:
		return malformed("ET2", "%v", err)
	case !top.list:
		return malformed("ET2", "the transaction is not an RLP list")
	case len(rest) != 0:
		return malformed("ET2", "%d bytes after the list", len(rest))
	}
	var items [txItems]rlpItem
	count := 0
	for body := top.payload; len(body) > 0; count++ {
		it, r, err := rlpNext(body)
		if err != nil {
			return malformed("ET2", "item %d: %v", count, err)
		}
		if count == txItems {
			return malformed("ET2", "more than %d items", txItems)
		}
		items[count] = it
		body = r
	}
	if count != txItems {
		return malformed("ET2", "%d items", count)
	}
	for i := range 8 {
		if items[i].list {
			return malformed("ET2", "item %d is a list", i)
		}
	}
	if !items[8].list {
		return malformed("ET2", "access_list is not a list")
	}
	if err := rlpCheckNested(items[8].payload); err != nil {
		return malformed("ET2", "access_list: %v", err)
	}

	if a.ChainID, err = smallInt(items[0], "chain_id"); err != nil {
		return err
	}
	if a.Nonce, err = smallInt(items[1], "nonce"); err != nil {
		return err
	}
	if a.MaxPriorityFee, err = bigInt(items[2], "max_priority_fee_per_gas"); err != nil {
		return err
	}
	if a.MaxFeePerGas, err = bigInt(items[3], "max_fee_per_gas"); err != nil {
		return err
	}
	if a.GasLimit, err = smallInt(items[4], "gas_limit"); err != nil {
		return err
	}
	if a.Value, err = bigInt(items[6], "value"); err != nil {
		return err
	}
	if CompareUint(a.MaxPriorityFee, a.MaxFeePerGas) > 0 {
		return malformed("ET4", "max_priority_fee_per_gas above max_fee_per_gas")
	}
	if len(items[5].payload) != 20 {
		return malformed("ET5", "to of %d bytes", len(items[5].payload))
	}
	copy(a.To[:], items[5].payload)
	if len(a.Value) == 0 {
		return malformed("ET6", "value 0")
	}
	if len(items[8].payload) != 0 {
		return malformed("ET7", "access_list is not empty")
	}
	if a.Deposit, err = DecodeDepositCall(items[7].payload); err != nil {
		var re *ruleError
		if errors.As(err, &re) {
			return malformed("ET8", "data: %s (rule %s)", re.msg, re.rule)
		}
		return err
	}
	a.MaxPriorityFee = bytes.Clone(a.MaxPriorityFee)
	a.MaxFeePerGas = bytes.Clone(a.MaxFeePerGas)
	a.Value = bytes.Clone(a.Value)
	a.items = top.payload
	return nil
}

// intBytes reads a canonical integer: a string without a leading zero byte
// of at most max bytes. RLP alone admits 0x00 as a one-byte string; as an
// integer it is not canonical.
func intBytes(it rlpItem, name string, max int) ([]byte, error) {
	switch {
	case len(it.payload) > max:
		return nil, malformed("ET3", "%s of %d bytes", name, len(it.payload))
	case len(it.payload) > 0 && it.payload[0] == 0:
		return nil, malformed("ET3", "%s with a leading zero byte", name)
	}
	return it.payload, nil
}

func bigInt(it rlpItem, name string) ([]byte, error) { return intBytes(it, name, maxIntBytes) }

func smallInt(it rlpItem, name string) (uint64, error) {
	b, err := intBytes(it, name, maxSmallBytes)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	if v > math.MaxInt64 {
		return 0, malformed("ET3", "%s above 2^63-1", name)
	}
	return v, nil
}

// CompareUint compares two big-endian integers without leading zeros.
func CompareUint(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}

// SigHash is keccak256 of the unsigned transaction: the digest the payer key
// signs.
func (a TxAction) SigHash() [32]byte { return keccak256(a.Unsigned) }

// RequirementsHash binds the exact PaymentRequirements bytes the server sent.
func RequirementsHash(raw []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{byte(len(RequirementsTag))})
	h.Write([]byte(RequirementsTag))
	h.Write(raw)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// EncodeTxAction returns the canonical action for an unsigned transaction,
// the resource and the requirements hash, and refuses one that
// DecodeTxAction with this build's table would refuse.
func EncodeTxAction(unsigned []byte, resource string, requirementsHash [32]byte) ([]byte, error) {
	b := cborHeadBytes(majorMap, 4)
	b = append(b, cborHeadBytes(majorUint, 1)...)
	b = append(b, cborHeadBytes(majorUint, actionVersion)...)
	b = append(b, cborHeadBytes(majorUint, 2)...)
	b = append(b, cborHeadBytes(majorBytes, uint64(len(unsigned)))...)
	b = append(b, unsigned...)
	b = append(b, cborHeadBytes(majorUint, 3)...)
	b = append(b, cborHeadBytes(majorText, uint64(len(resource)))...)
	b = append(b, resource...)
	b = append(b, cborHeadBytes(majorUint, 4)...)
	b = append(b, cborHeadBytes(majorBytes, 32)...)
	b = append(b, requirementsHash[:]...)
	if _, err := DecodeTxAction(b); err != nil {
		return nil, err
	}
	return b, nil
}

func cborHeadBytes(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= math.MaxUint8:
		return []byte{m | 24, byte(n)}
	case n <= math.MaxUint16:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= math.MaxUint32:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// caipChain is the "eip155:<chain_id>" prefix of the facts' asset and
// recipient.
func caipChain(chainID uint64) string { return "eip155:" + strconv.FormatUint(chainID, 10) }

func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}
