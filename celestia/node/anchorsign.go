package node

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"sync"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/user"
	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
)

const pffTypeURL = fibretypes.MsgPayForFibreTypeURL

// pffTxBaseGas covers what the PayForFibre estimates leave out: the account
// reads, the tx size cost and the account's own signature check.
const pffTxBaseGas = 100_000

// TxParams fixes the account state and the price a signature commits to.
type TxParams struct {
	AccountNumber uint64
	Sequence      uint64
	// GasPrice is in utia per unit of gas; the fee is ceil(gas * GasPrice).
	GasPrice *big.Rat
	// TimeoutHeight is the last height the tx may be included at; 0 is none.
	TimeoutHeight uint64
}

// AnchorSigner signs the anchor tx of a pending reference and never
// broadcasts it: the caller archives the bytes first and then sends them.
type AnchorSigner interface {
	// Address is the 20-byte account that signs.
	Address(ctx context.Context) ([]byte, error)
	// SignPFB returns the signed tx holding one MsgPayForBlobs for the share
	// version 1 blob of data under namespace with this account as the blob
	// signer. The blob itself is not in the tx; a BlobTx wraps both.
	SignPFB(ctx context.Context, namespace, data []byte, p TxParams) ([]byte, error)
	// SignPFF returns the signed tx holding one MsgPayForFibre: msg is a
	// MsgPayForFibre in protobuf, and its signer is replaced by this account.
	SignPFF(ctx context.Context, msg []byte, p TxParams) ([]byte, error)
}

var expectedSeq = regexp.MustCompile(`expected (\d+)`)

// ExpectedSequence reads the sequence a node expects from a sequence
// mismatch error.
func ExpectedSequence(err error) (uint64, bool) {
	if err == nil || !errors.Is(err, ErrSequenceMismatch) {
		return 0, false
	}
	m := expectedSeq.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	n, perr := strconv.ParseUint(m[1], 10, 64)
	return n, perr == nil
}

type keyringAnchorSigner struct {
	keyName string
	addr    []byte
	bech    string

	mu     sync.Mutex
	signer *user.Signer
}

// NewAnchorSigner signs with keyName of kr for chainID. The keyring is only
// read and used to sign; no network is touched.
func NewAnchorSigner(kr keyring.Keyring, keyName, chainID string) (AnchorSigner, error) {
	if kr == nil || keyName == "" || chainID == "" {
		return nil, errors.New("node: anchor signer needs a keyring, a key name and a chain id")
	}
	rec, err := kr.Key(keyName)
	if err != nil {
		return nil, fmt.Errorf("%w: key %q: %w", ErrKeyring, keyName, err)
	}
	addr, err := rec.GetAddress()
	if err != nil {
		return nil, fmt.Errorf("%w: key %q: %w", ErrKeyring, keyName, err)
	}
	if len(addr) != 20 {
		return nil, fmt.Errorf("%w: key %q has an address of %d bytes", ErrUnsupported, keyName, len(addr))
	}
	bech, err := bech32.ConvertAndEncode(signerBech32Prefix, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	enc := encoding.MakeConfig(app.ModuleEncodingRegisters...)
	s, err := user.NewSigner(kr, enc.TxConfig, chainID)
	if err != nil {
		return nil, fmt.Errorf("node: signer: %w", err)
	}
	return &keyringAnchorSigner{keyName: keyName, addr: append([]byte(nil), addr...), bech: bech, signer: s}, nil
}

func (k *keyringAnchorSigner) Address(context.Context) ([]byte, error) {
	return append([]byte(nil), k.addr...), nil
}

func (k *keyringAnchorSigner) SignPFB(_ context.Context, namespace, data []byte, p TxParams) ([]byte, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return nil, fmt.Errorf("node: namespace: %w", err)
	}
	b, err := libshare.NewV1Blob(ns, data, k.addr)
	if err != nil {
		return nil, fmt.Errorf("node: blob: %w", err)
	}
	msg, err := blobtypes.NewMsgPayForBlobs(k.bech, appconsts.Version, b)
	if err != nil {
		return nil, fmt.Errorf("node: pay for blobs: %w", err)
	}
	gas := blobtypes.DefaultEstimateGas(msg)
	gas += gas / 10
	return k.sign(msg, gas, p)
}

func (k *keyringAnchorSigner) SignPFF(_ context.Context, raw []byte, p TxParams) ([]byte, error) {
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("node: pay for fibre: %w", err)
	}
	msg.Signer = k.bech
	if err := msg.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("node: pay for fibre: %w", err)
	}
	gas := fibretypes.EstimateGasForPayForFibre(msg.PaymentPromise.BlobSize) +
		fibretypes.EstimateGasForPayForFibreSignatureVerification(uint64(len(msg.ValidatorSignatures))) + pffTxBaseGas
	gas += gas / 10
	return k.sign(&msg, gas, p)
}

func (k *keyringAnchorSigner) sign(msg sdktypes.Msg, gas uint64, p TxParams) ([]byte, error) {
	fee, err := feeFor(gas, p.GasPrice)
	if err != nil {
		return nil, err
	}
	opts := []user.TxOption{user.SetGasLimit(gas), user.SetFee(fee)}
	if p.TimeoutHeight != 0 {
		opts = append(opts, user.SetTimeoutHeight(p.TimeoutHeight))
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	// The account is replaced on every call: the caller owns the sequence.
	if err := k.signer.AddAccount(user.NewAccount(k.keyName, p.AccountNumber, p.Sequence)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyring, err)
	}
	tx, _, err := k.signer.CreateTx([]sdktypes.Msg{msg}, opts...)
	if err != nil {
		return nil, fmt.Errorf("node: sign: %w", err)
	}
	return tx, nil
}

// feeFor is ceil(gas * price), refusing a missing or negative price and a fee
// the coin cannot hold.
func feeFor(gas uint64, price *big.Rat) (uint64, error) {
	if price == nil || price.Sign() < 0 {
		return 0, errors.New("node: no gas price")
	}
	f := new(big.Rat).Mul(new(big.Rat).SetUint64(gas), price)
	q, r := new(big.Int).QuoRem(f.Num(), f.Denom(), new(big.Int))
	if r.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() || q.Uint64() > math.MaxInt64 {
		return 0, fmt.Errorf("node: fee %s out of range", q)
	}
	return q.Uint64(), nil
}

// PFFMessage returns the MsgPayForFibre of a signed PayForFibre tx in
// protobuf: the certificate and the promise it carries.
func PFFMessage(tx []byte) ([]byte, error) {
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return nil, fmt.Errorf("node: tx: %w", err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return nil, fmt.Errorf("node: tx body: %w", err)
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil || body.Messages[0].TypeUrl != pffTypeURL {
		return nil, errors.New("node: tx does not hold exactly one MsgPayForFibre")
	}
	return append([]byte(nil), body.Messages[0].Value...), nil
}

// TxTimeoutHeight returns the timeout_height of a signed tx; 0 is none.
func TxTimeoutHeight(tx []byte) (uint64, error) {
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return 0, fmt.Errorf("node: tx: %w", err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return 0, fmt.Errorf("node: tx body: %w", err)
	}
	return body.TimeoutHeight, nil
}

// TxSequence returns the account sequence a signed single-signer tx was
// signed at.
func TxSequence(tx []byte) (uint64, error) {
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return 0, fmt.Errorf("node: tx: %w", err)
	}
	var ai cosmostx.AuthInfo
	if err := ai.Unmarshal(raw.AuthInfoBytes); err != nil {
		return 0, fmt.Errorf("node: tx auth info: %w", err)
	}
	if len(ai.SignerInfos) != 1 {
		return 0, fmt.Errorf("node: tx has %d signers, want 1", len(ai.SignerInfos))
	}
	return ai.SignerInfos[0].Sequence, nil
}
