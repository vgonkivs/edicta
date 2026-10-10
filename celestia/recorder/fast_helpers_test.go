package recorder_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	squaretx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
)

// anchorSigner is a real keyring signer on an in-memory key.
func anchorSigner(t testing.TB, chainID string) (node.AnchorSigner, []byte) {
	t.Helper()
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	_, _, err := kr.NewMnemonic("recorder", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	s, err := node.NewAnchorSigner(kr, "recorder", chainID)
	require.NoError(t, err)
	addr, err := s.Address(context.Background())
	require.NoError(t, err)
	return s, addr
}

// anchorNode fakes the own consensus node of the fast path. Broadcast results
// are scripted per call; a nil result accepts the tx and calls onAccept.
type anchorNode struct {
	mu      sync.Mutex
	acc     node.AccountInfo
	results []error
	sent    [][]byte
	txs     map[[32]byte]node.TxStatus
	// before runs at every broadcast, before anything is decided.
	before   func(raw []byte)
	onAccept func(raw []byte)
	// strict makes the node check sequences as CheckTx does: a tx is taken
	// only at exactly the committed sequence plus the txs it holds.
	strict   bool
	next     uint64
	accepted map[[32]byte]bool
}

// beStrict turns on the sequence check, starting at the committed sequence.
func (n *anchorNode) beStrict() {
	n.mu.Lock()
	n.strict, n.next, n.accepted = true, n.acc.Sequence, map[[32]byte]bool{}
	n.mu.Unlock()
}

// check is called under mu for a broadcast without a scripted result.
func (n *anchorNode) check(raw []byte) error {
	if !n.strict {
		return nil
	}
	tx := innerTx(raw)
	h := sha256.Sum256(tx)
	if n.accepted[h] {
		return fmt.Errorf("%w: tx already exists in cache", node.ErrAlreadyInMempool)
	}
	seq, err := node.TxSequence(tx)
	if err != nil {
		return fmt.Errorf("%w: %w", node.ErrRejected, err)
	}
	if seq != n.next {
		return fmt.Errorf("%w: account sequence mismatch, expected %d, got %d: incorrect account sequence", node.ErrSequenceMismatch, n.next, seq)
	}
	n.next++
	n.accepted[h] = true
	return nil
}

func newAnchorNode() *anchorNode {
	return &anchorNode{acc: node.AccountInfo{Number: 7, Sequence: 3}, txs: map[[32]byte]node.TxStatus{}}
}

func (n *anchorNode) Account(context.Context, string) (node.AccountInfo, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.acc, nil
}

func (n *anchorNode) MinGasPrice(context.Context) (*big.Rat, error) { return big.NewRat(1, 250), nil }

func (n *anchorNode) Broadcast(_ context.Context, raw []byte) ([32]byte, error) {
	n.mu.Lock()
	before, onAccept := n.before, n.onAccept
	n.sent = append(n.sent, bytes.Clone(raw))
	var err error
	if len(n.results) > 0 {
		err, n.results = n.results[0], n.results[1:]
	} else {
		err = n.check(raw)
	}
	n.mu.Unlock()
	if before != nil {
		before(raw)
	}
	if err != nil {
		return [32]byte{}, err
	}
	if onAccept != nil {
		onAccept(raw)
	}
	return sha256.Sum256(innerTx(raw)), nil
}

func (n *anchorNode) Tx(_ context.Context, h [32]byte) (node.TxStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.txs[h], nil
}

func (n *anchorNode) setTx(tx []byte, st node.TxStatus) {
	n.mu.Lock()
	n.txs[sha256.Sum256(tx)] = st
	n.mu.Unlock()
}

func (n *anchorNode) script(errs ...error) {
	n.mu.Lock()
	n.results = append(n.results, errs...)
	n.mu.Unlock()
}

func (n *anchorNode) sends() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([][]byte(nil), n.sent...)
}

// innerTx is the tx a BlobTx carries, or raw itself.
func innerTx(raw []byte) []byte {
	if btx, ok, err := squaretx.UnmarshalBlobTx(raw); ok && err == nil {
		return btx.Tx
	}
	return raw
}

// txSequence is the signer sequence of a signed Cosmos tx.
func txSequence(t testing.TB, tx []byte) uint64 {
	t.Helper()
	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(tx))
	var ai cosmostx.AuthInfo
	require.NoError(t, ai.Unmarshal(raw.AuthInfoBytes))
	require.Len(t, ai.SignerInfos, 1)
	return ai.SignerInfos[0].Sequence
}

func mismatch(expected uint64) error {
	return fmt.Errorf("%w: account sequence mismatch, expected %d, got 3: incorrect account sequence", node.ErrSequenceMismatch, expected)
}

var errTransport = errors.New("connection reset")
