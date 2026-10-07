package railtx_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
)

// fundCons lets a test choose what Broadcast answers and script the status
// lookups while the other reads keep working.
type fundCons struct {
	*nodefake.Consensus
	bcastErr    error
	onBroadcast func()
	txScript    []node.TxStatus
	afterTx     func(call int)
	txCalls     int
	noIndex     bool
}

func (f *fundCons) Broadcast(ctx context.Context, raw []byte) ([32]byte, error) {
	if f.onBroadcast != nil {
		f.onBroadcast()
	}
	if f.bcastErr != nil {
		return [32]byte{}, f.bcastErr
	}
	return f.Consensus.Broadcast(ctx, raw)
}

// Tx answers from the script, one entry per lookup, then from the fake.
func (f *fundCons) Tx(ctx context.Context, hash [32]byte) (node.TxStatus, error) {
	f.txCalls++
	if f.afterTx != nil {
		defer f.afterTx(f.txCalls)
	}
	if len(f.txScript) > 0 {
		st := f.txScript[0]
		f.txScript = f.txScript[1:]
		return st, nil
	}
	return f.Consensus.Tx(ctx, hash)
}

func (f *fundCons) TxIndex(ctx context.Context) error {
	if f.noIndex {
		return fmt.Errorf("%w: off", node.ErrTxIndexDisabled)
	}
	return f.Consensus.TxIndex(ctx)
}

type fundEnv struct {
	cons    *fundCons
	consent *railtx.Consent
	funder  *railtx.Funder
	to      string
	path    string
	cfg     railtx.FunderConfig
}

const (
	fundHead   = 1000
	fundSeq    = 5
	fundAmount = 100
)

func newFundEnv(t *testing.T, mut func(*railtx.FunderConfig)) *fundEnv {
	t.Helper()
	fc := nodefake.NewConsensus("mocha-5")
	fc.SetHeight(fundHead)
	cons := &fundCons{Consensus: fc}
	consent := &railtx.Consent{}
	path := filepath.Join(t.TempDir(), "pending.json")
	cfg := railtx.FunderConfig{
		Consensus: cons, Consent: consent, GasLimit: 100000, Fee: 250, MaxFee: 1000,
		MaxAmount: 10000, PendingPath: path, ConfirmDelay: time.Millisecond,
		Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{7}, 32))),
	}
	if mut != nil {
		mut(&cfg)
	}
	f, err := railtx.NewFunder(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	fc.Accounts[f.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq}
	to, err := bech32.ConvertAndEncode("celestia", bytes.Repeat([]byte{9}, 20))
	require.NoError(t, err)
	return &fundEnv{cons: cons, consent: consent, funder: f, to: to, path: path, cfg: cfg}
}

// restart is a new process on the same state file.
func (e *fundEnv) restart(t *testing.T) *railtx.Funder {
	t.Helper()
	require.NoError(t, e.funder.Close())
	f, err := railtx.NewFunder(context.Background(), e.cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// sendSettled is Send as a caller uses it: a call that only settled the
// previous send is repeated.
func (e *fundEnv) sendSettled(t *testing.T, f *railtx.Funder) error {
	t.Helper()
	_, _, err := f.Send(context.Background(), e.to, fundAmount)
	if errors.Is(err, railtx.ErrSettled) {
		_, _, err = f.Send(context.Background(), e.to, fundAmount)
	}
	return err
}

func (e *fundEnv) send(t *testing.T) ([32]byte, uint64) {
	t.Helper()
	e.consent.Arm()
	h, th, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.NoError(t, err)
	return h, th
}

// proof is the first height at which a send with timeout height th is proven
// lost or landed.
func proof(th uint64) uint64 { return th + railtx.DefaultIndexerLagBlocks + 1 }

func TestFunderRefusesBeforeConsent(t *testing.T) {
	e := newFundEnv(t, nil)
	_, _, err := e.funder.Send(context.Background(), e.to, 100)
	require.ErrorIs(t, err, railtx.ErrNotStarted)
	assert.Empty(t, e.cons.Sent, "nothing is broadcast while the consent is unarmed")
	_, _, ok := e.funder.Pending()
	assert.False(t, ok)

	e.consent.Arm()
	_, _, err = e.funder.Send(context.Background(), e.to, 100)
	require.NoError(t, err)
	assert.Len(t, e.cons.Sent, 1)
}

func TestConsentZeroValueAndNilAreUnarmed(t *testing.T) {
	var c railtx.Consent
	require.ErrorIs(t, c.Check(), railtx.ErrNotStarted)
	var nilC *railtx.Consent
	require.ErrorIs(t, nilC.Check(), railtx.ErrNotStarted)
	c.Arm()
	require.NoError(t, c.Check())
}

func TestFunderSetsTimeoutHeightAndBody(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	hash, th, err := e.funder.Send(context.Background(), e.to, 4242)
	require.NoError(t, err)
	assert.Equal(t, uint64(1000+railtx.DefaultFundingTimeoutBlocks), th)
	require.Len(t, e.cons.Sent, 1)
	assert.Equal(t, sha256.Sum256(e.cons.Sent[0]), hash)

	var raw txtypes.TxRaw
	require.NoError(t, raw.Unmarshal(e.cons.Sent[0]))
	var body txtypes.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	assert.Equal(t, th, body.TimeoutHeight)
	assert.Equal(t, railtx.DefaultFundingMemo, body.Memo)
	require.Len(t, body.Messages, 1)
	var msg banktypes.MsgSend
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	assert.Equal(t, e.funder.Address(), msg.FromAddress)
	assert.Equal(t, e.to, msg.ToAddress)
	require.Len(t, msg.Amount, 1)
	assert.Equal(t, "utia", msg.Amount[0].Denom)
	assert.Equal(t, "4242", msg.Amount[0].Amount.String())

	h, thp, ok := e.funder.Pending()
	require.True(t, ok)
	assert.Equal(t, hash, h)
	assert.Equal(t, th, thp)
}

func TestFunderConfigurableTimeout(t *testing.T) {
	e := newFundEnv(t, func(c *railtx.FunderConfig) { c.TimeoutBlocks = 7 })
	e.consent.Arm()
	_, th, err := e.funder.Send(context.Background(), e.to, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(1007), th)
}

func TestFunderRefusals(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	_, _, err := e.funder.Send(ctx, e.to, 0)
	require.Error(t, err)
	_, _, err = e.funder.Send(ctx, e.to, e.cfg.MaxAmount+1)
	require.ErrorIs(t, err, railtx.ErrAmountAboveMax)
	_, _, err = e.funder.Send(ctx, e.funder.Address(), 5)
	require.ErrorIs(t, err, railtx.ErrSelfSend)
	_, _, err = e.funder.Send(ctx, strings.ToUpper(e.funder.Address()), 5)
	require.ErrorIs(t, err, railtx.ErrSelfSend, "the check is on the decoded address")
	_, _, err = e.funder.Send(ctx, "not-an-address", 5)
	require.ErrorIs(t, err, railtx.ErrBadRecipient)
	other, err := bech32.ConvertAndEncode("cosmos", bytes.Repeat([]byte{9}, 20))
	require.NoError(t, err)
	_, _, err = e.funder.Send(ctx, other, 5)
	require.ErrorIs(t, err, railtx.ErrBadRecipient, "an address of another chain")
	assert.Empty(t, e.cons.Sent)
}

func TestNewFunderValidation(t *testing.T) {
	good := func() railtx.FunderConfig {
		return railtx.FunderConfig{
			Consensus: nodefake.NewConsensus("mocha-5"), Consent: &railtx.Consent{}, GasLimit: 1,
			MaxAmount: 1, PendingPath: filepath.Join(t.TempDir(), "p.json"),
			Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{7}, 32))),
		}
	}
	for name, mut := range map[string]func(*railtx.FunderConfig){
		"nil consent":     func(c *railtx.FunderConfig) { c.Consent = nil },
		"nil consensus":   func(c *railtx.FunderConfig) { c.Consensus = nil },
		"zero gas":        func(c *railtx.FunderConfig) { c.GasLimit = 0 },
		"timeout too big": func(c *railtx.FunderConfig) { c.TimeoutBlocks = railtx.MaxFundingTimeoutBlocks + 1 },
		"no key":          func(c *railtx.FunderConfig) { c.Key = railtx.KeySource{} },
		"no max amount":   func(c *railtx.FunderConfig) { c.MaxAmount = 0 },
		"no state path":   func(c *railtx.FunderConfig) { c.PendingPath = "" },
		"max fee < fee":   func(c *railtx.FunderConfig) { c.Fee = 5; c.MaxFee = 4 },
		"negative delay":  func(c *railtx.FunderConfig) { c.ConfirmDelay = -1 },
		"huge lag":        func(c *railtx.FunderConfig) { c.IndexerLagBlocks = math.MaxUint64 },
		"lag over cap":    func(c *railtx.FunderConfig) { c.IndexerLagBlocks = railtx.MaxIndexerLagBlocks + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := good()
			mut(&c)
			_, err := railtx.NewFunder(context.Background(), c)
			require.Error(t, err)
		})
	}
	_, err := railtx.NewFunder(context.Background(), good())
	require.NoError(t, err)
}

func TestFunderNeverPrintsTheKey(t *testing.T) {
	e := newFundEnv(t, nil)
	for _, s := range []string{fmt.Sprintf("%v", e.funder), fmt.Sprintf("%+v", e.funder), fmt.Sprintf("%#v", e.funder)} {
		assert.Equal(t, "railtx.Funder", s)
	}
}

func TestFunderReadFailureBeforeSendIsNotPending(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	e.cons.Fail = errors.New("down")
	_, _, err := e.funder.Send(context.Background(), e.to, 5)
	require.Error(t, err)
	e.cons.Fail = nil
	_, _, ok := e.funder.Pending()
	assert.False(t, ok)
}

func notFound(h uint64) node.TxStatus { return node.TxStatus{NodeHeight: h} }

func TestFunderCommittedSendFreesTheNext(t *testing.T) {
	e := newFundEnv(t, nil)
	ctx := context.Background()
	hash, _ := e.send(t)
	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: 1002, NodeHeight: 1002})
	st, err := e.funder.Status(ctx, hash)
	require.NoError(t, err)
	assert.True(t, st.Found)
	e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
	_, _, err = e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSettled)
	assert.Len(t, e.cons.Sent, 1, "the call that settled sends nothing")
	require.NoError(t, e.sendSettled(t, e.funder))
	assert.NotEqual(t, hash[:], mustHash(t, readPending(t, e.path)), "the file now holds the new send")
}

func TestFunderUnclearBroadcastKeepsPending(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	e.cons.bcastErr = fmt.Errorf("%w: connection reset", node.ErrUnavailable)
	hash, th, err := e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrIndeterminate)
	assert.Equal(t, uint64(fundHead+railtx.DefaultFundingTimeoutBlocks), th, "the real timeout height, not zero")
	assert.NotZero(t, hash)
	_, pth, ok := e.funder.Pending()
	assert.True(t, ok, "the tx may have reached the mempool")
	assert.Equal(t, th, pth)

	e.cons.bcastErr = nil
	_, _, err = e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.Empty(t, e.cons.Sent)
}

func TestFunderRejectedSendIsNotPending(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	e.cons.bcastErr = fmt.Errorf("%w: insufficient funds", node.ErrRejected)
	_, th, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrRejected)
	assert.Zero(t, th, "a refused transaction cannot land")
	_, _, ok := e.funder.Pending()
	assert.False(t, ok)
	m := readPending(t, e.path)
	assert.Nil(t, m["hash"], "no pending send is left in the file")
	assert.EqualValues(t, fundSeq, m["must_reuse_sequence"], "the next send is bound to the same sequence")
}

func TestNewFunderRefusesANodeWithoutTxIndex(t *testing.T) {
	cons := &fundCons{Consensus: nodefake.NewConsensus("mocha-5"), noIndex: true}
	_, err := railtx.NewFunder(context.Background(), railtx.FunderConfig{
		Consensus: cons, Consent: &railtx.Consent{}, GasLimit: 1, MaxAmount: 1, PendingPath: filepath.Join(t.TempDir(), "p"),
		Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{7}, 32))),
	})
	require.ErrorIs(t, err, railtx.ErrTxIndexDisabled)
}

func TestFunderNoResendBeforeTheProofHeight(t *testing.T) {
	e := newFundEnv(t, nil)
	ctx := context.Background()
	hash, th := e.send(t)

	// Not found while the node is short of the proof height: the pinned
	// account read is unavailable, so nothing is cleared. A huge node height
	// in the lookup (a fast backend next to a lagging one) changes nothing.
	for _, h := range []uint64{fundHead + 1, th, th + railtx.DefaultIndexerLagBlocks} {
		e.cons.SetHeight(h)
		e.cons.SetTx(hash, notFound(math.MaxUint64))
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSendInFlight, "node height %d", h)
	}
	assert.Len(t, e.cons.Sent, 1, "the in-flight send is never replaced")
	_, _, ok := e.funder.Pending()
	require.True(t, ok)

	// A node that cannot be asked proves nothing.
	e.cons.SetHeight(proof(th))
	e.cons.Fail = errors.New("down")
	_, _, err := e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	e.cons.Fail = nil

	// At the proof height the signed sequence is still free: lost, so a new
	// send is allowed once the caller has re-read its balances.
	_, _, err = e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSettled)
	require.NoError(t, e.sendSettled(t, e.funder))
	assert.Len(t, e.cons.Sent, 2)
}

func TestFunderSplitAnswerKeepsThePendingSend(t *testing.T) {
	e := newFundEnv(t, nil)
	ctx := context.Background()
	hash, th := e.send(t)
	e.cons.SetHeight(proof(th))

	// The lookup lands on a backend whose index lags (not found) while the
	// height comes from a backend far ahead, and the account at the proof
	// height shows the sequence was used.
	e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
	e.cons.SetTx(hash, notFound(proof(th)+500))
	_, _, err := e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
	assert.Len(t, e.cons.Sent, 1)
	_, _, ok := e.funder.Pending()
	assert.True(t, ok, "the slot may have been used by this very send")

	// The same lookup is committed once it reaches a backend that has it.
	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: th - 5, NodeHeight: proof(th)})
	e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
	require.NoError(t, e.sendSettled(t, e.funder))
}

func TestFunderSecondLookupMustAgree(t *testing.T) {
	ctx := context.Background()
	t.Run("found without a height on the confirm lookup", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(proof(th))
		e.cons.txScript = []node.TxStatus{notFound(proof(th)), {Found: true}}
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSendInFlight)
		_, _, ok := e.funder.Pending()
		assert.True(t, ok)
	})
	t.Run("sequence moves between the lookups", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(proof(th))
		e.cons.afterTx = func(call int) {
			if call == 1 {
				e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
			}
		}
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
		assert.Len(t, e.cons.Sent, 1)
	})
	t.Run("found on the confirm lookup is committed, not lost", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(proof(th))
		e.cons.txScript = []node.TxStatus{notFound(proof(th)), {Found: true, Height: th - 1}}
		e.cons.SetAccountAt(e.funder.Address(), 1, node.AccountInfo{Number: 3, Sequence: fundSeq})
		e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
		require.NoError(t, e.sendSettled(t, e.funder))
		assert.Len(t, e.cons.Sent, 2)
	})
	t.Run("two agreeing lookups clear", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(proof(th))
		lookups := 0
		e.cons.afterTx = func(int) { lookups++ }
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSettled)
		assert.Equal(t, 2, lookups)
	})
}

func TestFunderFoundAtHeightZeroStaysPending(t *testing.T) {
	e := newFundEnv(t, nil)
	hash, th := e.send(t)
	e.cons.SetHeight(proof(th))
	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: 0, NodeHeight: proof(th)})
	_, _, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	_, _, ok := e.funder.Pending()
	assert.True(t, ok)
	assert.Len(t, e.cons.Sent, 1)
}

func TestFunderSequenceMismatchKeepsPending(t *testing.T) {
	e := newFundEnv(t, nil)
	ctx := context.Background()
	e.consent.Arm()
	e.cons.bcastErr = fmt.Errorf("%w: account sequence mismatch", node.ErrSequenceMismatch)
	_, th, err := e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSequenceMismatch)
	assert.NotZero(t, th, "a proxy may have admitted the first copy")
	_, pth, ok := e.funder.Pending()
	require.True(t, ok)
	assert.Equal(t, th, pth)

	e.cons.bcastErr = nil
	_, _, err = e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)

	// The slot was used on chain: it stays pending past the timeout.
	e.cons.SetHeight(proof(th))
	e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
	_, _, err = e.funder.Send(ctx, e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
	assert.Empty(t, e.cons.Sent)

	// Cleared only by the sequence rule: an unused slot at the proof height.
	e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq})
	require.NoError(t, e.sendSettled(t, e.funder))
}

func readPending(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func mustHash(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := hex.DecodeString(m["hash"].(string))
	require.NoError(t, err)
	return b
}

func TestFunderPersistsBeforeBroadcast(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	var seen map[string]any
	var mode os.FileMode
	e.cons.onBroadcast = func() {
		seen = readPending(t, e.path)
		fi, err := os.Stat(e.path)
		require.NoError(t, err)
		mode = fi.Mode().Perm()
	}
	hash, th, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.NoError(t, err)
	require.NotNil(t, seen, "the file exists when the broadcast starts")
	assert.Equal(t, os.FileMode(0o600), mode)
	assert.Equal(t, hex.EncodeToString(hash[:]), seen["hash"])
	assert.EqualValues(t, fundSeq, seen["sequence"])
	assert.EqualValues(t, th, seen["timeout_height"])
	assert.Equal(t, e.to, seen["to"])
	assert.EqualValues(t, fundAmount, seen["amount"])
	assert.Equal(t, e.funder.Address(), seen["from"])
}

func TestFunderCrashBeforeBroadcastIsResolvedOnRestart(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	e.cons.bcastErr = errors.New("killed")
	hash, th, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.Error(t, err)

	f2 := e.restart(t)
	h, pth, ok := f2.Pending()
	require.True(t, ok, "the send is reloaded")
	assert.Equal(t, hash, h)
	assert.Equal(t, th, pth)
	_, _, err = f2.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.Empty(t, e.cons.Sent)

	// It never reached the node: at the proof height the slot is free and the
	// rerun sends once.
	e.cons.SetHeight(proof(th))
	e.cons.bcastErr = nil
	require.NoError(t, e.sendSettled(t, f2))
	require.Len(t, e.cons.Sent, 1)
	assert.NotEqual(t, hash, sha256.Sum256(e.cons.Sent[0]), "a fresh transaction")
}

func TestFunderCrashAfterBroadcastIsResolvedOnRestart(t *testing.T) {
	e := newFundEnv(t, nil)
	hash, th := e.send(t)
	require.Len(t, e.cons.Sent, 1)

	f2 := e.restart(t)
	e.cons.SetHeight(proof(th))
	e.cons.SetAccountAt(f2.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
	_, _, err := f2.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSequenceAdvanced, "included but not found by the lookup: never sent twice")
	assert.Len(t, e.cons.Sent, 1)

	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: th - 3, NodeHeight: proof(th)})
	e.cons.Accounts[f2.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
	require.NoError(t, e.sendSettled(t, f2))
	assert.Len(t, e.cons.Sent, 2)
	assert.NotEqual(t, hash[:], mustHash(t, readPending(t, e.path)))
}

func TestFunderRefusesAnUntrustedStateFile(t *testing.T) {
	good := func(t *testing.T) *fundEnv {
		e := newFundEnv(t, nil)
		e.send(t)
		require.NoError(t, e.funder.Close())
		return e
	}
	t.Run("loose mode", func(t *testing.T) {
		e := good(t)
		require.NoError(t, os.Chmod(e.path, 0o644))
		_, err := railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("garbage", func(t *testing.T) {
		e := good(t)
		require.NoError(t, os.WriteFile(e.path, []byte("{nope"), 0o600))
		_, err := railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("another key", func(t *testing.T) {
		e := good(t)
		cfg := e.cfg
		cfg.Key = railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{8}, 32)))
		_, err := railtx.NewFunder(context.Background(), cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("timeout height out of range", func(t *testing.T) {
		e := good(t)
		m := readPending(t, e.path)
		m["timeout_height"] = uint64(math.MaxInt64) + 1
		b, err := json.Marshal(m)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(e.path, b, 0o600))
		_, err = railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("unwritable state sends nothing", func(t *testing.T) {
		e := newFundEnv(t, nil)
		cfg := e.cfg
		cfg.PendingPath = filepath.Join(t.TempDir(), "missing", "p.json")
		_, err := railtx.NewFunder(context.Background(), cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
}

func TestFunderHugeValuesDoNotWrap(t *testing.T) {
	// A node that reports a head near 2^64 cannot wrap the timeout height.
	e := newFundEnv(t, nil)
	e.consent.Arm()
	e.cons.SetHeight(math.MaxUint64 - 5)
	_, _, err := e.funder.Send(context.Background(), e.to, fundAmount)
	require.Error(t, err)
	assert.Empty(t, e.cons.Sent)
	_, _, ok := e.funder.Pending()
	assert.False(t, ok)

	// With the largest lag and the largest legal timeout height the proof
	// height is still computed without wrapping: it lies above the node's
	// head, so nothing is cleared.
	e2 := newFundEnv(t, func(c *railtx.FunderConfig) { c.IndexerLagBlocks = railtx.MaxIndexerLagBlocks })
	e2.cons.SetHeight(math.MaxInt64 - railtx.DefaultFundingTimeoutBlocks)
	e2.consent.Arm()
	_, th, err := e2.funder.Send(context.Background(), e2.to, fundAmount)
	require.NoError(t, err)
	assert.EqualValues(t, int64(math.MaxInt64), int64(th))
	_, _, err = e2.funder.Send(context.Background(), e2.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.Len(t, e2.cons.Sent, 1)
}

func feeOf(t *testing.T, raw []byte) string {
	t.Helper()
	var tr txtypes.TxRaw
	require.NoError(t, tr.Unmarshal(raw))
	var ai txtypes.AuthInfo
	require.NoError(t, ai.Unmarshal(tr.AuthInfoBytes))
	return ai.Fee.Amount[0].Amount.String()
}

func TestFunderFeeCap(t *testing.T) {
	ctx := context.Background()
	t.Run("node price above the cap is refused before signing", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		e.cons.MinPrice = big.NewRat(1, 50) // 100000 gas * 0.02 = 2000 > MaxFee 1000
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrFeeAboveMax)
		assert.Empty(t, e.cons.Sent)
		_, _, ok := e.funder.Pending()
		assert.False(t, ok)
	})
	t.Run("node price above the configured fee raises it within the cap", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		e.cons.MinPrice = big.NewRat(1, 125) // 800
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.NoError(t, err)
		assert.Equal(t, "800", feeOf(t, e.cons.Sent[0]))
	})
	t.Run("a price that rounds up", func(t *testing.T) {
		e := newFundEnv(t, func(c *railtx.FunderConfig) { c.Fee = 1; c.MaxFee = 100001 })
		e.consent.Arm()
		e.cons.MinPrice = big.NewRat(1, 3) // 33333.3 rounds to 33334
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.NoError(t, err)
		assert.Equal(t, "33334", feeOf(t, e.cons.Sent[0]))
	})
	t.Run("a cheap node keeps the configured fee", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.NoError(t, err)
		assert.Equal(t, "400", feeOf(t, e.cons.Sent[0]), "default fake price 1/250 asks 400 > 250")
	})
}

func TestFunderNormalisesTheRecipient(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	_, _, err := e.funder.Send(context.Background(), strings.ToUpper(e.to), fundAmount)
	require.NoError(t, err)
	var raw txtypes.TxRaw
	require.NoError(t, raw.Unmarshal(e.cons.Sent[0]))
	var body txtypes.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	var msg banktypes.MsgSend
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	assert.Equal(t, e.to, msg.ToAddress)
}

func TestSettleResolvesWithoutSending(t *testing.T) {
	e := newFundEnv(t, nil)
	ctx := context.Background()
	cleared, err := e.funder.Settle(ctx)
	require.NoError(t, err)
	assert.False(t, cleared, "nothing pending")

	hash, th := e.send(t)
	e.cons.SetHeight(th - 1)
	cleared, err = e.funder.Settle(ctx)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.False(t, cleared)

	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: th - 2, NodeHeight: th - 1})
	cleared, err = e.funder.Settle(ctx)
	require.NoError(t, err)
	assert.True(t, cleared)
	_, _, ok := e.funder.Pending()
	assert.False(t, ok)
	assert.Len(t, e.cons.Sent, 1)
}

// A reloaded send commits between the caller's balance read and its Send: the
// amount was computed without it, so that Send must not go out.
func TestReloadedSendCommitsBetweenBalanceReadAndSend(t *testing.T) {
	e := newFundEnv(t, nil)
	hash, th := e.send(t)
	f2 := e.restart(t)

	// The caller reads balances here; the send is still pending.
	_, _, ok := f2.Pending()
	require.True(t, ok)

	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: th - 4, NodeHeight: th - 3})
	e.cons.Accounts[f2.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
	_, _, err := f2.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrSettled)
	assert.Len(t, e.cons.Sent, 1, "nothing broadcast by the call that cleared the old send")

	require.NoError(t, e.sendSettled(t, f2), "after re-reading balances the caller sends again")
	assert.Len(t, e.cons.Sent, 2)
}

func TestFunderRefusesASequenceAlreadyUsed(t *testing.T) {
	e := newFundEnv(t, nil)
	hash, th := e.send(t)
	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: th - 4, NodeHeight: th - 3})
	_, err := e.funder.Settle(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, fundSeq, readPending(t, e.path)["last_committed_sequence"])

	// The next read comes from a backend that has not applied the block yet.
	_, _, err = e.funder.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrStaleSequence)
	assert.Len(t, e.cons.Sent, 1)
	_, _, ok := e.funder.Pending()
	assert.False(t, ok, "nothing was made pending")

	f2 := e.restart(t)
	_, _, err = f2.Send(context.Background(), e.to, fundAmount)
	require.ErrorIs(t, err, railtx.ErrStaleSequence, "the floor survives a restart")

	e.cons.Accounts[f2.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
	require.NoError(t, e.sendSettled(t, f2))
}

func TestSequenceAdvancedResolvedByTheTxThatUsedTheSlot(t *testing.T) {
	setup := func(t *testing.T) (*fundEnv, [32]byte, uint64) {
		e := newFundEnv(t, nil)
		hash, th := e.send(t)
		e.cons.SetHeight(proof(th))
		e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
		return e, hash, th
	}
	t.Run("not indexed stays pending", func(t *testing.T) {
		e, _, _ := setup(t)
		_, err := e.funder.Settle(context.Background())
		require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
		_, _, ok := e.funder.Pending()
		assert.True(t, ok)
	})
	t.Run("another transaction holds the slot", func(t *testing.T) {
		e, _, th := setup(t)
		e.cons.SetTxBySequence(e.funder.Address(), fundSeq, node.SeqTx{Hash: [32]byte{1}, Height: th - 9})
		cleared, err := e.funder.Settle(context.Background())
		require.NoError(t, err)
		assert.True(t, cleared)
		assert.EqualValues(t, fundSeq, readPending(t, e.path)["last_committed_sequence"])
		assert.Nil(t, readPending(t, e.path)["must_reuse_sequence"])
	})
	t.Run("our own transaction found by sequence is committed", func(t *testing.T) {
		e, hash, th := setup(t)
		e.cons.SetTxBySequence(e.funder.Address(), fundSeq, node.SeqTx{Hash: hash, Height: th - 9})
		cleared, err := e.funder.Settle(context.Background())
		require.NoError(t, err)
		assert.True(t, cleared)
	})
	t.Run("a lookup that fails keeps it pending", func(t *testing.T) {
		e, _, _ := setup(t)
		e.cons.SetTxBySequence(e.funder.Address(), fundSeq, node.SeqTx{Height: 0})
		_, err := e.funder.Settle(context.Background())
		require.ErrorIs(t, err, railtx.ErrSequenceAdvanced)
	})
}

func TestAbandon(t *testing.T) {
	ctx := context.Background()
	t.Run("needs the consent", func(t *testing.T) {
		e := newFundEnv(t, nil)
		require.ErrorIs(t, e.funder.Abandon(ctx), railtx.ErrNotStarted)
	})
	t.Run("nothing to abandon", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		require.ErrorIs(t, e.funder.Abandon(ctx), railtx.ErrNothingToAbandon)
	})
	t.Run("a send that can still land is refused", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(th)
		require.ErrorIs(t, e.funder.Abandon(ctx), railtx.ErrSendInFlight)
		_, _, ok := e.funder.Pending()
		assert.True(t, ok)
	})
	t.Run("advanced sequence is abandoned and logged", func(t *testing.T) {
		e := newFundEnv(t, nil)
		hash, th := e.send(t)
		e.cons.SetHeight(proof(th))
		e.cons.SetAccountAt(e.funder.Address(), proof(th), node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
		require.NoError(t, e.funder.Abandon(ctx))
		_, _, ok := e.funder.Pending()
		assert.False(t, ok)
		assert.EqualValues(t, fundSeq, readPending(t, e.path)["last_committed_sequence"])
		b, err := os.ReadFile(e.path + ".log")
		require.NoError(t, err)
		assert.Contains(t, string(b), hex.EncodeToString(hash[:]))
		fi, err := os.Stat(e.path + ".log")
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
		require.NoError(t, e.sendSettled(t, e.funder))
	})
	t.Run("a binding the chain moved past", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		e.cons.bcastErr = fmt.Errorf("%w: min gas price", node.ErrRejected)
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrRejected)
		e.cons.bcastErr = nil

		require.ErrorIs(t, e.funder.Abandon(ctx), railtx.ErrNothingToAbandon, "the bound sequence is still free")
		e.cons.SetAccountAt(e.funder.Address(), 1, node.AccountInfo{Number: 3, Sequence: fundSeq + 1})
		require.NoError(t, e.funder.Abandon(ctx))
		assert.Nil(t, readPending(t, e.path)["must_reuse_sequence"])
	})
}

func TestClearWithoutProofBindsTheNextSequence(t *testing.T) {
	ctx := context.Background()
	t.Run("rejected broadcast", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.consent.Arm()
		e.cons.bcastErr = fmt.Errorf("%w: refused", node.ErrRejected)
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrRejected)
		e.cons.bcastErr = nil

		// The proxy retried: the first copy landed and the node now says S+1.
		e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
		_, _, err = e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSequenceBound)
		assert.Empty(t, e.cons.Sent)

		f2 := e.restart(t)
		_, _, err = f2.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSequenceBound, "the binding survives a restart")

		e.cons.Accounts[f2.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq}
		require.NoError(t, e.sendSettled(t, f2))
		assert.Nil(t, readPending(t, e.path)["must_reuse_sequence"], "the new pending send covers the sequence")
	})
	t.Run("lost clear", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, th := e.send(t)
		e.cons.SetHeight(proof(th))
		_, _, err := e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSettled)
		assert.EqualValues(t, fundSeq, readPending(t, e.path)["must_reuse_sequence"])

		e.cons.Accounts[e.funder.Address()] = node.AccountInfo{Number: 3, Sequence: fundSeq + 1}
		_, _, err = e.funder.Send(ctx, e.to, fundAmount)
		require.ErrorIs(t, err, railtx.ErrSequenceBound)
		assert.Len(t, e.cons.Sent, 1)
	})
}

func TestFunderStateFileHygiene(t *testing.T) {
	t.Run("a second funder on the same state is refused", func(t *testing.T) {
		e := newFundEnv(t, nil)
		_, err := railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
		require.NoError(t, e.funder.Close())
		f, err := railtx.NewFunder(context.Background(), e.cfg)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	})
	t.Run("a planted symlink is never followed", func(t *testing.T) {
		e := newFundEnv(t, nil)
		target := filepath.Join(t.TempDir(), "victim")
		require.NoError(t, os.WriteFile(target, []byte("keep"), 0o644))
		require.NoError(t, os.Symlink(target, e.path+".tmp"))
		e.send(t)
		b, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, "keep", string(b))
		fi, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	})
	t.Run("a symlink in place of the state file", func(t *testing.T) {
		e := newFundEnv(t, nil)
		require.NoError(t, e.funder.Close())
		target := filepath.Join(t.TempDir(), "real")
		require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
		require.NoError(t, os.Symlink(target, e.path))
		_, err := railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("a directory others can write to", func(t *testing.T) {
		e := newFundEnv(t, nil)
		require.NoError(t, e.funder.Close())
		require.NoError(t, os.Chmod(filepath.Dir(e.path), 0o777))
		_, err := railtx.NewFunder(context.Background(), e.cfg)
		require.ErrorIs(t, err, railtx.ErrPendingState)
	})
	t.Run("no temp file is left behind", func(t *testing.T) {
		e := newFundEnv(t, nil)
		e.send(t)
		ents, err := os.ReadDir(filepath.Dir(e.path))
		require.NoError(t, err)
		for _, en := range ents {
			assert.NotContains(t, en.Name(), ".pending-")
		}
	})
}
