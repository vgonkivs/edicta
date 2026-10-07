package railtx_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

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

// fundCons lets a test choose what Broadcast answers while the other reads
// keep working.
type fundCons struct {
	*nodefake.Consensus
	bcastErr error
}

func (f *fundCons) Broadcast(ctx context.Context, raw []byte) ([32]byte, error) {
	if f.bcastErr != nil {
		return [32]byte{}, f.bcastErr
	}
	return f.Consensus.Broadcast(ctx, raw)
}

type fundEnv struct {
	cons    *fundCons
	consent *railtx.Consent
	funder  *railtx.Funder
	to      string
}

func newFundEnv(t *testing.T, mut func(*railtx.FunderConfig)) *fundEnv {
	t.Helper()
	fc := nodefake.NewConsensus("mocha-5")
	fc.SetHeight(1000)
	cons := &fundCons{Consensus: fc}
	consent := &railtx.Consent{}
	cfg := railtx.FunderConfig{
		Consensus: cons, Consent: consent, GasLimit: 100000, Fee: 250,
		Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{7}, 32))),
	}
	if mut != nil {
		mut(&cfg)
	}
	f, err := railtx.NewFunder(context.Background(), cfg)
	require.NoError(t, err)
	fc.Accounts[f.Address()] = node.AccountInfo{Number: 3, Sequence: 5}
	to, err := bech32.ConvertAndEncode("celestia", bytes.Repeat([]byte{9}, 20))
	require.NoError(t, err)
	return &fundEnv{cons: cons, consent: consent, funder: f, to: to}
}

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

func TestFunderNoResendInsideTimeoutWindow(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	hash, th, err := e.funder.Send(ctx, e.to, 100)
	require.NoError(t, err)

	// Not found, node still at or before timeout_height + lag: it can land.
	for _, h := range []uint64{1001, th, th + railtx.DefaultIndexerLagBlocks} {
		e.cons.SetTx(hash, node.TxStatus{NodeHeight: h})
		_, _, err = e.funder.Send(ctx, e.to, 100)
		require.ErrorIs(t, err, railtx.ErrSendInFlight, "node height %d", h)
	}
	assert.Len(t, e.cons.Sent, 1, "the in-flight send is never replaced")

	// A node that cannot be asked proves nothing.
	e.cons.SetTx(hash, node.TxStatus{})
	_, _, err = e.funder.Send(ctx, e.to, 100)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.Len(t, e.cons.Sent, 1)

	// Past the window and still not found: lost, a new send is allowed.
	e.cons.SetTx(hash, node.TxStatus{NodeHeight: th + railtx.DefaultIndexerLagBlocks + 1})
	_, _, err = e.funder.Send(ctx, e.to, 100)
	require.NoError(t, err)
	assert.Len(t, e.cons.Sent, 2)
}

func TestFunderCommittedSendFreesTheNext(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	hash, _, err := e.funder.Send(ctx, e.to, 100)
	require.NoError(t, err)
	e.cons.SetTx(hash, node.TxStatus{Found: true, Height: 1002, NodeHeight: 1002})
	st, err := e.funder.Status(ctx, hash)
	require.NoError(t, err)
	assert.True(t, st.Found)
	_, _, err = e.funder.Send(ctx, e.to, 100)
	require.NoError(t, err)
}

func TestFunderUnclearBroadcastKeepsPending(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	e.cons.bcastErr = fmt.Errorf("%w: connection reset", node.ErrUnavailable)
	_, _, err := e.funder.Send(ctx, e.to, 100)
	require.ErrorIs(t, err, railtx.ErrIndeterminate)
	_, _, ok := e.funder.Pending()
	assert.True(t, ok, "the tx may have reached the mempool")

	e.cons.bcastErr = nil
	_, _, err = e.funder.Send(ctx, e.to, 100)
	require.ErrorIs(t, err, railtx.ErrSendInFlight)
	assert.Empty(t, e.cons.Sent)
}

func TestFunderRejectedSendIsNotPending(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	e.cons.bcastErr = fmt.Errorf("%w: insufficient funds", node.ErrRejected)
	_, _, err := e.funder.Send(context.Background(), e.to, 100)
	require.ErrorIs(t, err, railtx.ErrRejected)
	_, _, ok := e.funder.Pending()
	assert.False(t, ok, "a transaction the node refused cannot land")
}

func TestFunderRefusals(t *testing.T) {
	e := newFundEnv(t, nil)
	e.consent.Arm()
	ctx := context.Background()
	_, _, err := e.funder.Send(ctx, e.to, 0)
	require.Error(t, err)
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
			Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{7}, 32))),
		}
	}
	for name, mut := range map[string]func(*railtx.FunderConfig){
		"nil consent":     func(c *railtx.FunderConfig) { c.Consent = nil },
		"nil consensus":   func(c *railtx.FunderConfig) { c.Consensus = nil },
		"zero gas":        func(c *railtx.FunderConfig) { c.GasLimit = 0 },
		"timeout too big": func(c *railtx.FunderConfig) { c.TimeoutBlocks = railtx.MaxFundingTimeoutBlocks + 1 },
		"no key":          func(c *railtx.FunderConfig) { c.Key = railtx.KeySource{} },
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
