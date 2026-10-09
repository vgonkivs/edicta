package bankaction_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/test/bankvec"
)

const gate1PubKeyHex = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"

func TestEndToEndOffline(t *testing.T) {
	e := bankvec.E2ECase(t)
	action := bankvec.Hex(t, e.ActionHex)
	ex := e.Executor

	require.Equal(t, bankaction.ActionType, e.Commitment.Input.Action.Type)
	require.Contains(t, e.Gate.ActionTypes, bankaction.ActionType)

	salt := bankvec.Hex(t, e.SaltHex)
	ah, err := commitment.ActionHash(bankaction.ActionType, salt, action)
	require.NoError(t, err)
	assert.Equal(t, e.Commitment.Input.Action.Hash, hex.EncodeToString(ah[:]))

	sa, h, err := commitment.VerifyAuthorization(bankvec.Hex(t, e.Authorization.SignedHex), commitment.AuthorizationCheck{
		GatePubKey: ed25519.PublicKey(bankvec.Hex(t, gate1PubKeyHex)),
		GateID:     e.Gate.GateID,
		ActionType: bankaction.ActionType,
		Action:     action,
		ActionSalt: salt,
		Now:        bankvec.U64(t, ex.Now),
		SkewS:      bankvec.U64(t, ex.SkewS),
	})
	require.NoError(t, err)
	require.NotZero(t, h)
	assert.Equal(t, e.Commitment.HashHex, hex.EncodeToString(sa.Authorization.CommitmentHash))

	a, m, err := bankaction.CheckExecution(action,
		domain(ex.Domain), bankaction.Limits{})
	require.NoError(t, err)

	tau, err := bankaction.BlockIntervalMs(headers(t, ex.Headers))
	require.NoError(t, err)
	assert.Equal(t, bankvec.U64(t, ex.TauMs), tau)

	th, err := bankaction.TimeoutHeight(bankaction.TimeoutInput{
		HeadHeight: bankvec.U64(t, ex.HeadHeight),
		HeadTime:   bankvec.U64(t, ex.HeadTime),
		TauMs:      tau,
		Expires:    sa.Authorization.Expires,
		SkewS:      bankvec.U64(t, ex.SkewS),
		MaxBlocks:  bankvec.U64(t, ex.MaxBlocks),
		Now:        bankvec.U64(t, ex.Now),
	})
	require.NoError(t, err)
	assert.Equal(t, bankvec.U64(t, ex.TimeoutHeight), th)

	ch := commitment.Hash(sa.Authorization.CommitmentHash)
	assert.Equal(t, ex.Memo, hex.EncodeToString(ch[:]))
	body, err := bankaction.Body(a.Msg, ch, th)
	require.NoError(t, err)
	assert.Equal(t, bankvec.Hex(t, ex.BodyHex), body)
	_, err = bankaction.CheckBody(a, ch, body)
	require.NoError(t, err)

	require.Equal(t, pricetrigger.MediaType, e.Context.MediaType)
	pt, err := pricetrigger.Decode(bankvec.Hex(t, e.Context.CBORHex))
	require.NoError(t, err)
	assert.Equal(t, failedChecks(e.Context.ExpectedFails), pricetrigger.Verify(pt, m, bankvec.U64(t, e.Commitment.Input.IssuedAt)))
}

func failedChecks(ids []string) []pricetrigger.Check {
	out := []pricetrigger.Check{}
	for _, id := range ids {
		out = append(out, pricetrigger.Check(id))
	}
	return out
}

func TestEndToEndExecutorStopsAtExpiry(t *testing.T) {
	e := bankvec.E2ECase(t)
	ex := e.Executor
	in := bankaction.TimeoutInput{
		HeadHeight: bankvec.U64(t, ex.HeadHeight),
		HeadTime:   bankvec.U64(t, ex.HeadTime),
		TauMs:      bankvec.U64(t, ex.TauMs),
		Expires:    bankvec.U64(t, e.Authorization.Input.Expires),
		SkewS:      bankvec.U64(t, ex.SkewS),
		MaxBlocks:  bankvec.U64(t, ex.MaxBlocks),
		Now:        bankvec.U64(t, e.Authorization.Input.Expires) - bankvec.U64(t, ex.SkewS),
	}
	_, err := bankaction.TimeoutHeight(in)
	require.ErrorIs(t, err, bankaction.ErrExpired)
}
