// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer"
	"github.com/vgonkivs/edicta/services/signer/signertest"
)

func TestEachAgentIsPaidByItsOwnPayer(t *testing.T) {
	e := newEnvOpts(t, envOpts{agent2: true})
	require.NotEqual(t, e.keys.PayerAddress(), e.keys2.PayerAddress())

	for _, k := range []signertest.Keys{e.keys, e.keys2} {
		action, err := signertest.NewDeposit(e.clk.Now()).Action()
		require.NoError(t, err)
		d, err := signertest.NewDecision(k, action, e.clk.Now(), signertest.DecisionOpts{})
		require.NoError(t, err)
		// Both deposits carry nonce 7: each payer has its own nonce
		// sequence, so one agent's deposit in flight never holds the other's.
		out, err := e.svc.Sign(context.Background(), request(d))
		require.NoError(t, err)
		a, err := edenescrow.DecodeTxAction(d.Action)
		require.NoError(t, err)
		_, payer, err := edenescrow.ParseSigned(a, out.Signed)
		require.NoError(t, err)
		assert.Equal(t, k.PayerAddress(), payer, "signed by the payer pinned to the envelope's agent")
		assert.Equal(t, k.PayerAddress(), e.entry(d.Hash).Payer)
	}
}

func TestAnAgentWithoutAWalletIsRefused(t *testing.T) {
	e := newEnvOpts(t, envOpts{agent2: true})
	svc, err := signer.New(e.cfg, signer.Deps{
		Store: e.store, Handlers: []signer.Handler{e.h},
		Wallets: map[signer.WalletKey]signer.WalletBackend{walletKey(t, e.keys, 714): mustWallet(t, e.keys)},
	})
	require.NoError(t, err)
	require.ErrorContains(t, svc.Start(context.Background()), "no payer key for agent",
		"a pinned payer without its wallet refuses to start")
}
