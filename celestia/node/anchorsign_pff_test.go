package node

import (
	"context"
	"math/big"
	"testing"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

// uploadMsg is what an uploader returns for the live blob: the promise and
// the validator signatures of the live PayForFibre, with no signer.
func uploadMsg(t *testing.T, signer string) (fibretypes.MsgPayForFibre, []byte) {
	t.Helper()
	raw, err := PFFMessage(fibrefix.LoadLive(t).PFFTx)
	require.NoError(t, err)
	var m fibretypes.MsgPayForFibre
	require.NoError(t, m.Unmarshal(raw))
	m.Signer = signer
	b, err := m.Marshal()
	require.NoError(t, err)
	return m, b
}

func decodeTx(t *testing.T, tx []byte) (cosmostx.TxBody, cosmostx.AuthInfo) {
	t.Helper()
	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(tx))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	var ai cosmostx.AuthInfo
	require.NoError(t, ai.Unmarshal(raw.AuthInfoBytes))
	return body, ai
}

func TestAnchorSignerPFFCarriesTheUploadUnchanged(t *testing.T) {
	s := testAnchorSigner(t)
	ctx := context.Background()
	addr, err := s.Address(ctx)
	require.NoError(t, err)
	bech, err := bech32.ConvertAndEncode(signerBech32Prefix, addr)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		signer string
		p      TxParams
	}{
		{"unset signer, with timeout", "", TxParams{AccountNumber: 7, Sequence: 42, GasPrice: big.NewRat(1, 250), TimeoutHeight: 500}},
		{"foreign signer replaced", "celestia1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnrql8a", TxParams{AccountNumber: 1, Sequence: 0, GasPrice: big.NewRat(3, 2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, raw := uploadMsg(t, tc.signer)
			tx, err := s.SignPFF(ctx, raw, tc.p)
			require.NoError(t, err)

			seq, err := TxSequence(tx)
			require.NoError(t, err)
			assert.Equal(t, tc.p.Sequence, seq, "signed at the given sequence")
			body, ai := decodeTx(t, tx)
			assert.Equal(t, tc.p.TimeoutHeight, body.TimeoutHeight)

			require.NotNil(t, ai.Fee)
			gas := new(big.Rat).Mul(new(big.Rat).SetUint64(ai.Fee.GasLimit), tc.p.GasPrice)
			fee := new(big.Int).Quo(new(big.Int).Add(gas.Num(), new(big.Int).Sub(gas.Denom(), big.NewInt(1))), gas.Denom())
			require.Len(t, ai.Fee.Amount, 1)
			assert.Equal(t, fee.String(), ai.Fee.Amount[0].Amount.String(), "fee = ceil(gas * price)")
			assert.Greater(t, ai.Fee.GasLimit, fibretypes.EstimateGasForPayForFibre(want.PaymentPromise.BlobSize),
				"the gas limit covers the estimate and the signature checks")

			gotRaw, err := PFFMessage(tx)
			require.NoError(t, err)
			var got fibretypes.MsgPayForFibre
			require.NoError(t, got.Unmarshal(gotRaw))
			assert.Equal(t, bech, got.Signer, "the anchor account signs")
			want.Signer = bech
			assert.Equal(t, want, got, "the promise and the validator signatures are carried unchanged")

			f, ok, err := fibrecert.ParsePFF(tx)
			require.NoError(t, err)
			require.True(t, ok)
			require.NoError(t, fibrecert.VerifyOwner(f), "the owner's promise signature still verifies")

			again, err := s.SignPFF(ctx, raw, tc.p)
			require.NoError(t, err)
			assert.Equal(t, tx, again, "deterministic for one account state")
		})
	}
}

func TestAnchorSignerPFFRefuses(t *testing.T) {
	s := testAnchorSigner(t)
	ctx := context.Background()
	_, raw := uploadMsg(t, "")
	empty, err := (&fibretypes.MsgPayForFibre{}).Marshal()
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		msg []byte
		p   TxParams
	}{
		"no gas price":       {raw, TxParams{Sequence: 1}},
		"negative gas price": {raw, TxParams{Sequence: 1, GasPrice: big.NewRat(-1, 1)}},
		"empty message":      {empty, TxParams{GasPrice: big.NewRat(1, 1)}},
		"not a message":      {[]byte{0xff, 0xff}, TxParams{GasPrice: big.NewRat(1, 1)}},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := s.SignPFF(ctx, tc.msg, tc.p)
			require.Error(t, err)
			assert.Nil(t, tx)
		})
	}
}
