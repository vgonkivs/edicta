package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAnchorSigner(t testing.TB) AnchorSigner {
	t.Helper()
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	_, _, err := kr.NewMnemonic("anchor", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	s, err := NewAnchorSigner(kr, "anchor", "devnet-1")
	require.NoError(t, err)
	return s
}

var anchorNS = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{7}, 10)...)

func TestExpectedSequence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want uint64
		ok   bool
	}{
		{"cosmos wording", fmt.Errorf("%w: account sequence mismatch, expected 5, got 3: incorrect account sequence", ErrSequenceMismatch), 5, true},
		{"zero", fmt.Errorf("%w: expected 0, got 1", ErrSequenceMismatch), 0, true},
		{"max uint64", fmt.Errorf("%w: expected 18446744073709551615, got 1", ErrSequenceMismatch), 1<<64 - 1, true},
		{"overflow", fmt.Errorf("%w: expected 18446744073709551616, got 1", ErrSequenceMismatch), 0, false},
		{"no number", fmt.Errorf("%w: incorrect account sequence", ErrSequenceMismatch), 0, false},
		{"not a mismatch", errors.New("account sequence mismatch, expected 5, got 3"), 0, false},
		{"nil", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ExpectedSequence(tc.err)
			require.Equal(t, tc.ok, ok)
			if ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestAnchorSignerPFBCommitsToTheGivenAccountState(t *testing.T) {
	s := testAnchorSigner(t)
	for _, tc := range []struct {
		name string
		p    TxParams
	}{
		{"with timeout", TxParams{AccountNumber: 7, Sequence: 42, GasPrice: big.NewRat(1, 250), TimeoutHeight: 120}},
		{"no timeout", TxParams{AccountNumber: 1, Sequence: 0, GasPrice: big.NewRat(2, 1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := s.SignPFB(context.Background(), anchorNS, []byte("payload"), tc.p)
			require.NoError(t, err)
			seq, err := TxSequence(tx)
			require.NoError(t, err)
			assert.Equal(t, tc.p.Sequence, seq)

			var raw cosmostx.TxRaw
			require.NoError(t, raw.Unmarshal(tx))
			var body cosmostx.TxBody
			require.NoError(t, body.Unmarshal(raw.BodyBytes))
			assert.Equal(t, tc.p.TimeoutHeight, body.TimeoutHeight)

			again, err := s.SignPFB(context.Background(), anchorNS, []byte("payload"), tc.p)
			require.NoError(t, err)
			assert.Equal(t, tx, again, "deterministic for one account state")
		})
	}
}

func TestAnchorSignerRefuses(t *testing.T) {
	s := testAnchorSigner(t)
	ctx := context.Background()
	_, err := s.SignPFB(ctx, anchorNS, []byte("x"), TxParams{Sequence: 1})
	require.Error(t, err, "no gas price")
	_, err = s.SignPFB(ctx, anchorNS, []byte("x"), TxParams{Sequence: 1, GasPrice: big.NewRat(-1, 1)})
	require.Error(t, err, "negative gas price")
	_, err = s.SignPFB(ctx, []byte{1, 2}, []byte("x"), TxParams{GasPrice: big.NewRat(1, 1)})
	require.Error(t, err, "bad namespace")
	_, err = s.SignPFF(ctx, []byte{0xff, 0xff}, TxParams{GasPrice: big.NewRat(1, 1)})
	require.Error(t, err, "not a MsgPayForFibre")
	_, err = NewAnchorSigner(nil, "anchor", "devnet-1")
	require.Error(t, err)
}

func TestTxSequenceAndPFFMessageRefuseForeignBytes(t *testing.T) {
	s := testAnchorSigner(t)
	pfb, err := s.SignPFB(context.Background(), anchorNS, []byte("payload"), TxParams{Sequence: 3, GasPrice: big.NewRat(1, 1)})
	require.NoError(t, err)
	_, err = PFFMessage(pfb)
	require.Error(t, err, "a PFB carries no MsgPayForFibre")

	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(pfb))
	var ai cosmostx.AuthInfo
	require.NoError(t, ai.Unmarshal(raw.AuthInfoBytes))
	ai.SignerInfos = append(ai.SignerInfos, ai.SignerInfos[0])
	raw.AuthInfoBytes, err = ai.Marshal()
	require.NoError(t, err)
	two, err := raw.Marshal()
	require.NoError(t, err)

	for name, tx := range map[string][]byte{"empty": nil, "garbage": {0xff, 0x01}, "two signers": two} {
		t.Run(name, func(t *testing.T) {
			_, err := TxSequence(tx)
			require.Error(t, err)
		})
	}
}

func FuzzTxSequence(f *testing.F) {
	s := testAnchorSigner(f)
	tx, err := s.SignPFB(context.Background(), anchorNS, []byte("payload"), TxParams{Sequence: 9, GasPrice: big.NewRat(1, 1)})
	require.NoError(f, err)
	f.Add(tx)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00, 0x12, 0x02, 0x12, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		seq, err := TxSequence(b)
		if err != nil {
			return
		}
		var raw cosmostx.TxRaw
		require.NoError(t, raw.Unmarshal(b))
		var ai cosmostx.AuthInfo
		require.NoError(t, ai.Unmarshal(raw.AuthInfoBytes))
		require.Len(t, ai.SignerInfos, 1)
		assert.Equal(t, ai.SignerInfos[0].Sequence, seq)
		_, _ = PFFMessage(b)
	})
}

func FuzzExpectedSequence(f *testing.F) {
	f.Add("account sequence mismatch, expected 5, got 3")
	f.Add("expected 18446744073709551616")
	f.Add("")
	f.Fuzz(func(t *testing.T, msg string) {
		ExpectedSequence(fmt.Errorf("%w: %s", ErrSequenceMismatch, msg))
		_, ok := ExpectedSequence(errors.New(msg))
		assert.False(t, ok, "only a sequence mismatch carries an expected sequence")
	})
}
