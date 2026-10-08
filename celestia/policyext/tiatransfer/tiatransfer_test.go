package tiatransfer_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/policy"
)

type vectors struct {
	Extractor struct {
		ID         string `json:"id"`
		ActionType string `json:"action_type"`
	} `json:"extractor"`
	Cases []struct {
		ID        string `json:"id"`
		ActionHex string `json:"action_hex"`
		Facts     struct {
			Kind, Asset, Amount, Recipient, Scale string
		}
		FactsCBORHex string `json:"facts_cbor_hex"`
	} `json:"cases"`
	Reject []struct {
		ID          string `json:"id"`
		ActionHex   string `json:"action_hex"`
		ExpectError string `json:"expect_error"`
	} `json:"reject"`
}

func load(t testing.TB) vectors {
	b, err := os.ReadFile("../../../spec/vectors/profiles/bank-send/tia_transfer_facts.json")
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func TestIdentity(t *testing.T) {
	v := load(t)
	x := tiatransfer.New()
	assert.Equal(t, v.Extractor.ID, x.ID())
	assert.Equal(t, v.Extractor.ActionType, x.ActionType())
}

func TestVectors(t *testing.T) {
	v := load(t)
	require.NotEmpty(t, v.Cases)
	require.Len(t, v.Reject, 15)
	x := tiatransfer.New()
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			action, err := hex.DecodeString(c.ActionHex)
			require.NoError(t, err)
			f, err := x.Extract(action)
			require.NoError(t, err)
			assert.Equal(t, c.Facts.Kind, f.Kind)
			assert.Equal(t, c.Facts.Asset, f.Asset)
			assert.Equal(t, c.Facts.Recipient, f.Recipient)
			assert.Equal(t, uint64(6), f.Scale)
			assert.Equal(t, c.Facts.Amount, hex.EncodeToString(f.Amount))
			enc, err := policy.EncodeFacts(&f)
			require.NoError(t, err)
			assert.Equal(t, c.FactsCBORHex, hex.EncodeToString(enc))
		})
	}
	for _, c := range v.Reject {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "ErrFactsInvalid", c.ExpectError)
			action, err := hex.DecodeString(c.ActionHex)
			require.NoError(t, err)
			f, err := x.Extract(action)
			require.Error(t, err)
			assert.Empty(t, f)
		})
	}
}

func TestDeterministicAndNoAliasing(t *testing.T) {
	v := load(t)
	action, err := hex.DecodeString(v.Cases[0].ActionHex)
	require.NoError(t, err)
	x := tiatransfer.New()
	a, err := x.Extract(action)
	require.NoError(t, err)
	a.Amount[0] ^= 0xff
	b, err := x.Extract(action)
	require.NoError(t, err)
	assert.Equal(t, v.Cases[0].Facts.Amount, hex.EncodeToString(b.Amount))
}

func FuzzExtract(f *testing.F) {
	v := load(f)
	for _, c := range v.Cases {
		b, err := hex.DecodeString(c.ActionHex)
		require.NoError(f, err)
		f.Add(b)
	}
	for _, c := range v.Reject {
		b, err := hex.DecodeString(c.ActionHex)
		require.NoError(f, err)
		f.Add(b)
	}
	x := tiatransfer.New()
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := x.Extract(b)
		if err != nil {
			return
		}
		require.NoError(t, got.Validate())
		again, err := x.Extract(b)
		require.NoError(t, err)
		require.Equal(t, got, again)
		// Accepted bytes are exactly the canonical action.
		a, err := bankaction.Decode(b)
		require.NoError(t, err)
		enc, err := bankaction.Encode(a)
		require.NoError(t, err)
		require.Equal(t, enc, b)
	})
}
