package ibkr_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

const (
	orderVectors = "../../../spec/vectors/profiles/dca-agent/ibkr_order.json"
	coidVectors  = "../../../spec/vectors/profiles/dca-agent/client_order_id.json"
)

func unhex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

type execCase struct {
	ID     string `json:"id"`
	Config struct {
		Account     string `json:"account"`
		MaxNotional string `json:"max_notional"`
	} `json:"config"`
	CBORHex string `json:"cbor_hex"`
	Expect  string `json:"expect_error"`
}

type orderFile struct {
	Cases    []struct{ ID, CBORHex string } `json:"-"`
	Executor []execCase                     `json:"executor"`
}

var sentinels = map[string]error{
	"ibkr.ErrRiskLimit":       ibkr.ErrRiskLimit,
	"ibkr.ErrAccountMismatch": ibkr.ErrAccountMismatch,
	"ibkrorder.ErrInvalid":    ibkrorder.ErrInvalid,
	"ibkrorder.ErrMalformed":  ibkrorder.ErrMalformed,
}

func TestVectorExecutorChecks(t *testing.T) {
	raw, err := os.ReadFile(orderVectors)
	require.NoError(t, err)
	var f orderFile
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Len(t, f.Executor, 9)

	for _, c := range f.Executor {
		t.Run(c.ID, func(t *testing.T) {
			max, err := strconv.ParseUint(c.Config.MaxNotional, 10, 64)
			require.NoError(t, err)
			cfg := ibkr.CheckConfig{Account: c.Config.Account, MaxNotional: max}
			action := unhex(t, c.CBORHex)

			o, err := ibkr.CheckOrder(cfg, action)
			if c.Expect == "" {
				require.NoError(t, err)
				require.NotNil(t, o)
				return
			}
			want, ok := sentinels[c.Expect]
			require.Truef(t, ok, "unknown sentinel %s", c.Expect)
			require.ErrorIs(t, err, want)
			assert.Nil(t, o)
		})
	}
}

// The order handed to the broker mapping comes from the authorized bytes
// only: bytes that are not the unique encoding are refused, never repaired.
func TestCheckOrderParsesAuthorizedBytesAsIs(t *testing.T) {
	raw, err := os.ReadFile(orderVectors)
	require.NoError(t, err)
	var f struct {
		Malformed []struct{ ID, CBORHex string } `json:"malformed"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	cfg := ibkr.CheckConfig{Account: "DU1234567"}
	for _, m := range f.Malformed {
		_, err := ibkr.CheckOrder(cfg, unhex(t, m.CBORHex))
		require.ErrorIsf(t, err, ibkrorder.ErrMalformed, m.ID)
	}
	_, err = ibkr.CheckOrder(cfg, nil)
	require.ErrorIs(t, err, ibkrorder.ErrMalformed)
}

func TestCheckOrderReturnsTheDecodedOrder(t *testing.T) {
	raw, err := os.ReadFile(orderVectors)
	require.NoError(t, err)
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			CBORHex string `json:"cbor_hex"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	for _, c := range f.Cases {
		b := unhex(t, c.CBORHex)
		want, err := ibkrorder.Decode(b)
		require.NoError(t, err)
		got, err := ibkr.CheckOrder(ibkr.CheckConfig{Account: want.Account}, b)
		require.NoError(t, err, c.ID)
		assert.Equal(t, want, got, c.ID)
	}
}

func TestCheckOrderPrecedence(t *testing.T) {
	// Vector bodies: malformed < invalid < account < risk limit.
	raw, err := os.ReadFile(orderVectors)
	require.NoError(t, err)
	var f orderFile
	require.NoError(t, json.Unmarshal(raw, &f))
	byID := map[string]execCase{}
	for _, c := range f.Executor {
		byID[c.ID] = c
	}
	invalid := byID["exec_invalid_before_account"]
	_, err = ibkr.CheckOrder(ibkr.CheckConfig{Account: "DU0000000", MaxNotional: 1}, unhex(t, invalid.CBORHex))
	require.ErrorIs(t, err, ibkrorder.ErrInvalid)
	assert.NotErrorIs(t, err, ibkr.ErrAccountMismatch)

	acct := byID["exec_account_before_risk"]
	_, err = ibkr.CheckOrder(ibkr.CheckConfig{Account: "DU7654321", MaxNotional: 1}, unhex(t, acct.CBORHex))
	require.ErrorIs(t, err, ibkr.ErrAccountMismatch)
	assert.NotErrorIs(t, err, ibkr.ErrRiskLimit)
}

func TestVectorClientOrderID(t *testing.T) {
	raw, err := os.ReadFile(coidVectors)
	require.NoError(t, err)
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			HashHex string `json:"commitment_hash_hex"`
			COID    string `json:"client_order_id"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Len(t, f.Cases, 14)

	lower64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	seen := map[string]string{}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var h commitment.Hash
			copy(h[:], unhex(t, c.HashHex))
			got := ibkr.ClientOrderID(h)
			assert.Equal(t, c.COID, got)
			assert.Regexp(t, lower64, got)
			assert.Equal(t, got, ibkr.ClientOrderID(h), "deterministic")
			if prev, dup := seen[got]; dup {
				t.Fatalf("%s and %s share a client order id", prev, c.ID)
			}
			seen[got] = c.ID
		})
	}
}

func TestClientOrderIDBoundaries(t *testing.T) {
	var zero, ones commitment.Hash
	for i := range ones {
		ones[i] = 0xff
	}
	assert.Equal(t, hex.EncodeToString(zero[:]), ibkr.ClientOrderID(zero))
	assert.Equal(t, hex.EncodeToString(ones[:]), ibkr.ClientOrderID(ones))
	assert.Len(t, ibkr.ClientOrderID(zero), 64)
}
