package fibrecert_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
)

const vectorPath = "../../spec/vectors/da/fibre_cert.json"

// num reads a JSON number that the vectors may write as a decimal string.
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseInt(strings.Trim(string(b), `"`), 10, 64)
	if err != nil {
		return err
	}
	*n = num(v)
	return nil
}

type certWant struct {
	SignaturesLen    int    `json:"signatures_len"`
	ValidatorsLen    int    `json:"validators_len"`
	Valid            int    `json:"valid"`
	Invalid          int    `json:"invalid"`
	Empty            int    `json:"empty"`
	InvalidAfterStop int    `json:"invalid_after_stop"`
	SignedPower      num    `json:"signed_power"`
	TotalPower       num    `json:"total_power"`
	Required         num    `json:"required"`
	SignedShare      string `json:"signed_share"`
	AtMostTwoThirds  bool   `json:"at_most_two_thirds"`
}

type expectWant struct {
	Verdict     string    `json:"verdict"`
	Rule        string    `json:"rule"`
	Fails       []string  `json:"fails"`
	Certificate *certWant `json:"certificate"`
}

type mutation struct {
	ID     string     `json:"id"`
	Target string     `json:"target"`
	Height num        `json:"height"`
	Offset num        `json:"offset"`
	Xor    string     `json:"xor"`
	Expect expectWant `json:"expect"`
}

type boundaryCase struct {
	ID         string `json:"id"`
	Validators []struct {
		PubKeyHex string `json:"pubkey_hex"`
		Power     num    `json:"power"`
	} `json:"validators"`
	SignaturesHex []string   `json:"signatures_hex"`
	Expect        expectWant `json:"expect"`
}

type thresholdRow struct {
	ID              string `json:"id"`
	Signed          num    `json:"signed"`
	Total           num    `json:"total"`
	Required        num    `json:"required"`
	Accept          bool   `json:"accept"`
	AtMostTwoThirds bool   `json:"at_most_two_thirds"`
}

type hexHeader struct {
	Height    num    `json:"height"`
	HeaderHex string `json:"header_hex"`
}

type vectorFile struct {
	Live struct {
		Raw struct {
			ChainID        string `json:"chain_id"`
			PFFTxHex       string `json:"pff_tx_hex"`
			HistoricalInfo struct {
				Hex string `json:"hex"`
			} `json:"historical_info"`
			CometValsets []struct {
				Height num    `json:"height"`
				Hex    string `json:"hex"`
			} `json:"cometbft_valsets"`
			Headers []hexHeader `json:"headers"`
		} `json:"raw"`
		Derived struct {
			Binding struct {
				ChainID       string `json:"chain_id"`
				NamespaceHex  string `json:"namespace_hex"`
				CommitmentHex string `json:"commitment_hex"`
				BlobSize      num    `json:"blob_size"`
			} `json:"binding"`
			MsgSigner string `json:"msg_signer"`
			Promise   struct {
				Height             num    `json:"height"`
				BlobSize           num    `json:"blob_size"`
				BlobVersion        num    `json:"blob_version"`
				CreationTimestamp  string `json:"creation_timestamp"`
				SignerPublicKeyHex string `json:"signer_public_key_hex"`
				OwnerSignatureHex  string `json:"owner_signature_hex"`
			} `json:"promise"`
			SignBytesHex        string   `json:"sign_bytes_hex"`
			ValidatorSigsHex    []string `json:"validator_signatures_hex"`
			OwnerSignatureValid bool     `json:"owner_signature_valid"`
			Validators          []struct {
				PubKeyHex string `json:"pubkey_hex"`
				Tokens    num    `json:"tokens"`
			} `json:"validators"`
			Certificate certWant `json:"certificate"`
			Cv7Matched  string   `json:"cv7_matched"`
		} `json:"derived"`
	} `json:"live"`
	Mutations           []mutation `json:"mutations"`
	UndetectedMutations []mutation `json:"undetected_mutations"`
	Boundary            struct {
		Cases []boundaryCase `json:"cases"`
	} `json:"boundary"`
	Threshold []thresholdRow `json:"threshold"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	require.NoError(t, err)
	var v vectorFile
	require.NoError(t, json.Unmarshal(raw, &v))
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func (v *vectorFile) pffTx(t *testing.T) []byte { return unhex(t, v.Live.Raw.PFFTxHex) }

func (v *vectorFile) header(t *testing.T, h num) []byte {
	t.Helper()
	for _, x := range v.Live.Raw.Headers {
		if x.Height == h {
			return unhex(t, x.HeaderHex)
		}
	}
	require.FailNowf(t, "missing header", "height %d", h)
	return nil
}

func (v *vectorFile) cometValset(t *testing.T, h num) []byte {
	t.Helper()
	for _, x := range v.Live.Raw.CometValsets {
		if x.Height == h {
			return unhex(t, x.Hex)
		}
	}
	require.FailNowf(t, "missing valset", "height %d", h)
	return nil
}

// inputs is everything the verifier feeds into the package for one case.
type inputs struct {
	tx, historicalInfo, promiseHeader, nextHeader, nextValset []byte
}

func (v *vectorFile) liveInputs(t *testing.T) inputs {
	t.Helper()
	h := v.Live.Derived.Promise.Height
	return inputs{
		tx:             v.pffTx(t),
		historicalInfo: unhex(t, v.Live.Raw.HistoricalInfo.Hex),
		promiseHeader:  v.header(t, h),
		nextHeader:     v.header(t, h+1),
		nextValset:     v.cometValset(t, h+1),
	}
}

func (v *vectorFile) binding(t *testing.T) fibrecert.Binding {
	t.Helper()
	b := v.Live.Derived.Binding
	var c [32]byte
	copy(c[:], unhex(t, b.CommitmentHex))
	return fibrecert.Binding{
		ChainID:    b.ChainID,
		Namespace:  unhex(t, b.NamespaceHex),
		Commitment: c,
		BlobSize:   uint32(b.BlobSize),
	}
}

func flip(t *testing.T, b []byte, m mutation) []byte {
	t.Helper()
	out := append([]byte(nil), b...)
	require.Less(t, int(m.Offset), len(out))
	out[m.Offset] ^= unhex(t, m.Xor)[0]
	return out
}

func (v *vectorFile) applyMutation(t *testing.T, in inputs, m mutation) inputs {
	t.Helper()
	p := v.Live.Derived.Promise.Height
	switch m.Target {
	case "pff_tx":
		in.tx = flip(t, in.tx, m)
	case "historical_info":
		in.historicalInfo = flip(t, in.historicalInfo, m)
	case "cometbft_valset":
		require.Equal(t, p+1, m.Height)
		in.nextValset = flip(t, in.nextValset, m)
	case "header":
		switch m.Height {
		case p:
			in.promiseHeader = flip(t, in.promiseHeader, m)
		case p + 1:
			in.nextHeader = flip(t, in.nextHeader, m)
		}
	default:
		require.FailNowf(t, "unknown target", "%s", m.Target)
	}
	return in
}

func parseOK(t *testing.T, tx []byte) fibrecert.PFF {
	t.Helper()
	f, ok, err := fibrecert.ParsePFF(tx)
	require.NoError(t, err)
	require.True(t, ok)
	return f
}

func assertReport(t *testing.T, want certWant, got fibrecert.Report) {
	t.Helper()
	require.Equal(t, int64(want.SignedPower), got.SignedPower)
	require.Equal(t, int64(want.TotalPower), got.TotalPower)
	require.Equal(t, int64(want.Required), got.Required)
	require.Equal(t, want.Valid, got.Valid)
	require.Equal(t, want.Invalid, got.Invalid)
	require.Equal(t, want.Empty, got.Empty)
	require.Equal(t, want.InvalidAfterStop, got.InvalidAfterStop)
	require.Equal(t, want.AtMostTwoThirds, got.AtMostTwoThirds)
	require.Equal(t, want.SignedShare, strconv.FormatFloat(got.Share(), 'f', 6, 64))
}

func edKey(t *testing.T, s string) ed25519.PublicKey {
	t.Helper()
	return ed25519.PublicKey(unhex(t, s))
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	require.NoError(t, err)
	return ts
}

func readLivePFF() ([]byte, error) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		return nil, err
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return hex.DecodeString(v.Live.Raw.PFFTxHex)
}
