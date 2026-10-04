// Package bankvec loads the bank-send profile vectors for tests.
package bankvec

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "spec", "vectors", "profiles", "bank-send")
}

// Load decodes one vector file into v.
func Load(tb testing.TB, name string, v any) {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join(dir(), name))
	require.NoError(tb, err)
	require.NoError(tb, json.Unmarshal(raw, v))
}

// Hex decodes lower-case hex.
func Hex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

// U64 parses a decimal string uint.
func U64(tb testing.TB, s string) uint64 {
	tb.Helper()
	u, err := strconv.ParseUint(s, 10, 64)
	require.NoError(tb, err)
	return u
}

type Coin struct {
	Denom  string `json:"denom"`
	Amount string `json:"amount"`
}

type MsgInput struct {
	From   string `json:"from_address"`
	To     string `json:"to_address"`
	Amount Coin   `json:"amount"`
}

type MsgCase struct {
	ID      string   `json:"id"`
	HRP     string   `json:"hrp"`
	Input   MsgInput `json:"input"`
	FromHex string   `json:"from_hex"`
	ToHex   string   `json:"to_hex"`
	MsgHex  string   `json:"msg_hex"`
}

type MsgReject struct {
	ID         string `json:"id"`
	Desc       string `json:"description"`
	HRP        string `json:"hrp"`
	MsgHex     string `json:"msg_hex"`
	ExpectErr  string `json:"expect_error"`
	SDKAccepts bool   `json:"sdk_unmarshal_ok"`
}

type MsgFile struct {
	TypeURL string      `json:"type_url"`
	Cases   []MsgCase   `json:"cases"`
	Reject  []MsgReject `json:"reject"`
}

func Msgs(tb testing.TB) MsgFile {
	tb.Helper()
	var f MsgFile
	Load(tb, "msg_send.json", &f)
	return f
}

// Msg returns the canonical bytes and hrp of a msg_send case by id.
func Msg(tb testing.TB, id string) (msg []byte, hrp string) {
	tb.Helper()
	for _, c := range Msgs(tb).Cases {
		if c.ID == id {
			return Hex(tb, c.MsgHex), c.HRP
		}
	}
	require.FailNow(tb, "no msg case "+id)
	return nil, ""
}

type ActionInput struct {
	ChainID string `json:"chain_id"`
	MsgHex  string `json:"msg_hex"`
}

type ActionCase struct {
	ID      string      `json:"id"`
	MsgRef  string      `json:"msg_ref"`
	Input   ActionInput `json:"input"`
	CBORHex string      `json:"cbor_hex"`
	HashHex string      `json:"action_hash_hex"`
}

type CBORReject struct {
	ID        string `json:"id"`
	Desc      string `json:"description"`
	CBORHex   string `json:"cbor_hex"`
	ExpectErr string `json:"expect_error"`
}

type ActionFile struct {
	ActionType string       `json:"action_type"`
	Cases      []ActionCase `json:"cases"`
	Reject     []CBORReject `json:"reject"`
}

func Actions(tb testing.TB) ActionFile {
	tb.Helper()
	var f ActionFile
	Load(tb, "action.json", &f)
	return f
}

type Body struct {
	ID            string `json:"id"`
	MsgRef        string `json:"msg_ref"`
	HashHex       string `json:"commitment_hash_hex"`
	TimeoutHeight string `json:"timeout_height"`
	Memo          string `json:"memo"`
	BodyHex       string `json:"body_hex"`
}

type BodyReject struct {
	ID        string `json:"id"`
	Desc      string `json:"description"`
	MsgRef    string `json:"msg_ref"`
	HashHex   string `json:"commitment_hash_hex"`
	BodyHex   string `json:"body_hex"`
	ExpectErr string `json:"expect_error"`
}

type Signed struct {
	ID       string `json:"id"`
	BodyRef  string `json:"body_ref"`
	ChainID  string `json:"chain_id"`
	TxRawHex string `json:"tx_raw_hex"`
	TxHash   string `json:"tx_hash_hex"`
	RailRef  string `json:"rail_ref"`
}

type TxFile struct {
	Body   []Body       `json:"body"`
	Reject []BodyReject `json:"body_reject"`
	Signed []Signed     `json:"signed"`
}

func Txs(tb testing.TB) TxFile {
	tb.Helper()
	var f TxFile
	Load(tb, "tx.json", &f)
	return f
}

type Domain struct {
	ChainID string `json:"chain_id"`
	HRP     string `json:"hrp"`
	Denom   string `json:"denom"`
	Sender  string `json:"sender"`
}

type ExecCase struct {
	ID           string   `json:"id"`
	Desc         string   `json:"description"`
	Domain       Domain   `json:"domain"`
	Destinations []string `json:"destinations"`
	MaxAmount    string   `json:"max_amount"`
	ActionHex    string   `json:"action_hex"`
	ExpectErr    string   `json:"expect_error"`
}

type ExecFile struct {
	Cases []ExecCase `json:"cases"`
}

func Execs(tb testing.TB) ExecFile {
	tb.Helper()
	var f ExecFile
	Load(tb, "executor.json", &f)
	return f
}

type Header struct {
	Height string `json:"height"`
	TimeNs string `json:"time_ns"`
}

type Interval struct {
	ID      string   `json:"id"`
	Desc    string   `json:"description"`
	Headers []Header `json:"headers"`
	TauMs   string   `json:"tau_ms"`
}

type TimeoutCase struct {
	ID            string `json:"id"`
	HeadHeight    string `json:"head_height"`
	HeadTime      string `json:"head_time"`
	TauMs         string `json:"tau_ms"`
	Expires       string `json:"expires"`
	SkewS         string `json:"skew_s"`
	MaxBlocks     string `json:"max_timeout_blocks"`
	Now           string `json:"now"`
	TimeoutHeight string `json:"timeout_height"`
	ExpectErr     string `json:"expect_error"`
}

type TimeoutFile struct {
	Slowdown  string        `json:"slowdown_factor"`
	LimitMax  string        `json:"max_timeout_blocks_limit"`
	Intervals []Interval    `json:"interval"`
	Cases     []TimeoutCase `json:"cases"`
}

func Timeouts(tb testing.TB) TimeoutFile {
	tb.Helper()
	var f TimeoutFile
	Load(tb, "timeout_height.json", &f)
	return f
}

type PTObservation struct {
	Source     string `json:"source"`
	Price      string `json:"price"`
	ObservedAt string `json:"observed_at"`
	FetchedAt  string `json:"fetched_at"`
}

type PTInput struct {
	StrategyID string `json:"strategy_id"`
	Asset      struct {
		Feed    string `json:"feed"`
		AssetID string `json:"asset_id"`
		Quote   string `json:"quote"`
	} `json:"asset"`
	Observations []PTObservation `json:"observations"`
	Baseline     struct {
		Price string `json:"price"`
		SetAt string `json:"set_at"`
	} `json:"baseline"`
	ThresholdBP string `json:"threshold_bp"`
	Direction   string `json:"direction"`
	MoveBP      string `json:"move_bp"`
	Branch      struct {
		Name      string `json:"name"`
		ToAddress string `json:"to_address"`
		Amount    string `json:"amount"`
		Denom     string `json:"denom"`
	} `json:"branch"`
	Reason string `json:"reason"`
}

type PTCase struct {
	ID      string  `json:"id"`
	Input   PTInput `json:"input"`
	CBORHex string  `json:"cbor_hex"`
}

type PTConsistency struct {
	ID            string   `json:"id"`
	ContextHex    string   `json:"context_cbor_hex"`
	MsgRef        string   `json:"msg_ref"`
	HRP           string   `json:"hrp"`
	IssuedAt      string   `json:"issued_at"`
	ExpectedFails []string `json:"expect_failed"`
}

type PTFile struct {
	MediaType   string          `json:"media_type"`
	Cases       []PTCase        `json:"cases"`
	Reject      []CBORReject    `json:"reject"`
	Consistency []PTConsistency `json:"consistency"`
}

func Triggers(tb testing.TB) PTFile {
	tb.Helper()
	var f PTFile
	Load(tb, "price_trigger.json", &f)
	return f
}

type E2E struct {
	ID        string `json:"id"`
	NowGate   string `json:"now_gate"`
	ActionHex string `json:"action_hex"`
	Gate      struct {
		GateID      string   `json:"gate_id"`
		ActionTypes []string `json:"action_types"`
	} `json:"gate"`
	Params struct {
		SkewS string `json:"skew_s"`
	} `json:"params"`
	Commitment struct {
		Input struct {
			Action struct {
				Type string `json:"type"`
				Hash string `json:"hash"`
			} `json:"action"`
			ValidUntil string `json:"valid_until"`
			IssuedAt   string `json:"issued_at"`
		} `json:"input"`
		HashHex string `json:"commitment_hash_hex"`
	} `json:"commitment"`
	Context struct {
		MediaType     string   `json:"media_type"`
		CBORHex       string   `json:"cbor_hex"`
		ExpectedFails []string `json:"expect_failed"`
	} `json:"context"`
	Authorization struct {
		SignedHex string `json:"signed_authorization_hex"`
		Input     struct {
			Expires string `json:"expires"`
			GateID  string `json:"gate_id"`
		} `json:"input"`
	} `json:"authorization"`
	Executor struct {
		Now           string   `json:"now"`
		SkewS         string   `json:"skew_s"`
		Domain        Domain   `json:"domain"`
		MaxBlocks     string   `json:"max_timeout_blocks"`
		Headers       []Header `json:"headers"`
		TauMs         string   `json:"tau_ms"`
		HeadHeight    string   `json:"head_height"`
		HeadTime      string   `json:"head_time"`
		TimeoutHeight string   `json:"timeout_height"`
		Memo          string   `json:"memo"`
		BodyHex       string   `json:"body_hex"`
	} `json:"executor"`
}

func E2ECase(tb testing.TB) E2E {
	tb.Helper()
	var f struct {
		Cases []E2E `json:"cases"`
	}
	Load(tb, "e2e.json", &f)
	require.Len(tb, f.Cases, 1)
	return f.Cases[0]
}
