// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type multiSourceFile struct {
	Revision      string   `json:"revision"`
	SourceResults []string `json:"source_results"`
	Cases         []struct {
		ID         string `json:"id"`
		MinLevel   string `json:"min_level"`
		MinSources string `json:"min_sources"`
		Phase      string `json:"phase"`
		Sources    []struct {
			Host     string `json:"host"`
			Operator string `json:"operator"`
			Result   string `json:"result"`
			Outcome  string `json:"outcome"`
			Binding  string `json:"binding"`
			Reason   string `json:"reason"`
		} `json:"sources"`
		Verify struct {
			Status  string `json:"status"`
			Level   string `json:"level"`
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
		} `json:"verify"`
		Await                   string `json:"await"`
		RecordAllowed           bool   `json:"record_allowed"`
		PaymentSignatureAllowed bool   `json:"payment_signature_allowed"`
		NonceReleaseAllowed     bool   `json:"nonce_release_allowed"`
	} `json:"cases"`
}

// setAsideBy makes an honest source fail one rule after it answered.
var setAsideBy = map[string]func(s *scenario, f *FakeSource){
	"settlement_code_mismatch": func(_ *scenario, f *FakeSource) { f.Code[0] ^= 1 },
	"settlement_chain_config":  func(_ *scenario, f *FakeSource) { f.Chain = 1 },
	"settlement_hash_mismatch": func(s *scenario, f *FakeSource) {
		tx := f.Txs[s.R]
		tx.Hash[0] ^= 1
		f.Txs[s.R] = tx
	},
}

// otherBlock serves the transaction in another block, consistently.
func otherBlock(s *scenario, f *FakeSource) {
	other := s.blockHash
	other[0] ^= 1
	tx := f.Txs[s.R]
	tx.BlockHash = other
	f.Txs[s.R] = tx
	rc := f.Receipts[s.R]
	rc.BlockHash = other
	rc.Logs = []LogView{rc.Logs[0]}
	rc.Logs[0].BlockHash = other
	f.Receipts[s.R] = rc
	h := s.header
	h.Hash = other
	f.Headers = map[[32]byte]HeaderView{other: h}
}

func reverted(s *scenario, f *FakeSource) {
	rc := f.Receipts[s.R]
	rc.Status, rc.Logs = 0, nil
	f.Receipts[s.R] = rc
}

// TestMultiSourceVectors builds one scripted source per vector source
// (labels B1, B2 for blocks, an r suffix or outcome reverted for a
// reverted receipt) and checks the report and Await's state against the
// combination table. The vectors do not model L2, so no source serves the
// whole block.
func TestMultiSourceVectors(t *testing.T) {
	var f multiSourceFile
	loadVector(t, "multi_source.json", &f)
	require.Equal(t, profileRevision(t), f.Revision)
	require.Equal(t, []string{string(StatePass), string(StateNotFound), string(StateUnconfirmed),
		string(StateUnavailable), string(StateSetAside)}, f.SourceResults)
	require.Len(t, f.Cases, 21)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			require.NotEqual(t, "violated", c.Verify.Status, "a source never makes a violation")
			s := newScenario(t)
			var srcs []Source
			for _, v := range c.Sources {
				src := s.source(v.Host)
				src.BlockTxsErr = errors.New("no full blocks")
				switch v.Result {
				case "pass":
					if strings.HasPrefix(v.Binding, "B2") {
						otherBlock(s, src)
					}
					if v.Outcome == "reverted" {
						require.True(t, v.Binding == "B1" || strings.HasSuffix(v.Binding, "r"), v.Binding)
						reverted(s, src)
					} else {
						require.Equal(t, "executed", v.Outcome)
						require.False(t, strings.HasSuffix(v.Binding, "r"))
					}
				case "not_found":
					src.Txs = nil
				case "unconfirmed":
					src.HeadNum = scnNumber + 1
				case "unavailable":
					src.ChainErr = errors.New("connection refused")
				case "set_aside":
					mod := setAsideBy[v.Reason]
					require.NotNil(t, mod, v.Reason)
					mod(s, src)
				default:
					t.Fatalf("result %q", v.Result)
				}
				srcs = append(srcs, &operated{FakeSource: src, op: v.Operator})
			}
			level, err := ParseLevel(c.MinLevel)
			require.NoError(t, err)
			minSources, err := strconv.Atoi(c.MinSources)
			require.NoError(t, err)
			cfg := Config{MinLevel: level, MinSources: minSources, PollInterval: time.Second}

			rep := settle(t, cfg, s.target, srcs...)
			assert.Equal(t, c.Verify.Status, string(rep.Status), "%v", rep.Err)
			if c.Verify.Status == "pass" {
				assert.Equal(t, c.Verify.Level, rep.Level.String())
				assert.Equal(t, c.Verify.Outcome, string(rep.Outcome))
			} else {
				assert.Equal(t, c.Verify.Reason, string(rep.Reason))
			}
			for i, sr := range rep.JSON().Sources {
				assert.Equal(t, c.Sources[i].Operator, sr.Operator)
			}

			chk := newTestChecker(t, cfg, srcs...)
			untilPassed := c.Phase == "until_passed"
			require.True(t, untilPassed || c.Phase == "polling", c.Phase)
			got := chk.poll(context.Background(), s.target, chk.srcs, untilPassed)
			assert.Equal(t, c.Await, string(got.State))
			assert.Equal(t, c.RecordAllowed, got.RecordAllowed())
			assert.Equal(t, c.PaymentSignatureAllowed, got.PaymentSignatureAllowed())
			assert.Equal(t, c.NonceReleaseAllowed, got.NonceReleaseAllowed())

			// Await ends in the same state whenever the poll is final.
			if untilPassed || got.State == AwaitExecuted || got.State == AwaitReverted {
				clk := &fakeClock{now: time.Unix(scnTime, 0)}
				clk.install(chk)
				until := clk.now
				if !untilPassed {
					until = until.Add(time.Minute)
				}
				rep, err := chk.Await(context.Background(), s.target, until)
				assert.Equal(t, c.Await, string(rep.State))
				assert.Equal(t, rep.RecordAllowed(), err == nil)
				assert.Equal(t, c.NonceReleaseAllowed, errors.Is(err, ErrNotFound))
				assert.Zero(t, clk.sleeps)
			}
		})
	}
}

// Sources without a label count by host; one label on two hosts counts once.
func TestOperatorLabels(t *testing.T) {
	s := newScenario(t)
	a, b := s.source("a.example"), s.source("b.example")
	assert.Equal(t, "a.example", OperatorOf(a))
	assert.Equal(t, 2, Operators([]Source{a, b}))
	la, lb := &operated{FakeSource: a, op: "one"}, &operated{FakeSource: b, op: "one"}
	assert.Equal(t, 1, Operators([]Source{la, lb}))
	assert.Equal(t, "b.example", OperatorOf(&operated{FakeSource: b}), "an empty label is the host")

	rep := settle(t, Config{}, s.target, la, lb)
	requireUnchecked(t, rep, ReasonBelowLevel)
	rep = settle(t, Config{}, s.target, a, b)
	require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
	assert.GreaterOrEqual(t, rep.Level, LevelMultiSource)
}

// The report names the deposit whenever the action decodes, and each
// source's operator and answer.
func TestReportDepositAndSourceResults(t *testing.T) {
	s := newScenario(t)
	nf := s.source("nf")
	nf.Txs = nil
	down := s.source("down")
	down.ChainErr = errors.New("down")
	shallow := s.source("shallow")
	shallow.HeadNum = scnNumber
	code := s.source("code")
	code.Code[0] ^= 1
	rep := settle(t, Config{}, s.target, s.source("a"), nf, down, shallow, code)
	j := rep.JSON()
	require.NotNil(t, j.Deposit)
	assert.Equal(t, s.action.DepositView(), *j.Deposit)
	var results []string
	for _, sr := range j.Sources {
		results = append(results, sr.Result)
		assert.Equal(t, sr.Name, sr.Operator)
	}
	assert.Equal(t, []string{"used", "not_found", "unavailable", "unconfirmed", "set_aside"}, results)

	tg := s.target
	tg.RailRef = "0x" + s.railRef
	assert.NotNil(t, settle(t, Config{}, tg, s.source("a")).Deposit, "decoded action, malformed rail_ref")
	refused, err := newTestChecker(t, Config{}, s.source("a")).SettlementOfAction(context.Background(), []byte{0xa0}, s.railRef, 1, 1)
	require.NoError(t, err)
	assert.Nil(t, refused.Deposit)
}
