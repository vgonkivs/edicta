// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func settle(t testing.TB, cfg Config, tg Target, srcs ...Source) Report {
	t.Helper()
	rep, err := newTestChecker(t, cfg, srcs...).Settlement(context.Background(), tg)
	require.NoError(t, err)
	return rep
}

// l0 asks for one source's word, which only an explicit configuration does.
var l0 = Config{MinLevel: LevelNodeAttested}

func requireUnchecked(t testing.TB, rep Report, reason Reason) {
	t.Helper()
	require.Equal(t, StatusUnchecked, rep.Status, "err %v", rep.Err)
	require.Equal(t, reason, rep.Reason, "err %v", rep.Err)
	require.ErrorIs(t, rep.Err, reason.Sentinel())
}

func TestSettlementL0Executed(t *testing.T) {
	s := newScenario(t)
	rep := settle(t, l0, s.target, s.source("rpc.a"))
	require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
	assert.Equal(t, LevelNodeAttested, rep.Level)
	assert.Equal(t, OutcomeExecuted, rep.Outcome)
	assert.True(t, rep.HasBlock)
	assert.Equal(t, uint64(scnNumber), rep.Block)
	assert.Equal(t, s.blockHash, rep.BlockHash)
	assert.Equal(t, uint64(1), rep.Index)
	assert.Equal(t, uint64(scnTime), rep.BlockTime)
	assert.True(t, rep.HasPayer)
	assert.Equal(t, s.payer, rep.Payer)
	assert.Empty(t, rep.Warnings)
	require.Len(t, rep.Sources, 1)
	assert.Equal(t, SourceUsed, rep.Sources[0].Result)

	j := rep.JSON()
	assert.Equal(t, "eden-escrow-v1", j.Profile)
	assert.Equal(t, "L0", j.Level)
	assert.Equal(t, "executed", j.Outcome)
	require.NotNil(t, j.TransactionIndex)
	assert.Equal(t, uint64(1), *j.TransactionIndex)
	assert.Equal(t, "0x"+hex.EncodeToString(s.payer[:]), j.Payer)
}

func TestSettlementReverted(t *testing.T) {
	s := newScenario(t)
	s.receipt.Status, s.receipt.Logs = 0, nil
	src := s.source("rpc.a")
	rep := settle(t, l0, s.target, src)
	require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
	assert.Equal(t, OutcomeReverted, rep.Outcome)
}

func TestSettlementLevels(t *testing.T) {
	t.Run("two agreeing sources with the block reach L2", func(t *testing.T) {
		s := newScenario(t)
		rep := settle(t, Config{MinLevel: LevelReceiptProven}, s.target, s.source("a"), s.source("b"))
		require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
		assert.Equal(t, LevelReceiptProven, rep.Level)
		require.Len(t, rep.Sources, 2)
		assert.Equal(t, SourceUsed, rep.Sources[0].Result)
		assert.Equal(t, SourceAgree, rep.Sources[1].Result)
	})
	t.Run("block proof failing stays at L1", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		a.BlockTxsErr, b.BlockRcptErr = errors.New("down"), errors.New("down")
		rep := settle(t, Config{}, s.target, a, b)
		require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
		assert.Equal(t, LevelMultiSource, rep.Level)
	})
	t.Run("block proof failing with L2 required is unchecked", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		a.BlockRcpt[s.blockHash] = [][]byte{s.blockRcpt[1], s.blockRcpt[0]}
		b.BlockRcpt[s.blockHash] = [][]byte{s.blockRcpt[0]}
		rep := settle(t, Config{MinLevel: LevelReceiptProven}, s.target, a, b)
		requireUnchecked(t, rep, ReasonBlockProof)
	})
	t.Run("the second source's block can prove it", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		a.BlockTxs[s.blockHash] = [][]byte{s.blockTxs[0]}
		rep := settle(t, Config{MinLevel: LevelReceiptProven}, s.target, a, b)
		require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
		assert.Equal(t, LevelReceiptProven, rep.Level)
	})
	t.Run("L2 reports the proven header's time, not the used source's", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		h := a.Headers[s.blockHash]
		h.Time += 500 // same claimed hash, a lying timestamp
		a.Headers[s.blockHash] = h
		tg := s.target
		tg.Expires = scnTime + 100
		rep := settle(t, Config{MinLevel: LevelReceiptProven}, tg, a, b)
		require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
		assert.Equal(t, LevelReceiptProven, rep.Level)
		assert.Equal(t, uint64(scnTime), rep.BlockTime)
		assert.Equal(t, uint64(scnNumber), rep.Block)
		assert.Empty(t, rep.Warnings, "no warning from the unproven timestamp")
	})
	t.Run("one source below L1 is below the level", func(t *testing.T) {
		s := newScenario(t)
		b := s.source("b")
		b.Txs = nil
		rep := settle(t, Config{MinLevel: LevelMultiSource}, s.target, s.source("a"), b)
		requireUnchecked(t, rep, ReasonBelowLevel)
		assert.Equal(t, SourceUsed, rep.Sources[0].Result)
		assert.Equal(t, ReasonNotFound, rep.Sources[1].Reason)
	})
	t.Run("a source short of the depth makes it retry later", func(t *testing.T) {
		s := newScenario(t)
		b := s.source("b")
		b.HeadNum = scnNumber + 3
		rep := settle(t, Config{MinLevel: LevelMultiSource}, s.target, s.source("a"), b)
		requireUnchecked(t, rep, ReasonUnconfirmed)
	})
	t.Run("a header that hashes elsewhere is no L2", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		for _, src := range []*FakeSource{a, b} {
			h := src.Headers[s.blockHash]
			h.GasUsed++
			src.Headers[s.blockHash] = h
		}
		rep := settle(t, Config{}, s.target, a, b)
		require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
		assert.Equal(t, LevelMultiSource, rep.Level)
	})
	t.Run("an unknown header field is no L2", func(t *testing.T) {
		s := newScenario(t)
		a, b := s.source("a"), s.source("b")
		for _, src := range []*FakeSource{a, b} {
			h := src.Headers[s.blockHash]
			h.Unknown = []string{"slotNumber"}
			src.Headers[s.blockHash] = h
		}
		rep := settle(t, Config{MinLevel: LevelReceiptProven}, s.target, a, b)
		requireUnchecked(t, rep, ReasonBlockProof)
	})
}

func TestSettlementDisagree(t *testing.T) {
	s := newScenario(t)
	a, b := s.source("a"), s.source("b")
	// b names another block for the same transaction, consistently.
	other := s.blockHash
	other[0] ^= 1
	tx := b.Txs[s.R]
	tx.BlockHash = other
	b.Txs[s.R] = tx
	rc := b.Receipts[s.R]
	rc.BlockHash = other
	rc.Logs = []LogView{rc.Logs[0]}
	rc.Logs[0].BlockHash = other
	b.Receipts[s.R] = rc
	h := s.header
	h.Hash = other
	b.Headers[other] = h
	rep := settle(t, Config{}, s.target, a, b)
	requireUnchecked(t, rep, ReasonDisagree)
	assert.Equal(t, SourceUsed, rep.Sources[0].Result)
	assert.Equal(t, SourceSetAside, rep.Sources[1].Result)
	assert.Equal(t, ReasonDisagree, rep.Sources[1].Reason)
}

func TestSettlementSourceRules(t *testing.T) {
	tests := []struct {
		name   string
		mod    func(s *scenario, f *FakeSource)
		reason Reason
	}{
		{"chain id unavailable", func(_ *scenario, f *FakeSource) { f.ChainErr = errors.New("timeout") }, ReasonSourceUnavailable},
		{"other chain", func(_ *scenario, f *FakeSource) { f.Chain = 1 }, ReasonChainConfig},
		{"code unavailable", func(_ *scenario, f *FakeSource) { f.CodeErr = errors.New("timeout") }, ReasonSourceUnavailable},
		{"other code", func(_ *scenario, f *FakeSource) { f.Code[0] ^= 1 }, ReasonCodeMismatch},
		{"transaction unknown", func(_ *scenario, f *FakeSource) { f.Txs = nil }, ReasonNotFound},
		{"transaction unavailable", func(_ *scenario, f *FakeSource) { f.TxErr = errors.New("502") }, ReasonSourceUnavailable},
		{"served hash differs", func(s *scenario, f *FakeSource) {
			tx := f.Txs[s.R]
			tx.Hash[0] ^= 1
			f.Txs[s.R] = tx
		}, ReasonHashMismatch},
		{"lying field", func(s *scenario, f *FakeSource) {
			tx := f.Txs[s.R]
			tx.Nonce = []byte{0x08}
			f.Txs[s.R] = tx
		}, ReasonHashMismatch},
		{"non-canonical quantity", func(s *scenario, f *FakeSource) {
			tx := f.Txs[s.R]
			tx.Nonce = []byte{0x00, 0x07}
			f.Txs[s.R] = tx
		}, ReasonSourceUnavailable},
		{"unknown type", func(s *scenario, f *FakeSource) {
			tx := f.Txs[s.R]
			tx.Type = 0x7e
			f.Txs[s.R] = tx
		}, ReasonTxType},
		{"pending", func(s *scenario, f *FakeSource) {
			tx := f.Txs[s.R]
			tx.Included = false
			f.Txs[s.R] = tx
		}, ReasonUnconfirmed},
		{"below depth", func(_ *scenario, f *FakeSource) { f.HeadNum = scnNumber + DefaultConfirmDepth - 1 }, ReasonUnconfirmed},
		{"head behind the block", func(_ *scenario, f *FakeSource) { f.HeadNum = scnNumber - 1 }, ReasonUnconfirmed},
		{"head unavailable", func(_ *scenario, f *FakeSource) { f.HeadErr = errors.New("timeout") }, ReasonSourceUnavailable},
		{"no receipt", func(_ *scenario, f *FakeSource) { f.Receipts = nil }, ReasonDisagree},
		{"receipt unavailable", func(_ *scenario, f *FakeSource) { f.ReceiptErr = errors.New("timeout") }, ReasonSourceUnavailable},
		{"receipt in another block", func(s *scenario, f *FakeSource) {
			rc := f.Receipts[s.R]
			rc.BlockHash[0] ^= 1
			f.Receipts[s.R] = rc
		}, ReasonDisagree},
		{"receipt at another index", func(s *scenario, f *FakeSource) {
			rc := f.Receipts[s.R]
			rc.Index = 0
			f.Receipts[s.R] = rc
		}, ReasonDisagree},
		{"receipt of another transaction", func(s *scenario, f *FakeSource) {
			rc := f.Receipts[s.R]
			rc.TxHash[0] ^= 1
			f.Receipts[s.R] = rc
		}, ReasonDisagree},
		{"log of another address", func(s *scenario, f *FakeSource) {
			rc := f.Receipts[s.R]
			rc.Logs = []LogView{rc.Logs[0]}
			rc.Logs[0].Address[0] ^= 1
			f.Receipts[s.R] = rc
		}, ReasonLogMismatch},
		{"reverted with a log", func(s *scenario, f *FakeSource) {
			rc := f.Receipts[s.R]
			rc.Status = 0
			f.Receipts[s.R] = rc
		}, ReasonLogMismatch},
		{"no header", func(_ *scenario, f *FakeSource) { f.Headers = nil }, ReasonDisagree},
		{"header unavailable", func(_ *scenario, f *FakeSource) { f.HeaderErr = errors.New("timeout") }, ReasonSourceUnavailable},
		{"header of another number", func(s *scenario, f *FakeSource) {
			h := f.Headers[s.blockHash]
			h.Number++
			f.Headers[s.blockHash] = h
		}, ReasonDisagree},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			bad := s.source("bad")
			tc.mod(s, bad)

			rep := settle(t, l0, s.target, bad)
			requireUnchecked(t, rep, tc.reason)
			require.Len(t, rep.Sources, 1)
			assert.Equal(t, SourceSetAside, rep.Sources[0].Result)
			assert.Equal(t, tc.reason, rep.Sources[0].Reason)

			// The source is set aside and the next one decides.
			rep = settle(t, l0, s.target, bad, s.source("good"))
			require.Equal(t, StatusPass, rep.Status, "%v", rep.Err)
			assert.Equal(t, LevelNodeAttested, rep.Level)
			assert.Equal(t, SourceSetAside, rep.Sources[0].Result)
			assert.Equal(t, SourceUsed, rep.Sources[1].Result)
		})
	}
}

func TestSettlementReasonPrecedence(t *testing.T) {
	s := newScenario(t)
	notFound, down, shallow := s.source("a"), s.source("b"), s.source("c")
	notFound.Txs = nil
	down.ChainErr = errors.New("down")
	shallow.HeadNum = scnNumber
	t.Run("first source's reason", func(t *testing.T) {
		requireUnchecked(t, settle(t, Config{}, s.target, notFound, down), ReasonNotFound)
		requireUnchecked(t, settle(t, Config{}, s.target, down, notFound), ReasonSourceUnavailable)
	})
	t.Run("a source short of the depth wins", func(t *testing.T) {
		requireUnchecked(t, settle(t, Config{}, s.target, notFound, down, shallow), ReasonUnconfirmed)
	})
}

func TestSettlementWrongTxIsViolated(t *testing.T) {
	s := newScenario(t)
	// The claimed rail_ref names a validly signed transaction that is not
	// the authorized one: the vector's other nonce.
	var f signedFile
	loadVector(t, "signed.json", &f)
	var otherHex string
	for _, c := range f.ExactTx {
		if c.ID == "other_nonce" {
			otherHex = c.SignedHex
		}
	}
	other := unhex(t, otherHex)
	R := keccak256(other)
	tx := txViewOf(t, other)
	tx.Included, tx.BlockHash, tx.BlockNumber = true, s.blockHash, scnNumber

	first := s.source("a")
	first.Txs = nil
	liar := s.source("b")
	liar.Txs = map[[32]byte]TxView{R: tx}
	never := s.source("c")
	tg := s.target
	tg.RailRef = hexOf(R)
	rep := settle(t, Config{}, tg, first, liar, never)
	require.Equal(t, StatusViolated, rep.Status)
	assert.Equal(t, ReasonWrongTx, rep.Reason)
	require.ErrorIs(t, rep.Err, ErrWrongTx)
	require.ErrorIs(t, rep.Err, ErrViolation)
	assert.False(t, rep.HasPayer)
	require.Len(t, rep.Sources, 2, "no source is asked after the violation")
	assert.Equal(t, SourceSetAside, rep.Sources[0].Result)
	assert.Equal(t, SourceUsed, rep.Sources[1].Result)
	assert.Zero(t, never.TotalCalls())
	assert.Equal(t, "violated", rep.JSON().Status)
}

func TestSettlementTimeWarnings(t *testing.T) {
	s := newScenario(t)
	tg := s.target
	tg.Expires, tg.TRef = scnTime-1, scnTime+1
	rep := settle(t, l0, tg, s.source("a"))
	require.Equal(t, StatusPass, rep.Status)
	assert.Equal(t, []string{WarnAfterExpires, WarnBeforeReference}, rep.Warnings)

	tg.TRef = 0
	rep = settle(t, l0, tg, s.source("a"))
	assert.Equal(t, []string{WarnAfterExpires}, rep.Warnings)
}

func TestSettlementDA(t *testing.T) {
	s := newScenario(t)
	cfg := l0
	cfg.ApplyDefaults()
	da := &FakeDA{Height: 15152868, Included: true}
	c, err := NewChecker(cfg, []Source{s.source("a")}, da)
	require.NoError(t, err)
	rep, err := c.Settlement(context.Background(), s.target)
	require.NoError(t, err)
	require.NotNil(t, rep.DA)
	assert.Equal(t, []uint64{scnNumber}, da.Asked)
	j := rep.JSON()
	require.NotNil(t, j.DAIncluded)
	assert.Equal(t, uint64(15152868), j.DAIncluded.Height)

	da.Included, da.Height = false, 0
	rep, err = c.Settlement(context.Background(), s.target)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, rep.Status)
	assert.Nil(t, rep.JSON().DAIncluded)

	da.Err = errors.New("node down")
	rep, err = c.Settlement(context.Background(), s.target)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, rep.Status, "the DA report never changes the outcome")
}

func TestSettlementActionRefused(t *testing.T) {
	s := newScenario(t)
	src := s.source("a")
	chk := newTestChecker(t, Config{}, src)
	rep, err := chk.SettlementOfAction(context.Background(), []byte{0xa0}, s.railRef, 1, 1)
	require.NoError(t, err)
	requireUnchecked(t, rep, ReasonActionRefused)
	rep, err = chk.Settlement(context.Background(), Target{RailRef: s.railRef})
	require.NoError(t, err)
	requireUnchecked(t, rep, ReasonActionRefused)
	assert.Zero(t, src.TotalCalls())
}

func TestSettlementDevRowRefusedInProduction(t *testing.T) {
	if devBuild() {
		t.Skip("the dev row decodes in an edictadev build")
	}
	var f actionFile
	loadVector(t, "action.json", &f)
	for _, c := range f.Cases {
		if c.Build != "edictadev" {
			continue
		}
		s := newScenario(t)
		chk := newTestChecker(t, Config{}, s.source("a"))
		rep, err := chk.SettlementOfAction(context.Background(), unhex(t, c.CBORHex), s.railRef, 1, 1)
		require.NoError(t, err)
		requireUnchecked(t, rep, ReasonActionRefused)
	}
}

func TestSettlementCancelled(t *testing.T) {
	s := newScenario(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := newTestChecker(t, Config{}, s.source("a")).Settlement(ctx, s.target)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, StatusUnchecked, rep.Status)
}

func TestConfig(t *testing.T) {
	var c Config
	c.ApplyDefaults()
	require.NoError(t, c.ValidateBasic())
	assert.Equal(t, LevelMultiSource, c.MinLevel, "L1 unless L0 is configured")
	assert.Equal(t, DefaultMinSources, c.MinSources)
	assert.Equal(t, uint64(DefaultConfirmDepth), c.ConfirmDepth)
	assert.Equal(t, DefaultAwaitGrace, c.AwaitGrace)

	bad := []func(*Config){
		func(c *Config) { c.MinLevel = 0 },
		func(c *Config) { c.MinLevel = LevelReceiptProven + 1 },
		func(c *Config) { c.MinSources = 1 },
		func(c *Config) { c.MinSources = MaxSources + 1 },
		func(c *Config) { c.ConfirmDepth = MaxConfirmDepth + 1 },
		func(c *Config) { c.PollInterval = -time.Second },
		func(c *Config) { c.PollInterval = 2 * MaxPollInterval },
		func(c *Config) { c.AwaitGrace = -1 },
		func(c *Config) { c.AwaitGrace = MaxAwaitGrace + 1 },
	}
	for i, mod := range bad {
		cc := c
		mod(&cc)
		assert.Error(t, cc.ValidateBasic(), "case %d", i)
		_, err := NewChecker(cc, []Source{&FakeSource{SrcName: "a"}}, nil)
		assert.Error(t, err, "case %d", i)
	}

	_, err := NewChecker(c, nil, nil)
	assert.Error(t, err)
	_, err = NewChecker(c, []Source{&FakeSource{SrcName: "a"}, &FakeSource{SrcName: "a"}}, nil)
	assert.Error(t, err, "two sources on one host")
	_, err = NewChecker(c, []Source{&FakeSource{}}, nil)
	assert.Error(t, err, "unnamed source")
	_, err = NewChecker(c, []Source{nil}, nil)
	assert.Error(t, err)

	// Too few operators for the level is not a configuration error: the
	// checker still finds a wrong transaction, and its pass needs the level.
	s := newScenario(t)
	one, err := NewChecker(c, []Source{s.source("a")}, nil)
	require.NoError(t, err)
	rep, err := one.Settlement(context.Background(), s.target)
	require.NoError(t, err)
	requireUnchecked(t, rep, ReasonBelowLevel)

	for _, s := range []string{"L0", "L1", "L2"} {
		l, err := ParseLevel(s)
		require.NoError(t, err)
		assert.Equal(t, s, l.String())
	}
	_, err = ParseLevel("L3")
	assert.Error(t, err)
}

func TestReasonSentinelRoundTrip(t *testing.T) {
	for _, s := range reasonSentinels {
		assert.Equal(t, s.reason, ReasonOf(s.err))
		assert.Equal(t, s.err, s.reason.Sentinel())
	}
	assert.Equal(t, ReasonSourceUnavailable, ReasonOf(errors.New("anything")))
}

func hexOf(h [32]byte) string { return hex.EncodeToString(h[:]) }
