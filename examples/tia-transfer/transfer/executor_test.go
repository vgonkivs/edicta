package transfer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/test/bankvec"
)

var errCrash = errors.New("injected crash")

func TestActionTypeMatchesTheProfile(t *testing.T) {
	assert.Equal(t, bankaction.ActionType, transfer.ActionType)
}

func TestSentinelsAreTheProfileSentinels(t *testing.T) {
	assert.Same(t, bankaction.ErrChainMismatch, transfer.ErrChainMismatch)
	assert.Same(t, bankaction.ErrSenderMismatch, transfer.ErrSenderMismatch)
	assert.Same(t, bankaction.ErrDenomMismatch, transfer.ErrDenomMismatch)
	assert.Same(t, bankaction.ErrDestination, transfer.ErrDestination)
	assert.Same(t, bankaction.ErrRiskLimit, transfer.ErrRiskLimit)
	assert.Same(t, bankaction.ErrExpired, transfer.ErrExpired)
}

func TestExecuteHappyPath(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 2
	h := chash(1)
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, h, action), action, testSalt)
	require.NoError(t, err)

	require.Equal(t, 1, r.rail.signCalls())
	assert.Equal(t, []string{chainID}, r.rail.chainIDs, "the chain id comes from the action")
	require.NotEmpty(t, r.rail.broadcasts)
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
	assert.Equal(t, headH+2, res.Height)
	assert.Zero(t, res.Code)

	a, err := bankaction.Decode(action)
	require.NoError(t, err)
	th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
	require.NoError(t, err, "body is Body(msg, commitment_hash, timeout_height)")
	assert.Greater(t, th, headH)
	assert.Contains(t, string(r.rail.bodies[0]), hex.EncodeToString(h[:]), "memo is the commitment hash")

	assert.Equal(t, []string{"begin", "prepare", "finish"}, r.store.calls())
	for _, b := range r.rail.broadcasts {
		assert.Equal(t, r.rail.signed[0], b)
	}
}

func TestPersistsBeforeBroadcast(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 1
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.NoError(t, err)
	assert.Zero(t, r.store.broadcastsAtPrepare, "Prepare is durable before the first Broadcast")
}

func TestPrepareFailureMeansNoBroadcast(t *testing.T) {
	r := newRig(t)
	r.store.failPrep = errCrash
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.ErrorIs(t, err, errCrash)
	assert.Zero(t, r.rail.broadcastCalls())
}

func TestTimeoutHeightFromExpiry(t *testing.T) {
	tests := []struct {
		name    string
		expires uint64
		mod     func(*transfer.Config)
		want    func(t *testing.T) uint64
	}{
		{
			name: "from expires minus skew with a doubled block interval", expires: nowUnix + 600,
			want: func(t *testing.T) uint64 {
				th, err := bankaction.TimeoutHeight(bankaction.TimeoutInput{
					HeadHeight: headH, HeadTime: nowUnix, TauMs: blockS * 1000,
					Expires: nowUnix + 600, SkewS: skew, MaxBlocks: 200, Now: nowUnix,
				})
				require.NoError(t, err)
				return th
			},
		},
		{
			name: "capped at the default 200 blocks", expires: nowUnix + 7200,
			want: func(*testing.T) uint64 { return headH + 200 },
		},
		{
			name: "capped at the configured blocks", expires: nowUnix + 7200,
			mod:  func(c *transfer.Config) { c.MaxTimeoutBlocks = 20 },
			want: func(*testing.T) uint64 { return headH + 20 },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mods []func(*transfer.Config)
			if tc.mod != nil {
				mods = append(mods, tc.mod)
			}
			r := newRig(t, mods...)
			r.rail.includeAt = headH + 1
			h := chash(2)
			action := actionBytes(t, chainID, validMsg())
			auth := goodAuth(t, h, action, func(a *commitment.Authorization) { a.Expires = tc.expires })
			_, err := r.exec.Execute(bg, auth, action, testSalt)
			require.NoError(t, err)
			a, err := bankaction.Decode(action)
			require.NoError(t, err)
			th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
			require.NoError(t, err)
			assert.Equal(t, tc.want(t), th)
		})
	}
}

func TestTooCloseToExpiryAbandonsWithoutSigning(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*fakeRail)
	}{
		{"slow blocks leave no block before expiry", func(r *fakeRail) { r.interval = 10 * time.Minute }},
		{"valid for less than one block", func(r *fakeRail) {}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.mod(r.rail)
			action := actionBytes(t, chainID, validMsg())
			exp := nowUnix + 600
			if i == 1 {
				exp = nowUnix + skew + 1 // still valid, but under one block of budget
			}
			auth := goodAuth(t, chash(3), action, func(a *commitment.Authorization) { a.Expires = exp })
			_, err := r.exec.Execute(bg, auth, action, testSalt)
			require.ErrorIs(t, err, transfer.ErrExpired)
			assert.Zero(t, r.rail.signCalls())
			assert.Zero(t, r.rail.broadcastCalls())
			assert.True(t, r.store.has("abandon"))
		})
	}
}

func TestRejectionsMakeNoBroadcast(t *testing.T) {
	good := actionBytes(t, chainID, validMsg())
	other := actionBytes(t, "other-1", validMsg())
	badMsg := actionBytes(t, chainID, bankmsg.MsgSend{From: otherDst, To: receiver, Denom: denom, Amount: 1})
	badDenom := actionBytes(t, chainID, bankmsg.MsgSend{From: sender, To: receiver, Denom: "uatom", Amount: 1})

	tests := []struct {
		name   string
		mod    func(*transfer.Config)
		auth   func(t *testing.T) []byte
		action []byte
		want   error
	}{
		{"signed by another key", nil,
			func(t *testing.T) []byte { return authorize(t, seedKey(8), chash(1), bankaction.ActionType, good) },
			good, commitment.ErrSignatureInvalid},
		{"another gate id", nil,
			func(t *testing.T) []byte {
				return goodAuth(t, chash(1), good, func(a *commitment.Authorization) { a.GateID = "gate-other" })
			},
			good, commitment.ErrScopeMismatch},
		{"another action type", nil,
			func(t *testing.T) []byte { return authorize(t, seedKey(7), chash(1), "application/x-other", good) },
			good, commitment.ErrActionMismatch},
		{"tampered action bytes", nil,
			func(t *testing.T) []byte { return goodAuth(t, chash(1), good) },
			append(append([]byte(nil), good...), 0), commitment.ErrActionMismatch},
		{"expired authorization", nil,
			func(t *testing.T) []byte {
				return goodAuth(t, chash(1), good, func(a *commitment.Authorization) { a.Expires = nowUnix + skew })
			},
			good, commitment.ErrExpired},
		{"garbage authorization", nil,
			func(*testing.T) []byte { return []byte{0xff, 0x00} }, good, nil},
		{"action for another chain", nil, nil, other, transfer.ErrChainMismatch},
		{"sender is not the executor account", nil, nil, badMsg, transfer.ErrSenderMismatch},
		{"denom differs", nil, nil, badDenom, transfer.ErrDenomMismatch},
		{"destination not allowed",
			func(c *transfer.Config) { c.Destinations = []string{otherDst} }, nil, good, transfer.ErrDestination},
		{"amount above the limit",
			func(c *transfer.Config) { c.MaxAmount = 999 }, nil, good, transfer.ErrRiskLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mods []func(*transfer.Config)
			if tc.mod != nil {
				mods = append(mods, tc.mod)
			}
			r := newRig(t, mods...)
			auth := tc.auth
			if auth == nil {
				auth = func(t *testing.T) []byte { return goodAuth(t, chash(1), tc.action) }
			}
			_, err := r.exec.Execute(bg, auth(t), tc.action, testSalt)
			require.Error(t, err)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}
			assert.Zero(t, r.rail.signCalls())
			assert.Zero(t, r.rail.broadcastCalls())
			assert.False(t, r.store.has("prepare"))
		})
	}
}

func TestSpecVectorsOfTheExecutor(t *testing.T) {
	want := map[string]error{
		"bankaction.ErrMalformed":    bankaction.ErrMalformed,
		"bankmsg.ErrMalformed":       bankmsg.ErrMalformed,
		"transfer.ErrChainMismatch":  transfer.ErrChainMismatch,
		"transfer.ErrDenomMismatch":  transfer.ErrDenomMismatch,
		"transfer.ErrDestination":    transfer.ErrDestination,
		"transfer.ErrRiskLimit":      transfer.ErrRiskLimit,
		"transfer.ErrSenderMismatch": transfer.ErrSenderMismatch,
	}
	for _, c := range bankvec.Execs(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			r := newRig(t, func(cfg *transfer.Config) {
				cfg.Destinations = c.Destinations
				cfg.MaxAmount = bankvec.U64(t, c.MaxAmount)
			})
			r.rail.includeAt = headH + 1
			dom := transfer.Domain{ChainID: c.Domain.ChainID, Denom: c.Domain.Denom, HRP: c.Domain.HRP, Sender: c.Domain.Sender}
			e, err := transfer.NewExecutor(r.cfg, dom, r.rail, r.store, r.clock)
			require.NoError(t, err)
			action := bankvec.Hex(t, c.ActionHex)
			_, err = e.Execute(bg, goodAuth(t, chash(9), action), action, testSalt)
			if c.ExpectErr == "" {
				require.NoError(t, err)
				assert.Equal(t, 1, r.rail.signCalls())
				return
			}
			sentinel, ok := want[c.ExpectErr]
			require.True(t, ok, c.ExpectErr)
			require.ErrorIs(t, err, sentinel)
			assert.Zero(t, r.rail.broadcastCalls())
		})
	}
}

func TestSignFailuresMakeNoBroadcast(t *testing.T) {
	t.Run("signer error abandons", func(t *testing.T) {
		r := newRig(t)
		r.rail.signErr = errCrash
		action := actionBytes(t, chainID, validMsg())
		_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
		require.ErrorIs(t, err, errCrash)
		assert.Zero(t, r.rail.broadcastCalls())
		assert.True(t, r.store.has("abandon"))
		assert.False(t, r.store.has("prepare"))
	})
	t.Run("signed body differs from the built body", func(t *testing.T) {
		r := newRig(t)
		r.rail.badBody = true
		action := actionBytes(t, chainID, validMsg())
		_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
		require.Error(t, err)
		assert.Zero(t, r.rail.broadcastCalls())
		assert.False(t, r.store.has("prepare"))
	})
	t.Run("head unavailable", func(t *testing.T) {
		r := newRig(t)
		r.rail.headErr = errCrash
		action := actionBytes(t, chainID, validMsg())
		_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
		require.ErrorIs(t, err, errCrash)
		assert.Zero(t, r.rail.signCalls())
		assert.Zero(t, r.rail.broadcastCalls())
	})
	t.Run("store refuses to begin", func(t *testing.T) {
		r := newRig(t)
		r.store.failBegin = errCrash
		action := actionBytes(t, chainID, validMsg())
		_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
		require.ErrorIs(t, err, errCrash)
		assert.Zero(t, r.rail.signCalls())
		assert.Zero(t, r.rail.broadcastCalls())
	})
}

func TestRebroadcastsTheSameBytesUntilIncluded(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 5
	r.rail.broadcastErrs = []error{errCrash}
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.NoError(t, err)
	assert.Equal(t, 1, r.rail.signCalls(), "one signature for the decision")
	assert.Greater(t, r.rail.broadcastCalls(), 1)
	for _, b := range r.rail.broadcasts {
		assert.Equal(t, r.rail.signed[0], b, "every send is byte-identical")
	}
	assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
	for _, w := range r.clock.waited() {
		assert.Equal(t, 10*time.Second, w, "default rebroadcast interval")
	}
}

func TestRebroadcastIntervalIsConfigurable(t *testing.T) {
	r := newRig(t, func(c *transfer.Config) { c.RebroadcastEvery = 3 * time.Second })
	r.rail.includeAt = headH + 3
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.NoError(t, err)
	require.NotEmpty(t, r.clock.waited())
	for _, w := range r.clock.waited() {
		assert.Equal(t, 3*time.Second, w)
	}
}

func TestHandsOffAfterTimeoutHeight(t *testing.T) {
	r := newRig(t)
	action := actionBytes(t, chainID, validMsg())
	h := chash(4)
	_, err := r.exec.Execute(bg, goodAuth(t, h, action), action, testSalt)
	require.ErrorIs(t, err, transfer.ErrHandedOff)

	a, err := bankaction.Decode(action)
	require.NoError(t, err)
	th, err := bankaction.CheckBody(a, h, r.rail.bodies[0])
	require.NoError(t, err)

	assert.Equal(t, 1, r.rail.signCalls(), "no new tx for this decision")
	require.Greater(t, r.rail.broadcastCalls(), 1)
	for i, bh := range r.rail.bcastHeights {
		assert.LessOrEqual(t, bh, th, "broadcast %d after timeout_height", i)
		assert.Equal(t, r.rail.signed[0], r.rail.broadcasts[i])
	}
	last := len(r.rail.statusHeight) - 1
	require.GreaterOrEqual(t, last, 0)
	assert.Greater(t, r.rail.statusHeight[last], th+3, "final status after timeout_height plus the lag margin")
	require.GreaterOrEqual(t, last, 1)
	assert.Greater(t, r.rail.statusHeight[last-1], th+3, "a second status check confirmed it")
	assert.Greater(t, r.rail.statusTimes[last], r.rail.statusTimes[last-1], "the second check is delayed")
	assert.True(t, r.store.has("handoff"))
	assert.False(t, r.store.has("finish"))
}

func TestFailedOnChainIsTerminal(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 1
	r.rail.code = 5
	action := actionBytes(t, chainID, validMsg())
	res, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.ErrorIs(t, err, transfer.ErrFailedOnChain)
	assert.Equal(t, uint32(5), res.Code)
	assert.Equal(t, 1, r.rail.signCalls())
	assert.True(t, r.store.has("finish"))
}

func TestDuplicateAuthorizationExecutesOnce(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 1
	action := actionBytes(t, chainID, validMsg())
	auth := goodAuth(t, chash(1), action)
	first, err := r.exec.Execute(bg, auth, action, testSalt)
	require.NoError(t, err)
	n := r.rail.broadcastCalls()

	again, err := r.exec.Execute(bg, auth, action, testSalt)
	require.ErrorIs(t, err, transfer.ErrSeen)
	assert.Equal(t, first, again, "the stored outcome comes back")
	assert.Equal(t, 1, r.rail.signCalls())
	assert.Equal(t, n, r.rail.broadcastCalls())

	t.Run("a second authorization for the same commitment hash", func(t *testing.T) {
		auth2 := goodAuth(t, chash(1), action, func(a *commitment.Authorization) { a.Expires = nowUnix + 500 })
		_, err := r.exec.Execute(bg, auth2, action, testSalt)
		require.ErrorIs(t, err, transfer.ErrSeen)
		assert.Equal(t, 1, r.rail.signCalls())
	})
}

func TestConcurrentDuplicatesSignOnce(t *testing.T) {
	r := newRig(t)
	r.rail.includeAt = headH + 3
	action := actionBytes(t, chainID, validMsg())
	auth := goodAuth(t, chash(1), action)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.exec.Execute(bg, auth, action, testSalt)
			if err != nil {
				assert.ErrorIs(t, err, transfer.ErrSeen)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, r.rail.signCalls())
	r.rail.mu.Lock()
	defer r.rail.mu.Unlock()
	for _, b := range r.rail.broadcasts {
		assert.Equal(t, r.rail.signed[0], b)
	}
}

func TestResumeAfterCrash(t *testing.T) {
	h := chash(6)
	action := actionBytes(t, chainID, validMsg())

	crashAtFirstBroadcast := func(r *rig) (context.Context, func()) {
		ctx, cancel := context.WithCancel(bg)
		r.rail.onBroadcast = func(n int) {
			if n == 1 {
				cancel()
			}
		}
		return ctx, cancel
	}

	t.Run("prepared, crashed on the first broadcast", func(t *testing.T) {
		r := newRig(t)
		r.rail.includeAt = headH + 3
		ctx, cancel := crashAtFirstBroadcast(r)
		defer cancel()
		_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
		require.Error(t, err)
		first := r.rail.signed[0]

		r.rail.onBroadcast = nil
		e2 := r.restart()
		res, err := e2.Resume(bg, h)
		require.NoError(t, err)
		assert.Equal(t, 1, r.rail.signCalls(), "never signs a second tx for the decision")
		assert.Equal(t, sha256.Sum256(first), res.TxHash)
		for _, b := range r.rail.broadcasts {
			assert.Equal(t, first, b)
		}
	})

	t.Run("broadcast, crashed before finish: found by hash", func(t *testing.T) {
		r := newRig(t)
		r.rail.includeAt = headH + 1
		r.store.failFinish = errCrash
		_, err := r.exec.Execute(bg, goodAuth(t, h, action), action, testSalt)
		require.Error(t, err)
		sent := r.rail.broadcastCalls()

		e2 := r.restart()
		res, err := e2.Resume(bg, h)
		require.NoError(t, err)
		assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
		assert.Contains(t, r.rail.statusHashes, res.TxHash, "looked up by hash")
		assert.Equal(t, 1, r.rail.signCalls())
		assert.GreaterOrEqual(t, r.rail.broadcastCalls(), sent)
	})

	t.Run("begun but never prepared is abandoned, not signed", func(t *testing.T) {
		r := newRig(t)
		r.store.failPrep = errCrash
		_, err := r.exec.Execute(bg, goodAuth(t, h, action), action, testSalt)
		require.Error(t, err)
		r.store.failPrep = nil
		signs := r.rail.signCalls()

		e2 := r.restart()
		_, err = e2.Resume(bg, h)
		require.Error(t, err)
		assert.Equal(t, signs, r.rail.signCalls(), "Resume never signs")
		assert.Zero(t, r.rail.broadcastCalls())
		assert.True(t, r.store.has("abandon"))
	})

	t.Run("after expiry Resume only looks, never broadcasts", func(t *testing.T) {
		r := newRig(t)
		ctx, cancel := crashAtFirstBroadcast(r)
		defer cancel()
		_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
		require.Error(t, err)
		r.rail.onBroadcast = nil
		sent := r.rail.broadcastCalls()
		r.clock.set(nowUnix + 600)

		_, err = r.restart().Resume(bg, h)
		require.ErrorIs(t, err, transfer.ErrHandedOff)
		assert.Equal(t, sent, r.rail.broadcastCalls())
		assert.Equal(t, 1, r.rail.signCalls())
		assert.True(t, r.store.has("handoff"))
	})

	t.Run("after expiry a committed tx is still reported", func(t *testing.T) {
		r := newRig(t)
		r.rail.includeAt = headH + 1
		r.rail.frozen = false
		ctx, cancel := crashAtFirstBroadcast(r)
		defer cancel()
		_, err := r.exec.Execute(ctx, goodAuth(t, h, action), action, testSalt)
		require.Error(t, err)
		r.rail.onBroadcast = nil
		r.clock.set(nowUnix + 900)

		res, err := r.restart().Resume(bg, h)
		require.NoError(t, err)
		assert.Equal(t, sha256.Sum256(r.rail.signed[0]), res.TxHash)
		assert.Equal(t, 1, r.rail.signCalls())
	})

	t.Run("finished record returns the stored outcome", func(t *testing.T) {
		r := newRig(t)
		r.rail.includeAt = headH + 1
		res, err := r.exec.Execute(bg, goodAuth(t, h, action), action, testSalt)
		require.NoError(t, err)
		n := r.rail.broadcastCalls()
		again, err := r.restart().Resume(bg, h)
		require.NoError(t, err)
		assert.Equal(t, res, again)
		assert.Equal(t, n, r.rail.broadcastCalls())
	})

	t.Run("unknown commitment", func(t *testing.T) {
		r := newRig(t)
		_, err := r.exec.Resume(bg, chash(0x77))
		require.Error(t, err)
		assert.Zero(t, r.rail.signCalls())
		assert.Zero(t, r.rail.broadcastCalls())
	})
}

func TestRecordRequest(t *testing.T) {
	r := newRig(t)
	h := chash(8)
	pub, sig, err := r.exec.RecordRequest(h, "ABCD")
	require.NoError(t, err)
	assert.Equal(t, seedKey(5).Public().(ed25519.PublicKey), pub)
	require.NoError(t, commitment.VerifyRecordRequest(h, gateID, "ABCD", pub, sig))
	assert.Error(t, commitment.VerifyRecordRequest(h, "gate-other", "ABCD", pub, sig), "bound to the gate id")
	assert.Error(t, commitment.VerifyRecordRequest(h, gateID, "ABCE", pub, sig), "bound to the rail ref")

	t.Run("without a sign key", func(t *testing.T) {
		r := newRig(t, func(c *transfer.Config) { c.SignKey = nil })
		_, _, err := r.exec.RecordRequest(h, "ABCD")
		require.Error(t, err)
	})
}

func TestNewExecutorValidation(t *testing.T) {
	dom := transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender}
	c := newClock()
	rail := newRail(c)
	st := transfer.NewMemStore()
	base := transfer.Config{GatePubKey: gatePub(), GateID: gateID, SkewS: skew, SignKey: seedKey(5)}

	tests := []struct {
		name string
		mod  func(*transfer.Config, *transfer.Domain)
	}{
		{"short gate key", func(c *transfer.Config, _ *transfer.Domain) { c.GatePubKey = c.GatePubKey[:5] }},
		{"empty gate id", func(c *transfer.Config, _ *transfer.Domain) { c.GateID = "" }},
		{"skew above 300", func(c *transfer.Config, _ *transfer.Domain) { c.SkewS = 301 }},
		{"timeout blocks above the profile cap", func(c *transfer.Config, _ *transfer.Domain) {
			c.MaxTimeoutBlocks = bankaction.MaxTimeoutBlocks + 1
		}},
		{"negative rebroadcast interval", func(c *transfer.Config, _ *transfer.Domain) { c.RebroadcastEvery = -1 }},
		{"bad sign key length", func(c *transfer.Config, _ *transfer.Domain) { c.SignKey = c.SignKey[:5] }},
		{"empty chain id", func(_ *transfer.Config, d *transfer.Domain) { d.ChainID = "" }},
		{"empty sender", func(_ *transfer.Config, d *transfer.Domain) { d.Sender = "" }},
		{"empty denom", func(_ *transfer.Config, d *transfer.Domain) { d.Denom = "" }},
		{"empty hrp", func(_ *transfer.Config, d *transfer.Domain) { d.HRP = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, d := base, dom
			cfg.GatePubKey = append(ed25519.PublicKey(nil), base.GatePubKey...)
			cfg.SignKey = append(ed25519.PrivateKey(nil), base.SignKey...)
			tc.mod(&cfg, &d)
			_, err := transfer.NewExecutor(cfg, d, rail, st, c)
			require.ErrorIs(t, err, transfer.ErrInvalidConfig)
		})
	}
	t.Run("nil dependencies", func(t *testing.T) {
		_, err := transfer.NewExecutor(base, dom, nil, st, c)
		require.ErrorIs(t, err, transfer.ErrInvalidConfig)
		_, err = transfer.NewExecutor(base, dom, rail, nil, c)
		require.ErrorIs(t, err, transfer.ErrInvalidConfig)
		_, err = transfer.NewExecutor(base, dom, rail, st, nil)
		require.ErrorIs(t, err, transfer.ErrInvalidConfig)
	})
	t.Run("valid", func(t *testing.T) {
		_, err := transfer.NewExecutor(base, dom, rail, st, c)
		require.NoError(t, err)
	})
}

func TestMaxFeeIsHandedToTheSigner(t *testing.T) {
	r := newRig(t, func(c *transfer.Config) { c.MaxFee = 7777 })
	r.rail.includeAt = headH + 1
	action := actionBytes(t, chainID, validMsg())
	_, err := r.exec.Execute(bg, goodAuth(t, chash(1), action), action, testSalt)
	require.NoError(t, err)
	assert.Equal(t, []uint64{7777}, r.rail.maxFees, "Rail.Sign(ctx, body, chainID, maxFee) enforces the cap")
}
