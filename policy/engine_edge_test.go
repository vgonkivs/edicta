package policy_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func edgeMandate(t *testing.T, mod func(*policy.Mandate)) *policy.Mandate {
	t.Helper()
	m, _ := testMandate(t)
	m.Assets[0].PerActionMax = nil
	m.Assets[0].Periods = []policy.PeriodLimit{{Hours: 1, Max: []byte{100}}}
	if mod != nil {
		mod(m)
	}
	require.NoError(t, m.ValidateBasic())
	return m
}

func admission(amount uint64) policy.Admission {
	return policy.Admission{Facts: policy.Facts{Kind: "transfer", Asset: "x:a", Amount: policy.AmountFromUint64(amount)}}
}

func mustAllow(t *testing.T, m *policy.Mandate, l policy.Ledger, amount, th uint64) policy.Step {
	t.Helper()
	s, err := policy.Evaluate(m, l, admission(amount), th)
	require.NoError(t, err)
	return s
}

// The hour a window reaches back to is counted fully, but never a bucket that
// ended before the window began.
func TestRollingWindowAtBucketBoundaries(t *testing.T) {
	const k = 1000 * policy.BucketSeconds
	cases := []struct {
		name     string
		firstTH  uint64
		secondTH uint64
		allowed  bool
	}{
		{"same bucket", k + 10, k + 3599, false},
		{"previous bucket, 1 s apart", k - 1, k, false},
		{"previous bucket, 3599 s apart", k - 1, k + 3598, false},
		{"previous bucket, exactly one hour apart", k - 1, k + 3599, true},
		{"first second of a bucket then the next bucket's first second", k, k + 3600, false},
		{"first second of a bucket, an hour and a second later", k, k + 3601, false},
		{"first second of a bucket, two buckets later", k, k + 7200, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := edgeMandate(t, nil)
			s1 := mustAllow(t, m, policy.GenesisLedger(), 60, c.firstTH)
			_, err := policy.Evaluate(m, s1.Next, admission(60), c.secondTH)
			if c.allowed {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, policy.ErrPeriodLimit)
		})
	}
}

func TestLimitsAllowEqualityAndDenyOneMore(t *testing.T) {
	m := edgeMandate(t, func(m *policy.Mandate) {
		m.Assets[0].Periods[0].Max = []byte{200}
		m.CountLimits = []policy.CountLimit{{Hours: 1, MaxCount: 2}}
	})
	l := policy.GenesisLedger()
	l = mustAllow(t, m, l, 50, 5000).Next
	_, err := policy.Evaluate(m, l, admission(151), 5001)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)
	l = mustAllow(t, m, l, 100, 5001).Next
	_, err = policy.Evaluate(m, l, admission(1), 5002)
	require.ErrorIs(t, err, policy.ErrCountLimit, "the third action breaks the count, the sum would still fit")
}

func TestCountLimitCountsEveryAsset(t *testing.T) {
	m := edgeMandate(t, func(m *policy.Mandate) {
		m.Assets = append(m.Assets, policy.AssetRule{Asset: "x:b", Scale: 0, PerActionMax: []byte{9}})
		m.CountLimits = []policy.CountLimit{{Hours: 2, MaxCount: 2}}
	})
	l := mustAllow(t, m, policy.GenesisLedger(), 10, 7200).Next
	b := policy.Admission{Facts: policy.Facts{Kind: "transfer", Asset: "x:b", Amount: []byte{1}}, Asset: 1}
	step, err := policy.Evaluate(m, l, b, 7201)
	require.NoError(t, err)
	_, err = policy.Evaluate(m, step.Next, admission(1), 7202)
	require.ErrorIs(t, err, policy.ErrCountLimit)
}

// An older anchor time is attributed to the latest time seen, never to a
// bucket behind the open one; min_spacing still reads the raw anchor time of
// the last allow.
func TestAnchorTimeGoingBackwards(t *testing.T) {
	const k = 500 * policy.BucketSeconds
	m := edgeMandate(t, func(m *policy.Mandate) { m.MinSpacing = 1000 })

	s1 := mustAllow(t, m, policy.GenesisLedger(), 10, k+3000)
	require.EqualValues(t, k+3000, s1.EvalTime)

	t.Run("inside the spacing", func(t *testing.T) {
		_, err := policy.Evaluate(m, s1.Next, admission(1), k+2500)
		require.ErrorIs(t, err, policy.ErrMinSpacing)
		_, err = policy.Evaluate(m, s1.Next, admission(1), k+3999)
		require.ErrorIs(t, err, policy.ErrMinSpacing)
	})
	t.Run("exactly at the spacing", func(t *testing.T) {
		s := mustAllow(t, m, s1.Next, 1, k+4000)
		assert.EqualValues(t, k+4000, s.EvalTime)
		assert.EqualValues(t, k/policy.BucketSeconds+1, s.Next.State.Open.Index, "the new time is in the next hour")
		require.NotNil(t, s.ClosedBucket)
	})

	t.Run("no spacing: backwards time lands in the open bucket", func(t *testing.T) {
		m := edgeMandate(t, nil)
		a := mustAllow(t, m, policy.GenesisLedger(), 10, k+3000)
		b := mustAllow(t, m, a.Next, 10, k-100)
		assert.EqualValues(t, k+3000, b.EvalTime, "T_eff is the last T_eff")
		assert.EqualValues(t, k+3000, b.Next.State.LastT)
		assert.EqualValues(t, k-100, b.Next.State.LastTH, "the raw anchor time is kept for spacing")
		assert.Equal(t, a.Next.State.Open.Index, b.Next.State.Open.Index)
		assert.EqualValues(t, 2, b.Next.State.Open.Count)
		assert.Nil(t, b.ClosedBucket, "no hour closes on an older anchor")
		assert.Empty(t, b.Next.Closed)
		_, err := policy.Evaluate(m, b.Next, admission(81), k-50)
		require.ErrorIs(t, err, policy.ErrPeriodLimit, "the older anchor does not escape the window")
	})
}

// A denied request changes nothing, also when the denied time would have
// rolled the hour.
func TestDenyDoesNotMutateTheLedgerOrRollOver(t *testing.T) {
	m := edgeMandate(t, nil)
	l := mustAllow(t, m, policy.GenesisLedger(), 90, 3600*10+5).Next
	before, err := policy.HashState(&l.State)
	require.NoError(t, err)
	nSet := len(l.Set.Buckets)

	_, err = policy.Evaluate(m, l, admission(11), 3600*10+3599)
	require.ErrorIs(t, err, policy.ErrPeriodLimit)
	_, err = policy.Evaluate(m, l, admission(101), 3600*30)
	require.ErrorIs(t, err, policy.ErrPeriodLimit, "a fresh hour still holds only 100")

	after, err := policy.HashState(&l.State)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.Len(t, l.Set.Buckets, nSet)
	assert.Len(t, l.State.Open.Sums, 1)
	assert.Equal(t, []byte{90}, l.State.Open.Sums[0].Sum)
	assert.EqualValues(t, 1, l.State.Open.Count)
	require.NoError(t, l.Validate())
}

// An allow must not alter the ledger it started from either: the gate keeps
// that value for a retry and the verifier for the signed prev_state.
func TestAllowDoesNotAliasTheInputLedger(t *testing.T) {
	m := edgeMandate(t, nil)
	l := mustAllow(t, m, policy.GenesisLedger(), 10, 3600*10).Next
	l = mustAllow(t, m, l, 10, 3600*11).Next
	snap, err := policy.EncodeState(&l.State)
	require.NoError(t, err)
	for i, th := range []uint64{3600*11 + 1, 3600 * 12, 3600 * 40} {
		_, err := policy.Evaluate(m, l, admission(5), th)
		require.NoError(t, err, i)
		now, err := policy.EncodeState(&l.State)
		require.NoError(t, err)
		require.Equal(t, snap, now, "state changed by an evaluation at %d", th)
		require.NoError(t, l.Validate())
	}
}

type accepted struct {
	tEff, th, amt uint64
}

// A model written from the rule's wording: an hour bucket counts when its
// last second is not before the window's first second.
func modelWindow(acc []accepted, tEff, hours uint64, sum bool) uint64 {
	var out uint64
	for _, a := range acc {
		bucketEnd := a.tEff/policy.BucketSeconds*policy.BucketSeconds + policy.BucketSeconds - 1
		if int64(bucketEnd) >= int64(tEff)-int64(hours*policy.BucketSeconds)+1 {
			if sum {
				out += a.amt
			} else {
				out++
			}
		}
	}
	return out
}

func TestEngineAgreesWithTheModelAndKeepsTheRollingBound(t *testing.T) {
	for seed := int64(1); seed <= 6; seed++ {
		rng := rand.New(rand.NewSource(seed))
		hoursP := uint64(1 + rng.Intn(30))
		hoursC := uint64(1 + rng.Intn(30))
		spacing := uint64(rng.Intn(3)) * uint64(rng.Intn(5000))
		m := edgeMandate(t, func(m *policy.Mandate) {
			m.Assets[0].Periods = []policy.PeriodLimit{{Hours: hoursP, Max: []byte{200}}}
			m.CountLimits = []policy.CountLimit{{Hours: hoursC, MaxCount: 7}}
			m.MinSpacing = spacing
		})
		l := policy.GenesisLedger()
		var acc []accepted
		now := uint64(3600 * 1000)
		var lastT, lastTH uint64
		for i := 0; i < 600; i++ {
			switch rng.Intn(10) {
			case 0:
				now += uint64(rng.Intn(400)) * 3600 // long gaps exercise pruning
			default:
				now += uint64(rng.Intn(5000))
			}
			th := now
			if rng.Intn(4) == 0 && now > 8000 {
				th = now - uint64(rng.Intn(8000)) // an older anchor
			}
			amt := uint64(1 + rng.Intn(120))

			tEff := th
			if len(acc) > 0 {
				tEff = max(th, lastT)
			}
			want := error(nil)
			switch {
			case len(acc) > 0 && spacing > 0 && th < lastTH+spacing:
				want = policy.ErrMinSpacing
			case modelWindow(acc, tEff, hoursP, true)+amt > 200:
				want = policy.ErrPeriodLimit
			case modelWindow(acc, tEff, hoursC, false)+1 > 7:
				want = policy.ErrCountLimit
			}

			step, err := policy.Evaluate(m, l, admission(amt), th)
			if want != nil {
				require.ErrorIs(t, err, want, "seed %d step %d th %d amt %d", seed, i, th, amt)
				require.ErrorIs(t, err, policy.ErrDenied)
				continue
			}
			require.NoError(t, err, "seed %d step %d th %d amt %d", seed, i, th, amt)
			require.Equal(t, tEff, step.EvalTime)
			l = step.Next
			acc = append(acc, accepted{tEff: tEff, th: th, amt: amt})
			lastT, lastTH = tEff, th

			require.NoError(t, l.Validate())
			h, err := policy.HashState(&l.State)
			require.NoError(t, err)
			require.Equal(t, h, step.NewHash)
			require.LessOrEqual(t, len(l.Closed), policy.MaxClosed)
			back, err := policy.NewLedger(l.State, l.Closed, l.Set)
			require.NoError(t, err)
			require.Equal(t, l.State, back.State)
		}
		require.NotEmpty(t, acc, "seed %d", seed)

		// Rolling bound on the attribution time: no true window of the rule's
		// length holds more than the limits, whatever the buckets say.
		for i := range acc {
			var sum, n uint64
			for j := range acc {
				d := int64(acc[i].tEff) - int64(acc[j].tEff)
				if d >= 0 && d < int64(hoursP*policy.BucketSeconds) {
					sum += acc[j].amt
				}
				if d >= 0 && d < int64(hoursC*policy.BucketSeconds) {
					n++
				}
			}
			assert.LessOrEqual(t, sum, uint64(200), "seed %d: period sum ending at %d", seed, acc[i].tEff)
			assert.LessOrEqual(t, n, uint64(7), "seed %d: count ending at %d", seed, acc[i].tEff)
		}
		for i := 1; i < len(acc); i++ {
			assert.GreaterOrEqual(t, acc[i].tEff, acc[i-1].tEff, "T_eff never goes back")
			if spacing > 0 {
				assert.GreaterOrEqual(t, acc[i].th, acc[i-1].th+spacing, "allowed anchors are spaced")
			}
		}
	}
}

func TestHistoryCapacityIsADistinctDeny(t *testing.T) {
	maxAmt := make([]byte, 32)
	for i := range maxAmt {
		maxAmt[i] = 0xff
	}
	m := edgeMandate(t, func(m *policy.Mandate) {
		m.Assets[0].Periods = nil
		m.Assets[0].PerActionMax = maxAmt
	})
	a := policy.Admission{Facts: policy.Facts{Kind: "transfer", Asset: "x:a", Amount: maxAmt}}
	l := mustAllow(t, m, policy.GenesisLedger(), 1, 3600).Next
	_, err := policy.Evaluate(m, l, a, 3601)
	require.ErrorIs(t, err, policy.ErrHistoryFull)
	require.ErrorIs(t, err, policy.ErrDenied)
	assert.Equal(t, "ErrHistoryFull", policy.ReasonOf(err))
	assert.NotErrorIs(t, err, policy.ErrPeriodLimit)

	l = policy.GenesisLedger()
	for i := 0; i < policy.MaxPairs; i++ {
		s, err := policy.Apply(l, policy.Delta{Asset: "x:" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Scale: 0, Amount: []byte{1}, TH: 3600})
		require.NoError(t, err)
		l = s.Next
	}
	_, err = policy.Apply(l, policy.Delta{Asset: "x:zz", Amount: []byte{1}, TH: 3600})
	require.ErrorIs(t, err, policy.ErrHistoryFull)
}

// Times the state cannot hold must not turn into an allow.
func TestTimesBeyondTheStateRangeNeverAllow(t *testing.T) {
	m := edgeMandate(t, nil)
	for _, th := range []uint64{1 << 63, ^uint64(0)} {
		s, err := policy.Evaluate(m, policy.GenesisLedger(), admission(1), th)
		if err == nil {
			require.NoError(t, s.Next.Validate(), "an allow must leave a valid state (th %d)", th)
		}
	}
}

func TestPrunedWindowNeverReadsMissingBuckets(t *testing.T) {
	m := edgeMandate(t, func(m *policy.Mandate) {
		m.Assets[0].Periods = []policy.PeriodLimit{{Hours: 744, Max: []byte{100}}}
	})
	l := policy.GenesisLedger()
	th := uint64(3600 * 100)
	last := th
	l = mustAllow(t, m, l, 60, th).Next
	for i := 0; i < 8; i++ {
		th += 3600 * 200
		s, err := policy.Evaluate(m, l, admission(60), th)
		if th-last < 3600*744 {
			require.ErrorIs(t, err, policy.ErrPeriodLimit)
			continue
		}
		require.NoError(t, err)
		l, last = s.Next, th
		assert.LessOrEqual(t, len(l.Closed), policy.MaxClosed)
	}
	assert.Greater(t, last, uint64(3600*100), "an allow after the window passed")
}
