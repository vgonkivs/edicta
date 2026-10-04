package pricetrigger_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/test/bankvec"
)

func toPayload(t *testing.T, in bankvec.PTInput) *pricetrigger.Payload {
	t.Helper()
	p := &pricetrigger.Payload{
		StrategyID: in.StrategyID,
		Asset: pricetrigger.Asset{
			Feed: in.Asset.Feed, AssetID: in.Asset.AssetID, Quote: in.Asset.Quote,
		},
		Baseline: pricetrigger.Baseline{
			Price: bankvec.U64(t, in.Baseline.Price),
			SetAt: bankvec.U64(t, in.Baseline.SetAt),
		},
		ThresholdBP: bankvec.U64(t, in.ThresholdBP),
		Direction:   bankvec.U64(t, in.Direction),
		MoveBP:      bankvec.U64(t, in.MoveBP),
		Branch: pricetrigger.Branch{
			Name:      in.Branch.Name,
			ToAddress: in.Branch.ToAddress,
			Amount:    bankvec.U64(t, in.Branch.Amount),
			Denom:     in.Branch.Denom,
		},
		Reason: in.Reason,
	}
	for _, o := range in.Observations {
		p.Observations = append(p.Observations, pricetrigger.Observation{
			Source:     o.Source,
			Price:      bankvec.U64(t, o.Price),
			ObservedAt: bankvec.U64(t, o.ObservedAt),
			FetchedAt:  bankvec.U64(t, o.FetchedAt),
		})
	}
	return p
}

func TestMediaType(t *testing.T) {
	assert.Equal(t, "application/vnd.edicta.price-trigger.v0+cbor", pricetrigger.MediaType)
	assert.Equal(t, pricetrigger.MediaType, bankvec.Triggers(t).MediaType)
}

func TestEncodeVectors(t *testing.T) {
	f := bankvec.Triggers(t)
	require.Len(t, f.Cases, 4)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := pricetrigger.Encode(toPayload(t, c.Input))
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.CBORHex), got)
		})
	}
}

func TestDecodeRoundTripsVectors(t *testing.T) {
	for _, c := range bankvec.Triggers(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			raw := bankvec.Hex(t, c.CBORHex)
			got, err := pricetrigger.Decode(raw)
			require.NoError(t, err)
			assert.Equal(t, toPayload(t, c.Input), got)

			again, err := pricetrigger.Encode(got)
			require.NoError(t, err)
			assert.Equal(t, raw, again)
		})
	}
}

func TestDecodeRejectVectors(t *testing.T) {
	f := bankvec.Triggers(t)
	require.Len(t, f.Reject, 25)
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			require.Equal(t, "pricetrigger.ErrMalformed", r.ExpectErr)
			_, err := pricetrigger.Decode(bankvec.Hex(t, r.CBORHex))
			require.ErrorIs(t, err, pricetrigger.ErrMalformed)
		})
	}
}

func TestEncodeRefusesInvalid(t *testing.T) {
	base := toPayload(t, bankvec.Triggers(t).Cases[0].Input)
	tests := []struct {
		name string
		mut  func(p *pricetrigger.Payload)
	}{
		{"no observations", func(p *pricetrigger.Payload) { p.Observations = nil }},
		{"nine observations", func(p *pricetrigger.Payload) {
			p.Observations = make([]pricetrigger.Observation, 9)
			for i := range p.Observations {
				p.Observations[i] = base.Observations[0]
			}
		}},
		{"oldest first", func(p *pricetrigger.Payload) {
			o := p.Observations[0]
			older := o
			older.ObservedAt--
			newer := o
			newer.ObservedAt++
			p.Observations = []pricetrigger.Observation{older, newer}
		}},
		{"zero price", func(p *pricetrigger.Payload) { p.Observations[0].Price = 0 }},
		{"zero baseline", func(p *pricetrigger.Payload) { p.Baseline.Price = 0 }},
		{"lower-case quote", func(p *pricetrigger.Payload) { p.Asset.Quote = "usd" }},
		{"threshold 0", func(p *pricetrigger.Payload) { p.ThresholdBP = 0 }},
		{"threshold 10001", func(p *pricetrigger.Payload) { p.ThresholdBP = 10001 }},
		{"direction 3", func(p *pricetrigger.Payload) { p.Direction = 3 }},
		{"direction 0", func(p *pricetrigger.Payload) { p.Direction = 0 }},
		{"price 2^63", func(p *pricetrigger.Payload) { p.Observations[0].Price = 1 << 63 }},
		{"zero amount", func(p *pricetrigger.Payload) { p.Branch.Amount = 0 }},
		{"upper-case address", func(p *pricetrigger.Payload) { p.Branch.ToAddress = strings.ToUpper(p.Branch.ToAddress) }},
		{"reason 1025", func(p *pricetrigger.Payload) { p.Reason = strings.Repeat("a", 1025) }},
		{"reason invalid UTF-8", func(p *pricetrigger.Payload) { p.Reason = "\xff" }},
		{"empty strategy", func(p *pricetrigger.Payload) { p.StrategyID = "" }},
		{"strategy 65", func(p *pricetrigger.Payload) { p.StrategyID = strings.Repeat("a", 65) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := toPayload(t, bankvec.Triggers(t).Cases[0].Input)
			tc.mut(p)
			_, err := pricetrigger.Encode(p)
			require.ErrorIs(t, err, pricetrigger.ErrMalformed)
		})
	}
}

func TestReasonIsOptionalAndMayBeNonASCII(t *testing.T) {
	p := toPayload(t, bankvec.Triggers(t).Cases[0].Input)
	p.Reason = "price up, \u00fcbung"
	raw, err := pricetrigger.Encode(p)
	require.NoError(t, err)
	got, err := pricetrigger.Decode(raw)
	require.NoError(t, err)
	assert.Equal(t, p.Reason, got.Reason)

	p.Reason = strings.Repeat("a", 1024)
	_, err = pricetrigger.Encode(p)
	require.NoError(t, err)
}

func TestMoveBP(t *testing.T) {
	const max = uint64(1<<63 - 1)
	tests := []struct {
		name  string
		p, b  uint64
		want  uint64
		valid bool
	}{
		{"up 1 percent", 512300000, 507200000, 100, true},
		{"floors", 10099, 10000, 99, true},
		{"equal", 5, 5, 0, true},
		{"down", 9900, 10000, 100, true},
		{"down floors", 9901, 10000, 99, true},
		{"double", 2, 1, 10000, true},
		{"wide intermediate, 64-bit product would wrap", max, 1 << 62, 9999, true},
		{"wide intermediate, down", 1 << 62, max, 4999, true},
		{"result beyond uint63", max, 1, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pricetrigger.MoveBP(tc.p, tc.b)
			assert.Equal(t, tc.valid, ok)
			if tc.valid {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestMoveBPMatchesVectors(t *testing.T) {
	for _, c := range bankvec.Triggers(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			p := toPayload(t, c.Input)
			got, ok := pricetrigger.MoveBP(p.Observations[0].Price, p.Baseline.Price)
			require.True(t, ok)
			assert.Equal(t, p.MoveBP, got)
		})
	}
}

func TestVerifyConsistencyVectors(t *testing.T) {
	f := bankvec.Triggers(t)
	require.Len(t, f.Consistency, 9)
	for _, c := range f.Consistency {
		t.Run(c.ID, func(t *testing.T) {
			p, err := pricetrigger.Decode(bankvec.Hex(t, c.ContextHex))
			require.NoError(t, err)
			raw, hrp := bankvec.Msg(t, c.MsgRef)
			require.Equal(t, c.HRP, hrp)
			m, err := bankmsg.Decode(raw, hrp)
			require.NoError(t, err)

			got := pricetrigger.Verify(p, m, bankvec.U64(t, c.IssuedAt))
			want := []pricetrigger.Check{}
			for _, id := range c.ExpectedFails {
				want = append(want, pricetrigger.Check(id))
			}
			assert.Equal(t, want, got)
		})
	}
}

func TestCheckIDs(t *testing.T) {
	assert.Equal(t, pricetrigger.Check("PT1"), pricetrigger.CheckMove)
	assert.Equal(t, pricetrigger.Check("PT2"), pricetrigger.CheckDirection)
	assert.Equal(t, pricetrigger.Check("PT3"), pricetrigger.CheckThreshold)
	assert.Equal(t, pricetrigger.Check("PT4"), pricetrigger.CheckBranch)
	assert.Equal(t, pricetrigger.Check("PT5"), pricetrigger.CheckFetchedBeforeIssue)
}

func TestVerifyEqualPricesFailsDirection(t *testing.T) {
	c := bankvec.Triggers(t).Cases[0]
	p := toPayload(t, c.Input)
	p.Observations[0].Price = p.Baseline.Price
	p.MoveBP = 0
	raw, hrp := bankvec.Msg(t, "msg_minimal")
	m, err := bankmsg.Decode(raw, hrp)
	require.NoError(t, err)

	got := pricetrigger.Verify(p, m, 1<<62)
	assert.Contains(t, got, pricetrigger.CheckDirection)
	assert.Contains(t, got, pricetrigger.CheckThreshold)
	assert.NotContains(t, got, pricetrigger.CheckMove)
}

func TestVerifyFetchedAtBoundary(t *testing.T) {
	c := bankvec.Triggers(t).Cases[0]
	p := toPayload(t, c.Input)
	raw, hrp := bankvec.Msg(t, "msg_minimal")
	m, err := bankmsg.Decode(raw, hrp)
	require.NoError(t, err)
	f := p.Observations[0].FetchedAt

	assert.Empty(t, pricetrigger.Verify(p, m, f))
	assert.Equal(t, []pricetrigger.Check{pricetrigger.CheckFetchedBeforeIssue}, pricetrigger.Verify(p, m, f-1))
}

func FuzzDecode(f *testing.F) {
	tf := bankvec.Triggers(f)
	for _, c := range tf.Cases {
		f.Add(bankvec.Hex(f, c.CBORHex))
	}
	for _, r := range tf.Reject {
		f.Add(bankvec.Hex(f, r.CBORHex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := pricetrigger.Decode(b)
		if err != nil {
			require.ErrorIs(t, err, pricetrigger.ErrMalformed)
			return
		}
		again, err := pricetrigger.Encode(p)
		require.NoError(t, err)
		require.Equal(t, b, again)
		assert.GreaterOrEqual(t, len(p.Observations), 1)
		assert.LessOrEqual(t, len(p.Observations), 8)
	})
}

func FuzzMoveBP(f *testing.F) {
	f.Add(uint64(512300000), uint64(507200000))
	f.Add(uint64(1<<63-1), uint64(1<<62))
	f.Fuzz(func(t *testing.T, p, b uint64) {
		if b == 0 || p > 1<<63-1 || b > 1<<63-1 {
			return
		}
		got, ok := pricetrigger.MoveBP(p, b)
		if !ok {
			return
		}
		d := p - b
		if b > p {
			d = b - p
		}
		// got = floor(d*10000/b), checked without a 128-bit type:
		// got*b <= d*10000 < (got+1)*b, compared through the quotient/remainder of d.
		q, r := d/b, d%b
		wantHi := q * 10000
		wantLo := r * 10000 / b
		if r > (1<<64-1)/10000 {
			return
		}
		assert.Equal(t, wantHi+wantLo, got)
	})
}
