package transfer_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

func TestBroadcastDeadlineIsAbsoluteAndNeverRounded(t *testing.T) {
	cases := map[string]struct {
		skew uint64
		// before is how long before expires - skew the clock reads, with a
		// fractional second.
		before time.Duration
		// wantAbs is true when the deadline must equal expires - skew exactly.
		wantAbs bool
	}{
		"skew 30, 0.4 s before the send stop": {30, 400 * time.Millisecond, true},
		"skew 30, 0.9 s before the send stop": {30, 900 * time.Millisecond, true},
		"skew 0, 0.4 s before expires":        {0, 400 * time.Millisecond, true},
		"skew 0, 1.5 s before expires":        {0, 1500 * time.Millisecond, true},
		"skew 30, far from the send stop":     {30, 60*time.Second + 400*time.Millisecond, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(cfg *transfer.Config) { cfg.SkewS = c.skew })
			action := actionBytes(t, chainID, validMsg())
			h := chash(31)
			chainAt(r, action, h, 10)
			stop := time.Unix(int64(expiresAt-c.skew), 0)
			now := stop.Add(-c.before)
			r.rail.onHeight = func(n int) {
				if n == 1 {
					r.clock.setTime(now)
				}
			}
			_, err := r.exec.Execute(bg, goodAuth(t, h, action), action)
			require.ErrorIs(t, err, transfer.ErrHandedOff)

			calls := r.rail.calls("broadcast")
			require.NotEmpty(t, calls, "the send was still valid")
			first := calls[0]
			require.True(t, first.hasDeadline)
			if c.wantAbs {
				assert.True(t, first.deadline.Equal(stop), "deadline %s, want %s", first.deadline, stop)
			}
			assert.False(t, first.deadline.After(stop), "deadline %s is after expires - skew %s", first.deadline, stop)
			assert.False(t, first.deadline.After(now.Add(10*time.Second)), "deadline outlives the resend interval")
		})
	}
}
