package heightcheck_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

const heightKey = "x-cosmos-block-height"

func TestEchoHeight(t *testing.T) {
	cases := []struct {
		name string
		md   metadata.MD
		want uint64
		ok   bool
	}{
		{"exact echo", metadata.Pairs(heightKey, "1082620"), 1082620, true},
		{"exact echo of one", metadata.Pairs(heightKey, "1"), 1, true},
		{"nil metadata", nil, 5, false},
		{"empty metadata", metadata.MD{}, 5, false},
		{"other headers only", metadata.Pairs("content-type", "application/grpc"), 5, false},
		{"different height", metadata.Pairs(heightKey, "6"), 5, false},
		{"latest instead of pinned", metadata.Pairs(heightKey, "9000000"), 5, false},
		{"empty value", metadata.Pairs(heightKey, ""), 5, false},
		{"not a number", metadata.Pairs(heightKey, "five"), 5, false},
		{"negative", metadata.Pairs(heightKey, "-5"), 5, false},
		{"overflow", metadata.Pairs(heightKey, "18446744073709551621"), 5, false},
		{"leading zero", metadata.Pairs(heightKey, "05"), 5, false},
		{"leading zeros on a long height", metadata.Pairs(heightKey, "0001082620"), 1082620, false},
		{"zero is canonical", metadata.Pairs(heightKey, "0"), 0, true},
		{"plus sign", metadata.Pairs(heightKey, "+5"), 5, false},
		{"surrounding space", metadata.Pairs(heightKey, " 5"), 5, false},
		{"hex", metadata.Pairs(heightKey, "0x5"), 5, false},
		{"conflicting values", metadata.Pairs(heightKey, "5", heightKey, "6"), 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := heightcheck.EchoHeight(tc.md, tc.want)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
		})
	}
}

func TestHeaderHeight(t *testing.T) {
	require.NoError(t, heightcheck.HeaderHeight(77, 77))
	require.ErrorIs(t, heightcheck.HeaderHeight(78, 77), heightcheck.ErrHeightIgnored)
	require.ErrorIs(t, heightcheck.HeaderHeight(0, 77), heightcheck.ErrHeightIgnored)
}

func TestFlag(t *testing.T) {
	var f heightcheck.Flag
	assert.False(t, f.Ignoring())
	f.Mark()
	assert.True(t, f.Ignoring())
	f.Mark()
	assert.True(t, f.Ignoring())
	f.Clear()
	assert.False(t, f.Ignoring())
}

func TestFlagNilIsSafeAndNeverSet(t *testing.T) {
	var f *heightcheck.Flag
	require.NotPanics(t, func() {
		f.Mark()
		f.Clear()
	})
	assert.False(t, f.Ignoring())
}

func TestFlagConcurrent(t *testing.T) {
	var f heightcheck.Flag
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				f.Mark()
				_ = f.Ignoring()
				f.Clear()
			}
		}()
	}
	wg.Wait()
	assert.False(t, f.Ignoring())
}

type fakeEndpoint struct {
	name   string
	role   heightcheck.Role
	status heightcheck.Status
	err    error
	calls  int
}

func (f *fakeEndpoint) Name() string { return f.name }
func (f *fakeEndpoint) Role() heightcheck.Role {
	if f.role == 0 {
		return heightcheck.RoleConsensus
	}
	return f.role
}
func (f *fakeEndpoint) Canary(context.Context) (heightcheck.Status, error) {
	f.calls++
	return f.status, f.err
}

type record struct {
	level slog.Level
	msg   string
}

type captureHandler struct {
	mu   sync.Mutex
	recs []record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, record{r.Level, r.Message})
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }
func (h *captureHandler) lines() []record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]record(nil), h.recs...)
}

func TestStartupHonoured(t *testing.T) {
	h := &captureHandler{}
	ep := &fakeEndpoint{name: "own-node", status: heightcheck.Honoured}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h), ep)
	require.NoError(t, err)
	assert.False(t, obs)
	require.Len(t, h.lines(), 1)
	assert.Equal(t, "own-node: height honoured", h.lines()[0].msg)
	assert.Equal(t, slog.LevelInfo, h.lines()[0].level)
}

func TestStartupHeightIgnoringEndpointIsObservationsOnlyWithOneLine(t *testing.T) {
	h := &captureHandler{}
	ep := &fakeEndpoint{name: "quicknode-mocha", status: heightcheck.Ignoring}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h), ep)
	require.NoError(t, err)
	assert.True(t, obs)
	assert.Equal(t, 1, ep.calls)
	require.Len(t, h.lines(), 1, "exactly one line per endpoint")
	assert.Equal(t, "quicknode-mocha: height-ignoring, observations-only mode", h.lines()[0].msg)
	assert.Equal(t, slog.LevelWarn, h.lines()[0].level)
}

func TestStartupInconclusiveCountsAsNotPassedAndNeverBlocksStart(t *testing.T) {
	h := &captureHandler{}
	ep := &fakeEndpoint{name: "flaky", status: heightcheck.Inconclusive, err: errors.New("timeout")}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h), ep)
	require.NoError(t, err)
	assert.True(t, obs)
	require.Len(t, h.lines(), 1)
	assert.Contains(t, h.lines()[0].msg, "flaky")
	assert.Equal(t, slog.LevelWarn, h.lines()[0].level)
}

func TestStartupOneLinePerEndpointAndWorstWins(t *testing.T) {
	h := &captureHandler{}
	eps := []heightcheck.Endpoint{
		&fakeEndpoint{name: "bridge", role: heightcheck.RoleBridge, status: heightcheck.Honoured},
		&fakeEndpoint{name: "consensus", status: heightcheck.Ignoring},
		&fakeEndpoint{name: "backup", status: heightcheck.Honoured},
	}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h), eps...)
	require.NoError(t, err)
	assert.True(t, obs, "one height-ignoring endpoint turns the gate-wide mode on")
	lines := h.lines()
	require.Len(t, lines, 3)
	for i, name := range []string{"bridge", "consensus", "backup"} {
		assert.True(t, strings.HasPrefix(lines[i].msg, name+":"), lines[i].msg)
	}
}

func TestStartupAllHonouredIsNotObservationsOnly(t *testing.T) {
	h := &captureHandler{}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h),
		&fakeEndpoint{name: "a", status: heightcheck.Honoured}, &fakeEndpoint{name: "b", status: heightcheck.Honoured})
	require.NoError(t, err)
	assert.False(t, obs)
	assert.Len(t, h.lines(), 2)
}

func TestStartupFailingBridgeIsLoggedButNotObservationsOnly(t *testing.T) {
	cases := []struct {
		name string
		st   heightcheck.Status
		err  error
	}{
		{"ignoring", heightcheck.Ignoring, nil},
		{"inconclusive", heightcheck.Inconclusive, errors.New("timeout")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &captureHandler{}
			br := &fakeEndpoint{name: "bridge", role: heightcheck.RoleBridge, status: tc.st, err: tc.err}
			obs, err := heightcheck.Startup(context.Background(), slog.New(h), br)
			require.NoError(t, err)
			assert.False(t, obs, "a bridge never drives observations-only")
			require.Len(t, h.lines(), 1)
			assert.Equal(t, slog.LevelWarn, h.lines()[0].level)
			assert.True(t, strings.HasPrefix(h.lines()[0].msg, "bridge:"))
		})
	}
}

func TestStartupFailingBridgeDoesNotHideHealthyConsensus(t *testing.T) {
	h := &captureHandler{}
	obs, err := heightcheck.Startup(context.Background(), slog.New(h),
		&fakeEndpoint{name: "cons", status: heightcheck.Honoured},
		&fakeEndpoint{name: "bridge", role: heightcheck.RoleBridge, status: heightcheck.Ignoring})
	require.NoError(t, err)
	assert.False(t, obs)
	assert.Len(t, h.lines(), 2)
}

func TestStartupFailingConsensusWithHonestBridgeIsObservationsOnly(t *testing.T) {
	obs, err := heightcheck.Startup(context.Background(), slog.New(&captureHandler{}),
		&fakeEndpoint{name: "bridge", role: heightcheck.RoleBridge, status: heightcheck.Honoured},
		&fakeEndpoint{name: "cons", status: heightcheck.Inconclusive, err: errors.New("x")})
	require.NoError(t, err)
	assert.True(t, obs)
}
