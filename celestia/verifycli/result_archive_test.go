package verifycli

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/archive/httparchive"
	"github.com/vgonkivs/edicta/engine/verifier"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// spyChecker is the bank checker that first reads the archived execution
// results of one key through what the verifier gives it.
type spyChecker struct {
	*bankChecker
	chainID string
	ref     [32]byte

	mu   sync.Mutex
	seen []verifier.ArchivedResult
}

func (s *spyChecker) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	if in.Archived != nil {
		got, err := in.Archived.ExecutionResults(ctx, s.chainID, s.ref)
		if err != nil {
			return verifier.ExecutionFacts{}, err
		}
		s.mu.Lock()
		s.seen = append(s.seen, got...)
		s.mu.Unlock()
	}
	return s.bankChecker.CheckExecution(ctx, in)
}

// A record that only a further archive copy holds reaches the execution
// check, in either form of the flag; the archive itself is read first.
func TestResultArchiveCopiesReachTheExecutionCheck(t *testing.T) {
	ctx := context.Background()
	fix := execresultfix.Load(t).Records[0]
	rec := fix.Build(t)
	var ref [32]byte
	copy(ref[:], rec.RailRef)

	second := t.TempDir()
	st, err := fsarchive.Open(second, nil)
	require.NoError(t, err)
	_, err = st.Put(ctx, rec)
	require.NoError(t, err)
	empty := t.TempDir()
	_, err = fsarchive.Open(empty, nil)
	require.NoError(t, err)
	ro, err := fsarchive.OpenReadOnly(second, nil)
	require.NoError(t, err)
	srv := httptest.NewServer(httparchive.NewHandler(ro))
	t.Cleanup(srv.Close)

	ok := []cometfake.Result{{Code: 0, Data: []byte("r"), GasWanted: 10, GasUsed: 9}}
	run := func(t *testing.T, extra ...string) (*spyChecker, int, string) {
		t.Helper()
		w := newProvenWorld(t, provenOpts{results: ok})
		var spy *spyChecker
		orig := newBankChecker
		newBankChecker = func(txURLs []string, headersURL string, crossURLs []string, trust verifier.HeaderTrust, info *trustInfo,
			chainID string) (verifier.ExecutionChecker, error) {
			chk, err := orig(txURLs, headersURL, crossURLs, trust, info, chainID)
			if err != nil {
				return nil, err
			}
			spy = &spyChecker{bankChecker: chk.(*bankChecker), chainID: rec.ChainID, ref: ref}
			return spy, nil
		}
		t.Cleanup(func() { newBankChecker = orig })
		args := append([]string{"verify", hexOf(w.s.hash[:]), "--archive", w.s.archiveDir, "--gate-key", w.s.gateKey,
			"--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json"}, extra...)
		code, out := exec(t, args)
		require.NotNil(t, spy, out)
		return spy, code, out
	}

	t.Run("directory", func(t *testing.T) {
		spy, code, out := run(t, "--result-archive", empty, "--result-archive", second)
		assert.Equal(t, exitValid, code, out)
		require.Len(t, spy.seen, 1)
		assert.Equal(t, second, spy.seen[0].Copy)
		require.NoError(t, spy.seen[0].Err)
		assert.Equal(t, rec, spy.seen[0].Record)
	})
	t.Run("url", func(t *testing.T) {
		spy, code, out := run(t, "--result-archive", srv.URL)
		assert.Equal(t, exitValid, code, out)
		require.Len(t, spy.seen, 1)
		assert.Equal(t, srv.URL, spy.seen[0].Copy)
		assert.Equal(t, rec, spy.seen[0].Record)
	})
	t.Run("without the flag the archive alone is read", func(t *testing.T) {
		spy, code, out := run(t)
		assert.Equal(t, exitValid, code, out)
		assert.Empty(t, spy.seen)
	})
}

func TestResultArchiveUsage(t *testing.T) {
	s := newScenario(t, scenarioOpts{})
	dir := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"without --check-execution": {
			s.args("verify", "--trusted", s.chain.trustedFile(t, checkpointH, nil), "--result-archive", dir),
			"--result-archive is used only with --check-execution",
		},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := exec(t, c.args)
			assert.Equal(t, codeUsage, code, out)
			assert.Contains(t, out, c.want)
		})
	}

	_, err := openResultCopies([]string{dir, dir})
	require.ErrorContains(t, err, "given twice")
	_, err = openResultCopies([]string{dir + "/missing"})
	require.ErrorContains(t, err, "not a directory")
	_, err = openResultCopies([]string{"ftp://archive.example"})
	require.Error(t, err)
	copies, err := openResultCopies([]string{dir, "https://archive.example"})
	require.NoError(t, err)
	require.Len(t, copies, 2)
	assert.Equal(t, dir, copies[0].Name)
	assert.Equal(t, "https://archive.example", copies[1].Name)
	for _, c := range copies {
		_, ok := c.Reader.(archive.ExecResultReader)
		assert.True(t, ok)
	}
}
