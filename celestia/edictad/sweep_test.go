package edictad_test

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
)

// sweepCase leaves two authorized decisions in the registry whose
// Authorization records were never written: the archive refused them.
func sweepCase(t *testing.T) (e *env, fs *faultStore, real *fsarchive.Store, d1, d2 decision) {
	t.Helper()
	e, fs, real, base := archiveEnv(t)
	e.start()
	d1, d2 = e.decision(base, 1), e.decision(base, 2)
	fs.failKind(archive.KindAuthorization, errArchiveDown)
	for _, d := range []decision{d1, d2} {
		st, _, _ := e.authorizeRaw(d)
		require.Equal(t, 200, st, "a failed Authorization record never changes the answer")
	}
	require.NoError(t, e.srv.Shutdown(bg))
	for _, d := range []decision{d1, d2} {
		_, err := real.Authorization(bg, d.hash)
		require.ErrorIs(t, err, archive.ErrNotFound)
	}
	return e, fs, real, d1, d2
}

func decisionFile(e *env, h commitment.Hash) string {
	return filepath.Join(e.path("archive"), filepath.FromSlash(archive.HashPath(archive.KindDecision, h)))
}

func TestSweepFillsMissingAuthorizationRecordsBeforeTheListener(t *testing.T) {
	e, fs, real, d1, d2 := sweepCase(t)
	require.NoError(t, os.Remove(decisionFile(e, d2.hash)), "d2 now looks like a pre-archive registry entry")
	fs.failKind(archive.KindAuthorization, nil)

	var seenAtListen bool
	listen := e.deps.Listen
	e.deps.Listen = func(network, addr string) (net.Listener, error) {
		_, err := real.Authorization(bg, d1.hash)
		seenAtListen = err == nil
		return listen(network, addr)
	}
	e.start()
	assert.True(t, seenAtListen, "the sweep runs before the listener starts")

	auth, err := real.Authorization(bg, d1.hash)
	require.NoError(t, err)
	assert.Nil(t, auth.K2, "a record repaired from the registry has no K2 inputs")
	assert.NotEmpty(t, auth.SignedAuthorization)
	assert.NotZero(t, auth.AuthorizedAt)

	_, err = real.Authorization(bg, d2.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "an entry without a decision record is skipped")

	logs := e.logs.String()
	assert.Contains(t, logs, "archive sweep")
	assert.Contains(t, logs, "repaired=1")
	assert.Contains(t, logs, "no_decision=1")
	assert.Contains(t, logs, "conflicts=0")
	assert.Contains(t, logs, "failed=0")
}

func TestSweepFailureNeverBlocksStartup(t *testing.T) {
	e, fs, real, d1, _ := sweepCase(t)
	fs.failKind(archive.KindAuthorization, errArchiveDown)

	e.start()
	resp, err := http.Get("http://" + e.srv.Addr() + "/v1/health")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	_, err = real.Authorization(bg, d1.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
	assert.Contains(t, e.logs.String(), "failed=2")
}

func TestSweepRepeatsWhileWorkIsLeft(t *testing.T) {
	e, fs, real, d1, d2 := sweepCase(t)
	fs.failKind(archive.KindAuthorization, errArchiveDown)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	_, err := real.Authorization(bg, d1.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "the startup sweep could not write")

	fs.failKind(archive.KindAuthorization, nil)
	tick <- t0
	require.Eventually(t, func() bool {
		_, e1 := real.Authorization(bg, d1.hash)
		_, e2 := real.Authorization(bg, d2.hash)
		return e1 == nil && e2 == nil
	}, 10*time.Second, 5*time.Millisecond, "the next run fills what the startup run could not")
}

func TestStartupSweepLeavesCompleteRecordsAlone(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	before, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	require.NoError(t, e.srv.Shutdown(bg))
	n := fs.putCount(archive.KindAuthorization)

	e.start()
	after, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the K2 inputs of a complete record are never overwritten")
	assert.Equal(t, n, fs.putCount(archive.KindAuthorization), "nothing to repair, nothing written")
	assert.Contains(t, e.logs.String(), "repaired=0")
}
