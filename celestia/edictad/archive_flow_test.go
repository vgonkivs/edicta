package edictad_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// archiveEnv is a blob-mode env with a real gate, a staged blob and a
// fault-injecting archive over a real filesystem archive.
func archiveEnv(t *testing.T) (*env, *faultStore, *fsarchive.Store, *commitment.Commitment) {
	t.Helper()
	e := newEnv(t)
	e.deps.WrapGate = nil
	base := e.stage()
	fs, real := e.withArchive()
	return e, fs, real, base
}

func hasCode(body []byte, code string) bool { return bytes.Contains(body, []byte(code)) }

func TestAuthorizeArchivesTheDecisionThenTheAuthorization(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)

	st, _, body := e.authorizeRaw(d)
	require.Equal(t, 200, st)

	dec, err := real.Decision(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, d.env, dec.Envelope, "the envelope exactly as presented")
	assert.Equal(t, d.action, dec.Action, "the action bytes exactly as presented")

	auth, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(body, auth.SignedAuthorization), "the archived Authorization is the one returned")
	assert.NotZero(t, auth.AuthorizedAt)
	require.NotNil(t, auth.K2, "an Authorization the gate issued carries the K2 inputs")
	assert.Equal(t, commitment.DACelestiaBlob, auth.K2.DA)
	assert.EqualValues(t, t0.Unix(), auth.K2.CheckedAt)
	assert.NotZero(t, auth.K2.BlockTime)
	assert.NotZero(t, auth.K2.BlobRetentionS)

	state, err := real.State(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAuthorized, state.State)
	assert.Equal(t, []archive.Kind{archive.KindDecision, archive.KindAuthorization}, fs.puts,
		"the decision is durable before the Authorization")
}

func TestUnsignedOrUnlistedInputNeverReachesTheArchive(t *testing.T) {
	e, fs, _, base := archiveEnv(t)
	e.start()
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	forged := e.decision(base, 1)
	forged.env, _ = gatefix.SignWith(t, stranger, forged.c)

	swapped := e.decision(base, 2)
	swapped.action = []byte("other action bytes")

	unlistedType := e.decision(base, 3, func(c *commitment.Commitment) {
		h, err := commitment.ActionHash("application/vnd.other.v0+cbor", []byte{0xa1, 3, 1, 2})
		require.NoError(t, err)
		c.Action.Type, c.Action.Hash = "application/vnd.other.v0+cbor", h[:]
	})
	stranger2 := e.decision(base, 4, func(c *commitment.Commitment) { c.AgentID = "agent-unknown" })

	for name, d := range map[string]decision{
		"signature by another key": forged,
		"other action bytes":       swapped,
		"action type not allowed":  unlistedType,
		"agent not allowlisted":    stranger2,
	} {
		t.Run(name, func(t *testing.T) {
			st, _, _ := e.authorizeRaw(d)
			assert.GreaterOrEqual(t, st, 400)
			assert.Less(t, st, 500)
			assert.Zero(t, fs.putCount(archive.KindDecision), "the archive stage runs after G, L and A")
		})
	}
}

func TestArchiveDownIs503AndTheNonceStaysUnused(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindDecision, errArchiveDown)
	st, retryAfter, body := e.authorizeRaw(d)
	require.Equal(t, 503, st)
	assert.True(t, hasCode(body, "ErrArchiveUnavailable"), "body %q", body)
	ra, err := strconv.Atoi(retryAfter)
	require.NoError(t, err, "Retry-After %q", retryAfter)
	assert.GreaterOrEqual(t, ra, 1)
	_, err = real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "nothing is signed or archived while the archive is down")
	assert.Zero(t, fs.putCount(archive.KindAuthorization))

	// The archive is back: the same bytes are authorized, which they could not
	// be if the failed attempt had spent the nonce.
	fs.failKind(archive.KindDecision, nil)
	st, _, _ = e.authorizeRaw(d)
	require.Equal(t, 200, st)

	entries := e.registryKeys()
	require.Len(t, entries, 1, "exactly one registry entry")
	assert.EqualValues(t, d.hash, entries[0].CommitmentHash)
}

func TestArchiveDownBeforeAnyStoreTimeoutIsStill503Retryable(t *testing.T) {
	e, fs, _, base := archiveEnv(t)
	e.start()
	fs.failAll(errArchiveDown)
	for tag := byte(1); tag <= 3; tag++ {
		st, ra, _ := e.authorizeRaw(e.decision(base, tag))
		require.Equal(t, 503, st)
		assert.NotEmpty(t, ra)
	}
}

func TestStoredDecisionConflictRule(t *testing.T) {
	t.Run("the same record again is idempotent", func(t *testing.T) {
		e, _, real, base := archiveEnv(t)
		d := e.decision(base, 1)
		_, err := real.Put(bg, &archive.DecisionRecord{Envelope: d.env, Action: d.action})
		require.NoError(t, err)
		e.start()
		st, _, _ := e.authorizeRaw(d)
		require.Equal(t, 200, st)
	})
	t.Run("a stored record with other action bytes is refused", func(t *testing.T) {
		e, _, real, base := archiveEnv(t)
		d := e.decision(base, 1)
		_, err := real.Put(bg, &archive.DecisionRecord{Envelope: d.env, Action: []byte("not the committed bytes")})
		require.NoError(t, err)
		e.start()
		st, ra, body := e.authorizeRaw(d)
		require.Equal(t, 503, st)
		assert.NotEmpty(t, ra)
		assert.True(t, hasCode(body, "ErrArchiveUnavailable"))
	})
	t.Run("a stored envelope whose signature does not verify is refused", func(t *testing.T) {
		e, _, real, base := archiveEnv(t)
		d := e.decision(base, 1)
		bad := bytes.Clone(d.env)
		bad[len(bad)-1] ^= 1
		_, err := real.Put(bg, &archive.DecisionRecord{Envelope: bad, Action: d.action})
		require.NoError(t, err, "the archive keys by the commitment hash, so the damaged envelope takes the key")
		e.start()
		st, _, body := e.authorizeRaw(d)
		require.Equal(t, 503, st)
		assert.True(t, hasCode(body, "ErrArchiveUnavailable"))
	})
}

func TestRejectionMarkers(t *testing.T) {
	cases := []struct {
		name string
		want string
		mk   func(e *env, base *commitment.Commitment) decision
		pre  func(e *env, base *commitment.Commitment) // runs before the case request
	}{
		{"anchor not found", "ErrAnchorNotFound", func(e *env, base *commitment.Commitment) decision {
			return e.decision(base, 1, func(c *commitment.Commitment) { c.PayloadRef.Commitment[0] ^= 1 })
		}, nil},
		{"issued before the anchor", "ErrIssuedBeforeAnchor", func(e *env, base *commitment.Commitment) decision {
			return e.decision(base, 1, func(c *commitment.Commitment) { c.IssuedAt = uint64(t0.Unix()) - 1500 })
		}, nil},
		{"nonce used by another commitment", "ErrNonceUsed", func(e *env, base *commitment.Commitment) decision {
			return e.decisionAct(base, 1, []byte{0xa1, 1, 1, 9})
		}, func(e *env, base *commitment.Commitment) {
			st, _, _ := e.authorizeRaw(e.decision(base, 1))
			require.Equal(t, 200, st)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _, real, base := archiveEnv(t)
			e.start()
			if tc.pre != nil {
				tc.pre(e, base)
			}
			d := tc.mk(e, base)
			st, _, _ := e.authorizeRaw(d)
			require.GreaterOrEqual(t, st, 400)

			m, err := real.Rejection(bg, d.hash, tc.want)
			require.NoError(t, err, "the marker carries the error name")
			assert.Equal(t, tc.want, m.Error)
			assert.Equal(t, "gate-test-1", m.GateID)
			assert.EqualValues(t, t0.Unix(), m.RejectedAt)
			state, err := real.State(bg, d.hash)
			require.NoError(t, err)
			assert.Equal(t, archive.StateRejected, state.State)
			assert.Equal(t, []string{tc.want}, state.Rejections)
		})
	}
}

func TestOperationalErrorsWriteNoMarker(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)
	e.chain.Fail = node.ErrUnavailable
	st, _, body := e.authorizeRaw(d)
	require.Equal(t, 503, st)
	assert.True(t, hasCode(body, "ErrChainUnavailable"))
	assert.Zero(t, fs.putCount(archive.KindRejection), "an unreadable chain says nothing about the decision")
	state, err := real.State(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StatePending, state.State, "the decision is archived and undecided")
	assert.Empty(t, state.Rejections)

	e.chain.Fail = nil
	st, _, _ = e.authorizeRaw(d)
	assert.Equal(t, 200, st, "the nonce was not spent")
}

func TestFailedMarkerWriteKeepsTheVerdict(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	st, _, _ := e.authorizeRaw(e.decision(base, 1))
	require.Equal(t, 200, st)

	fs.failKind(archive.KindRejection, errArchiveDown)
	d := e.decisionAct(base, 1, []byte{0xa1, 1, 1, 9})
	st, _, body := e.authorizeRaw(d)
	require.Equal(t, 409, st, "the verdict is the gate's, not the marker write's")
	assert.True(t, hasCode(body, "ErrNonceUsed"))
	assert.Equal(t, 1, fs.putCount(archive.KindRejection))
	_, err := real.Rejection(bg, d.hash, "ErrNonceUsed")
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestFailedAuthorizationRecordStillAnswers200AndTheRetryRepairsIt(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	tick := make(chan time.Time)
	e.deps.SweepTick = tick
	e.start()
	d := e.decision(base, 1)

	fs.failKind(archive.KindAuthorization, errArchiveDown)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	_, err := real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)

	fs.failKind(archive.KindAuthorization, nil)
	st, _, body := e.authorizeRaw(d)
	require.Equal(t, 409, st, "the nonce is used by this very commitment")
	assert.True(t, hasCode(body, "ErrNonceUsed"))
	_, err = real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "a replay writes no record: the queued one carries the retention inputs")
	tick <- t0
	var auth *archive.AuthorizationRecord
	require.Eventually(t, func() bool {
		auth, err = real.Authorization(bg, d.hash)
		return err == nil
	}, 10*time.Second, 5*time.Millisecond, "the queued record is written by the next sweep")
	assert.NotNil(t, auth.K2, "with the inputs the issuing request had")
	assert.True(t, bytes.Contains(body, auth.SignedAuthorization))
	assert.Zero(t, fs.putCount(archive.KindRejection), "a same-commitment retry is no rejection")
	state, err := real.State(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAuthorized, state.State)
	assert.Empty(t, state.Rejections)
}

// While the archive is down a retry of an authorized decision gets 503: the
// archive stage comes before the nonce read.
func TestRetryOfAnAuthorizedDecisionWhileTheArchiveIsDownIs503(t *testing.T) {
	e, fs, _, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)

	fs.failAll(errArchiveDown)
	st, ra, body := e.authorizeRaw(d)
	require.Equal(t, 503, st)
	assert.NotEmpty(t, ra)
	assert.True(t, hasCode(body, "ErrArchiveUnavailable"))

	fs.failAll(nil)
	st, _, _ = e.authorizeRaw(d)
	assert.Equal(t, 409, st)
}

func TestTheLosingRequestOfARaceWritesNoK2Record(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)

	const n = 8
	statuses := make([]int, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], errs[i] = e.authorizeStatus(d)
		}()
	}
	wg.Wait()
	wins := 0
	for i := range n {
		require.NoError(t, errs[i])
		switch statuses[i] {
		case 200:
			wins++
		case 409:
		default:
			require.Failf(t, "unexpected status", "request %d: %d", i, statuses[i])
		}
	}
	require.Equal(t, 1, wins, "at most one Authorization per nonce")

	withK2 := 0
	for _, a := range fs.authorizationPuts() {
		if a.K2 != nil {
			withK2++
		}
	}
	assert.Equal(t, 1, withK2, "only the winner knows the inputs of the Authorization it issued")
	assert.Len(t, fs.authorizationPuts(), 1, "a replay writes no record of its own")
	stored, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	require.NotNil(t, stored.K2, "the stored record has the retention inputs")
	assert.Equal(t, commitment.DACelestiaBlob, stored.K2.DA)
	assert.Zero(t, fs.putCount(archive.KindRejection))
	state, err := real.State(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAuthorized, state.State)
	assert.Len(t, e.registryKeys(), 1)
}

func TestStoredAuthorizationKeepsItsInputsUnderConcurrentIdenticalRequests(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	const rounds, n = 30, 6
	for r := range rounds {
		d := e.decision(base, byte(r+1))
		statuses := make([]int, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				statuses[i], errs[i] = e.authorizeStatus(d)
			}()
		}
		wg.Wait()
		wins := 0
		for i := range n {
			require.NoError(t, errs[i])
			if statuses[i] == 200 {
				wins++
			} else {
				require.Equal(t, 409, statuses[i])
			}
		}
		require.Equal(t, 1, wins, "round %d", r)
		stored, err := real.Authorization(bg, d.hash)
		require.NoError(t, err, "round %d", r)
		require.NotNil(t, stored.K2, "round %d: the stored record lost its inputs", r)
	}
	assert.Len(t, fs.authorizationPuts(), rounds, "one record per decision")
}

func TestSequentialReplayKeepsTheStoredInputs(t *testing.T) {
	e, fs, real, base := archiveEnv(t)
	e.start()
	d := e.decision(base, 1)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	before, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	require.NotNil(t, before.K2)

	for range 3 {
		st, _, _ = e.authorizeRaw(d)
		require.Equal(t, 409, st)
	}
	after, err := real.Authorization(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.Len(t, fs.authorizationPuts(), 1)
}

func TestDefaultArchiveIsTheFilesystemArchiveOfTheConfiguredDir(t *testing.T) {
	e := newEnv(t)
	e.deps.WrapGate = nil
	base := e.stage()
	require.Nil(t, e.deps.Archive)
	e.start()
	d := e.decision(base, 1)
	st, _, _ := e.authorizeRaw(d)
	require.Equal(t, 200, st)
	require.NoError(t, e.srv.Shutdown(bg))

	ro, err := fsarchive.OpenReadOnly(e.path("archive"), nil)
	require.NoError(t, err)
	state, err := ro.State(bg, d.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAuthorized, state.State)
}

func TestStartRefusesAnUnusableArchiveDirBeforeTheRegistry(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.path("archive"), []byte("not a directory"), 0o600)
	srv, err := edictad.Start(bg, e.cfg(), e.deps)
	require.Error(t, err)
	require.Nil(t, srv)
	assert.Zero(t, e.listens)
	assert.False(t, e.registryExists(), "the archive opens before the registry")
}
