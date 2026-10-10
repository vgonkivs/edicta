package edictad_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
)

// A policy_deny the store refused is not counted as archived: the next retry
// refused for the same reason writes it.
func TestPrivateDenyRefusedByTheStoreIsWrittenOnTheNextRetry(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	parts := len(p.privateParts())

	p.fs.failKind(archive.KindPolicyDeny, archive.ErrNotFound)
	d := p.send(1, 6_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	require.Equal(t, 1, p.fs.putCount(archive.KindPolicyDeny))

	p.fs.failKind(archive.KindPolicyDeny, nil)
	st, _, _ = p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.Equal(t, 2, p.fs.putCount(archive.KindPolicyDeny), "the refused deny is written again")

	st, _, _ = p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.Equal(t, 2, p.fs.putCount(archive.KindPolicyDeny), "a stored deny is not written again")
	assert.Equal(t, parts+2, len(p.privateParts()))
}

// A deny whose decision record could not be archived writes nothing and
// reserves nothing: the next retry archives the decision and the deny.
func TestPrivateDenyAfterAFailedDecisionWriteIsNotMarkedStored(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()

	p.fs.failKind(archive.KindDecision, errArchiveDown)
	d := p.send(1, 6_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	require.Zero(t, p.fs.putCount(archive.KindPolicyDeny))

	p.fs.failKind(archive.KindDecision, nil)
	st, _, _ = p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.Equal(t, 1, p.fs.putCount(archive.KindPolicyDeny))
	_, err := p.real.Rejection(bg, d.hash, "ErrDenied")
	require.NoError(t, err)
}

// During an outage the queued deny keeps its reservation: retries add no
// PrivatePart or deny, so the archive does not show how many attempts were
// denied, and the queued deny is written exactly once when the store is back.
func TestPrivateDenyQueuedDuringAnOutageIsWrittenOnce(t *testing.T) {
	p := newPrivateEnv(t)
	tick := make(chan time.Time)
	p.deps.SweepTick = tick
	p.startPolicy()
	parts := len(p.privateParts())

	p.fs.failKind(archive.KindPolicyDeny, errArchiveDown)
	d := p.send(1, 6_000_000)
	for range 4 {
		st, _, _ := p.authorizeRaw(d)
		require.GreaterOrEqual(t, st, 400)
	}
	assert.Equal(t, 1, p.fs.putCount(archive.KindPolicyDeny), "retries during the outage queue no other deny")
	assert.Equal(t, parts+1, len(p.privateParts()), "one PrivatePart however many attempts")

	tick <- t0
	tick <- t0
	assert.GreaterOrEqual(t, p.fs.putCount(archive.KindPolicyDeny), 2, "the queued deny is retried")
	assert.Zero(t, p.storedDenies(d))

	p.fs.failKind(archive.KindPolicyDeny, nil)
	tick <- t0
	eventually(t, func() bool { return p.storedDenies(d) == 1 }, "the queued deny is written")
	tick <- t0
	tick <- t0
	n := p.fs.putCount(archive.KindPolicyDeny)
	st, _, _ := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.Equal(t, n, p.fs.putCount(archive.KindPolicyDeny), "a stored deny is not written again")
	assert.Equal(t, 1, p.storedDenies(d), "written exactly once")
	assert.Equal(t, parts+1, len(p.privateParts()))
}

// storedDenies counts the policy_deny records the archive holds for d.
func (p *policyEnv) storedDenies(d decision) int {
	p.t.Helper()
	rel, err := archive.PolicyDenyPath(d.hash, "ErrDenied")
	require.NoError(p.t, err)
	n := 0
	for name := range p.archiveFiles() {
		if filepath.Dir(name) == filepath.Dir(rel) {
			n++
		}
	}
	return n
}
