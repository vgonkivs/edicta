package gate_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/test/gatefix"
)

var errArchiveDown = errors.New("archive down")

// callLog orders events across several fakes.
type callLog struct {
	mu sync.Mutex
	ev []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	l.ev = append(l.ev, s)
	l.mu.Unlock()
}

func (l *callLog) events() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// fakeArchiver is idempotent per commitment hash and refuses different bytes
// under a stored key.
type fakeArchiver struct {
	log *callLog

	mu            sync.Mutex
	calls         []gate.DecisionRecord
	deadlines     []time.Time
	hasDeadline   []bool
	stored        map[commitment.Hash]gate.DecisionRecord
	err           error
	writeThenFail bool
	block         bool
	onPut         func()
}

func newFakeArchiver(log *callLog) *fakeArchiver {
	return &fakeArchiver{log: log, stored: make(map[commitment.Hash]gate.DecisionRecord)}
}

func (a *fakeArchiver) setErr(err error) {
	a.mu.Lock()
	a.err = err
	a.mu.Unlock()
}

func (a *fakeArchiver) Put(ctx context.Context, rec gate.DecisionRecord) error {
	rec.Envelope = bytes.Clone(rec.Envelope)
	rec.Action = bytes.Clone(rec.Action)
	if a.log != nil {
		a.log.add("archive.put")
	}
	a.mu.Lock()
	a.calls = append(a.calls, rec)
	dl, ok := ctx.Deadline()
	a.deadlines = append(a.deadlines, dl)
	a.hasDeadline = append(a.hasDeadline, ok)
	err, block, wtf, hook := a.err, a.block, a.writeThenFail, a.onPut
	a.mu.Unlock()
	if hook != nil {
		hook()
	}
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if err != nil && !wtf {
		return err
	}
	a.mu.Lock()
	old, exists := a.stored[rec.CommitmentHash]
	switch {
	case !exists:
		a.stored[rec.CommitmentHash] = rec
	case !bytes.Equal(old.Envelope, rec.Envelope) || !bytes.Equal(old.Action, rec.Action):
		a.mu.Unlock()
		return errors.New("conflict")
	}
	a.mu.Unlock()
	return err
}

func (a *fakeArchiver) puts() []gate.DecisionRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]gate.DecisionRecord(nil), a.calls...)
}

func (a *fakeArchiver) records() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.stored)
}

func withArchiver(a gate.Archiver) gatefix.Option {
	return gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = a })
}

func archivedEnv(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *fakeArchiver, *commitment.Commitment, []byte, commitment.Hash) {
	t.Helper()
	a := newFakeArchiver(nil)
	e, c, b, h := happy(t, append([]gatefix.Option{withArchiver(a)}, opts...)...)
	return e, a, c, b, h
}

func TestArchiveStageRunsOnlyAfterSignatureAllowlistAndAction(t *testing.T) {
	type row struct {
		name  string
		want  error
		build func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte)
	}
	std := func(t *testing.T, a *fakeArchiver, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
		return happy(t, append([]gatefix.Option{withArchiver(a)}, opts...)...)
	}
	rows := []row{
		{"signature by another key", commitment.ErrSignatureInvalid, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, _, _ := std(t, a)
			b, _ := gatefix.SignWith(t, gatefix.Key(t, "agent2"), c)
			return e, c, b, gatefix.Action(t)
		}},
		{"zero signature", commitment.ErrSignatureInvalid, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, _, _ := std(t, a)
			b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
			require.NoError(t, err)
			return e, c, b, gatefix.Action(t)
		}},
		{"garbage envelope", commitment.ErrMalformed, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, _, _ := std(t, a)
			return e, c, []byte{0xff, 0x00}, gatefix.Action(t)
		}},
		{"action type not configured", commitment.ErrActionTypeNotAllowed, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e := gatefix.New(t, withArchiver(a))
			c := gatefix.WithAction(t, gatefix.Template(t), "application/json", gatefix.Action(t))
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b, gatefix.Action(t)
		}},
		{"agent not in the allowlist", gate.ErrAgentNotAllowed, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e := gatefix.New(t, withArchiver(a), gatefix.WithAllowlist(map[string][]byte{"someone-else": gatefix.Pub(t, "agent2")}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b, gatefix.Action(t)
		}},
		{"allowlist maps the id to another key", gate.ErrAgentKeyMismatch, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e := gatefix.New(t, withArchiver(a), gatefix.WithAllowlist(map[string][]byte{"dca-agent-1": gatefix.Pub(t, "agent2")}))
			c := gatefix.Template(t)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			return e, c, b, gatefix.Action(t)
		}},
		{"wrong action bytes", commitment.ErrActionMismatch, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, b, _ := std(t, a)
			return e, c, b, gatefix.OtherAction(t, 1)
		}},
		{"empty action bytes", commitment.ErrActionSize, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, b, _ := std(t, a)
			return e, c, b, nil
		}},
		{"da not allowed", gate.ErrDANotAllowed, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, b, _ := std(t, a, gatefix.WithConfig(func(c *gate.Config) { c.AllowedDA = []commitment.DA{commitment.DAFibre} }))
			return e, c, b, gatefix.Action(t)
		}},
		{"expired", commitment.ErrExpired, func(t *testing.T, a *fakeArchiver) (*gatefix.Env, *commitment.Commitment, []byte, []byte) {
			e, c, b, _ := std(t, a, gatefix.WithNow(1791000900))
			return e, c, b, gatefix.Action(t)
		}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			a := newFakeArchiver(nil)
			e, c, b, action := tc.build(t, a)
			res, err := e.AuthorizeWith(b, action)
			e.RequireRejected(c, err, tc.want)
			assert.Empty(t, a.puts(), "the archive was written for a request refused before the stage")
			assert.False(t, res.DecisionArchived)
			assert.Empty(t, res.Authorization)
		})
	}
}

func TestArchiveStagePutsExactBytes(t *testing.T) {
	e, a, c, b, h := archivedEnv(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.True(t, res.DecisionArchived)
	puts := a.puts()
	require.Len(t, puts, 1)
	assert.Equal(t, h, puts[0].CommitmentHash)
	assert.Equal(t, b, puts[0].Envelope)
	assert.Equal(t, gatefix.Action(t), puts[0].Action)
	assert.Equal(t, res.CommitmentHash, puts[0].CommitmentHash)
	_, err = e.Entry(c)
	require.NoError(t, err)
}

// mutatingArchiver scribbles over the record it is given, as a careless
// implementation might.
type mutatingArchiver struct{ inner *fakeArchiver }

func (m *mutatingArchiver) Put(ctx context.Context, rec gate.DecisionRecord) error {
	err := m.inner.Put(ctx, rec)
	for i := range rec.Envelope {
		rec.Envelope[i] ^= 0xff
	}
	for i := range rec.Action {
		rec.Action[i] ^= 0xff
	}
	return err
}

func TestArchiverMutatingItsRecordDoesNotAffectTheGate(t *testing.T) {
	inner := newFakeArchiver(nil)
	e, c, b, h := happy(t, withArchiver(&mutatingArchiver{inner: inner}))
	in := bytes.Clone(b)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	assert.Equal(t, in, b, "the presented envelope is not written through")
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
}

func TestArchiveStageOrder(t *testing.T) {
	log := &callLog{}
	a := newFakeArchiver(log)
	e, _, b, _ := happy(t, withArchiver(a), gatefix.WithFaultyRegistry())
	e.Faulty.Before("Get", func() { log.add("registry.get") })
	e.Faulty.Before("Consume", func() { log.add("registry.consume") })
	e.DA.OnFetch(func() { log.add("da.fetch") })
	_, err := e.Authorize(b)
	require.NoError(t, err)
	got := log.events()
	require.Equal(t, "archive.put", got[0], "the archive is the first stateful call: %v", got)
	require.Contains(t, got, "registry.get")
	require.Contains(t, got, "registry.consume")
	assert.Equal(t, []string{"archive.put", "registry.get", "da.fetch", "registry.consume"}, got)
}

func TestArchiveStageOrderAgainstSignerAndChain(t *testing.T) {
	log := &callLog{}
	a := newFakeArchiver(log)
	e, c, b, _ := happy(t, withArchiver(a))
	e.Anchors.Fail(errors.New("lookup failed"))
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	assert.Equal(t, []string{"archive.put"}, log.events(), "the archive precedes the anchor lookup")
	e.RequireUntouched(c)
}

func TestArchiveErrorIsUnavailableAndRetryable(t *testing.T) {
	e, a, c, b, h := archivedEnv(t)
	a.setErr(errArchiveDown)

	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
	require.ErrorIs(t, err, errArchiveDown, "the cause stays reachable")
	assert.Empty(t, res.Authorization)
	assert.False(t, res.DecisionArchived)
	assert.Equal(t, h, res.CommitmentHash)
	e.RequireUntouched(c)
	require.EqualValues(t, 0, e.DA.Fetches(), "nothing is read after the archive failed")
	m, err := e.Reg.Meta(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(gatefix.Epoch), m.Watermark, "the watermark did not move")

	a.setErr(nil)
	res, err = e.Authorize(b)
	require.NoError(t, err, "the same request succeeds once the archive is back")
	require.NotEmpty(t, res.Authorization)
	assert.True(t, res.DecisionArchived)
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)

	_, err = e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed, "exactly one Authorization per nonce")
}

func TestArchiveWrittenThenFailedYieldsNoAuthorization(t *testing.T) {
	e, a, c, b, _ := archivedEnv(t)
	a.mu.Lock()
	a.err, a.writeThenFail = errArchiveDown, true
	a.mu.Unlock()
	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
	assert.Empty(t, res.Authorization)
	e.RequireUntouched(c)
	assert.Equal(t, 1, a.records(), "the record is durable although the gate refused")

	a.mu.Lock()
	a.err = nil
	a.mu.Unlock()
	_, err = e.Authorize(b)
	require.NoError(t, err)
	assert.Equal(t, 1, a.records())
}

func TestArchiveTimeout(t *testing.T) {
	t.Run("a stuck archive is unavailable", func(t *testing.T) {
		e, a, c, b, _ := archivedEnv(t, gatefix.WithConfig(func(c *gate.Config) { c.ArchiveWriteTimeout = time.Millisecond }))
		a.mu.Lock()
		a.block = true
		a.mu.Unlock()
		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
		assert.Empty(t, res.Authorization)
		e.RequireUntouched(c)

		a.mu.Lock()
		a.block = false
		a.mu.Unlock()
		_, err = e.Authorize(b)
		require.NoError(t, err)
	})
	t.Run("the write context carries the configured deadline", func(t *testing.T) {
		e, a, _, b, _ := archivedEnv(t, gatefix.WithConfig(func(c *gate.Config) { c.ArchiveWriteTimeout = 7 * time.Second }))
		start := time.Now()
		_, err := e.Authorize(b)
		require.NoError(t, err)
		require.Len(t, a.hasDeadline, 1)
		require.True(t, a.hasDeadline[0])
		remaining := a.deadlines[0].Sub(start)
		assert.Greater(t, remaining, 6*time.Second)
		assert.LessOrEqual(t, remaining, 7*time.Second+time.Second)
	})
	t.Run("the default is ten seconds", func(t *testing.T) {
		assert.Equal(t, 10*time.Second, gate.DefaultConfig().ArchiveWriteTimeout)
	})
}

func TestArchiveParentContext(t *testing.T) {
	t.Run("cancelled during the write is a context error", func(t *testing.T) {
		a := newFakeArchiver(nil)
		e, c, b, _ := happy(t, withArchiver(a))
		ctx, cancel := context.WithCancel(context.Background())
		a.mu.Lock()
		a.block = true
		a.onPut = cancel
		a.mu.Unlock()
		_, err := e.Gate.Authorize(ctx, b, gatefix.Action(t))
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, gate.ErrArchiveUnavailable)
		e.RequireUntouched(c)
	})
	t.Run("already cancelled never reaches the archive", func(t *testing.T) {
		a := newFakeArchiver(nil)
		e, c, b, _ := happy(t, withArchiver(a))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.Gate.Authorize(ctx, b, gatefix.Action(t))
		require.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, a.puts())
		e.RequireUntouched(c)
	})
}

func TestNilArchiverBehaviourUnchanged(t *testing.T) {
	e, c, b, h := happy(t)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	assert.False(t, res.DecisionArchived, "no archiver, no archive stage")
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
}

func TestDuplicatePutIsIdempotent(t *testing.T) {
	e, a, c, b, _ := archivedEnv(t)
	first, err := e.Authorize(b)
	require.NoError(t, err)
	second, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed, "the duplicate is a replay, not an archive failure")
	assert.NotErrorIs(t, err, gate.ErrArchiveUnavailable)
	assert.Equal(t, first.Authorization, second.Authorization)
	assert.True(t, second.DecisionArchived)
	puts := a.puts()
	require.Len(t, puts, 2, "the stage runs before the nonce is read")
	assert.Equal(t, puts[0], puts[1])
	assert.Equal(t, 1, a.records())
	_, err = e.Entry(c)
	require.NoError(t, err)
}

func TestArchivedDecisionRefusedLaterStaysArchived(t *testing.T) {
	a := newFakeArchiver(nil)
	e := gatefix.New(t, withArchiver(a))
	c := gatefix.Template(t)
	e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c))
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrPayloadUnavailable)
	assert.True(t, res.DecisionArchived, "the stage passed before the verdict")
	e.RequireUntouched(c)
	require.Len(t, a.puts(), 1)
	assert.Equal(t, h, a.puts()[0].CommitmentHash)
}

func TestConcurrentSameRequestAuthorizesOnce(t *testing.T) {
	a := newFakeArchiver(nil)
	e, c, b, _ := happy(t, withArchiver(a))
	const n = 16
	var wg sync.WaitGroup
	var ok, used atomic.Int32
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.Authorize(b)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, gate.ErrNonceUsed):
				used.Add(1)
			default:
				assert.NoError(t, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	assert.EqualValues(t, 1, ok.Load())
	assert.EqualValues(t, n-1, used.Load())
	assert.Equal(t, 1, a.records())
	_, err := e.Entry(c)
	require.NoError(t, err)
}

func TestArchiveConfigValidation(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		c := validConfig()
		c.ArchiveWriteTimeout = d
		require.ErrorIs(t, c.ValidateBasic(), gate.ErrInvalidConfig, "timeout %v", d)
	}
	c := validConfig()
	c.ArchiveWriteTimeout = time.Nanosecond
	require.NoError(t, c.ValidateBasic())
}

func TestResultAuthorizedAt(t *testing.T) {
	t.Run("the clock reading used for the Authorization", func(t *testing.T) {
		e, _, b, _ := happy(t)
		e.DA.OnFetch(func() { e.Clock.Advance(5 * time.Second) })
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, gatefix.Now+5, res.AuthorizedAt)
		assert.Equal(t, gatefix.Now, res.K2.CheckedAt, "the check time stays the first reading")
		ent, err := e.Entry(mustCommitment(t, b))
		require.NoError(t, err)
		assert.Equal(t, ent.AuthorizedAt, res.AuthorizedAt)
	})
	t.Run("replay returns the stored time", func(t *testing.T) {
		e, c, b, _ := happy(t)
		first, err := e.Authorize(b)
		require.NoError(t, err)
		e.Clock.Advance(20 * time.Second)
		second, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.NotEmpty(t, second.Authorization)
		assert.Equal(t, first.AuthorizedAt, second.AuthorizedAt)
		_ = c
	})
	t.Run("zero on a refusal", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithNow(1791000900))
		res, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrExpired)
		assert.Zero(t, res.AuthorizedAt)
	})
}

func mustCommitment(t *testing.T, envelope []byte) *commitment.Commitment {
	t.Helper()
	s, err := commitment.DecodeSigned(envelope)
	require.NoError(t, err)
	return &s.Commitment
}

// sourcedParams adds a retention source to the chain parameters fake.
type sourcedParams struct {
	*gatetest.ChainParams
	src   gate.RetentionSource
	calls atomic.Int32
}

var _ gate.SourcedChainParams = (*sourcedParams)(nil)

func (p *sourcedParams) FibreRetentionSourced(ctx context.Context, height uint64) (uint64, gate.RetentionSource, error) {
	p.calls.Add(1)
	v, err := p.FibreRetention(ctx, height)
	if err != nil {
		return 0, 0, err
	}
	return v, p.src, nil
}

func fibreWithParams(t *testing.T, p *sourcedParams) (*gatefix.Env, *commitment.Commitment, []byte) {
	t.Helper()
	e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
		p.ChainParams = d.Params.(*gatetest.ChainParams)
		d.Params = p
	}))
	c := gatefix.FibreTemplate(t)
	e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c)-5)
	e.DA.Put(c.PayloadRef, gatefix.FibreBlob())
	e.Chain.SetLatest(14400)
	e.Chain.SetAt(c.PayloadRef.Height, 14300)
	b, _ := gatefix.Sign(t, "agent1", c)
	return e, c, b
}

func TestK2RecordsRetentionSource(t *testing.T) {
	for _, src := range []gate.RetentionSource{1, 2, 3} {
		t.Run(string(rune('0'+src)), func(t *testing.T) {
			p := &sourcedParams{src: src}
			e, c, b := fibreWithParams(t, p)
			res, err := e.Authorize(b)
			require.NoError(t, err)
			assert.Equal(t, gate.K2Inputs{
				DA:                 commitment.DAFibre,
				CheckedAt:          gatefix.Now,
				BlockTime:          gatefix.BlockTime(c),
				RetentionStart:     gatefix.BlockTime(c) - 5,
				RetentionLatestS:   14400,
				RetentionAtHeightS: 14300,
				RetentionSource:    src,
			}, res.K2)
			assert.Positive(t, p.calls.Load(), "the sourced reader was used")
		})
	}

	t.Run("plain params leave the source unset", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.FibreTemplate(t)
		e.StageDA(c, gatefix.FibreBlob())
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, commitment.DAFibre, res.K2.DA)
		assert.Zero(t, res.K2.RetentionSource)
		assert.NotZero(t, res.K2.RetentionAtHeightS)
	})

	t.Run("an unreadable at-height value is still unavailable", func(t *testing.T) {
		p := &sourcedParams{src: 1}
		e, c, b := fibreWithParams(t, p)
		e.Chain.FailHistorical(errors.New("pruned state"))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrRetentionUnavailable)
	})

	t.Run("da = 2 records the blob retention and no Fibre fields", func(t *testing.T) {
		p := &sourcedParams{src: 3}
		e := gatefix.New(t,
			gatefix.WithConfig(func(c *gate.Config) { c.BlobRetentionS = 14400 }),
			gatefix.WithDeps(func(d *gate.Deps) {
				p.ChainParams = d.Params.(*gatetest.ChainParams)
				d.Params = p
			}))
		c := gatefix.Template(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		assert.Equal(t, gate.K2Inputs{
			DA:             commitment.DACelestiaBlob,
			CheckedAt:      gatefix.Now,
			BlockTime:      gatefix.BlockTime(c),
			BlobRetentionS: 14400,
		}, res.K2)
	})
}

func TestRetentionSourceValuesMatchTheArchiveEnum(t *testing.T) {
	assert.EqualValues(t, archive.RetentionDirect, gate.RetentionSource(retention.SourceDirect))
	assert.EqualValues(t, archive.RetentionObserved, gate.RetentionSource(retention.SourceObserved))
	assert.EqualValues(t, archive.RetentionBoth, gate.RetentionSource(retention.SourceBoth))
	assert.EqualValues(t, 1, retention.SourceDirect)
	assert.EqualValues(t, 2, retention.SourceObserved)
	assert.EqualValues(t, 3, retention.SourceBoth)
}
