package recorder_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

var decisionBlob = []byte("decision payload")

// diedAfterPayloadWrite leaves a payload record behind whose submit never
// reached the chain, as a process killed right after the write would.
func diedAfterPayloadWrite(t *testing.T, dir string, ch *nodefake.Chain, blob []byte) {
	t.Helper()
	sub := newLanding(ch)
	sub.NoLand, sub.Err = true, context.Canceled
	_, err := mk(t, archCfg(openArchive(t, dir)), sub, ev(t, ch, blob)).Publish(bg, blob)
	require.Error(t, err)
	require.Equal(t, 1, sub.Calls)
}

func grow(ch *nodefake.Chain, to uint64) {
	for h := genesis + 1; h <= to; h++ {
		ch.AddHeader(blockAt(h))
	}
}

func settleCfg(st archive.Store, settle uint64) recorder.Config {
	c := archCfg(st)
	c.SettleBlocks = settle
	return c
}

func TestStaleIntentIsEventuallySubmittedExactlyOnce(t *testing.T) {
	t.Run("one scan covers the window", func(t *testing.T) {
		dir := t.TempDir()
		ch := newChain()
		diedAfterPayloadWrite(t, dir, ch, decisionBlob)

		grow(ch, genesis+400)
		sub := newLanding(ch)
		rec := mk(t, settleCfg(openArchive(t, dir), 256), sub, ev(t, ch, decisionBlob))
		p, err := rec.Publish(bg, decisionBlob)
		require.NoError(t, err)
		assert.Equal(t, 1, sub.Calls)
		assert.Equal(t, genesis+401, p.Ref.Height)
	})

	t.Run("the scan resumes across calls", func(t *testing.T) {
		const settle = 2000
		dir := t.TempDir()
		ch := newChain()
		diedAfterPayloadWrite(t, dir, ch, decisionBlob)

		grow(ch, genesis+2500)
		sub := newLanding(ch)
		rec := mk(t, settleCfg(openArchive(t, dir), settle), sub, ev(t, ch, decisionBlob))
		_, err := rec.Publish(bg, decisionBlob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "one call reads at most the scan cap")
		assert.Zero(t, sub.Calls)

		p, err := rec.Publish(bg, decisionBlob)
		require.NoError(t, err, "the second call finishes the window instead of starting over")
		assert.Equal(t, 1, sub.Calls)
		assert.Equal(t, genesis+2501, p.Ref.Height)

		p2, err := rec.Publish(bg, decisionBlob)
		require.NoError(t, err)
		assert.Equal(t, p, p2)
		assert.Equal(t, 1, sub.Calls)
	})

	t.Run("an earlier submit inside the window is found, not repeated", func(t *testing.T) {
		dir := t.TempDir()
		ch := newChain()
		first := newLanding(ch)
		first.Err, first.ErrAfterLand = context.DeadlineExceeded, true
		_, err := mk(t, settleCfg(openArchive(t, dir), 256), first, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		grow(ch, genesis+400)

		sub := newLanding(ch)
		p, err := mk(t, settleCfg(openArchive(t, dir), 256), sub, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.NoError(t, err)
		assert.Zero(t, sub.Calls)
		assert.Equal(t, genesis+1, p.Ref.Height)
	})
}

func TestLaggingNodeNeverSubmits(t *testing.T) {
	dir := t.TempDir()
	ch := newChain()
	diedAfterPayloadWrite(t, dir, ch, decisionBlob)

	behind := nodefake.NewChain(signer)
	behind.AddHeader(blockAt(genesis - 10))
	sub := newLanding(behind)
	st := openArchive(t, dir)
	rec := mk(t, settleCfg(st, 256), sub, ev(t, behind, decisionBlob))
	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Zero(t, sub.Calls, "a node behind the intent height says nothing about earlier submits")

	_, err = st.Evidence(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, decisionBlob))
	require.ErrorIs(t, err, archive.ErrNotFound)

	// Once the node has caught up the call goes on as usual.
	grow(behind, genesis+300)
	p, err := rec.Publish(bg, decisionBlob)
	require.NoError(t, err)
	assert.Equal(t, 1, sub.Calls)
	assert.Equal(t, genesis+301, p.Ref.Height)
}

type zeroHead struct{ node.Reader }

func (zeroHead) Head(context.Context) (node.Header, error) { return node.Header{}, nil }

func TestHeadAtHeightZeroIsRefusedBeforeAnything(t *testing.T) {
	for name, withArchive := range map[string]bool{"with archive": true, "without archive": false} {
		t.Run(name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			rd := ev(t, zeroHead{ch}, decisionBlob)
			c := cfg()
			var st archive.Store
			if withArchive {
				st = openArchive(t, t.TempDir())
				c = archCfg(st)
			}
			_, err := mk(t, c, sub, rd).Publish(bg, decisionBlob)
			require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
			assert.Zero(t, sub.Calls)
			if withArchive {
				_, err = st.Payload(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, decisionBlob))
				require.ErrorIs(t, err, archive.ErrNotFound, "no intent height 0 is archived")
			}
		})
	}
}

func TestArchivedEvidenceIsReadBeforeSubmitting(t *testing.T) {
	t.Run("a restart answers from the archived anchor without paying", func(t *testing.T) {
		dir := t.TempDir()
		ch := newChain()
		first := newLanding(ch)
		p, err := mk(t, archCfg(openArchive(t, dir)), first, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.NoError(t, err)

		second := newLanding(ch)
		p2, err := mk(t, archCfg(openArchive(t, dir)), second, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.NoError(t, err)
		assert.Zero(t, second.Calls)
		assert.Equal(t, p, p2)
	})

	t.Run("an anchor the node cannot show yet is not visible, and nothing is paid", func(t *testing.T) {
		cases := map[string]func(ch *nodefake.Chain){
			"no header at the anchor height": func(*nodefake.Chain) {},
			"header without the blob": func(ch *nodefake.Chain) {
				ch.AddHeader(blockAt(genesis + 1))
			},
		}
		for name, prep := range cases {
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				ch := newChain()
				_, err := mk(t, archCfg(openArchive(t, dir)), newLanding(ch), ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
				require.NoError(t, err)

				other := newChain()
				prep(other)
				sub := newLanding(other)
				_, err = mk(t, archCfg(openArchive(t, dir)), sub, ev(t, other, decisionBlob)).Publish(bg, decisionBlob)
				require.ErrorIs(t, err, recorder.ErrNotVisible)
				assert.Zero(t, sub.Calls, "the archived evidence says the blob was paid for")
				assert.Zero(t, other.Submitted)
			})
		}
	})

	t.Run("a damaged evidence record is an archive fault and nothing is paid", func(t *testing.T) {
		dir := t.TempDir()
		ch := newChain()
		_, err := mk(t, archCfg(openArchive(t, dir)), newLanding(ch), ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.NoError(t, err)
		rel, err := archive.DataPath(archive.KindEvidence, commitment.DACelestiaBlob, realCommitment(t, ns, signer, decisionBlob))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte("not a record"), 0o644))

		sub := newLanding(ch)
		_, err = mk(t, archCfg(openArchive(t, dir)), sub, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
		require.ErrorIs(t, err, archive.ErrCorrupt)
		assert.Zero(t, sub.Calls)
	})
}

func TestEvidenceCheckFailureArchivesNothingAndFinishesNothing(t *testing.T) {
	signedWith := func(mut func(sh *cmtproto.SignedHeader)) func(*evReader) {
		return func(r *evReader) {
			r.signed = func(hd node.Header) ([]byte, error) {
				var sh cmtproto.SignedHeader
				if err := sh.Unmarshal(signedHeaderOf(t, hd)); err != nil {
					return nil, err
				}
				mut(&sh)
				return sh.Marshal()
			}
		}
	}
	cases := map[string]func(*evReader){
		"header of another height": signedWith(func(sh *cmtproto.SignedHeader) { sh.Header.Height++ }),
		"no commit":                signedWith(func(sh *cmtproto.SignedHeader) { sh.Commit = nil }),
		"no header":                signedWith(func(sh *cmtproto.SignedHeader) { sh.Header = nil }),
		"another data hash":        signedWith(func(sh *cmtproto.SignedHeader) { sh.Header.DataHash[0] ^= 1 }),
		"empty data hash":          signedWith(func(sh *cmtproto.SignedHeader) { sh.Header.DataHash = nil }),
		"undecodable": func(r *evReader) {
			r.signed = func(node.Header) ([]byte, error) { return []byte{0xff, 0xff, 0xff}, nil }
		},
		"a bare header instead of a signed one": func(r *evReader) {
			r.signed = func(hd node.Header) ([]byte, error) {
				return (&cmtproto.Header{ChainID: hd.ChainID, Height: int64(hd.Height), DataHash: hd.DataRoot}).Marshal()
			}
		},
		"signed header cannot be read": func(r *evReader) {
			r.signed = func(node.Header) ([]byte, error) { return nil, errBoom }
		},
		"proof of another blob": func(r *evReader) {
			wrong := realSquare(t, []byte("another payload")).proof
			r.proof = func() (node.CommitmentProof, error) { return wrong, nil }
		},
		"proof cannot be read": func(r *evReader) {
			r.proof = func() (node.CommitmentProof, error) { return nil, errBoom }
		},
	}
	for name, bend := range cases {
		t.Run(name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			st := openArchive(t, t.TempDir())
			rd := ev(t, ch, decisionBlob)
			bend(rd)
			rec := mk(t, archCfg(st), sub, rd)
			comm := realCommitment(t, ns, signer, decisionBlob)

			_, err := rec.Publish(bg, decisionBlob)
			require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
			assert.NotErrorIs(t, err, recorder.ErrArchiveUnavailable)
			assert.NotErrorIs(t, err, recorder.ErrNotVisible)
			assert.Equal(t, 1, sub.Calls)
			_, err = st.Evidence(bg, commitment.DACelestiaBlob, comm)
			require.ErrorIs(t, err, archive.ErrNotFound, "evidence that fails its checks is never archived")

			rd.signed, rd.proof = nil, nil
			p, err := rec.Publish(bg, decisionBlob)
			require.NoError(t, err, "the failed call finished nothing, so a retry completes")
			assert.Equal(t, 1, sub.Calls, "the retry never pays again")
			evd, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
			require.NoError(t, err)
			assert.Equal(t, p.Ref.Height, evd.Height)
		})
	}
}

func TestNewRefusesAnArchiveWithoutASignedHeaderReader(t *testing.T) {
	ch := newChain()
	st := openArchive(t, t.TempDir())

	_, err := recorder.New(archCfg(st), newLanding(ch), ch)
	require.Error(t, err, "found before paying, not after")
	assert.ErrorContains(t, err, "signed headers")

	_, err = recorder.New(archCfg(st), newLanding(ch), ev(t, ch, decisionBlob))
	require.NoError(t, err)
	_, err = recorder.New(cfg(), newLanding(ch), ch)
	require.NoError(t, err, "without an archive no header reader is needed")
}

func TestSettleBlocksValidation(t *testing.T) {
	tests := []struct {
		name   string
		settle uint64
		ok     bool
	}{
		{"default", 0, true},
		{"floor", 256, true},
		{"large", 1 << 20, true},
		{"just below the floor", 255, false},
		{"one", 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg()
			c.SettleBlocks = tc.settle
			err := c.ValidateBasic()
			_, nerr := recorder.New(c, newLanding(newChain()), newChain())
			if tc.ok {
				require.NoError(t, err)
				require.NoError(t, nerr)
				return
			}
			require.Error(t, err)
			require.Error(t, nerr)
		})
	}
	t.Run("a bad namespace is refused by both", func(t *testing.T) {
		c := cfg()
		c.Namespace = []byte{1}
		require.Error(t, c.ValidateBasic())
	})
}

// racingStore stores another process's payload record first, with an earlier
// intent height, so the caller's own Put finds the same payload already there.
type racingStore struct {
	archive.Store
	once   sync.Once
	intent uint64
	t      *testing.T
}

func (s *racingStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	if p, ok := r.(*archive.PayloadRecord); ok {
		s.once.Do(func() {
			early := *p
			early.IntentHeight = s.intent
			_, err := s.Store.Put(ctx, &early)
			require.NoError(s.t, err)
		})
	}
	return s.Store.Put(ctx, r)
}

func TestUnchangedPayloadPutReReadsTheRecord(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	inner := openArchive(t, t.TempDir())
	rs := &racingStore{Store: inner, intent: genesis - 50, t: t}
	rec := mk(t, settleCfg(rs, 256), sub, ev(t, ch, decisionBlob))

	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the other writer's earlier intent opens a settle window")
	assert.Zero(t, sub.Calls, "the intent height of the first writer counts, not ours")
	pr, err := inner.Payload(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, decisionBlob))
	require.NoError(t, err)
	assert.EqualValues(t, genesis-50, pr.IntentHeight)
}
