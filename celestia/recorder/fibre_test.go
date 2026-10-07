package recorder_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/sdk"
)

var _ sdk.Publisher = (*recorder.FibreRecorder)(nil)

func TestFibreConfigDefaults(t *testing.T) {
	c := recorder.FibreConfig{Namespace: ns}.WithDefaults()
	assert.EqualValues(t, 1<<20, c.MaxDataBytes)
	assert.Equal(t, 5*time.Minute, c.SubmitTimeout)
	assert.Equal(t, 2*time.Minute, c.UploadDrain)
	assert.Equal(t, 2, c.MaxDraining)
	assert.Equal(t, 60*time.Second, c.VisibleTimeout)
	assert.Equal(t, time.Second, c.PollInterval)
	assert.GreaterOrEqual(t, c.ScanBlocks, uint64(1024))
	assert.EqualValues(t, 1066, c.SettleBlocks)
	assert.Equal(t, 60*time.Second, c.MaxClockSkew)
	assert.Equal(t, 4096, c.MaxPending)

	set := recorder.FibreConfig{Namespace: ns, SubmitTimeout: time.Second, MaxDraining: 7, SettleBlocks: 300}.WithDefaults()
	assert.Equal(t, time.Second, set.SubmitTimeout)
	assert.Equal(t, 7, set.MaxDraining)
	assert.EqualValues(t, 300, set.SettleBlocks)
}

func TestFibreConfigValidateBasic(t *testing.T) {
	good := recorder.FibreConfig{Namespace: ns, OwnNode: true}.WithDefaults()
	require.NoError(t, good.ValidateBasic())

	tests := []struct {
		name string
		mod  func(c *recorder.FibreConfig)
	}{
		{"own node not attested", func(c *recorder.FibreConfig) { c.OwnNode = false }},
		{"short namespace", func(c *recorder.FibreConfig) { c.Namespace = ns[:28] }},
		{"reserved namespace", func(c *recorder.FibreConfig) { c.Namespace = make([]byte, 29) }},
		{"settle below the floor", func(c *recorder.FibreConfig) { c.SettleBlocks = 1065 }},
		{"settle of one", func(c *recorder.FibreConfig) { c.SettleBlocks = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mod(&c)
			require.Error(t, c.ValidateBasic())
		})
	}
	t.Run("the settle floor is accepted", func(t *testing.T) {
		c := good
		c.SettleBlocks = 1066
		require.NoError(t, c.ValidateBasic())
	})
	t.Run("the own node refusal says what to set", func(t *testing.T) {
		c := good
		c.OwnNode = false
		assert.ErrorContains(t, c.ValidateBasic(), "OwnNode")
	})
}

func TestNewFibreRefusals(t *testing.T) {
	t.Run("without the own node attestation", func(t *testing.T) {
		f := newFibreFx(t)
		c := f.cfg(f.openArchive(t.TempDir()))
		c.OwnNode = false
		_, err := recorder.NewFibre(c, f.deps())
		require.Error(t, err)
		assert.ErrorContains(t, err, "OwnNode")
	})
	t.Run("without an archive", func(t *testing.T) {
		f := newFibreFx(t)
		_, err := recorder.NewFibre(f.cfg(nil), f.deps())
		require.Error(t, err)
	})
	t.Run("submit endpoint differs from the consensus read endpoint", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Endpt = "public.example:9090"
		_, err := recorder.NewFibre(f.cfg(f.openArchive(t.TempDir())), f.deps())
		require.Error(t, err)
	})
	t.Run("same endpoint spelled differently is the same node", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Endpt = "https://Consensus.Example:9090"
		_, err := recorder.NewFibre(f.cfg(f.openArchive(t.TempDir())), f.deps())
		require.NoError(t, err)
	})
	t.Run("same host on another port is another node", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Endpt = "consensus.example:9091"
		_, err := recorder.NewFibre(f.cfg(f.openArchive(t.TempDir())), f.deps())
		require.Error(t, err)
	})
	t.Run("data cap above the committer cap", func(t *testing.T) {
		f := newFibreFx(t)
		d := f.deps()
		var err error
		d.Committer, err = fibrecommit.New(1024)
		require.NoError(t, err)
		c := f.cfg(f.openArchive(t.TempDir()))
		c.MaxDataBytes = 2048
		_, err = recorder.NewFibre(c, d)
		require.Error(t, err)
	})
	deps := map[string]func(d *recorder.FibreDeps){
		"no submitter": func(d *recorder.FibreDeps) { d.Submitter = nil },
		"no reader":    func(d *recorder.FibreDeps) { d.Reader = nil },
		"no chain":     func(d *recorder.FibreDeps) { d.Chain = nil },
		"no committer": func(d *recorder.FibreDeps) { d.Committer = nil },
		"no chain id":  func(d *recorder.FibreDeps) { d.ChainID = "" },
	}
	for name, mod := range deps {
		t.Run(name, func(t *testing.T) {
			f := newFibreFx(t)
			d := f.deps()
			mod(&d)
			_, err := recorder.NewFibre(f.cfg(f.openArchive(t.TempDir())), d)
			require.Error(t, err)
		})
	}
}

func TestFibreCostUtia(t *testing.T) {
	tests := []struct {
		size uint64
		want uint64
	}{
		{0, 650_000},
		{1, 695_000},
		{262_144, 695_000},
		{262_145, 740_000},
		{16 << 20, 650_000 + 45_000*64},
	}
	for _, tc := range tests {
		got := recorder.FibreCostUtia(tc.size)
		assert.Equal(t, tc.want, got, "upload size %d", tc.size)
		assert.Equal(t, fibretypes.EstimateGasForPayForFibre(uint32(tc.size)), got, "the chain charges one utia per gas unit")
	}
}

func TestFibrePublishLiveVector(t *testing.T) {
	f := newFibreFx(t)
	l := f.l
	st := f.openArchive(t.TempDir())
	f.sub.Plan = f.ok(l.Height)
	rec := f.newRec(f.cfg(st))

	pub, err := rec.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, pub.Ref.DA)
	assert.Equal(t, l.Ref.Namespace, pub.Ref.Namespace)
	assert.Equal(t, l.Ref.Commitment, pub.Ref.Commitment)
	assert.Equal(t, l.Height, pub.Ref.Height)
	assert.Empty(t, pub.Ref.Signer, "a da = 1 reference names no signer")
	assert.EqualValues(t, l.Header.Time.Unix(), pub.BlockTime)
	assert.EqualValues(t, l.Created.Unix(), pub.RetentionStart, "floor of the promise creation time")
	assert.Equal(t, 1, f.sub.Calls())
	_, err = commitment.EncodePayloadRef(pub.Ref)
	require.NoError(t, err)

	pr, err := st.Payload(bg, commitment.DAFibre, l.Ref.Commitment)
	require.NoError(t, err)
	assert.Equal(t, f.blob, pr.Blob)
	assert.Empty(t, pr.Namespace)
	assert.Empty(t, pr.Signer)
	assert.EqualValues(t, startHead, pr.IntentHeight, "the head before the submit")

	ev, err := st.Evidence(bg, commitment.DAFibre, l.Ref.Commitment)
	require.NoError(t, err)
	want := l.Evidence(t)
	assert.Equal(t, want.Namespace, ev.Namespace)
	assert.Equal(t, l.Height, ev.Height)
	assert.Equal(t, want.AnchorTx, ev.AnchorTx)
	assert.Equal(t, want.SystemBlob, ev.SystemBlob)
	assert.Equal(t, want.SystemBlobProof, ev.SystemBlobProof)
	assert.Equal(t, want.HistoricalInfo, ev.HistoricalInfo)
	assert.Equal(t, want.PromiseHeight, ev.PromiseHeight)
	assert.EqualValues(t, 1, ev.AnchorTxIndex, "the index the node reports")
	assert.Zero(t, ev.TxCode)
	assert.Equal(t, l.PromiseValsetNext(t), ev.PromiseValset, "the set that the promise header's next validators hash commits to")

	var sh cmtproto.SignedHeader
	require.NoError(t, sh.Unmarshal(ev.Header))
	ch, err := cmttypes.HeaderFromProto(sh.Header)
	require.NoError(t, err)
	assert.Equal(t, l.HeaderHashes[l.Height], []byte(ch.Hash()))
	assert.Equal(t, l.HeaderHashes[l.Height], sh.Commit.BlockID.Hash, "the commit is bound to the header")
	var ph cmtproto.SignedHeader
	require.NoError(t, ph.Unmarshal(ev.PromiseHeader))
	pch, err := cmttypes.HeaderFromProto(ph.Header)
	require.NoError(t, err)
	assert.Equal(t, l.HeaderHashes[l.PromiseHeight], []byte(pch.Hash()))

	facts, err := anchorverify.Fibre().VerifyAnchor(pub.Ref, ev)
	require.NoError(t, err, "what the Recorder archived is what the verifier accepts")
	assert.EqualValues(t, pub.BlockTime, facts.BlockTime)
	assert.EqualValues(t, pub.RetentionStart, facts.RetentionStart)
	assert.Equal(t, l.HeaderHashes[l.Height], facts.AnchorHeaderHash)

	again, err := rec.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, pub, again)
	assert.Equal(t, 1, f.sub.Calls(), "the verified blob answers from memory")
}

func TestFibrePayloadIsArchivedBeforeTheSubmit(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	seen := false
	inner := f.ok(f.l.Height)
	f.sub.Plan = func(call int, n, d []byte) nodefake.SubmitPlan {
		seen = true
		p, err := st.Payload(bg, commitment.DAFibre, f.l.Ref.Commitment)
		assert.NoError(t, err, "the archive holds the payload before the submit")
		if err == nil {
			assert.Equal(t, f.blob, p.Blob)
		}
		_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
		assert.ErrorIs(t, err, archive.ErrNotFound, "no evidence before the anchor is read back")
		return inner(call, n, d)
	}
	_, err := f.newRec(f.cfg(st)).Publish(bg, f.blob)
	require.NoError(t, err)
	assert.True(t, seen)
}

func TestFibreBlobBoundsAndEmptyBlob(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	f.sub.Plan = f.ok(f.l.Height)
	rec := f.newRec(f.cfg(st))

	_, err := rec.Publish(bg, make([]byte, 2000))
	require.ErrorIs(t, err, recorder.ErrTooLarge)
	_, err = rec.Publish(bg, nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Zero(t, f.sub.Calls())
	assert.Zero(t, f.sub.EscrowReads())

	orig := append([]byte(nil), f.blob...)
	_, err = rec.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, orig, f.blob, "the blob is never modified")
}

func TestFibreEscrowShortSubmitsNothing(t *testing.T) {
	const margin = 1000
	f := newFibreFx(t)
	cost := recorder.FibreCostUtia(f.us)
	st := f.openArchive(t.TempDir())
	c := f.cfg(st)
	c.EscrowMarginUtia = margin
	rec := f.newRec(c)
	f.sub.Plan = f.ok(f.l.Height)

	f.sub.SetEscrow(node.Escrow{AvailableUtia: cost + margin - 1, PendingWithdrawalUtia: 5})
	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrEscrowInsufficient)
	var sf *recorder.EscrowShortfall
	require.True(t, errors.As(err, &sf))
	assert.Equal(t, cost+margin, sf.NeedUtia)
	assert.Equal(t, cost+margin-1, sf.AvailableUtia)
	assert.EqualValues(t, 1, sf.ShortUtia, "the shortfall is exact")
	assert.Zero(t, f.sub.Calls(), "nothing is submitted without the escrow")

	f.sub.SetEscrow(node.Escrow{AvailableUtia: cost + margin})
	pub, err := rec.Publish(bg, f.blob)
	require.NoError(t, err, "the exact amount pays")
	assert.Equal(t, f.l.Height, pub.Ref.Height)
	assert.Equal(t, 1, f.sub.Calls())
}

func TestFibreEscrowReadFailureSubmitsNothing(t *testing.T) {
	f := newFibreFx(t)
	f.sub.EscrowErr = node.ErrUnavailable
	f.sub.Plan = f.ok(f.l.Height)
	_, err := f.newRec(f.cfg(f.openArchive(t.TempDir()))).Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.NotErrorIs(t, err, recorder.ErrEscrowInsufficient)
	assert.Zero(t, f.sub.Calls())
	assert.Positive(t, f.sub.EscrowReads())
}

func TestFibreEscrowCountsSubmitsInFlight(t *testing.T) {
	f := newFibreFx(t)
	cost := recorder.FibreCostUtia(f.us)
	f.sub.SetEscrow(node.Escrow{AvailableUtia: cost + cost/2})
	entered, release := make(chan struct{}), make(chan struct{})
	inner := f.ok(f.l.Height)
	f.sub.Plan = func(call int, n, d []byte) nodefake.SubmitPlan {
		p := inner(call, n, d)
		p.Block = release
		close(entered)
		return p
	}
	rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))

	done := make(chan error, 1)
	go func() { _, err := rec.Publish(bg, f.blob); done <- err }()
	<-entered

	_, err := rec.Publish(bg, []byte{1, 2, 3})
	require.ErrorIs(t, err, recorder.ErrEscrowInsufficient, "the balance already pays for the upload in flight")
	var sf *recorder.EscrowShortfall
	require.True(t, errors.As(err, &sf))
	assert.Equal(t, 2*cost, sf.NeedUtia)
	assert.Equal(t, 1, f.sub.Calls())

	close(release)
	require.NoError(t, <-done)
}

func TestFibreSubmitMismatch(t *testing.T) {
	cases := map[string]func(r *node.FibreResult){
		"blob id version":    func(r *node.FibreResult) { r.BlobID[0] = 1 },
		"blob id commitment": func(r *node.FibreResult) { r.BlobID[5] ^= 1 },
		"commitment":         func(r *node.FibreResult) { r.Commitment[0] ^= 1 },
		"namespace": func(r *node.FibreResult) {
			r.Namespace = append([]byte(nil), r.Namespace...)
			r.Namespace[28] ^= 1
		},
		"blob size": func(r *node.FibreResult) { r.BlobSize++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFibreFx(t)
			st := f.openArchive(t.TempDir())
			f.sub.Plan = func(_ int, n, d []byte) nodefake.SubmitPlan {
				r := f.result(n, d, f.l.Height)
				mutate(&r)
				return nodefake.SubmitPlan{Result: r}
			}
			rec := f.newRec(f.cfg(st))

			_, err := rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrSubmitMismatch)
			assert.Equal(t, 1, f.sub.Calls())

			_, err = rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrSubmitMismatch, "sticky for this blob")
			assert.Equal(t, 1, f.sub.Calls(), "a second call submits nothing")
			_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
			require.ErrorIs(t, err, archive.ErrNotFound)
		})
	}
}

func TestFibreArchiveDownBeforeSubmitSubmitsNothing(t *testing.T) {
	cases := map[string]func(s *flakyStore){
		"payload write":   func(s *flakyStore) { s.failPut(archive.KindPayload, errBoom) },
		"payload read":    func(s *flakyStore) { s.failGet(archive.KindPayload, errBoom) },
		"evidence read":   func(s *flakyStore) { s.failGet(archive.KindEvidence, errBoom) },
		"payload corrupt": func(s *flakyStore) { s.failGet(archive.KindPayload, archive.ErrCorrupt) },
	}
	for name, down := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFibreFx(t)
			fs := newFlaky(f.openArchive(t.TempDir()))
			down(fs)
			f.sub.Plan = f.ok(f.l.Height)
			rec := f.newRec(f.cfg(fs))

			_, err := rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
			assert.Zero(t, f.sub.Calls(), "nothing is submitted without the payload archived")
			assert.Zero(t, f.sub.EscrowReads())
		})
	}
}

func TestFibreEvidenceWriteFailureRetryPaysNothing(t *testing.T) {
	t.Run("same process", func(t *testing.T) {
		f := newFibreFx(t)
		fs := newFlaky(f.openArchive(t.TempDir()))
		fs.failPut(archive.KindEvidence, errBoom)
		f.sub.Plan = f.ok(f.l.Height)
		rec := f.newRec(f.cfg(fs))

		_, err := rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
		require.Equal(t, 1, f.sub.Calls())
		_, err = fs.Store.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
		require.ErrorIs(t, err, archive.ErrNotFound)

		fs.failPut(archive.KindEvidence, nil)
		pub, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)
		assert.Equal(t, 1, f.sub.Calls(), "the retry pays nothing")
		assert.Equal(t, f.l.Height, pub.Ref.Height)
		_, err = fs.Store.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
		require.NoError(t, err)
	})
	t.Run("after a restart", func(t *testing.T) {
		f := newFibreFx(t)
		dir := t.TempDir()
		fs := newFlaky(f.openArchive(dir))
		fs.failPut(archive.KindEvidence, errBoom)
		f.sub.Plan = f.ok(f.l.Height)
		_, err := f.newRec(f.cfg(fs)).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)

		pub, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.NoError(t, err)
		assert.Equal(t, 1, f.sub.Calls(), "the scan finds the PayForFibre that was paid for")
		assert.Equal(t, f.l.Height, pub.Ref.Height)
	})
}

func TestFibreEvidenceFirstAnswersOffline(t *testing.T) {
	published := func(t *testing.T) (*fibreFx, string, sdk.Published) {
		f := newFibreFx(t)
		dir := t.TempDir()
		f.sub.Plan = f.ok(f.l.Height)
		pub, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.NoError(t, err)
		require.Equal(t, 1, f.sub.Calls())
		return f, dir, pub
	}
	t.Run("the header is still served", func(t *testing.T) {
		f, dir, pub := published(t)
		got, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.NoError(t, err)
		assert.Equal(t, pub, got)
		assert.Equal(t, 1, f.sub.Calls())
	})
	t.Run("the node pruned the header", func(t *testing.T) {
		f, dir, pub := published(t)
		f.grow(f.l.Height + 5)
		f.node.Prune(f.l.Height + 1)
		got, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.NoError(t, err, "no chain read of the blob is needed")
		assert.Equal(t, pub, got)
		assert.Equal(t, 1, f.sub.Calls())
	})
	t.Run("the node serves another header at the anchor height", func(t *testing.T) {
		f, dir, _ := published(t)
		other := f.l.Header
		other.Time = other.Time.Add(time.Second)
		f.node.SetSignedHeader(f.l.Height, fibrefixBound(t, other))
		_, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
		assert.Equal(t, 1, f.sub.Calls())
	})
	t.Run("the stored evidence fails verification", func(t *testing.T) {
		f, dir, _ := published(t)
		st := f.openArchive(dir)
		rel, err := archive.DataPath(archive.KindEvidence, commitment.DAFibre, f.l.Ref.Commitment)
		require.NoError(t, err)
		require.NoError(t, writeFile(dir, rel, []byte("not a record")))
		_, err = f.newRec(f.cfg(st)).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
		require.ErrorIs(t, err, archive.ErrCorrupt)
		assert.Equal(t, 1, f.sub.Calls())
	})
}

func TestFibreStoredEvidenceOfAnotherBindingIsAConflict(t *testing.T) {
	cases := map[string]func(ev *archive.EvidenceRecord){
		"another namespace": func(ev *archive.EvidenceRecord) {
			ev.Namespace = append([]byte(nil), ev.Namespace...)
			ev.Namespace[28] ^= 1
		},
		"tampered system blob": func(ev *archive.EvidenceRecord) {
			ev.SystemBlob = append([]byte(nil), ev.SystemBlob...)
			ev.SystemBlob[3] ^= 1
		},
		"cut proof": func(ev *archive.EvidenceRecord) { ev.SystemBlobProof = ev.SystemBlobProof[:len(ev.SystemBlobProof)-1] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFibreFx(t)
			st := f.openArchive(t.TempDir())
			ev := f.l.Evidence(t)
			mutate(ev)
			f.diedAfterPayload(st)
			_, err := st.Put(bg, ev)
			require.NoError(t, err)
			f.sub.Plan = f.ok(f.l.Height)
			_, err = f.newRec(f.cfg(st)).Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
			assert.Zero(t, f.sub.Calls(), "stored evidence says the blob was paid for")
		})
	}
}

func TestFibreClockSkewSubmitsNothing(t *testing.T) {
	for name, skew := range map[string]time.Duration{"clock ahead": 90 * time.Second, "clock behind": -90 * time.Second} {
		t.Run(name, func(t *testing.T) {
			f := newFibreFx(t)
			f.skew.Store(int64(skew))
			f.sub.Plan = f.ok(f.l.Height)
			rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))

			_, err := rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrClockSkew)
			assert.Zero(t, f.sub.Calls(), "the promise would be dated by a wrong clock")
			assert.Zero(t, f.sub.EscrowReads())

			f.skew.Store(int64(30 * time.Second))
			pub, err := rec.Publish(bg, f.blob)
			require.NoError(t, err, "within the bound the clock is accepted")
			assert.Equal(t, 1, f.sub.Calls())
			assert.Equal(t, f.l.Height, pub.Ref.Height)
		})
	}
}

func TestFibreNodeProblemsBeforeSubmitSubmitNothing(t *testing.T) {
	t.Run("head cannot be read", func(t *testing.T) {
		f := newFibreFx(t)
		f.node.FailLatest = node.ErrUnavailable
		_, err := f.newRec(f.cfg(f.openArchive(t.TempDir()))).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
		assert.Zero(t, f.sub.Calls())
	})
	t.Run("head at height zero", func(t *testing.T) {
		f := newFibreFx(t)
		f.node.SetHead(0)
		_, err := f.newRec(f.cfg(f.openArchive(t.TempDir()))).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
		assert.Zero(t, f.sub.Calls())
	})
}

// Each case bends one thing the node says about the anchor after the PFF
// landed. Nothing may be archived, and a retry after the node is right again
// completes without paying twice.
func TestFibreEvidenceChecksRefuseWhatTheNodeSaysWrong(t *testing.T) {
	hash := func(f *fibreFx) [32]byte { return sha256Sum(f.l.PFFTx) }
	cases := []struct {
		name string
		bend func(f *fibreFx)
	}{
		{"commit not bound to the header", func(f *fibreFx) {
			f.node.SetSignedHeader(f.l.Height, unboundSigned(t, f.l.Header))
		}},
		{"signed header of another height", func(f *fibreFx) {
			h := f.l.Header
			h.Height++
			f.node.SetSignedHeader(f.l.Height, fibrefixBound(t, h))
		}},
		{"promise header commit not bound", func(f *fibreFx) {
			f.node.SetSignedHeader(f.l.PromiseHeight, unboundSigned(t, f.l.PromiseHeaderProto(t)))
		}},
		{"promise validator set does not hash to the next validators hash", func(f *fibreFx) {
			f.node.SetValidatorSet(f.l.PromiseHeight+1, []byte{0x0a, 0x00})
		}},
		{"no promise validator set", func(f *fibreFx) {
			f.node.SetValidatorSet(f.l.PromiseHeight+1, nil)
		}},
		{"tx placed at another height", func(f *fibreFx) {
			f.node.SetTxPlace(hash(f), node.TxPlacement{Height: f.l.Height + 1, Index: 1, Status: "COMMITTED"})
		}},
		{"tx not committed", func(f *fibreFx) {
			f.node.SetTxPlace(hash(f), node.TxPlacement{Height: f.l.Height, Index: 1, Status: "PENDING"})
		}},
		{"tx placed with a failure code", func(f *fibreFx) {
			f.node.SetTxPlace(hash(f), node.TxPlacement{Height: f.l.Height, Index: 1, Code: 5, Status: "COMMITTED"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFibreFx(t)
			st := f.openArchive(t.TempDir())
			f.sub.Plan = func(_ int, n, d []byte) nodefake.SubmitPlan {
				f.node.Land(*f.pff(f.l.Height))
				tc.bend(f)
				return nodefake.SubmitPlan{Result: f.result(n, d, f.l.Height)}
			}
			rec := f.newRec(f.cfg(st))

			_, err := rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
			assert.NotErrorIs(t, err, recorder.ErrArchiveUnavailable)
			assert.Equal(t, 1, f.sub.Calls())
			_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
			require.ErrorIs(t, err, archive.ErrNotFound, "evidence that fails its checks is never archived")

			f.node.Land(*f.pff(f.l.Height))
			f.node.SetSignedHeader(f.l.PromiseHeight, fibrefixBound(t, f.l.PromiseHeaderProto(t)))
			f.node.SetValidatorSet(f.l.PromiseHeight+1, f.l.PromiseValsetNext(t))
			pub, err := rec.Publish(bg, f.blob)
			require.NoError(t, err, "the failed call finished nothing, so a retry completes")
			assert.Equal(t, 1, f.sub.Calls(), "the retry never pays again")
			assert.Equal(t, f.l.Height, pub.Ref.Height)
		})
	}
}

func TestFibreHistoricalInfoGoneBeforeTheReadBackIsNotVisible(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	f.sub.Plan = func(_ int, n, d []byte) nodefake.SubmitPlan {
		f.node.Land(*f.pff(f.l.Height))
		f.node.SetHistoricalInfo(f.l.PromiseHeight, nil)
		return nodefake.SubmitPlan{Result: f.result(n, d, f.l.Height)}
	}
	_, err := f.newRec(f.cfg(st)).Publish(bg, f.blob)
	require.Error(t, err)
	assert.True(t, errors.Is(err, recorder.ErrNodeUnavailable) || errors.Is(err, recorder.ErrNotVisible), "got %v", err)
	assert.Equal(t, 1, f.sub.Calls())
	_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestFibreConcurrentPublishesOfOneBlobSubmitOnce(t *testing.T) {
	f := newFibreFx(t)
	f.sub.Plan = f.ok(f.l.Height)
	rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))

	const n = 16
	var wg sync.WaitGroup
	pubs := make([]sdk.Published, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pubs[i], errs[i] = rec.Publish(bg, f.blob)
		}()
	}
	wg.Wait()

	ok := 0
	for i := range errs {
		if errs[i] == nil {
			ok++
			assert.Equal(t, f.l.Height, pubs[i].Ref.Height)
			continue
		}
		assert.ErrorIs(t, errs[i], recorder.ErrOutcomeUnknown, "a duplicate in flight is refused, never submitted")
	}
	assert.Positive(t, ok)
	assert.Equal(t, 1, f.sub.Calls())
	_, err := rec.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls())
}

func TestFibreContextEndsBeforeSubmitSubmitNothing(t *testing.T) {
	f := newFibreFx(t)
	f.sub.Plan = f.ok(f.l.Height)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err := f.newRec(f.cfg(f.openArchive(t.TempDir()))).Publish(ctx, f.blob)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, f.sub.Calls())
}
