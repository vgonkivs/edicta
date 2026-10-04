package gate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// blobEnv is a da = 2 commitment with the chain data staged, no blob placed.
func blobEnv(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
	t.Helper()
	e := gatefix.New(t, opts...)
	c := gatefix.Template(t)
	th := gatefix.BlockTime(c)
	e.StageChain(c, th, th)
	b, h := gatefix.Sign(t, "agent1", c)
	return e, c, b, h
}

func TestAvailabilityDAFirst(t *testing.T) {
	e, c, b, h := blobEnv(t)
	e.DA.Put(c.PayloadRef, gatefix.Blob(t))
	e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
	res, err := e.Authorize(b)
	require.NoErrorf(t, err, "res %+v err", res)
	require.Equalf(t, registry.PathDA, res.Path, "res %+v err %v", res, err)
	require.EqualValues(t, 0, e.Archive.Fetches(), "archive read although the DA layer served the blob")
	gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
}

func TestAvailabilityArchiveFallback(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *gatefix.Env, c *commitment.Commitment)
	}{
		{"DA reports the blob missing", func(e *gatefix.Env, c *commitment.Commitment) {}},
		{"DA fails", func(e *gatefix.Env, c *commitment.Commitment) { e.DA.Fail(errors.New("node down")) }},
		{"DA returns other bytes", func(e *gatefix.Env, c *commitment.Commitment) { e.DA.Put(c.PayloadRef, gatefix.BlobY(t)) }},
		{"DA returns a truncated blob", func(e *gatefix.Env, c *commitment.Commitment) {
			e.DA.Put(c.PayloadRef, gatefix.Blob(t)[:10])
		}},
		{"DA hangs until its timeout", func(e *gatefix.Env, c *commitment.Commitment) {
			e.DA.Hang()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, c, b, h := blobEnv(t, gatefix.WithConfig(func(cfg *gate.Config) { cfg.DATimeout = 20 * time.Millisecond }))
			tc.setup(e, c)
			e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
			res, err := e.Authorize(b)
			require.NoError(t, err, "Authorize")
			require.Equalf(t, registry.PathArchive, res.Path, "result %+v", res)
			gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathArchive, 0, gatefix.Now)
			ent, _ := e.Entry(c)
			require.Equalf(t, registry.PathArchive, ent.Path, "entry path %v", ent.Path)
			ev := e.Metrics.Events()
			require.Lenf(t, ev, 1, "metrics %+v", ev)
			require.EqualValuesf(t, registry.PathArchive, ev[0].Path, "metrics %+v", ev)
			require.True(t, ev[0].Authorized)
		})
	}
}

func TestAvailabilityBothMissing(t *testing.T) {
	t.Run("window holds: unavailable", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
		require.NotErrorIs(t, err, gate.ErrAnchorTooOld, "window holds, so the error must not be ErrAnchorTooOld")
		require.EqualValuesf(t, 1, e.DA.Fetches(), "fetches da=%d archive=%d", e.DA.Fetches(), e.Archive.Fetches())
		require.EqualValuesf(t, 1, e.Archive.Fetches(), "fetches da=%d archive=%d", e.DA.Fetches(), e.Archive.Fetches())
	})
	t.Run("window failed: anchor too old, also unavailable", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		routeArchive(e, c)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrAnchorTooOld)
		require.ErrorIs(t, err, gate.ErrPayloadUnavailable, "ErrAnchorTooOld must also match ErrPayloadUnavailable")
		require.EqualValues(t, 0, e.DA.Fetches(), "DA used although the window failed")
	})
	t.Run("a transient failure does not burn the nonce", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		e.DA.Fail(errors.New("node down"))
		_, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrPayloadUnavailable)
		e.RequireUntouched(c)
		e.DA.Fail(nil)
		e.DA.Put(c.PayloadRef, gatefix.Blob(t))
		_, err = e.Authorize(b)
		require.NoError(t, err, "retry")
	})
}

func TestAvailabilityIntegrity(t *testing.T) {
	t.Run("hash mismatch on both paths", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		e.DA.Put(c.PayloadRef, gatefix.BlobY(t))
		e.Archive.Put(c.PayloadRef, gatefix.BlobY(t))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("size mismatch on both paths", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		e.DA.Put(c.PayloadRef, gatefix.Blob(t)[:300])
		e.Archive.Put(c.PayloadRef, append(gatefix.Blob(t), 1))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadSizeMismatch)
	})
	t.Run("size checked before hash", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		e.DA.Put(c.PayloadRef, make([]byte, 302)) // wrong size and wrong hash
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadSizeMismatch)
		require.NotErrorIs(t, err, commitment.ErrPayloadHashMismatch, "size and hash errors both reported")
	})
	t.Run("blob of a share-version-0 post: hash ok, commitment differs", func(t *testing.T) {
		// Same bytes as X, but the anchored commitment is that of a blob with
		// other bytes: commitment bound to Y, hash bound to X.
		e := gatefix.New(t)
		c := gatefix.Template(t)
		c.PayloadRef.Commitment = gatefix.RealCommitment(t)
		c.PayloadRef.Commitment[0] ^= 1
		routeArchive(e, c)
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
	})
	t.Run("anchor X, sign hash of Y: archive path", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		y := gatefix.BlobY(t)
		sum := sha256sum(y)
		c.CiphertextHash = sum[:]
		routeArchive(e, c)
		e.Archive.Put(c.PayloadRef, y)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
	})
	t.Run("anchor X, sign hash of Y: DA serves X, archive serves Y, hash error wins", func(t *testing.T) {
		e, c, _, _ := blobEnv(t)
		c = gatefix.Clone(c)
		y := gatefix.BlobY(t)
		sum := sha256sum(y)
		c.CiphertextHash = sum[:]
		e.DA.Put(c.PayloadRef, gatefix.Blob(t))
		e.Archive.Put(c.PayloadRef, y)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("a recompute that fails with any error is a mismatch", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
			d.Committers = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: failingCommitter{}}
		}))
		c := gatefix.Template(t)
		routeArchive(e, c)
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
	})
}

type failingCommitter struct{}

func (failingCommitter) Check(_ commitment.PayloadRef, _ []byte) error {
	return gate.ErrDACommitmentMismatch
}

func TestAvailabilityFibre(t *testing.T) {
	fibre := func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
		e := gatefix.New(t)
		c := gatefix.FibreTemplate(t)
		th := gatefix.BlockTime(c)
		e.StageChain(c, th, th)
		b, _ := gatefix.Sign(t, "agent1", c)
		return e, c, b
	}
	t.Run("window failed: refused before any fetch", func(t *testing.T) {
		e, c, b := fibre(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.DA.Put(c.PayloadRef, gatefix.FibreBlob())
		e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrArchiveRecomputeUnsupported)
		require.EqualValuesf(t, 0, e.DA.Fetches()+e.Archive.Fetches(), "fetches da=%d archive=%d", e.DA.Fetches(), e.Archive.Fetches())
	})
	t.Run("DA missing inside the window: archive never read", func(t *testing.T) {
		e, c, b := fibre(t)
		e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrArchiveRecomputeUnsupported)
		require.EqualValues(t, 0, e.Archive.Fetches(), "archive fetched for a fibre commitment")
	})
	t.Run("DA returns wrong bytes: hash error outranks unsupported", func(t *testing.T) {
		e, c, b := fibre(t)
		bad := gatefix.FibreBlob()
		bad[0] ^= 1
		e.DA.Put(c.PayloadRef, bad)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("no committer is consulted for the DA path", func(t *testing.T) {
		e, c, b := fibre(t)
		e.DA.Put(c.PayloadRef, gatefix.FibreBlob())
		_, err := e.Authorize(b)
		require.NoError(t, err, "Authorize")
	})
	t.Run("a committer for fibre makes the archive path possible", func(t *testing.T) {
		ok := gatetest.NewDACommitter()
		e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
			d.Committers = map[commitment.DA]gate.DACommitter{commitment.DAFibre: ok, commitment.DACelestiaBlob: blobv1.New()}
		}))
		c := gatefix.FibreTemplate(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
		ok.Bind(c.PayloadRef.Commitment, gatefix.FibreBlob())
		b, _ := gatefix.Sign(t, "agent1", c)
		res, err := e.Authorize(b)
		require.NoErrorf(t, err, "res %+v err", res)
		require.Equalf(t, registry.PathArchive, res.Path, "res %+v err %v", res, err)
	})
}

func TestAvailabilityPrecedence(t *testing.T) {
	// hash > commitment > unsupported > too old > unavailable
	t.Run("hash outranks commitment mismatch", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		c.PayloadRef.Commitment[0] ^= 1 // archive bytes pass the hash and fail the commitment
		th := gatefix.BlockTime(c)
		e.StageChain(c, th, th)
		e.DA.Put(c.PayloadRef, gatefix.BlobY(t)) // DA bytes fail the hash
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("commitment mismatch outranks unavailable", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		c.PayloadRef.Commitment[0] ^= 1
		routeArchive(e, c)
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
		require.NotErrorIs(t, err, gate.ErrPayloadUnavailable, "lower-precedence sentinel reported")
	})
}
