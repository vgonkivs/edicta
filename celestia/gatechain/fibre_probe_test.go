package gatechain_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

type rawDL struct {
	mu    sync.Mutex
	fn    func(id [33]byte, maxSize uint64) ([]byte, error)
	calls int
	id    [33]byte
	max   uint64
}

func (r *rawDL) DownloadRaw(_ context.Context, id [33]byte, maxSize uint64) ([]byte, error) {
	r.mu.Lock()
	r.calls++
	r.id, r.max = id, maxSize
	fn := r.fn
	r.mu.Unlock()
	return fn(id, maxSize)
}

func (r *rawDL) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func rawJSON(data []byte) []byte {
	return []byte(`{"data":"` + base64.StdEncoding.EncodeToString(data) + `"}`)
}

func serving(raw []byte, err error) *rawDL {
	return &rawDL{fn: func([33]byte, uint64) ([]byte, error) { return raw, err }}
}

func probeOver(t *testing.T, l live, b block, raw gatechain.RawDownloader) gatechain.BridgeProbe {
	t.Helper()
	return gatechain.BridgeProbe{
		Anchors:      anchorsOver(b.chain(t, l), mochaID),
		Raw:          raw,
		Committer:    committer(t),
		LatestHeight: func(context.Context) (uint64, error) { return l.pffHeight + 10, nil },
		RetentionS:   func(context.Context) (uint64, error) { return 3600, nil },
		Now:          func() time.Time { return l.created.Add(10 * time.Minute) },
	}
}

func TestBridgeProbePasses(t *testing.T) {
	l := loadLive(t)
	raw := serving(rawJSON(l.payload), nil)
	res, err := probeOver(t, l, liveBlock(t), raw).Run(bg)
	require.NoError(t, err)
	assert.Equal(t, l.pffHeight, res.Height)
	assert.Equal(t, fibrecommit.BlobID([32]byte(l.commit)), res.BlobID)
	assert.Equal(t, 1, raw.count())
	assert.Equal(t, res.BlobID, raw.id)
	assert.EqualValues(t, l.blobSize, raw.max, "the size cap comes from the promise")
}

func TestBridgeProbeIncompatible(t *testing.T) {
	l := loadLive(t)
	big := make([]byte, 300_000)
	cases := map[string]*rawDL{
		"refused by the bridge":     serving(nil, errors.Join(node.ErrBridgeIncompatible, errors.New("http status 401"))),
		"missing permission":        serving(nil, errors.Join(node.ErrBridgeIncompatible, errors.New("missing permission"))),
		"renamed member":            serving([]byte(`{"Data":"ZQ=="}`), nil),
		"null result":               serving([]byte(`null`), nil),
		"extra member":              serving([]byte(`{"data":"ZQ==","x":1}`), nil),
		"not base64":                serving([]byte(`{"data":"!!"}`), nil),
		"blob of another size":      serving(rawJSON(big), nil),
		"blob with another content": serving(rawJSON([]byte{0x66}), nil),
		"empty blob":                serving(rawJSON(nil), nil),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := probeOver(t, l, liveBlock(t), raw).Run(bg)
			require.ErrorIs(t, err, node.ErrBridgeIncompatible)
			assert.NotErrorIs(t, err, gatechain.ErrProbeInconclusive)
			assert.Equal(t, 1, raw.count())
		})
	}
}

func TestBridgeProbeInconclusive(t *testing.T) {
	l := loadLive(t)
	good := func() *rawDL { return serving(rawJSON(l.payload), nil) }
	cases := []struct {
		name     string
		block    block
		mod      func(p *gatechain.BridgeProbe)
		raw      *rawDL
		wantCall int
	}{
		{"no anchored blob in the window", buildBlock(t, l.pffHeight), nil, good(), 0},
		{"retention margin too small", liveBlock(t), func(p *gatechain.BridgeProbe) {
			p.Now = func() time.Time { return l.created.Add(time.Hour) }
		}, good(), 0},
		{"margin larger than the retention", liveBlock(t), func(p *gatechain.BridgeProbe) { p.Margin = 2 * time.Hour }, good(), 0},
		{"window excludes the blob", liveBlock(t), func(p *gatechain.BridgeProbe) {
			p.LatestHeight = func(context.Context) (uint64, error) { return l.pffHeight + 40, nil }
			p.Window = 5
		}, good(), 0},
		{"transport failure of the download", liveBlock(t), nil, serving(nil, errors.New("connection reset")), 1},
		{"head unreadable", liveBlock(t), func(p *gatechain.BridgeProbe) {
			p.LatestHeight = func(context.Context) (uint64, error) { return 0, errors.New("down") }
		}, good(), 0},
		{"head below the offset", liveBlock(t), func(p *gatechain.BridgeProbe) {
			p.LatestHeight = func(context.Context) (uint64, error) { return 3, nil }
		}, good(), 0},
		{"retention unreadable", liveBlock(t), func(p *gatechain.BridgeProbe) {
			p.RetentionS = func(context.Context) (uint64, error) { return 0, errors.New("down") }
		}, good(), 0},
		{"incomplete probe", liveBlock(t), func(p *gatechain.BridgeProbe) { p.Committer = nil }, good(), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := probeOver(t, l, tc.block, tc.raw)
			if tc.mod != nil {
				tc.mod(&p)
			}
			_, err := p.Run(bg)
			require.ErrorIs(t, err, gatechain.ErrProbeInconclusive)
			assert.NotErrorIs(t, err, node.ErrBridgeIncompatible)
			assert.Equal(t, tc.wantCall, tc.raw.count())
		})
	}
	t.Run("a cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		raw := good()
		_, err := probeOver(t, l, liveBlock(t), raw).Run(ctx)
		require.ErrorIs(t, err, gatechain.ErrProbeInconclusive)
		assert.Zero(t, raw.count())
	})
}
