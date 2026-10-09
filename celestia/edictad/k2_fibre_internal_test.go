package edictad

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type sourcedParams struct{ gate.ChainParams }

func (p sourcedParams) FibreRetentionSourced(ctx context.Context, h uint64) (uint64, gate.RetentionSource, error) {
	v, err := p.FibreRetention(ctx, h)
	return v, gate.RetentionBoth, err
}

// A da = 1 Authorization is archived with the retention inputs the gate used
// and they read back unchanged.
func TestFibreAuthorizationArchivesItsRetentionInputs(t *testing.T) {
	c := gatefix.FibreTemplate(t)
	e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) { d.Params = sourcedParams{d.Params} }))
	e.StageDA(c, gatefix.FibreBlob())
	b, h := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	require.Equal(t, commitment.DAFibre, res.K2.DA)

	st, err := fsarchive.Open(t.TempDir(), nil)
	require.NoError(t, err)
	_, err = st.Put(context.Background(), &archive.DecisionRecord{Envelope: b, Form: archive.FormPublic, Action: gatefix.Action(t), ActionSalt: gatefix.Salt(t)})
	require.NoError(t, err)
	_, err = st.Put(context.Background(), &archive.AuthorizationRecord{
		SignedAuthorization: res.Authorization, AuthorizedAt: res.AuthorizedAt, K2: k2Record(res.K2),
	})
	require.NoError(t, err)

	got, err := st.Authorization(context.Background(), h)
	require.NoError(t, err)
	require.NotNil(t, got.K2)
	assert.Equal(t, commitment.DAFibre, got.K2.DA)
	assert.Equal(t, res.K2.CheckedAt, got.K2.CheckedAt)
	assert.Equal(t, res.K2.RetentionLatestS, got.K2.RetentionLatestS)
	assert.Equal(t, res.K2.RetentionAtHeightS, got.K2.RetentionAtHeightS)
	assert.EqualValues(t, res.K2.RetentionSource, got.K2.RetentionSource)
	assert.Equal(t, res.K2.RetentionStart, got.K2.PromiseCreated)
}
