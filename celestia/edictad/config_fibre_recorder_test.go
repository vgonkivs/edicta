package edictad_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

const fibreRecKeys = "max_blob_bytes = 1048576\nown_node = true\nescrow_margin_utia = 5\n" +
	"submit_timeout_s = 200\nupload_drain_s = 100\nclose_timeout_s = 120\n"

// fibreRecEdits is a valid da = fibre config with the Recorder enabled.
func fibreRecEdits(extra ...[2]string) [][2]string {
	return append([][2]string{
		rep(`da = "celestia_blob"`, "da = \"fibre\"\nfibre_chain_ids = [\""+fibreChainID+"\"]"),
		rep("min_app_version = 3\nmax_app_version = 10\n", ""),
		rep("[archive]\n", "[fibre]\nmax_data_bytes = 1048576\nmax_read_bytes = 1048576\n\n[archive]\n"),
		rep("max_blob_bytes = 1048576\n", fibreRecKeys),
	}, extra...)
}

func parseFibreRec(t *testing.T, e *env, extra ...[2]string) (edictad.Config, error) {
	t.Helper()
	return edictad.ParseConfig([]byte(e.tomlOf(fibreRecEdits(extra...)...)))
}

func TestFibreRecorderKeysAreParsed(t *testing.T) {
	e := newEnv(t)
	c, err := parseFibreRec(t, e)
	require.NoError(t, err)
	r := c.Recorder
	assert.True(t, r.OwnNode)
	assert.EqualValues(t, 5, r.EscrowMarginUtia)
	assert.EqualValues(t, 200, r.SubmitTimeoutS)
	assert.EqualValues(t, 100, r.UploadDrainS)
	assert.EqualValues(t, 120, r.CloseTimeoutS)
}

func TestFibreRecorderKeysTakeDefaults(t *testing.T) {
	e := newEnv(t)
	c, err := parseFibreRec(t, e, rep(fibreRecKeys, "max_blob_bytes = 1048576\nown_node = true\n"))
	require.NoError(t, err)
	assert.EqualValues(t, 300, c.Recorder.SubmitTimeoutS)
	assert.EqualValues(t, 120, c.Recorder.UploadDrainS)
	assert.EqualValues(t, 150, c.Recorder.CloseTimeoutS)
	assert.Zero(t, c.Recorder.EscrowMarginUtia)
}

func TestFibreRecorderIsAcceptedWithValidKeys(t *testing.T) {
	e := newEnv(t)
	_, err := parseFibreRec(t, e)
	require.NoError(t, err)
	assert.NotErrorIs(t, err, edictad.ErrDANotSupported)
}

func TestFibreRecorderConfigRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit [2]string
	}{
		{"own node false", rep("own_node = true", "own_node = false")},
		{"own node absent", rep("own_node = true\n", "")},
		{"close below drain", rep("close_timeout_s = 120", "close_timeout_s = 99")},
		{"submit timeout absurd", rep("submit_timeout_s = 200", "submit_timeout_s = 1099511627776")},
		{"drain absurd", rep("upload_drain_s = 100", "upload_drain_s = 1099511627776")},
		{"close absurd", rep("close_timeout_s = 120", "close_timeout_s = 1099511627776")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFibreRec(t, newEnv(t), tc.edit)
			require.ErrorIs(t, err, edictad.ErrConfig)
		})
	}
}

func TestFibreRecorderKeysNeedAFibreRecorder(t *testing.T) {
	for name, key := range map[string]string{
		"own_node":           "own_node = true\n",
		"escrow_margin_utia": "escrow_margin_utia = 1\n",
		"submit_timeout_s":   "submit_timeout_s = 5\n",
		"upload_drain_s":     "upload_drain_s = 5\n",
		"close_timeout_s":    "close_timeout_s = 5\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			_, err := edictad.ParseConfig([]byte(e.tomlOf(rep("max_blob_bytes = 1048576\n", "max_blob_bytes = 1048576\n"+key))))
			require.ErrorIs(t, err, edictad.ErrConfig, "a celestia_blob config with a da = fibre key never starts")
		})
	}
}

func TestWithDefaultsLeavesBlobRecorderKeysZero(t *testing.T) {
	e := newEnv(t)
	c := e.cfg().WithDefaults()
	r := c.Recorder
	assert.False(t, r.OwnNode)
	assert.Zero(t, r.SubmitTimeoutS+r.UploadDrainS+r.CloseTimeoutS+r.EscrowMarginUtia)
}

func TestValidateBasicDoesNotApplyRecorderDefaults(t *testing.T) {
	e := newEnv(t)
	for name, mod := range map[string]func(*edictad.Config){
		"submit timeout": func(c *edictad.Config) { c.Recorder.SubmitTimeoutS = 0 },
		"upload drain":   func(c *edictad.Config) { c.Recorder.UploadDrainS = 0 },
		"close timeout":  func(c *edictad.Config) { c.Recorder.CloseTimeoutS = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := parseFibreRec(t, e)
			require.NoError(t, err)
			mod(&c)
			require.ErrorIs(t, c.ValidateBasic(), edictad.ErrConfig)
		})
	}
}

func TestFibreRecorderConfigFromTheKeys(t *testing.T) {
	e := newEnv(t)
	c, err := parseFibreRec(t, e)
	require.NoError(t, err)
	st, err := fsarchive.Open(t.TempDir(), fibrefix.Committers(t))
	require.NoError(t, err)

	fc := c.FibreRecorderConfig(nsBytes, st)
	assert.Equal(t, nsBytes, fc.Namespace)
	assert.EqualValues(t, 1048576, fc.MaxDataBytes)
	assert.Equal(t, 200*time.Second, fc.SubmitTimeout)
	assert.Equal(t, 100*time.Second, fc.UploadDrain)
	assert.EqualValues(t, 5, fc.EscrowMarginUtia)
	assert.True(t, fc.OwnNode)
	assert.True(t, fc.Archive == st, "the Recorder writes to the gate's archive")
	require.NoError(t, fc.WithDefaults().ValidateBasic())
}
