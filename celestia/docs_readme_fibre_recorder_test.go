package celestia_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fibreRecorderKeys = []string{"own_node", "escrow_margin_utia", "submit_timeout_s", "upload_drain_s", "close_timeout_s"}

func TestReadmeFibreRecorderSection(t *testing.T) {
	b, err := os.ReadFile("README.md")
	require.NoError(t, err)
	doc := string(b)
	s := section(t, doc, "Fibre Recorder")

	for _, k := range fibreRecorderKeys {
		mentions(t, s, k)
	}
	mentions(t, s, `da = "fibre"`)
	mentions(t, s, "recorder.enabled")
	mentions(t, s, "Close")
	mentions(t, s, "ErrEscrowInsufficient")
	assert.Contains(t, strings.ToLower(s), "operator's own", "submission only through the operator's own node")

	assert.NotContains(t, doc, "is not wired into edictad yet", "the Recorder is wired")
	assert.NotContains(t, doc, "Fibre submission by the Recorder (when it is wired)")
}

func TestReadmeCarryOverWording(t *testing.T) {
	b, err := os.ReadFile("README.md")
	require.NoError(t, err)
	doc := string(b)
	assert.NotContains(t, doc, "finds an incompatible bridge at start",
		"the probe runs in the background after the listener is up, not at start")
	assert.NotContains(t, doc, "is found again by the sweep, which repairs it from the registry",
		"a record still queued at exit is repaired at the next start; a dropped one by the next tick")
}

func TestExampleConfigListsTheFibreRecorderKeys(t *testing.T) {
	b, err := os.ReadFile("cmd/edictad/edictad.example.toml")
	require.NoError(t, err)
	doc := string(b)
	for _, k := range fibreRecorderKeys {
		mentions(t, doc, k)
	}
	assert.NotContains(t, doc, "not wired yet")
}
