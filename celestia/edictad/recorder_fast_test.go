package edictad_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/policy"
)

const recFastKeys = "fast = true\nfast_dedicated_account = true\n"

// recFast adds [recorder] fast keys; lines replace the default ones.
func recFast(lines ...string) [2]string {
	body := recFastKeys
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	return rep("max_blob_bytes = 1048576\n", "max_blob_bytes = 1048576\n"+body)
}

// gateFastFor enables [gate.fast] for the Recorder's namespace.
func gateFastFor(extra ...string) [2]string {
	body := "enabled = true\nown_node = true\npending_namespaces = [\"" + hex.EncodeToString(nsBytes) + "\"]\n"
	for _, l := range extra {
		body += l + "\n"
	}
	return rep(anchorVerifierLine, anchorVerifierLine+"\n\n[gate.fast]\n"+body)
}

// maxUploadCost is the escrow cost of one upload of the largest blob.
func maxUploadCost(t *testing.T) uint64 {
	t.Helper()
	us, err := fibrecommit.UploadSize(1048576)
	require.NoError(t, err)
	return recorder.FibreCostUtia(us)
}

func fibreFastKeys(headroom uint64) []string {
	return []string{"fast = true", "fast_dedicated_account = true", `fast_upload_addr = "grpc.invalid:9090"`,
		fmt.Sprintf("fast_escrow_headroom_utia = %d", headroom)}
}

// mandateFor wraps any env with a signed mandate that allows fast mode.
func mandateFor(t *testing.T, e *env) *policyEnv {
	t.Helper()
	_, prv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p := &policyEnv{env: e, base: &commitment.Commitment{}, principal: prv}
	p.mandate = &policy.Mandate{
		Format: 1, Principal: prv.Public().(ed25519.PublicKey), GateID: "gate-test-1",
		Agents:    [][]byte{e.agentPub},
		NotBefore: uint64(t0.Unix()) - 86400, NotAfter: uint64(t0.Unix()) + 86400,
		MandateID: []byte("0123456789abcdef"), Version: 1, FastModeMaxDelay: fastDelay,
		Assets: []policy.AssetRule{{Asset: policyAsset, Scale: 6, PerActionMax: policy.AmountFromUint64(5_000_000)}},
	}
	p.file = p.sign(prv, p.mandate)
	return p
}

func (p *policyEnv) parseBlobFast(extra ...[2]string) (edictad.Config, error) {
	return edictad.ParseConfig([]byte(p.tomlOf(p.edits(extra...)...)))
}

func (p *policyEnv) parseFibreFast(extra ...[2]string) (edictad.Config, error) {
	return edictad.ParseConfig([]byte(p.tomlOf(p.edits(fibreRecEdits(extra...)...)...)))
}

func TestRecorderFastIsOffByDefault(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	c, err := p.parseBlobFast(gateFastFor())
	require.NoError(t, err)
	assert.False(t, c.Recorder.Fast)
	assert.Zero(t, c.Recorder.FastTimeoutBlocks, "no default without fast")
}

func TestRecorderFastBlobDefaults(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	c, err := p.parseBlobFast(gateFastFor(), recFast())
	require.NoError(t, err)
	assert.True(t, c.Recorder.Fast)
	assert.True(t, c.Recorder.FastDedicatedAccount)
	assert.EqualValues(t, 100, c.Recorder.FastTimeoutBlocks)
}

func TestRecorderFastFibreKeys(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	need := maxUploadCost(t)
	c, err := p.parseFibreFast(gateFastFor(), recFast(fibreFastKeys(need)...))
	require.NoError(t, err)
	assert.Zero(t, c.Recorder.FastTimeoutBlocks, "the promise window bounds a da = 1 anchor")
	assert.Equal(t, need, c.Recorder.FastEscrowHeadroomUtia)
	fc := c.FibreRecorderConfig(nsBytes, nil)
	assert.Equal(t, 5+need, fc.EscrowMarginUtia, "the headroom is kept in the escrow on top of the margin")
}

func TestRecorderFastBlobRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edits   [][2]string
		message string
	}{
		"keys without fast": {[][2]string{gateFastFor(), recFast("fast_dedicated_account = true")},
			"need recorder.fast"},
		"timeout without fast": {[][2]string{gateFastFor(), recFast("fast_timeout_blocks = 50")},
			"need recorder.fast"},
		"recorder disabled": {[][2]string{gateFastFor(), recFast(), rep("enabled = true\nnamespace", "enabled = false\nnamespace")},
			"recorder.fast needs recorder.enabled"},
		"gate not fast": {[][2]string{recFast()},
			"recorder.fast needs gate.fast.enabled"},
		"namespace not pending": {[][2]string{gateFastFor(), recFast(),
			rep(`namespace = "`+hex.EncodeToString(nsBytes)+`"`, `namespace = "`+hex.EncodeToString(append(nsBytes[:28:28], 8))+`"`)},
			"recorder.namespace in gate.fast.pending_namespaces"},
		"account not dedicated": {[][2]string{gateFastFor(), recFast("fast = true")},
			"recorder.fast_dedicated_account must be true"},
		"upload address with blob": {[][2]string{gateFastFor(), recFast(recFastKeys + `fast_upload_addr = "grpc.invalid:9090"`)},
			`need network.da = "fibre"`},
		"headroom with blob": {[][2]string{gateFastFor(), recFast(recFastKeys + "fast_escrow_headroom_utia = 1")},
			`need network.da = "fibre"`},
		"timeout below the floor": {[][2]string{gateFastFor(), recFast(recFastKeys + "fast_timeout_blocks = 12")},
			"recorder.fast_timeout_blocks"},
		"timeout above the ceiling": {[][2]string{gateFastFor(), recFast(recFastKeys + "fast_timeout_blocks = 1001")},
			"recorder.fast_timeout_blocks"},
		"timeout without slack": {[][2]string{gateFastFor(), recFast(recFastKeys + "fast_timeout_blocks = 13")},
			"must exceed gate.fast.max_h0_age_blocks + gate.fast.min_fast_slack_blocks"},
		"timeout without slack for a wider gate": {[][2]string{gateFastFor("max_h0_age_blocks = 40"), recFast(recFastKeys + "fast_timeout_blocks = 43")},
			"must exceed gate.fast.max_h0_age_blocks"},
	} {
		t.Run(name, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			_, err := p.parseBlobFast(tc.edits...)
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

func TestRecorderFastFibreRefusals(t *testing.T) {
	need := maxUploadCost(t)
	keys := func(drop string, more ...string) [2]string {
		var out []string
		for _, k := range fibreFastKeys(need) {
			if !strings.HasPrefix(k, drop+" ") {
				out = append(out, k)
			}
		}
		return recFast(append(out, more...)...)
	}
	for name, tc := range map[string]struct {
		edit    [2]string
		message string
	}{
		"no upload address":    {keys("fast_upload_addr"), "recorder.fast_upload_addr is required"},
		"other upload address": {keys("fast_upload_addr", `fast_upload_addr = "other.invalid:9090"`), "must be network.consensus_grpc.addr"},
		"no headroom":          {keys("fast_escrow_headroom_utia"), "recorder.fast_escrow_headroom_utia must be at least"},
		"headroom below one upload": {keys("fast_escrow_headroom_utia", fmt.Sprintf("fast_escrow_headroom_utia = %d", need-1)),
			fmt.Sprintf("at least %d utia", need)},
		"timeout with fibre": {keys("", "fast_timeout_blocks = 100"), `does not apply to da = "fibre"`},
		"not dedicated":      {keys("fast_dedicated_account"), "recorder.fast_dedicated_account must be true"},
	} {
		t.Run(name, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			_, err := p.parseFibreFast(gateFastFor(), tc.edit)
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

func TestRecorderFastUploadAddressIgnoresSchemeAndCase(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	var keys []string
	for _, k := range fibreFastKeys(maxUploadCost(t)) {
		if strings.HasPrefix(k, "fast_upload_addr") {
			k = `fast_upload_addr = "https://GRPC.invalid:9090"`
		}
		keys = append(keys, k)
	}
	_, err := p.parseFibreFast(gateFastFor(), recFast(keys...))
	require.NoError(t, err)
}
