package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

func exec(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out)
	return code, out.String()
}

// edicta-verify keeps its interface and its exit codes; the work is done by
// the library the edicta command shares.
func TestStillVerifiesAndKeepsItsExitCodes(t *testing.T) {
	l := fibrefix.LoadLive(t)
	d := l.WriteDecision(t, l.Evidence(t))
	trusted := l.TrustedFile(t, nil)
	h := hex.EncodeToString(d.Hash[:])

	code, out := exec(t, "verify", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, h)
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "verdict: valid")

	code, out = exec(t, "verify", "--archive", d.Dir, "--gate-key", d.GateKeyHex, h)
	assert.Equal(t, 2, code, out)

	code, out = exec(t, "replay", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, h)
	assert.Equal(t, 0, code, out)

	other := bytes.Clone(d.Hash[:])
	other[0] ^= 1
	code, out = exec(t, "verify", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, hex.EncodeToString(other))
	assert.Equal(t, 1, code, out)

	code, out = exec(t)
	assert.Equal(t, 4, code, out)
	code, out = exec(t, "verify", "--archive", "/nonexistent", "--gate-key", d.GateKeyHex, h)
	assert.Equal(t, 4, code, out)
}
