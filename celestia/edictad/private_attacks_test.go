package edictad_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// archiveFiles reads every file of the archive directory.
func (p *policyEnv) archiveFiles() map[string][]byte {
	p.t.Helper()
	out := map[string][]byte{}
	root := p.path("archive")
	require.NoError(p.t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = b
		return nil
	}))
	return out
}

// privateParts opens every kind 15 PrivatePart in the archive.
func (p *policyEnv) privateParts() [][]byte {
	p.t.Helper()
	var out [][]byte
	for rel := range p.archiveFiles() {
		dir, name := filepath.Split(rel)
		if filepath.Clean(dir) != filepath.Join("private", "4") {
			continue
		}
		raw, err := hex.DecodeString(name)
		if err != nil || len(raw) != 32 {
			continue
		}
		out = append(out, p.openPrivate(policy.PrivatePartKind, commitment.Hash(raw)))
	}
	return out
}

func TestPrivateStateSaltAndPartsStayOutOfTheOpen(t *testing.T) {
	p := newPrivateEnv(t)
	salt := sha256.Sum256([]byte("edictad private salt probe"))
	p.mandate.StateSalt = salt[:]
	p.file = p.sign(p.principal, p.mandate)
	p.startPolicy()

	var bodies [][]byte
	_, _, body := p.authorizeRaw(p.send(1, 1_000_000))
	bodies = append(bodies, body)
	for i, amount := range []uint64{6_000_000, 6_000_000, 7_000_000} {
		st, _, body := p.authorizeRaw(p.send(byte(10+i), amount))
		require.GreaterOrEqual(t, st, 400)
		bodies = append(bodies, body)
	}
	_, _, body = p.authorizeRaw(p.send(2, 1_000_000))
	bodies = append(bodies, body)

	parts := p.privateParts()
	require.GreaterOrEqual(t, len(parts), 5, "two allows and three distinct denies")
	for _, b := range bodies {
		for _, part := range parts {
			assert.False(t, bytes.Contains(b, part), "an HTTP answer carries a PrivatePart")
		}
	}

	forms := [][]byte{salt[:], []byte(hex.EncodeToString(salt[:])), []byte(base64.StdEncoding.EncodeToString(salt[:]))}
	files := p.archiveFiles()
	require.NotEmpty(t, files)
	for _, f := range forms {
		for name, b := range files {
			assert.False(t, bytes.Contains(b, f), "archive file %s carries the state_salt", name)
		}
		for i, b := range bodies {
			assert.False(t, bytes.Contains(b, f), "HTTP answer %d carries the state_salt", i)
		}
		assert.NotContains(t, p.logs.String(), string(f), "the log carries the state_salt")
	}
	// Control: the probe finds the salt where it must be, in the gate-local cell.
	require.NoError(t, p.srv.Shutdown(bg))
	assert.True(t, bytes.Contains(readFile(t, p.path("registry.db")), salt[:]))
}

// TestPrivateDenyFirstAttemptsRaceWriteOnce sends the same denied decision
// from many goroutines with no deny archived yet: exactly one kind 9 and one
// PrivatePart are written, and every attempt still issues the marker.
func TestPrivateDenyFirstAttemptsRaceWriteOnce(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)
	parts := len(p.privateParts())

	d := p.send(1, 6_000_000)
	const workers = 32
	var wg sync.WaitGroup
	statuses := make([]int, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := p.authorizeStatus(d)
			assert.NoError(t, err)
			statuses[i] = st
		}()
	}
	wg.Wait()
	for _, st := range statuses {
		assert.GreaterOrEqual(t, st, 400)
	}
	count := func(k archive.Kind) int {
		c := 0
		for _, x := range kindsOf(p.fs.puts, n) {
			if x == k {
				c++
			}
		}
		return c
	}
	assert.Equal(t, 1, count(archive.KindPolicyDeny), "one deny record under concurrent retries")
	assert.Equal(t, workers, count(archive.KindRejection), "the marker write on every attempt")
	assert.Equal(t, parts+1, len(p.privateParts()), "one PrivatePart for the one deny")
	_, err := p.real.Rejection(bg, d.hash, "ErrDenied")
	require.NoError(t, err)
}
