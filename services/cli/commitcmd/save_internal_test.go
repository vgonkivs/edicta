// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadFailStore fails its next failLoads loads and counts the saves.
type loadFailStore struct {
	m         map[string]State
	failLoads int
	saves     int
}

func (s *loadFailStore) Save(hash string, st State) error {
	s.saves++
	s.m[hash] = st
	return nil
}

func (s *loadFailStore) Load(hash string) (State, bool, error) {
	if s.failLoads > 0 {
		s.failLoads--
		return State{}, false, errors.New("too many open files")
	}
	st, ok := s.m[hash]
	return st, ok, nil
}

func TestSaveDoesNotOverwriteAStateItCannotRead(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	marked := State{Envelope: []byte{1}, PaymentSignature: "0xproof", RefusedAtMS: 3, HandoffAtMS: 5, HandoffOutcome: HandoffOutcomeSent}
	st := &loadFailStore{m: map[string]State{hash: marked}, failLoads: 1}
	s := &Service{State: st}
	r := &run{hexH: hash, st: State{Envelope: []byte{1}, Action: []byte{2}}}

	f := s.save(r)
	require.NotNil(t, f)
	assert.Equal(t, "state_unavailable", f.Code)
	assert.True(t, f.Retryable)
	assert.Equal(t, hash, f.CommitmentHash, "the failure carries the resume fields")
	assert.Zero(t, st.saves, "nothing is written over a state that could not be read")
	assert.Equal(t, marked, st.m[hash])

	// Readable again, the run keeps the marks it never had.
	require.Nil(t, s.save(r))
	got := st.m[hash]
	assert.Equal(t, []byte{2}, got.Action)
	assert.Equal(t, int64(3), got.RefusedAtMS)
	assert.Equal(t, int64(5), got.HandoffAtMS)
	assert.Equal(t, HandoffOutcomeSent, got.HandoffOutcome)
	assert.Equal(t, "0xproof", got.PaymentSignature)
}

func TestSaveDoesNotOverwriteAStateFileItCannotDecode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, err := NewFileStateStore(dir)
	require.NoError(t, err)
	hash := strings.Repeat("cd", 32)
	path := filepath.Join(dir, hash+".json")
	for name, data := range map[string]string{
		"a field of a newer binary": `{"envelope":"AQ==","handoff_at_ms":5,"handoff_later":1}`,
		"a truncated file":          `{"envelope":"AQ==","handoff_at_ms":5`,
	} {
		require.NoError(t, os.WriteFile(path, []byte(data), 0o600), name)
		s := &Service{State: st}
		f := s.save(&run{hexH: hash, st: State{Envelope: []byte{1}}})
		require.NotNil(t, f, name)
		assert.Equal(t, "state_unavailable", f.Code, name)
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, data, string(after), name)
	}
}
