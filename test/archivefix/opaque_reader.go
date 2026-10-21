// SPDX-License-Identifier: Apache-2.0

package archivefix

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ReaderCase is an archive_reader case of the unknown-da vectors: a decision
// record whose envelope has a da the reader does not define.
type ReaderCase struct {
	ID        string `json:"id"`
	RecordHex string `json:"record_cbor_hex"`
	Path      string `json:"path"`
	Cause     string `json:"v1_0_4_reader_cause"`
}

// Record returns the record bytes.
func (c ReaderCase) Record(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(c.RecordHex)
	require.NoError(t, err)
	return b
}

// Hash returns the commitment hash named by the case path.
func (c ReaderCase) Hash(t testing.TB) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(c.Path, "decision/"))
	require.NoError(t, err)
	var h [32]byte
	require.Equal(t, 32, copy(h[:], b))
	return h
}

// ReaderCases loads the archive_reader cases of verifier/reasons_v1.0.5.json.
func ReaderCases(t testing.TB) []ReaderCase {
	t.Helper()
	var d struct {
		Cases []ReaderCase `json:"archive_reader"`
	}
	readJSON(t, filepath.Join("..", "verifier", "reasons_v1.0.5.json"), &d)
	require.Len(t, d.Cases, 4)
	return d.Cases
}
