// Package execresultfix loads the archived execution result vectors. It is
// for tests only.
package execresultfix

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/internal/testkit"
)

type File struct {
	Revision  string      `json:"revision"`
	Kind      string      `json:"kind"`
	Records   []Record    `json:"records"`
	Reject    []Reject    `json:"reject"`
	Cases     []Case      `json:"cases"`
	Migration []Migration `json:"migration"`
}

type Record struct {
	ID             string            `json:"id"`
	Block          string            `json:"block"`
	Path           string            `json:"path"`
	Key            Query             `json:"key"`
	Input          map[string]string `json:"input"`
	CBORHex        string            `json:"record_cbor_hex"`
	SHA256Hex      string            `json:"record_sha256_hex"`
	V10ReaderCause string            `json:"v1_0_reader_cause"`
}

type Reject struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	CBORHex     string `json:"record_cbor_hex"`
	ExpectError string `json:"expect_error"`
	Cause       string `json:"cause"`
}

type Query struct {
	ChainID string `json:"chain_id"`
	RailRef string `json:"rail_ref"`
}

type Case struct {
	ID         string            `json:"id"`
	BaseRecord string            `json:"base_record"`
	CBORHex    string            `json:"record_cbor_hex"`
	Query      Query             `json:"query"`
	Trusted    map[string]string `json:"trusted"`
	Expect     Outcome           `json:"expect"`
}

type Outcome struct {
	Result string            `json:"result"`
	Rule   string            `json:"rule"`
	Reason string            `json:"reason"`
	Facts  map[string]string `json:"facts"`
}

// Migration is one block file of the gate's capture store, the records the
// archive already holds by path, and what the migration makes of each
// captured transaction. Capture is the store's JSON layout, kept raw so the
// test decodes it with the store's own types.
type Migration struct {
	ID      string            `json:"id"`
	Capture json.RawMessage   `json:"capture"`
	Stored  map[string]string `json:"stored"`
	Expect  []MigrationExpect `json:"expect"`
}

type MigrationExpect struct {
	RailRef     string `json:"rail_ref"`
	Result      string `json:"result"`
	Rule        string `json:"rule"`
	Equivalence string `json:"equivalence"`
	Path        string `json:"path"`
	CBORHex     string `json:"record_cbor_hex"`
}

// Path is the vector file.
func Path(tb testing.TB) string {
	return testkit.SpecPath(tb, "vectors/archive/execution_result_v1.1.json")
}

// Load reads the vector file.
func Load(t testing.TB) File {
	t.Helper()
	raw, err := os.ReadFile(Path(t))
	require.NoError(t, err)
	var f File
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, "v1.1", f.Revision)
	require.Equal(t, "19", f.Kind)
	return f
}

// Hex decodes a hex string of the vectors.
func Hex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, s)
	return b
}

// Uint parses a decimal string of the vectors.
func Uint(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err, s)
	return v
}

// RailRef is the 32-byte rail reference of a query.
func (q Query) RailRefBytes(t testing.TB) [32]byte {
	t.Helper()
	var out [32]byte
	b := Hex(t, q.RailRef)
	require.Len(t, b, 32)
	copy(out[:], b)
	return out
}

// Build is the record a records entry's input describes.
func (r Record) Build(t testing.TB) *archive.ExecutionResultRecord {
	t.Helper()
	in := r.Input
	opt := func(k string) []byte {
		if v, ok := in[k]; ok {
			return Hex(t, v)
		}
		return nil
	}
	return &archive.ExecutionResultRecord{
		ChainID: in["chain_id"], RailRef: Hex(t, in["rail_ref"]), Height: Uint(t, in["height"]), TxIndex: Uint(t, in["tx_index"]),
		Header: Hex(t, in["header"]), NextHeader: Hex(t, in["next_header"]), TxProof: Hex(t, in["tx_proof"]),
		PFBProof: opt("pfb_proof"), PFFProof: opt("pff_proof"), ClosingProof: opt("closing_proof"),
		Result: Hex(t, in["result"]), ResultsTotal: Uint(t, in["results_total"]), ResultPath: Hex(t, in["result_path"]),
	}
}
