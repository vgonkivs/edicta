// Package archivefix loads the archive vectors and builds records from them.
// It is for tests only.
package archivefix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

type Case struct {
	ID     string
	Kind   string
	Record archive.Record
	Key    string
	CBOR   []byte // nil for cases given by size and hash only
	Size   int
	SHA256 string
}

type Reject struct {
	ID    string
	CBOR  []byte
	Cause string
}

// RejectLarge is a reject vector given by a prefix and a generated suffix.
type RejectLarge struct {
	ID     string
	Prefix []byte
	Size   int
	SHA256 string
	Cause  string
}

// Bytes builds the record: the prefix followed by byte i = (7*i+3) mod 256
// up to Size, and checks the vector hash.
func (r RejectLarge) Bytes(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, r.Size)
	n := copy(b, r.Prefix)
	for i := 0; n+i < r.Size; i++ {
		b[n+i] = byte(7*i + 3)
	}
	sum := sha256.Sum256(b)
	require.Equal(t, r.SHA256, hex.EncodeToString(sum[:]), r.ID)
	return b
}

// Read is a stored-records scenario: the records are written without any
// write check and then read back.
type Read struct {
	ID     string
	Stored []string
	Kind   string
	Hash   string
	Expect string
}

type After struct {
	Hash       string
	State      string
	Rejections []string
}

type Step struct {
	Put    string
	Expect string
	After  *After
}

type Scenario struct {
	ID    string
	Steps []Step
	Final []string
}

type Fixture struct {
	Cases     map[string]Case
	Rejects   []Reject
	Large     []RejectLarge
	Reads     []Read
	Scenarios []Scenario
	// Fibre maps the SHA-256 of a da = 1 blob to its commitment.
	Fibre map[[32]byte][]byte
}

func vectorDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "spec", "vectors", "archive")
}

func readJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir(), name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

func Load(t testing.TB) *Fixture {
	t.Helper()
	var rec struct {
		Cases []struct {
			ID         string         `json:"id"`
			Kind       string         `json:"kind"`
			Input      map[string]any `json:"input"`
			Key        string         `json:"key"`
			CBORHex    string         `json:"record_cbor_hex"`
			RecordSize string         `json:"record_size"`
			RecordSHA  string         `json:"record_sha256_hex"`
		} `json:"cases"`
		Reject []struct {
			ID      string `json:"id"`
			CBORHex string `json:"record_cbor_hex"`
			Cause   string `json:"cause"`
		} `json:"reject"`
		RejectLarge []struct {
			ID     string `json:"id"`
			Prefix string `json:"record_prefix_hex"`
			Size   string `json:"record_size"`
			SHA    string `json:"record_sha256_hex"`
			Cause  string `json:"cause"`
		} `json:"reject_large"`
	}
	readJSON(t, "records.json", &rec)
	var st struct {
		DACheck []struct {
			DA         string `json:"da"`
			Commitment string `json:"commitment_hex"`
			BlobSHA    string `json:"blob_sha256_hex"`
		} `json:"da_check"`
		Reads []struct {
			ID     string   `json:"id"`
			Stored []string `json:"stored"`
			Read   struct {
				Kind string `json:"kind"`
				Hash string `json:"commitment_hash_hex"`
			} `json:"read"`
			Expect string `json:"expect"`
		} `json:"reads"`
		Scenarios []struct {
			ID    string   `json:"id"`
			Final []string `json:"final_records"`
			Steps []struct {
				Put    string `json:"put"`
				Expect string `json:"expect"`
				After  *struct {
					Hash  string   `json:"commitment_hash_hex"`
					State string   `json:"state"`
					Rej   []string `json:"rejections"`
				} `json:"state_after"`
			} `json:"steps"`
		} `json:"scenarios"`
	}
	readJSON(t, "state.json", &st)

	fx := &Fixture{Cases: map[string]Case{}, Fibre: map[[32]byte][]byte{}}
	for _, c := range rec.Cases {
		cs := Case{ID: c.ID, Kind: c.Kind, Key: c.Key, SHA256: c.RecordSHA, Record: Build(t, c.Input)}
		if c.CBORHex != "" {
			cs.CBOR = unhex(t, c.CBORHex)
		}
		if c.RecordSize != "" {
			cs.Size = int(num(t, c.RecordSize))
		}
		fx.Cases[c.ID] = cs
	}
	for _, r := range rec.Reject {
		fx.Rejects = append(fx.Rejects, Reject{ID: r.ID, CBOR: unhex(t, r.CBORHex), Cause: r.Cause})
	}
	for _, r := range rec.RejectLarge {
		fx.Large = append(fx.Large, RejectLarge{
			ID: r.ID, Prefix: unhex(t, r.Prefix), Size: int(num(t, r.Size)), SHA256: r.SHA, Cause: r.Cause,
		})
	}
	for _, r := range st.Reads {
		fx.Reads = append(fx.Reads, Read{ID: r.ID, Stored: r.Stored, Kind: r.Read.Kind, Hash: r.Read.Hash, Expect: r.Expect})
	}
	for _, d := range st.DACheck {
		if d.DA == "1" {
			var k [32]byte
			copy(k[:], unhex(t, d.BlobSHA))
			fx.Fibre[k] = unhex(t, d.Commitment)
		}
	}
	for _, s := range st.Scenarios {
		sc := Scenario{ID: s.ID, Final: s.Final}
		for _, p := range s.Steps {
			step := Step{Put: p.Put, Expect: p.Expect}
			if p.After != nil {
				step.After = &After{Hash: p.After.Hash, State: p.After.State, Rejections: p.After.Rej}
			}
			sc.Steps = append(sc.Steps, step)
		}
		fx.Scenarios = append(fx.Scenarios, sc)
	}
	return fx
}

// Causes maps a vector cause name to its sentinel.
var Causes = map[string]error{
	"ErrTooLarge":           commitment.ErrTooLarge,
	"ErrMalformed":          commitment.ErrMalformed,
	"ErrTrailingData":       commitment.ErrTrailingData,
	"ErrFloat":              commitment.ErrFloat,
	"ErrSimpleValue":        commitment.ErrSimpleValue,
	"ErrTag":                commitment.ErrTag,
	"ErrIndefiniteLength":   commitment.ErrIndefiniteLength,
	"ErrNonMinimalInt":      commitment.ErrNonMinimalInt,
	"ErrNestingTooDeep":     commitment.ErrNestingTooDeep,
	"ErrUnsortedMap":        commitment.ErrUnsortedMap,
	"ErrDuplicateKey":       commitment.ErrDuplicateKey,
	"ErrKeyType":            commitment.ErrKeyType,
	"ErrInvalidString":      commitment.ErrInvalidString,
	"ErrUnknownKey":         commitment.ErrUnknownKey,
	"ErrWrongType":          commitment.ErrWrongType,
	"ErrMissingField":       commitment.ErrMissingField,
	"ErrFieldSize":          commitment.ErrFieldSize,
	"ErrNonCanonical":       commitment.ErrNonCanonical,
	"ErrUnsupportedVersion": commitment.ErrUnsupportedVersion,
	"ErrIntRange":           commitment.ErrIntRange,
	"ErrInvalidEnum":        commitment.ErrInvalidEnum,
	"ErrZeroValue":          commitment.ErrZeroValue,
	"ErrInvalidNamespace":   commitment.ErrInvalidNamespace,
}

// ExpectedErr maps a step expectation to a sentinel; nil for written and
// unchanged.
func ExpectedErr(t testing.TB, s string) error {
	t.Helper()
	switch s {
	case "written", "unchanged", "ok":
		return nil
	case "archive.ErrConflict":
		return archive.ErrConflict
	case "archive.ErrNotFound":
		return archive.ErrNotFound
	case "archive.ErrCorrupt":
		return archive.ErrCorrupt
	case "gate.ErrDACommitmentMismatch":
		return gate.ErrDACommitmentMismatch
	}
	require.FailNow(t, "unknown expectation "+s)
	return nil
}

type fibreCommitter struct{ fx *Fixture }

// FibreCommitter is a da = 1 committer that knows only the vector blobs.
func (fx *Fixture) FibreCommitter() gate.DACommitter { return fibreCommitter{fx} }

func (f fibreCommitter) Check(ref commitment.PayloadRef, blob []byte) error {
	want, ok := f.fx.Fibre[sha256.Sum256(blob)]
	if !ok || string(want) != string(ref.Commitment) {
		return gate.ErrDACommitmentMismatch
	}
	return nil
}

// Files returns the slash-separated paths of the regular files under dir.
func Files(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	}))
	sort.Strings(out)
	return out
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func num(t testing.TB, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return n
}

func bytesOf(t testing.TB, m map[string]any, key string) []byte {
	t.Helper()
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case string:
		return unhex(t, x)
	case map[string]any:
		require.Equal(t, "affine-7-3", x["pattern"])
		out := make([]byte, num(t, x["size"].(string)))
		for i := range out {
			out[i] = byte(7*i + 3)
		}
		sum := sha256.Sum256(out)
		require.Equal(t, x["sha256_hex"], hex.EncodeToString(sum[:]))
		return out
	}
	require.FailNow(t, "bad bytes value for "+key)
	return nil
}

func numOf(t testing.TB, m map[string]any, key string) uint64 {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		return 0
	}
	return num(t, s)
}

// Build makes a record from a vector input object.
func Build(t testing.TB, in map[string]any) archive.Record {
	t.Helper()
	switch fmt.Sprint(in["kind"]) {
	case "payload":
		return &archive.PayloadRecord{
			DA:           commitment.DA(numOf(t, in, "da")),
			Commitment:   bytesOf(t, in, "commitment"),
			Namespace:    bytesOf(t, in, "namespace"),
			Signer:       bytesOf(t, in, "signer"),
			Blob:         bytesOf(t, in, "blob"),
			IntentHeight: numOf(t, in, "intent_height"),
		}
	case "evidence":
		return &archive.EvidenceRecord{
			DA:              commitment.DA(numOf(t, in, "da")),
			Commitment:      bytesOf(t, in, "commitment"),
			Namespace:       bytesOf(t, in, "namespace"),
			Height:          numOf(t, in, "height"),
			Header:          bytesOf(t, in, "header"),
			AnchorTx:        bytesOf(t, in, "anchor_tx"),
			AnchorTxIndex:   numOf(t, in, "anchor_tx_index"),
			AnchorTxProof:   bytesOf(t, in, "anchor_tx_proof"),
			BlobProof:       bytesOf(t, in, "blob_proof"),
			TxCode:          numOf(t, in, "tx_code"),
			SystemBlob:      bytesOf(t, in, "system_blob"),
			SystemBlobProof: bytesOf(t, in, "system_blob_proof"),
			PromiseHeight:   numOf(t, in, "promise_height"),
			PromiseHeader:   bytesOf(t, in, "promise_header"),
			HistoricalInfo:  bytesOf(t, in, "historical_info"),
		}
	case "decision", "17":
		return &archive.DecisionRecord{
			Envelope: bytesOf(t, in, "envelope"), Form: numOf(t, in, "form"),
			Action: bytesOf(t, in, "action"), ActionSalt: bytesOf(t, in, "action_salt"),
		}
	case "private_blob", "15":
		return &archive.PrivateBlobRecord{
			PlaintextKind: policy.PrivateKind(numOf(t, in, "plaintext_kind")),
			Hash:          bytesOf(t, in, "hash"), Envelope: bytesOf(t, in, "envelope"),
		}
	case "execution_reveal", "18":
		return &archive.RevealRecord{SignedReceipt: bytesOf(t, in, "signed_receipt"), ActionSalt: bytesOf(t, in, "action_salt")}
	case "authorization", "4":
		r := &archive.AuthorizationRecord{
			SignedAuthorization: bytesOf(t, in, "signed_authorization"),
			AuthorizedAt:        numOf(t, in, "authorized_at"),
		}
		if k, ok := in["k2"].(map[string]any); ok {
			r.K2 = &archive.K2Inputs{
				DA:                 commitment.DA(numOf(t, k, "da")),
				CheckedAt:          numOf(t, k, "checked_at"),
				BlockTime:          numOf(t, k, "block_time"),
				BlobRetentionS:     numOf(t, k, "blob_retention_s"),
				RetentionLatestS:   numOf(t, k, "retention_latest_s"),
				RetentionAtHeightS: numOf(t, k, "retention_at_height_s"),
				RetentionSource:    archive.RetentionSource(numOf(t, k, "retention_source")),
				PromiseCreated:     numOf(t, k, "promise_created"),
				FastWindow:         numOf(t, k, "fast_window"),
			}
		}
		return r
	case "anchor_intent", "13":
		return &archive.AnchorIntentRecord{
			DA:         commitment.DA(numOf(t, in, "da")),
			Commitment: bytesOf(t, in, "commitment"),
			Namespace:  bytesOf(t, in, "namespace"),
			RefHeight:  numOf(t, in, "ref_height"),
			Tx:         bytesOf(t, in, "tx"),
			Signer:     bytesOf(t, in, "signer"),
			CreatedAt:  numOf(t, in, "created_at"),
		}
	case "absence_proof", "14":
		return &archive.AbsenceProofRecord{
			DA:            commitment.DA(numOf(t, in, "da")),
			Commitment:    bytesOf(t, in, "commitment"),
			Namespace:     bytesOf(t, in, "namespace"),
			Height:        numOf(t, in, "height"),
			Header:        bytesOf(t, in, "header"),
			DAH:           bytesOf(t, in, "dah"),
			NamespaceData: bytesOf(t, in, "namespace_data"),
			Results:       bytesOf(t, in, "results"),
			NextHeader:    bytesOf(t, in, "next_header"),
		}
	case "rejection", "5":
		r := &archive.RejectionRecord{
			Error:      in["error"].(string),
			GateID:     in["gate_id"].(string),
			RejectedAt: numOf(t, in, "rejected_at"),
		}
		copy(r.CommitmentHash[:], bytesOf(t, in, "commitment_hash"))
		return r
	}
	require.FailNow(t, "unknown kind")
	return nil
}
