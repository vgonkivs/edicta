// Command fibrecommit-gen writes the Fibre (da = 1) commitment vectors
// (spec/vectors/da/fibre_commit.json) using only upstream code:
// celestia-app's fibre.NewBlob with the default blob config for blob
// version 0. It lives in its own module, with the replace set of the
// celestia-node release the Edicta celestia module builds against, so the
// main module never depends on celestia-app and no Edicta code can leak into
// the expected values.
//
// Usage (from this directory):
//
//	go run .           regenerate ../../da/fibre_commit.json
//	go run . -check    exit 1 if the file differs from a fresh generation
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/celestiaorg/celestia-app/v10/fibre"
)

const (
	maxInlineBlob = 1024
	patternName   = "affine-7-3"
	headerSize    = 5
	expectReject  = "ErrDACommitmentMismatch"
)

// The one Fibre blob anchored on Mocha that the 009 research recomputed
// against the chain. The generator does not touch the network: it recomputes
// the commitment from the payload and fails if it differs from what the
// chain recorded.
var live = liveRef{
	ChainID:       "mocha-5",
	Height:        "1402819",
	TxHash:        "63CE1560A08212CDE9B126D57A2FECF59FBF04E0F05DD033BE8918A48839B04E",
	NamespaceHex:  "000000000000000000000000000000000000000000706f70736d696e31",
	UploadSize:    "262144",
	ObservedOn:    "2026-10-05",
	commitmentHex: "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e",
	payload:       []byte{0x65},
}

type liveRef struct {
	ChainID      string `json:"chain_id"`
	Height       string `json:"height"`
	TxHash       string `json:"tx_hash"`
	NamespaceHex string `json:"namespace_hex"`
	UploadSize   string `json:"upload_size"`
	ObservedOn   string `json:"observed_on"`

	commitmentHex string
	payload       []byte
}

type file struct {
	Format    string            `json:"format"`
	Revision  string            `json:"revision"`
	Generator string            `json:"generator"`
	Upstream  map[string]string `json:"upstream"`
	Params    map[string]string `json:"params"`
	Patterns  map[string]string `json:"patterns"`
	Cases     []vector          `json:"cases"`
	Reject    []vector          `json:"reject"`
	AnchorK2  []anchorRoute     `json:"anchor_k2_with_fibre_committer"`
}

type vector struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	Size          string   `json:"size"`
	BlobHex       *string  `json:"blob_hex,omitempty"`
	BlobPattern   string   `json:"blob_pattern,omitempty"`
	BlobSHA256Hex string   `json:"blob_sha256_hex"`
	RowSize       string   `json:"row_size,omitempty"`
	UploadSize    string   `json:"upload_size,omitempty"`
	BlobIDHex     string   `json:"blob_id_hex,omitempty"`
	CommitmentHex string   `json:"commitment_hex"`
	Live          *liveRef `json:"live,omitempty"`
	ExpectError   string   `json:"expect_error,omitempty"`
}

// anchorRoute restates an anchor.json K2 case for a gate that has a da = 1
// committer: anchor.json itself stays byte-identical and keeps describing a
// gate without one.
type anchorRoute struct {
	AnchorRef        string `json:"anchor_ref"`
	WithoutCommitter string `json:"without_committer"`
	Route            string `json:"route"`
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

func describeBlob(v *vector, data []byte, isPattern bool) {
	sum := sha256.Sum256(data)
	v.Size = strconv.Itoa(len(data))
	v.BlobSHA256Hex = hex.EncodeToString(sum[:])
	if isPattern && len(data) > maxInlineBlob {
		v.BlobPattern = patternName
		return
	}
	h := hex.EncodeToString(data)
	v.BlobHex = &h
}

// commit runs the upstream encoder on a private copy, because NewBlob takes
// ownership of its input and may reuse it as row storage.
func commit(data []byte) (fibre.BlobID, int, int, error) {
	b, err := fibre.NewBlob(bytes.Clone(data), fibre.DefaultBlobConfigV0())
	if err != nil {
		return nil, 0, 0, err
	}
	defer b.Free()
	id := bytes.Clone(b.ID())
	return id, b.RowSize(), b.UploadSize(), nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

type inputs struct {
	payload   []byte // payload.json ciphertext_hash_small_blob, the minimal_lmt blob
	da2Commit []byte // da_blob.json share commitment of that blob
}

func readInputs(v0 string) (inputs, error) {
	var in inputs
	var payload struct {
		Cases []struct {
			ID      string `json:"id"`
			BlobHex string `json:"blob_hex"`
		} `json:"cases"`
	}
	var da struct {
		Cases []struct {
			ID            string `json:"id"`
			CommitmentHex string `json:"commitment_hex"`
		} `json:"cases"`
	}
	if err := readJSON(filepath.Join(v0, "payload.json"), &payload); err != nil {
		return in, err
	}
	if err := readJSON(filepath.Join(v0, "da_blob.json"), &da); err != nil {
		return in, err
	}
	for _, c := range payload.Cases {
		if c.ID == "ciphertext_hash_small_blob" {
			b, err := hex.DecodeString(c.BlobHex)
			if err != nil {
				return in, err
			}
			in.payload = b
		}
	}
	for _, c := range da.Cases {
		if c.ID == "blob_v1_minimal_lmt_payload" {
			b, err := hex.DecodeString(c.CommitmentHex)
			if err != nil {
				return in, err
			}
			in.da2Commit = b
		}
	}
	if in.payload == nil || len(in.da2Commit) != fibre.CommitmentSize {
		return in, errors.New("minimal_lmt payload blob or its share commitment not found in vector inputs")
	}
	return in, nil
}

func build(in inputs) (*file, error) {
	cfg := fibre.DefaultBlobConfigV0()
	f := &file{
		Format:    "edicta-vectors/v0",
		Revision:  "v0-draft.17",
		Generator: "spec/vectors/tools/fibrecommit-gen",
		Upstream: map[string]string{
			"celestia-app": "github.com/celestiaorg/celestia-app/v10 v10.4.0-mocha (fibre.NewBlob, fibre.DefaultBlobConfigV0, Blob.ID, Blob.RowSize, Blob.UploadSize)",
			"replace_set":  "identical to github.com/celestiaorg/celestia-node v0.34.2-mocha go.mod",
		},
		Params: map[string]string{
			"blob_version":  strconv.Itoa(int(cfg.BlobVersion)),
			"original_rows": strconv.Itoa(cfg.OriginalRows),
			"parity_rows":   strconv.Itoa(cfg.ParityRows),
			"min_row_size":  strconv.Itoa(cfg.RowSize(1)),
			"header_size":   strconv.Itoa(headerSize),
			"max_data_size": strconv.Itoa(cfg.MaxDataSize),
		},
		Patterns: map[string]string{
			patternName: "byte i of the blob is (7*i + 3) mod 256, for i from 0",
		},
	}

	add := func(id, desc string, data []byte, isPattern bool) (string, error) {
		blobID, rowSize, uploadSize, err := commit(data)
		if err != nil {
			return "", fmt.Errorf("%s: %w", id, err)
		}
		c := blobID.Commitment()
		v := vector{ID: id, Description: desc, RowSize: strconv.Itoa(rowSize),
			UploadSize: strconv.Itoa(uploadSize), BlobIDHex: hex.EncodeToString(blobID),
			CommitmentHex: hex.EncodeToString(c[:])}
		describeBlob(&v, data, isPattern)
		f.Cases = append(f.Cases, v)
		return v.CommitmentHex, nil
	}

	liveCommit, err := add("fibre_live_mocha_popsmin1",
		"Live Mocha blob: one byte 0x65 in namespace popsmin1, anchored by a PayForFibre at the given height. The commitment equals the one in the PFF and its EventPayForFibre.",
		live.payload, false)
	if err != nil {
		return nil, err
	}
	if liveCommit != live.commitmentHex {
		return nil, fmt.Errorf("live vector: upstream recompute %s differs from the chain's %s", liveCommit, live.commitmentHex)
	}
	lv := live
	f.Cases[len(f.Cases)-1].Live = &lv

	payloadCommit, err := add("fibre_minimal_lmt_payload",
		"The payload blob of valid vector minimal_lmt (payload.json ciphertext_hash_small_blob). minimal_lmt itself is da = 2; this is the commitment the same bytes would have as a Fibre blob.",
		in.payload, false)
	if err != nil {
		return nil, err
	}

	sizes := []struct {
		n    int
		desc string
	}{
		{1, "One byte: header plus data fill 6 bytes of the first 64-byte row; the upload is the minimum 4096 x 64."},
		{262139, "Header plus data = 262144 = 4096 x 64 exactly: the largest blob with the minimum row size."},
		{262140, "One byte more: the row size grows to 128 and the upload doubles."},
		{262144, "256 KiB of data: row size 128 because the 5-byte header does not fit in 64-byte rows."},
		{524283, "Header plus data = 4096 x 128 exactly."},
		{524284, "One byte more: row size 192."},
		{1048571, "Header plus data = 4096 x 256 exactly (1 MiB)."},
		{1048572, "One byte more: row size 320."},
		{8388608, "8 MiB of data: row size 2112, several 64-byte units per row."},
	}
	for _, s := range sizes {
		if _, err := add(fmt.Sprintf("fibre_size_%d", s.n), s.desc, pattern(s.n), true); err != nil {
			return nil, err
		}
	}

	rej := func(id, desc string, data []byte, isPattern bool, commitmentHex string) {
		v := vector{ID: id, Description: desc, CommitmentHex: commitmentHex, ExpectError: expectReject}
		describeBlob(&v, data, isPattern)
		f.Reject = append(f.Reject, v)
	}
	flipped := bytes.Clone(in.payload)
	flipped[len(flipped)-1] ^= 0x01
	rej("fibre_anchor_x_sign_hash_y",
		"Anchor X, sign H(Y): the anchored blob X is the minimal_lmt payload, the archive serves Y (last byte flipped). A commitment with ciphertext_hash = SHA-256(Y) passes P2; only the recompute rejects.",
		flipped, false, payloadCommit)
	rej("fibre_trailing_zero",
		"The anchored payload plus one zero byte, as a source that kept row padding would serve it.",
		append(bytes.Clone(in.payload), 0x00), false, payloadCommit)
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(in.payload)))
	rej("fibre_with_header",
		"The anchored payload with its 5-byte Fibre header (version 0, uint32 BE size) still in front: Download strips it, so a source that returns it serves other bytes.",
		append(hdr[:], in.payload...), false, payloadCommit)
	rej("fibre_da2_commitment",
		"The da = 2 share commitment of the same bytes (da_blob.json blob_v1_minimal_lmt_payload) presented as a Fibre commitment.",
		in.payload, false, hex.EncodeToString(in.da2Commit))
	rej("fibre_live_commitment_other_bytes",
		"The live Mocha commitment with the minimal_lmt payload: the commitment binds bytes only, so any other blob fails.",
		in.payload, false, live.commitmentHex)
	rej("fibre_empty",
		"Zero bytes: fibre.NewBlob refuses empty data, so no commitment exists and the committer reports a mismatch. Unreachable through the gate, where S6 rejects payload_size 0 first.",
		nil, false, live.commitmentHex)
	over := cfg.MaxDataSize + 1
	rej(fmt.Sprintf("fibre_size_%d", over),
		"One byte above the Fibre maximum (2^27 - 5): fibre.NewBlob returns ErrBlobTooLarge. S7 allows payload_size up to 2^27, so a da = 1 commitment of 2^27 - 4 .. 2^27 bytes passes stage S and fails here (no such blob can be anchored).",
		pattern(over), true, live.commitmentHex)
	if _, _, _, err := commit(pattern(over)); !errors.Is(err, fibre.ErrBlobTooLarge) {
		return nil, fmt.Errorf("over-maximum blob: want ErrBlobTooLarge, got %v", err)
	}
	if _, _, _, err := commit(nil); err == nil {
		return nil, errors.New("empty blob: upstream accepted it")
	}

	for _, id := range []string{"k2_fibre_one_second_over", "k2_fibre_creation_unknown",
		"k2_fibre_retention_lowered_over", "k2_fibre_governance_minimum_over"} {
		f.AnchorK2 = append(f.AnchorK2, anchorRoute{AnchorRef: id,
			WithoutCommitter: "ErrArchiveRecomputeUnsupported", Route: "archive"})
	}
	return f, nil
}

func run() error {
	check := flag.Bool("check", false, "compare with the existing file instead of writing it")
	v0 := flag.String("v0", filepath.Join("..", "..", "v0"), "core vector directory (inputs)")
	out := flag.String("out", filepath.Join("..", "..", "da", "fibre_commit.json"), "output file")
	flag.Parse()

	in, err := readInputs(*v0)
	if err != nil {
		return err
	}
	f, err := build(in)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *check {
		old, err := os.ReadFile(*out)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, b) {
			return fmt.Errorf("%s differs from a fresh generation", *out)
		}
		fmt.Printf("OK: %s matches (%d cases, %d reject)\n", *out, len(f.Cases), len(f.Reject))
		return nil
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d cases, %d reject)\n", *out, len(f.Cases), len(f.Reject))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fibrecommit-gen:", err)
		os.Exit(1)
	}
}
