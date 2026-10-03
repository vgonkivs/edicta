// Command dacommit-gen writes the celestia_blob share-commitment vectors
// (da_blob.json) using only upstream code: go-square for blob framing and
// the commitment, and the celestia-core RFC 6962 root the app itself passes
// to CreateCommitment. It lives in its own module so the main module never
// depends on celestia-core, and so that no Edicta code can leak into the
// expected values.
//
// Usage (from this directory):
//
//	go run .           regenerate ../../v0/da_blob.json
//	go run . -check    exit 1 if the file differs from a fresh generation
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/celestiaorg/go-square/v4/inclusion"
	"github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
)

// The app passes appconsts.SubtreeRootThreshold; it is a protocol constant
// that light clients hard-code, so it is pinned here rather than imported.
const subtreeRootThreshold = 64

// Blobs above this size are described by a pattern instead of hex so the
// JSON stays small; consumers regenerate them and check blob_sha256_hex.
const maxInlineBlob = 1024

const patternName = "affine-7-3"

type file struct {
	Format    string            `json:"format"`
	Generator string            `json:"generator"`
	Upstream  map[string]string `json:"upstream"`
	Patterns  map[string]string `json:"patterns"`
	Cases     []vector          `json:"cases"`
	Reject    []vector          `json:"reject"`
}

type vector struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	NamespaceHex  string `json:"namespace_hex"`
	SignerHex     string `json:"signer_hex"`
	Size          string `json:"size"`
	BlobHex       string `json:"blob_hex,omitempty"`
	BlobPattern   string `json:"blob_pattern,omitempty"`
	BlobSHA256Hex string `json:"blob_sha256_hex"`
	ShareCount    string `json:"share_count,omitempty"`
	CommitmentHex string `json:"commitment_hex"`
	ExpectError   string `json:"expect_error,omitempty"`
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

func commit(ns share.Namespace, data []byte, shareVersion uint8, signer []byte) ([]byte, int, error) {
	var (
		b   *share.Blob
		err error
	)
	switch shareVersion {
	case share.ShareVersionZero:
		b, err = share.NewV0Blob(ns, data)
	case share.ShareVersionOne:
		b, err = share.NewV1Blob(ns, data, signer)
	default:
		return nil, 0, fmt.Errorf("unsupported share version %d", shareVersion)
	}
	if err != nil {
		return nil, 0, err
	}
	shares, err := b.ToShares()
	if err != nil {
		return nil, 0, err
	}
	c, err := inclusion.CreateCommitment(b, merkle.HashFromByteSlices, subtreeRootThreshold)
	if err != nil {
		return nil, 0, err
	}
	return c, len(shares), nil
}

func describeBlob(v *vector, data []byte, isPattern bool) {
	sum := sha256.Sum256(data)
	v.Size = strconv.Itoa(len(data))
	v.BlobSHA256Hex = hex.EncodeToString(sum[:])
	if isPattern && len(data) > maxInlineBlob {
		v.BlobPattern = patternName
		return
	}
	v.BlobHex = hex.EncodeToString(data)
}

type inputs struct {
	ns      share.Namespace
	signer  []byte
	payload []byte
}

func readInputs(dir string) (inputs, error) {
	var in inputs
	var valid struct {
		Cases []struct {
			ID    string `json:"id"`
			Input struct {
				PayloadRef struct {
					Namespace string `json:"namespace"`
					Signer    string `json:"signer"`
				} `json:"payload_ref"`
			} `json:"input"`
		} `json:"cases"`
	}
	var payload struct {
		Cases []struct {
			ID      string `json:"id"`
			BlobHex string `json:"blob_hex"`
		} `json:"cases"`
	}
	if err := readJSON(filepath.Join(dir, "valid.json"), &valid); err != nil {
		return in, err
	}
	if err := readJSON(filepath.Join(dir, "payload.json"), &payload); err != nil {
		return in, err
	}
	for _, c := range valid.Cases {
		if c.ID != "minimal_lmt" {
			continue
		}
		nsb, err := hex.DecodeString(c.Input.PayloadRef.Namespace)
		if err != nil {
			return in, err
		}
		if in.ns, err = share.NewNamespaceFromBytes(nsb); err != nil {
			return in, err
		}
		if in.signer, err = hex.DecodeString(c.Input.PayloadRef.Signer); err != nil {
			return in, err
		}
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
	if len(in.signer) != share.SignerSize || in.payload == nil {
		return in, errors.New("minimal_lmt locator or payload blob not found in vector inputs")
	}
	return in, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func build(in inputs) (*file, error) {
	f := &file{
		Format:    "edicta-vectors/v0",
		Generator: "spec/vectors/tools/dacommit-gen",
		Upstream: map[string]string{
			"go-square":              "github.com/celestiaorg/go-square/v4 v4.0.1 (share.NewV1Blob, share.NewV0Blob, inclusion.CreateCommitment)",
			"merkle_root":            "github.com/cometbft/cometbft/crypto/merkle.HashFromByteSlices, replaced by github.com/celestiaorg/celestia-core v0.42.3 as in celestia-app v10.4.0-mocha",
			"subtree_root_threshold": strconv.Itoa(subtreeRootThreshold),
		},
		Patterns: map[string]string{
			patternName: "byte i of the blob is (7*i + 3) mod 256, for i from 0",
		},
	}
	nsHex := hex.EncodeToString(in.ns.Bytes())
	signerHex := hex.EncodeToString(in.signer)

	add := func(id, desc string, data []byte, isPattern bool) error {
		c, n, err := commit(in.ns, data, share.ShareVersionOne, in.signer)
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		v := vector{ID: id, Description: desc, NamespaceHex: nsHex, SignerHex: signerHex,
			ShareCount: strconv.Itoa(n), CommitmentHex: hex.EncodeToString(c)}
		describeBlob(&v, data, isPattern)
		f.Cases = append(f.Cases, v)
		return nil
	}

	first := share.FirstSparseShareContentSize - share.SignerSize
	cont := share.ContinuationSparseShareContentSize
	if err := add("blob_v1_minimal_lmt_payload",
		"The payload blob of valid vector minimal_lmt (payload.json ciphertext_hash_small_blob) with the minimal_lmt namespace and signer. minimal_lmt itself carries a placeholder commitment, so this is the commitment a real anchor of that blob has.",
		in.payload, false); err != nil {
		return nil, err
	}
	sizes := []struct {
		n    int
		desc string
	}{
		{1, "One byte: one share."},
		{first, "Fills the first share-version-1 share exactly (512 - 29 - 1 - 4 - 20 bytes)."},
		{first + 1, "One byte over the first share: two shares."},
		{first + cont, "Fills two shares exactly."},
		{first + cont + 1, "One byte over two shares: three shares."},
		{first + 63*cont, "Exactly 64 shares, the subtree root threshold."},
		{first + 63*cont + 1, "65 shares: the subtree width grows past the threshold."},
		{first + 127*cont, "Exactly 128 shares."},
		{first + 127*cont + 1, "129 shares."},
		{262144, "256 KiB, the size of valid vector blob_large_payload."},
		{1 << 20, "1 MiB."},
	}
	for _, s := range sizes {
		if err := add(fmt.Sprintf("blob_v1_size_%d", s.n), s.desc, pattern(s.n), true); err != nil {
			return nil, err
		}
	}

	rej := func(id, desc string, ns share.Namespace, signer, data []byte, commitment []byte) {
		v := vector{ID: id, Description: desc, NamespaceHex: hex.EncodeToString(ns.Bytes()),
			SignerHex: hex.EncodeToString(signer), CommitmentHex: hex.EncodeToString(commitment),
			ExpectError: "ErrDACommitmentMismatch"}
		describeBlob(&v, data, false)
		f.Reject = append(f.Reject, v)
	}
	payloadV1, _, err := commit(in.ns, in.payload, share.ShareVersionOne, in.signer)
	if err != nil {
		return nil, err
	}
	payloadV0, _, err := commit(in.ns, in.payload, share.ShareVersionZero, nil)
	if err != nil {
		return nil, err
	}
	otherSigner := bytes.Repeat([]byte{0x11}, share.SignerSize)
	payloadOtherSigner, _, err := commit(in.ns, in.payload, share.ShareVersionOne, otherSigner)
	if err != nil {
		return nil, err
	}
	otherNS := share.MustNewV0Namespace([]byte("edicta/d02"))
	payloadOtherNS, _, err := commit(otherNS, in.payload, share.ShareVersionOne, in.signer)
	if err != nil {
		return nil, err
	}

	rej("commitment_share_v0",
		"Commitment of the same bytes posted as a share-version-0 blob; the check recomputes with share version 1 and the signer.",
		in.ns, in.signer, in.payload, payloadV0)
	rej("commitment_other_signer",
		"Commitment of the same bytes posted by another account (signer 0x11 * 20); the locator names the minimal_lmt signer.",
		in.ns, in.signer, in.payload, payloadOtherSigner)
	rej("commitment_other_namespace",
		"Commitment of the same bytes in namespace edicta/d02; the locator names edicta/d01.",
		in.ns, in.signer, in.payload, payloadOtherNS)
	flipped := bytes.Clone(in.payload)
	flipped[len(flipped)-1] ^= 0x01
	rej("anchor_x_sign_hash_y",
		"Anchor X, sign H(Y): the anchored blob X is the minimal_lmt payload, the archive serves Y (last byte flipped). A commitment with ciphertext_hash = SHA-256(Y) passes P2; only the recompute rejects.",
		in.ns, in.signer, flipped, payloadV1)
	padded := append(bytes.Clone(in.payload), 0x00)
	rej("blob_with_trailing_zero",
		"The anchored payload plus one zero byte, as a producer that kept share padding would serve it.",
		in.ns, in.signer, padded, payloadV1)
	return f, nil
}

func run() error {
	check := flag.Bool("check", false, "compare with the existing file instead of writing it")
	dir := flag.String("dir", filepath.Join("..", "..", "v0"), "vector directory")
	flag.Parse()

	in, err := readInputs(*dir)
	if err != nil {
		return err
	}
	f, err := build(in)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	path := filepath.Join(*dir, "da_blob.json")
	if *check {
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, out) {
			return fmt.Errorf("%s differs from a fresh generation", path)
		}
		fmt.Printf("OK: %s matches (%d cases, %d reject)\n", path, len(f.Cases), len(f.Reject))
		return nil
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d cases, %d reject)\n", path, len(f.Cases), len(f.Reject))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dacommit-gen:", err)
		os.Exit(1)
	}
}
