// Package execcapture keeps, outside the archive, the proof of a rail
// transaction's execution result before the nodes prune it: the headers at
// height and height + 1, namespace proofs against the first one's data_hash
// that give the transaction's index, the transaction's result and the Merkle
// path from that result to the second one's last_results_hash. It is a writer-side store
// of the gate; verifiers do not read it.
package execcapture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrConflict is a write that disagrees with what the store holds for
	// the same key; the first write stays.
	ErrConflict = errors.New("execcapture: conflicting capture")
	// ErrInvalid is a capture or a key the store refuses.
	ErrInvalid = errors.New("execcapture: invalid capture")
)

// Result is the part of an ExecTxResult that the block's results hash
// covers.
type Result struct {
	Code      uint32 `json:"code"`
	Data      []byte `json:"data,omitempty"`
	GasWanted int64  `json:"gas_wanted"`
	GasUsed   int64  `json:"gas_used"`
}

// Proof is the RFC 6962 audit path of one result to last_results_hash.
type Proof struct {
	Total    int64    `json:"total"`
	Index    int64    `json:"index"`
	LeafHash []byte   `json:"leaf_hash"`
	Aunts    [][]byte `json:"aunts"`
}

// Tx is the capture of one transaction of a block.
type Tx struct {
	RailRef string `json:"rail_ref"`
	Index   uint32 `json:"tx_index"`
	Result  Result `json:"result"`
	Proof   Proof  `json:"proof"`
}

// Block is everything captured at (ChainID, Height): the protobuf headers
// at Height and Height + 1, the namespace proofs that give every captured
// transaction's index, and the transactions captured from that block. The
// header and the proofs are shared by all captures of the block.
type Block struct {
	ChainID    string           `json:"chain_id"`
	Height     uint64           `json:"height"`
	Header     []byte           `json:"header"`
	NextHeader []byte           `json:"next_header"`
	Namespaces []NamespaceProof `json:"namespace_proofs"`
	Txs        []Tx             `json:"txs"`
}

// Pending is a rail reference whose capture is not done yet.
type Pending struct {
	RailRef        string `json:"rail_ref"`
	CommitmentHash string `json:"commitment_hash"`
	// SeenHead is the chain head when the reference was first tracked; the
	// age of a capture whose height is not known yet counts from it.
	SeenHead uint64 `json:"seen_head,omitempty"`
	// ExecHeight is the height the transaction was found at, once known.
	ExecHeight uint64 `json:"exec_height,omitempty"`
	// FromSweep marks a reference that no Record announced: the sweep
	// found it.
	FromSweep bool `json:"from_sweep,omitempty"`
}

// Store keeps captures and the references still to capture. Every write is
// idempotent.
type Store interface {
	// PutBlock merges b into the block at (b.ChainID, b.Height). A different
	// next header, or another capture of the same rail reference, is
	// ErrConflict.
	PutBlock(ctx context.Context, b Block) error
	// Captured reports whether the rail reference is captured.
	Captured(ctx context.Context, railRef string) (bool, error)
	// Block reads the block at (chainID, height).
	Block(ctx context.Context, chainID string, height uint64) (Block, error)
	PutPending(ctx context.Context, p Pending) error
	ListPending(ctx context.Context) ([]Pending, error)
	DeletePending(ctx context.Context, railRef string) error
}

// Dir is a Store in a local directory:
//
//	blocks/<chain_id>/<height>.json   one Block
//	refs/<rail_ref>                   "<chain_id>/<height>" of its capture
//	pending/<rail_ref>.json           one Pending
//
// Files are written to a temporary name, synced and renamed.
type Dir struct {
	root string
	mu   sync.Mutex
}

// OpenDir opens or creates the store at root.
func OpenDir(root string) (*Dir, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: no directory", ErrInvalid)
	}
	for _, sub := range []string{"blocks", "refs", "pending"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o700); err != nil {
			return nil, fmt.Errorf("execcapture: %w", err)
		}
	}
	return &Dir{root: root}, nil
}

// ValidRailRef reports whether s is 64 lower-case hex characters, the form
// of a Celestia transaction hash in a receipt.
func ValidRailRef(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validChainID(s string) bool {
	if len(s) < 1 || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (d *Dir) blockPath(chainID string, height uint64) string {
	return filepath.Join(d.root, "blocks", chainID, strconv.FormatUint(height, 10)+".json")
}

// PutBlock merges b into the stored block.
func (d *Dir) PutBlock(_ context.Context, b Block) error {
	if !validChainID(b.ChainID) || b.Height == 0 || len(b.Header) == 0 || len(b.NextHeader) == 0 || len(b.Namespaces) == 0 {
		return fmt.Errorf("%w: block key, headers or namespace proofs", ErrInvalid)
	}
	for _, t := range b.Txs {
		if !ValidRailRef(t.RailRef) {
			return fmt.Errorf("%w: rail_ref", ErrInvalid)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, err := d.readBlock(b.ChainID, b.Height)
	switch {
	case errors.Is(err, os.ErrNotExist):
		cur = Block{ChainID: b.ChainID, Height: b.Height, Header: bytes.Clone(b.Header), NextHeader: bytes.Clone(b.NextHeader), Namespaces: b.Namespaces}
	case err != nil:
		return err
	case !bytes.Equal(cur.Header, b.Header) || !bytes.Equal(cur.NextHeader, b.NextHeader) || !sameJSON(cur.Namespaces, b.Namespaces):
		return fmt.Errorf("%w: other headers or namespace proofs at %s/%d", ErrConflict, b.ChainID, b.Height)
	}
	for _, t := range b.Txs {
		i := slices.IndexFunc(cur.Txs, func(c Tx) bool { return c.RailRef == t.RailRef })
		if i < 0 {
			cur.Txs = append(cur.Txs, t)
			continue
		}
		if !sameJSON(cur.Txs[i], t) {
			return fmt.Errorf("%w: another capture of %s", ErrConflict, t.RailRef)
		}
	}
	if err := d.writeJSON(d.blockPath(b.ChainID, b.Height), cur); err != nil {
		return err
	}
	for _, t := range b.Txs {
		where := b.ChainID + "/" + strconv.FormatUint(b.Height, 10)
		if err := d.writeFile(filepath.Join(d.root, "refs", t.RailRef), []byte(where)); err != nil {
			return err
		}
	}
	return nil
}

func sameJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// Captured reports whether railRef has a capture.
func (d *Dir) Captured(_ context.Context, railRef string) (bool, error) {
	if !ValidRailRef(railRef) {
		return false, fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	_, err := os.Stat(filepath.Join(d.root, "refs", railRef))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	}
	return false, fmt.Errorf("execcapture: %w", err)
}

// Block reads the block at (chainID, height); a missing one wraps
// os.ErrNotExist.
func (d *Dir) Block(_ context.Context, chainID string, height uint64) (Block, error) {
	if !validChainID(chainID) {
		return Block{}, fmt.Errorf("%w: chain id", ErrInvalid)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readBlock(chainID, height)
}

func (d *Dir) readBlock(chainID string, height uint64) (Block, error) {
	raw, err := os.ReadFile(d.blockPath(chainID, height))
	if err != nil {
		return Block{}, fmt.Errorf("execcapture: %w", err)
	}
	var b Block
	if err := json.Unmarshal(raw, &b); err != nil {
		return Block{}, fmt.Errorf("execcapture: block %s/%d: %w", chainID, height, err)
	}
	return b, nil
}

// PutPending writes p, replacing what the store holds for its reference.
func (d *Dir) PutPending(_ context.Context, p Pending) error {
	if !ValidRailRef(p.RailRef) {
		return fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writeJSON(filepath.Join(d.root, "pending", p.RailRef+".json"), p)
}

// ListPending returns every pending reference. A file that does not decode
// is skipped with an error joined to the result.
func (d *Dir) ListPending(_ context.Context) ([]Pending, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ents, err := os.ReadDir(filepath.Join(d.root, "pending"))
	if err != nil {
		return nil, fmt.Errorf("execcapture: %w", err)
	}
	var (
		out  []Pending
		errs []error
	)
	for _, e := range ents {
		name := e.Name()
		ref, ok := strings.CutSuffix(name, ".json")
		if !ok || !ValidRailRef(ref) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(d.root, "pending", name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var p Pending
		if err := json.Unmarshal(raw, &p); err != nil || p.RailRef != ref {
			errs = append(errs, fmt.Errorf("execcapture: pending %s does not decode", ref))
			continue
		}
		out = append(out, p)
	}
	return out, errors.Join(errs...)
}

// DeletePending removes the pending entry of railRef, if any.
func (d *Dir) DeletePending(_ context.Context, railRef string) error {
	if !ValidRailRef(railRef) {
		return fmt.Errorf("%w: rail_ref", ErrInvalid)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	err := os.Remove(filepath.Join(d.root, "pending", railRef+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("execcapture: %w", err)
	}
	return nil
}

func (d *Dir) writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("execcapture: %w", err)
	}
	return d.writeFile(path, raw)
}

func (d *Dir) writeFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("execcapture: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("execcapture: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(raw)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("execcapture: %w", werr)
	}
	return nil
}
