package archive

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/commitment"
)

// KindExecutionResult is the archived execution result of one ordinary rail
// transaction (since spec revision v1.1).
const KindExecutionResult Kind = 19

const (
	maxExecResultSize = 1 << 25
	maxChainIDLen     = 50
	maxResultPath     = 2048
	execDir           = "exec"
)

// ExecutionResultRecord proves that the transaction RailRef is at TxIndex of
// block Height of chain ChainID and has the result Result. Nothing in it is
// trusted: a reader ties both headers to its trusted chain and checks every
// proof. PFBProof, PFFProof and ClosingProof are nil when absent; Result and
// ResultPath may be empty.
type ExecutionResultRecord struct {
	ChainID      string
	RailRef      []byte
	Height       uint64
	TxIndex      uint64
	Header       []byte
	NextHeader   []byte
	TxProof      []byte
	PFBProof     []byte
	PFFProof     []byte
	ClosingProof []byte
	Result       []byte
	ResultsTotal uint64
	ResultPath   []byte
}

func (*ExecutionResultRecord) Kind() Kind { return KindExecutionResult }

// ExecResultReader is the optional read side of the execution result record.
// It returns ErrNotFound for an absent key and an ErrCorrupt error for a
// stored record that does not decode or does not carry its key.
type ExecResultReader interface {
	ExecutionResult(ctx context.Context, chainID string, railRef []byte) (*ExecutionResultRecord, error)
}

func execResultSchema() []fdef {
	return []fdef{
		{3, "chain_id", tChainID, pReq, 1, maxChainIDLen, nil},
		{4, "rail_ref", tBstr, pReq, 32, 32, nil},
		{5, "height", tUint, pReq, 0, 0, nil},
		{6, "tx_index", tUint, pReq, 0, 0, nil},
		{7, "header", tBstr, pReq, 1, maxOpaque, nil},
		{8, "next_header", tBstr, pReq, 1, maxOpaque, nil},
		{9, "tx_proof", tBstr, pReq, 1, maxOpaque, nil},
		{10, "pfb_proof", tBstr, pOpt, 1, maxOpaque, nil},
		{11, "pff_proof", tBstr, pOpt, 1, maxOpaque, nil},
		{12, "closing_proof", tBstr, pOpt, 1, maxOpaque, nil},
		{13, "result", tBstr, pReq, 0, maxOpaque, nil},
		{14, "results_total", tUint, pReq, 0, 0, nil},
		{15, "result_path", tAunts, pReq, 0, maxResultPath, nil},
	}
}

// ValidChainID reports whether s may be the chain id of an execution result:
// 1 to 50 bytes of [A-Za-z0-9._-], not starting with a dot, so that it is
// one plain segment of a canonical path.
func ValidChainID(s string) bool {
	if len(s) < 1 || len(s) > maxChainIDLen || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isChainIDChar(s[i]) {
			return false
		}
	}
	return true
}

func isChainIDChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// ExecResultPath is the path of an execution result record.
func ExecResultPath(chainID string, railRef []byte) (string, error) {
	if !ValidChainID(chainID) {
		return "", fmt.Errorf("archive: chain id %q: %w", chainID, commitment.ErrInvalidString)
	}
	if len(railRef) != 32 {
		return "", fmt.Errorf("archive: rail_ref of %d bytes: %w", len(railRef), commitment.ErrFieldSize)
	}
	return execDir + "/" + chainID + "/" + hex.EncodeToString(railRef), nil
}

func parseExecKey(parts []string) bool {
	return len(parts) == 3 && ValidChainID(parts[1]) && isLowerHex32(parts[2])
}

// isExecPath reports whether a canonical path names an execution result.
func isExecPath(path string) bool { return strings.HasPrefix(path, execDir+"/") }

// DecodeExecutionResult strictly decodes one execution result record. Every
// failure wraps ErrCorrupt and the cause. A record of any other kind is
// refused at the kind (ErrInvalidEnum). The result does not alias b.
func DecodeExecutionResult(b []byte) (*ExecutionResultRecord, error) {
	rec, err := decodeKinds(b, true, execKinds)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return rec.(*ExecutionResultRecord), nil
}

// DecodeAt strictly decodes the record stored under a canonical path with
// the reader of that path: an execution result under exec/, the general
// reader elsewhere. Every failure wraps ErrCorrupt and the cause.
func DecodeAt(path string, b []byte) (Record, error) {
	if isExecPath(path) {
		return DecodeExecutionResult(b)
	}
	return Decode(b)
}

func execKinds(k Kind) bool { return k == KindExecutionResult }

func buildExecResult(pm *pmap, bs func(*pmap, uint64) []byte, u func(*pmap, uint64) uint64) Record {
	r := &ExecutionResultRecord{
		ChainID: string(pm.items[3].b), RailRef: bs(pm, 4), Height: u(pm, 5), TxIndex: u(pm, 6),
		Header: bs(pm, 7), NextHeader: bs(pm, 8), TxProof: bs(pm, 9), PFBProof: bs(pm, 10), PFFProof: bs(pm, 11),
		ClosingProof: bs(pm, 12), Result: bs(pm, 13), ResultsTotal: u(pm, 14), ResultPath: bs(pm, 15),
	}
	// Keys 13 and 15 are required and may be empty; a decoded record always
	// holds them.
	if r.Result == nil {
		r.Result = []byte{}
	}
	if r.ResultPath == nil {
		r.ResultPath = []byte{}
	}
	return r
}

func encodeExecResult(w *mapWriter, r *ExecutionResultRecord) {
	w.uint(2, uint64(KindExecutionResult))
	w.text(3, r.ChainID)
	w.bytes(4, r.RailRef)
	w.uint(5, r.Height)
	w.uint(6, r.TxIndex)
	w.bytes(7, r.Header)
	w.bytes(8, r.NextHeader)
	w.bytes(9, r.TxProof)
	w.opt(10, r.PFBProof)
	w.opt(11, r.PFFProof)
	w.opt(12, r.ClosingProof)
	w.bytes(13, r.Result)
	w.uint(14, r.ResultsTotal)
	w.bytes(15, r.ResultPath)
}
