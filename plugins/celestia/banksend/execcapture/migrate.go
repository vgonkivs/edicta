package execcapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	"github.com/celestiaorg/go-square/v4/share"
	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/plugins/celestia/banksend/railverify"
)

// Archive is the gate's archive as the move of captures into it uses it.
type Archive interface {
	Put(ctx context.Context, r archive.Record) (archive.Outcome, error)
	archive.ExecResultReader
}

// rawReader serves the stored bytes of a record without decoding them, so
// that a record that does not decode can still be named by its hash.
type rawReader interface {
	Raw(ctx context.Context, key string) (io.ReadCloser, error)
}

// ErrRefused is a capture that is not moved into the archive: it does not
// map onto an execution result record, or the record does not check.
var ErrRefused = errors.New("execcapture: capture not moved into the archive")

// What became of one captured transaction.
const (
	// MigrationWritten: this run stored the record; the capture is dropped.
	MigrationWritten = "written"
	// MigrationAlreadyStored: an equivalent record held the key; the
	// capture is dropped.
	MigrationAlreadyStored = "already_stored"
	// MigrationRefused: the capture does not give a record that checks; it
	// stays.
	MigrationRefused = "refused"
	// MigrationKept: another record holds the key; the capture stays and
	// the conflict is reported.
	MigrationKept = "kept"
	// MigrationRetry: the archive could not be written or read; the next
	// run tries again.
	MigrationRetry = "retry"
)

// Equivalence of a stored record with the one built from the capture.
const (
	EquivalentBytes = "bytes"
	EquivalentFacts = "facts"
)

// Migrated is the outcome for one captured transaction.
type Migrated struct {
	ChainID     string
	Height      uint64
	RailRef     string
	Result      string
	Rule        string
	Equivalence string
	Path        string
	// Record is the record built from the capture; StoredHash is the
	// SHA-256 of the record the archive holds under its key, when read.
	Record     []byte
	StoredHash []byte
	Err        error
}

var (
	txNS  = share.TxNamespace.Bytes()
	pfbNS = share.PayForBlobNamespace.Bytes()
	pffNS = share.PayForFibreNamespace.Bytes()
)

// BuildRecord maps one captured transaction of its block file onto the
// execution result record: the block's chain id, height, headers and
// namespace proofs as stored, and the transaction's index, result leaf and
// path. A capture that does not map is ErrRefused.
func BuildRecord(b Block, t Tx) (*archive.ExecutionResultRecord, error) {
	refuse := func(format string, a ...any) (*archive.ExecutionResultRecord, error) {
		return nil, fmt.Errorf("%w: MG2: "+format, append([]any{ErrRefused}, a...)...)
	}
	if !ValidRailRef(t.RailRef) {
		return refuse("rail_ref is not 64 lower-case hex characters")
	}
	ref, _ := hex.DecodeString(t.RailRef)
	if t.Proof.Index != int64(t.Index) {
		return refuse("proof index %d differs from tx_index %d", t.Proof.Index, t.Index)
	}
	leaf, err := resultLeaf(t.Result)
	if err != nil {
		return refuse("result: %v", err)
	}
	if lh := sha256.Sum256(append([]byte{0}, leaf...)); !bytes.Equal(t.Proof.LeafHash, lh[:]) {
		return refuse("leaf_hash is not the hash of the result leaf")
	}
	path := make([]byte, 0, 32*len(t.Proof.Aunts))
	for i, a := range t.Proof.Aunts {
		if len(a) != 32 {
			return refuse("aunt %d is %d bytes", i, len(a))
		}
		path = append(path, a...)
	}
	if t.Proof.Total < 1 {
		return refuse("path total %d", t.Proof.Total)
	}
	rec := &archive.ExecutionResultRecord{
		ChainID: b.ChainID, RailRef: ref, Height: b.Height, TxIndex: uint64(t.Index),
		Header: bytes.Clone(b.Header), NextHeader: bytes.Clone(b.NextHeader),
		Result: leaf, ResultsTotal: uint64(t.Proof.Total), ResultPath: path,
	}
	seen := map[string]bool{}
	for i, np := range b.Namespaces {
		ns := string(np.Namespace)
		if seen[ns] {
			return refuse("namespace %x appears twice", np.Namespace)
		}
		seen[ns] = true
		var slot *[]byte
		switch ns {
		case string(txNS):
			slot = &rec.TxProof
		case string(pfbNS):
			slot = &rec.PFBProof
		case string(pffNS):
			slot = &rec.PFFProof
		default:
			if i != len(b.Namespaces)-1 {
				return refuse("entry %d of namespace %x is not the last", i, np.Namespace)
			}
			slot = &rec.ClosingProof
		}
		var sp proof.ShareProof
		if err := sp.Unmarshal(np.Proof); err != nil {
			return refuse("entry %d: %v", i, err)
		}
		s, e, ok := railverify.ShareProofSpan(sp, railverify.ShareProofWidth(sp))
		if !ok || s != np.Start || e != np.End {
			return refuse("entry %d: start and end are not the range its proof covers", i)
		}
		*slot = bytes.Clone(np.Proof)
	}
	if _, err := archive.Encode(rec); err != nil {
		return refuse("%v", err)
	}
	return rec, nil
}

// resultLeaf is the leaf the block's results hash covers for r: its
// deterministic fields, a zero one omitted.
func resultLeaf(r Result) ([]byte, error) {
	leaf, err := (&abci.ExecTxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}).Marshal()
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		leaf = []byte{}
	}
	return leaf, nil
}

// Conflicts is the number of captures that another record keeps out of the
// archive, at the last run that moved captures.
func (c *Capturer) Conflicts() uint64 { return c.conflicts.Load() }

// Migrate moves every captured transaction of the capture store into the
// archive and drops the captures the archive now proves. It is idempotent;
// a capture that stays is tried again on the next run. Without an archive,
// or while another Migrate runs, it does nothing.
//
// It runs beside Pass: moving a capture twice at once is harmless, since
// the write is idempotent and a capture is dropped only once the archive
// holds an equivalent record.
func (c *Capturer) Migrate(ctx context.Context) []Migrated {
	if c.arch == nil || !c.migrating.CompareAndSwap(false, true) {
		return nil
	}
	defer c.migrating.Store(false)
	blocks, err := c.store.Blocks(ctx)
	c.logBlocksErr(err)
	var (
		out  []Migrated
		kept uint64
	)
	for _, b := range blocks {
		for _, t := range b.Txs {
			if ctx.Err() != nil {
				return out
			}
			m := c.migrateTx(ctx, b, t)
			if m.Result == MigrationKept {
				kept++
			}
			out = append(out, m)
		}
	}
	c.conflicts.Store(kept)
	return out
}

// migrateTx builds the record of one capture, checks it, writes it, reads
// it back and drops the capture only when the archive holds an equivalent
// record. The capture is the gate's copy of a proof the nodes may have
// pruned, so every doubt keeps it.
func (c *Capturer) migrateTx(ctx context.Context, b Block, t Tx) Migrated {
	m := Migrated{ChainID: b.ChainID, Height: b.Height, RailRef: t.RailRef}
	rec, err := BuildRecord(b, t)
	if err != nil {
		return c.refused(m, "MG2", err)
	}
	m.Path, _ = archive.KeyPath(rec)
	m.Record, err = archive.Encode(rec)
	if err != nil {
		return c.refused(m, "MG2", err)
	}
	built, err := railverify.SelfCheckArchived(rec)
	if err != nil {
		return c.refused(m, "MG3", fmt.Errorf("%w: MG3: self-check %w", ErrRefused, err))
	}

	wctx, cancel := context.WithTimeout(ctx, c.archTimeout)
	written, err := c.arch.Put(wctx, rec)
	cancel()
	if err != nil && !errors.Is(err, archive.ErrCorrupt) && !errors.Is(err, archive.ErrConflict) {
		return c.retry(m, fmt.Errorf("execcapture: archive write: %w", err))
	}
	rctx, cancel := context.WithTimeout(ctx, c.archTimeout)
	stored, err := c.arch.ExecutionResult(rctx, b.ChainID, rec.RailRef)
	cancel()
	switch {
	case errors.Is(err, archive.ErrCorrupt):
		m.StoredHash = c.rawHash(ctx, m.Path)
		return c.kept(m, err)
	case err != nil:
		return c.retry(m, fmt.Errorf("execcapture: archive read back: %w", err))
	}
	sb, err := archive.Encode(stored)
	if err != nil {
		return c.kept(m, err)
	}
	sum := sha256.Sum256(sb)
	m.StoredHash = sum[:]
	switch {
	case bytes.Equal(sb, m.Record):
		m.Result, m.Equivalence = MigrationWritten, EquivalentBytes
		if written != archive.Written {
			m.Result = MigrationAlreadyStored
		}
	case sameFacts(stored, built):
		m.Result, m.Equivalence = MigrationAlreadyStored, EquivalentFacts
	default:
		return c.kept(m, errors.New("another record holds the key and is not equivalent to the built record"))
	}
	if err := c.store.MarkArchived(ctx, b.ChainID, b.Height, t.RailRef); err != nil {
		return c.retry(m, fmt.Errorf("execcapture: the record is archived, the capture is not dropped yet: %w", err))
	}
	c.logMu.Lock()
	delete(c.migrationLogged, t.RailRef)
	delete(c.retryLogged, t.RailRef)
	c.logMu.Unlock()
	return m
}

// sameFacts reports whether a stored record proves what the built one does:
// it checks, with the same height, index, result count and result, against
// headers of the same hashes, which fix data_hash and last_results_hash.
func sameFacts(stored *archive.ExecutionResultRecord, built railverify.ArchivedFacts) bool {
	f, err := railverify.SelfCheckArchived(stored)
	return err == nil && f.Height == built.Height && f.TxIndex == built.TxIndex && f.ResultsTotal == built.ResultsTotal &&
		bytes.Equal(f.Result, built.Result) && bytes.Equal(f.HeaderHash, built.HeaderHash) &&
		bytes.Equal(f.NextHeaderHash, built.NextHeaderHash)
}

func (c *Capturer) rawHash(ctx context.Context, path string) []byte {
	rr, ok := c.arch.(rawReader)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.archTimeout)
	defer cancel()
	rc, err := rr.Raw(ctx, path)
	if err != nil {
		return nil
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(rc, archive.MaxRecordSize+1)); err != nil {
		return nil
	}
	return h.Sum(nil)
}

// logBlocksErr logs a capture store read error once until it changes, so a
// block file that does not decode is not reported on every sweep.
func (c *Capturer) logBlocksErr(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if msg == c.blocksErr {
		return
	}
	c.blocksErr = msg
	if err != nil {
		c.log.Error("execcapture: capture store block files not all read", "err", err)
	}
}

func (c *Capturer) refused(m Migrated, rule string, err error) Migrated {
	m.Result, m.Rule, m.Err = MigrationRefused, rule, err
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if !c.migrationLogged[m.RailRef] {
		c.migrationLogged[m.RailRef] = true
		c.log.Error("execcapture: a capture does not give an execution result record that checks; it stays in the capture store",
			"rail_ref", m.RailRef, "chain_id", m.ChainID, "height", m.Height, "rule", rule, "err", err)
	}
	return m
}

func (c *Capturer) kept(m Migrated, err error) Migrated {
	m.Result, m.Rule, m.Err = MigrationKept, "MG5", err
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if !c.migrationLogged[m.RailRef] {
		c.migrationLogged[m.RailRef] = true
		built := sha256.Sum256(m.Record)
		c.log.Error("execcapture: ALERT another record holds the archive key of a capture and does not prove the same facts; "+
			"the capture stays the gate's copy of the proof. Write the built record into another archive copy that verifiers read",
			"path", m.Path, "built_sha256", hex.EncodeToString(built[:]), "stored_sha256", hex.EncodeToString(m.StoredHash), "err", err)
	}
	return m
}

// retry warns once per reference until it moves, so a persistent archive
// fault does not flood the log on every run.
func (c *Capturer) retry(m Migrated, err error) Migrated {
	m.Result, m.Err = MigrationRetry, err
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if !c.retryLogged[m.RailRef] {
		c.retryLogged[m.RailRef] = true
		c.log.Warn("execcapture: capture not moved into the archive yet, retried on the next run", "rail_ref", m.RailRef, "err", err)
	}
	return m
}
