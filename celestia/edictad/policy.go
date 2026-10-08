package edictad

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
)

// PolicyConfig is the optional [policy] table. Without a mandate the gate
// authorizes without a spending policy.
type PolicyConfig struct {
	// MandateFile holds the canonical SignedMandate, signed by the principal
	// for this gate_id. The decision age cap and the other limits are rules of
	// the mandate itself, not of this file.
	MandateFile string `toml:"mandate_file"`
}

// Enabled reports whether a mandate is configured.
func (p PolicyConfig) Enabled() bool { return p.MandateFile != "" }

// WithDefaults returns p unchanged: the table has no defaulted key.
func (p PolicyConfig) WithDefaults() PolicyConfig { return p }

// ValidateBasic checks what needs no other table; the archive requirement is
// checked by Config.
func (p PolicyConfig) ValidateBasic() error { return nil }

// policyExtractors is the registry of the actions this daemon can read facts
// from. Only bank sends on Celestia in utia are known.
func policyExtractors() (*policy.Extractors, error) {
	return policy.NewExtractors(tiatransfer.New())
}

// loadMandate reads and verifies the mandate file.
func loadMandate(path, gateID string) ([]byte, *policy.SignedMandate, commitment.Hash, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, commitment.Hash{}, fmt.Errorf("edictad: mandate file: %w", err)
	}
	sm, h, err := policy.VerifyMandate(b)
	if err != nil {
		return nil, nil, commitment.Hash{}, fmt.Errorf("edictad: mandate file: %w", err)
	}
	if sm.Mandate.GateID != gateID {
		return nil, nil, commitment.Hash{}, cfgErr("the mandate is bound to gate %q, not gate.gate_id %q", sm.Mandate.GateID, gateID)
	}
	return b, sm, h, nil
}

// polInfo is what the request path and the sweep need to archive policy
// records.
type polInfo struct {
	gateID     string
	counterKey [32]byte
	state      registry.StateRegistry
}

// publishMandate writes the mandate record and the genesis closed set. Both
// are idempotent; a failure refuses the start, because a verifier cannot
// check any verdict without them.
func publishMandate(ctx context.Context, aio *archiveIO, signed []byte, timeout time.Duration) error {
	genesis := policy.EmptyClosedSet()
	set, err := policy.EncodeClosedSet(&genesis)
	if err != nil {
		return fmt.Errorf("edictad: genesis closed set: %w", err)
	}
	for _, r := range []archive.Record{&archive.MandateRecord{SignedMandate: signed}, &archive.PolicyClosedRecord{ClosedSet: set}} {
		pctx, cancel := context.WithTimeout(ctx, timeout)
		_, err := aio.put(pctx, r)
		cancel()
		if err != nil {
			return fmt.Errorf("edictad: archive policy record %s: %w", r.Kind(), err)
		}
	}
	return nil
}

// successorRecord names the allow that consumed the verdict's previous state.
func (p *polInfo) successorRecord(verdict []byte, h commitment.Hash) (archive.Record, error) {
	sv, _, err := policy.DecodeSignedVerdict(verdict)
	if err != nil {
		return nil, err
	}
	prev, ok := sv.Verdict.PrevStateHash()
	if !ok {
		return nil, errors.New("the allow verdict has no previous state")
	}
	return &archive.PolicySuccessorRecord{
		GateID: p.gateID, CounterKey: bytes.Clone(p.counterKey[:]), StateHash: prev[:], CommitmentHash: h[:],
	}, nil
}

// allowRecords are the policy records of an allow, in archive order: the
// closed bucket and set if the allow closed an hour, the verdict, the
// successor.
func (p *polInfo) allowRecords(closedBucket, closedSet, verdict []byte, h commitment.Hash) ([]archive.Record, error) {
	var recs []archive.Record
	if len(closedBucket) > 0 {
		recs = append(recs, &archive.PolicyBucketRecord{Bucket: closedBucket}, &archive.PolicyClosedRecord{ClosedSet: closedSet})
	}
	recs = append(recs, &archive.PolicyAllowRecord{SignedVerdict: verdict})
	succ, err := p.successorRecord(verdict, h)
	if err != nil {
		return nil, err
	}
	return append(recs, succ), nil
}

// repair writes what the registry lets a scan rebuild: the retained closed
// buckets and the current closed set. A set that a later one replaced before
// its write succeeded is not rebuilt.
func (p *polInfo) repair(ctx context.Context, s *sweeper, st *sweepStats) {
	cell, err := p.state.State(ctx, registry.StateKey(p.counterKey))
	if err != nil {
		s.log.Error("edictad: archive sweep could not read the policy cell", "err", err)
		st.failed++
		return
	}
	if cell.Version == (commitment.Hash{}) {
		return
	}
	c, err := policy.DecodeCounter(cell.Value)
	if err != nil {
		s.log.Error("edictad: policy cell does not decode", "err", err)
		st.failed++
		return
	}
	if len(c.Ledger.Set.Buckets) == 0 {
		return // genesis: written at start
	}
	var recs []archive.Record
	for i := range c.Ledger.Closed {
		b, err := policy.EncodeBucket(&c.Ledger.Closed[i])
		if err != nil {
			s.log.Error("edictad: closed bucket does not encode", "err", err)
			st.failed++
			return
		}
		recs = append(recs, &archive.PolicyBucketRecord{Bucket: b})
	}
	set, err := policy.EncodeClosedSet(&c.Ledger.Set)
	if err != nil {
		s.log.Error("edictad: closed set does not encode", "err", err)
		st.failed++
		return
	}
	recs = append(recs, &archive.PolicyClosedRecord{ClosedSet: set})
	for _, r := range recs {
		s.put(ctx, r, st)
	}
}

// denyChain is the policy deny and then the rejection marker.
func denyChain(verdict []byte, marker *archive.RejectionRecord) *chain {
	return &chain{recs: []archive.Record{&archive.PolicyDenyRecord{SignedVerdict: verdict}, marker}}
}
