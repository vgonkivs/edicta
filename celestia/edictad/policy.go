package edictad

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
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

// compiledProfiles are the action types of the profiles this daemon is built
// with, and whether their executed transactions are public: a bank send is a
// public transaction.
var compiledProfiles = gate.ProfileSet{bankaction.ActionType: true}

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
// records. Under a mandate with auditors every record that would show the
// rules, the state or the decision content is written only sealed to them.
type polInfo struct {
	gateID     string
	counterKey [32]byte
	state      registry.StateRegistry
	mandate    *policy.Mandate
	sealer     policy.Sealer
	hasher     policy.StateHasher
	denies     *denyIndex
}

func newPolInfo(gateID string, m *policy.Mandate, state registry.StateRegistry) *polInfo {
	return &polInfo{gateID: gateID, counterKey: m.CounterKey(), state: state, mandate: m,
		sealer: privatebox.Sealer{}, hasher: policy.NewStateHasher(m), denies: newDenyIndex()}
}

// private reports whether the mandate has auditors.
func (p *polInfo) private() bool { return p != nil && len(p.mandate.Auditors) > 0 }

// sealed is the kind 15 record of a plaintext whose hash (before blinding)
// is plainHash.
func (p *polInfo) sealed(kind policy.PrivateKind, plaintext []byte, plainHash commitment.Hash) (archive.Record, error) {
	env, err := p.sealer.Seal(kind, plaintext, p.mandate.Auditors)
	if err != nil {
		return nil, err
	}
	key := p.hasher.BlobKey(kind, plainHash)
	return &archive.PrivateBlobRecord{PlaintextKind: kind, Hash: key[:], Envelope: env}, nil
}

// bucketRecord and closedRecord are a closed bucket and a closed set in the
// form of the mandate: clear, or sealed under their blinded keys.
func (p *polInfo) bucketRecord(b []byte) (archive.Record, error) {
	if !p.private() {
		return &archive.PolicyBucketRecord{Bucket: b}, nil
	}
	return p.sealed(policy.PrivateBucket, b, policy.HashBucketBytes(b))
}

func (p *polInfo) closedRecord(set []byte) (archive.Record, error) {
	if !p.private() {
		return &archive.PolicyClosedRecord{ClosedSet: set}, nil
	}
	return p.sealed(policy.PrivateClosedSet, set, policy.HashClosedSetBytes(set))
}

// partRecord seals the PrivatePart of a private-form verdict.
func (p *polInfo) partRecord(part []byte) (archive.Record, error) {
	if len(part) == 0 {
		return nil, errors.New("a private-form verdict without its PrivatePart")
	}
	return p.sealed(policy.PrivatePartKind, part, policy.PrivateHash(part))
}

// publishMandate writes the mandate record and the genesis closed set, sealed
// under a private mandate. Both are idempotent; a failure refuses the start,
// because a verifier cannot check any verdict without them.
func (p *polInfo) publishMandate(ctx context.Context, aio *archiveIO, signed []byte, timeout time.Duration) error {
	genesis := policy.EmptyClosedSet()
	set, err := policy.EncodeClosedSet(&genesis)
	if err != nil {
		return fmt.Errorf("edictad: genesis closed set: %w", err)
	}
	var mrec archive.Record = &archive.MandateRecord{SignedMandate: signed}
	if p.private() {
		_, h, err := policy.DecodeSignedMandate(signed)
		if err != nil {
			return fmt.Errorf("edictad: mandate: %w", err)
		}
		if mrec, err = p.sealed(policy.PrivateMandate, signed, h); err != nil {
			return fmt.Errorf("edictad: seal the mandate: %w", err)
		}
	}
	srec, err := p.closedRecord(set)
	if err != nil {
		return fmt.Errorf("edictad: seal the genesis closed set: %w", err)
	}
	for _, r := range []archive.Record{mrec, srec} {
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

// allowRecords are the policy records of an allow, in archive order: under a
// private mandate the sealed PrivatePart, then the closed bucket and set if
// the allow closed an hour, the verdict, the successor.
func (p *polInfo) allowRecords(closedBucket, closedSet, verdict, part []byte, h commitment.Hash) ([]archive.Record, error) {
	var recs []archive.Record
	if p.private() {
		r, err := p.partRecord(part)
		if err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	if len(closedBucket) > 0 {
		b, err := p.bucketRecord(closedBucket)
		if err != nil {
			return nil, err
		}
		s, err := p.closedRecord(closedSet)
		if err != nil {
			return nil, err
		}
		recs = append(recs, b, s)
	}
	recs = append(recs, &archive.PolicyAllowRecord{SignedVerdict: verdict})
	succ, err := p.successorRecord(verdict, h)
	if err != nil {
		return nil, err
	}
	return append(recs, succ), nil
}

// repair writes the retained closed buckets and the current closed set from
// the counter cell. Older sets and buckets come from the registry entries of
// the allows that closed them, when the scan reaches those entries.
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
		if err == nil {
			var r archive.Record
			if r, err = p.bucketRecord(b); err == nil {
				recs = append(recs, r)
			}
		}
		if err != nil {
			s.log.Error("edictad: closed bucket cannot be archived", "err", err)
			st.failed++
			return
		}
	}
	set, err := policy.EncodeClosedSet(&c.Ledger.Set)
	var srec archive.Record
	if err == nil {
		srec, err = p.closedRecord(set)
	}
	if err != nil {
		s.log.Error("edictad: closed set cannot be archived", "err", err)
		st.failed++
		return
	}
	recs = append(recs, srec)
	for _, r := range recs {
		s.put(ctx, r, st)
	}
}

// denyChain is the policy deny and then the rejection marker.
func denyChain(verdict []byte, marker *archive.RejectionRecord) *chain {
	return &chain{recs: []archive.Record{&archive.PolicyDenyRecord{SignedVerdict: verdict}, marker}}
}

// privateDenyMarker is the marker name of every policy deny under a private
// mandate: a public marker must not reveal the reason.
const privateDenyMarker = "ErrDenied"

// denyKey identifies the private denies that publish one record: a retry
// refused again for the same reason gets a fresh private_hash, and without
// the index every such retry would add a record.
type denyKey struct {
	h      commitment.Hash
	reason string
}

// denyIndex is the gate-local dedup index of private denies. It is not
// evidence: losing an entry only writes one more record. An entry is
// reserved before the deny's records are written and kept once the
// policy_deny write is acknowledged, so concurrent retries never both
// write; a failed write releases it.
type denyIndex struct {
	mu sync.Mutex
	m  map[denyKey]denyEntry
}

type denyEntry struct {
	until uint64 // valid_until of the decision: no later attempt reaches the policy
	done  bool
}

// maxDenyIndex bounds the index; expired entries go first.
const maxDenyIndex = 1 << 16

func newDenyIndex() *denyIndex { return &denyIndex{m: map[denyKey]denyEntry{}} }

// reserve reports whether the caller is to write the deny's records.
func (x *denyIndex) reserve(k denyKey, validUntil, now uint64) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.m[k]; ok {
		return false
	}
	if len(x.m) >= maxDenyIndex {
		for key, e := range x.m {
			if e.until < now {
				delete(x.m, key)
			}
		}
	}
	if len(x.m) >= maxDenyIndex {
		for key := range x.m {
			delete(x.m, key)
			break
		}
	}
	x.m[k] = denyEntry{until: validUntil}
	return true
}

func (x *denyIndex) commit(k denyKey) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e, ok := x.m[k]; ok {
		e.done = true
		x.m[k] = e
	}
}

func (x *denyIndex) release(k denyKey) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e, ok := x.m[k]; ok && !e.done {
		delete(x.m, k)
	}
}

// privateDeny writes the records of a private deny: the sealed PrivatePart,
// the deny under its private_hash, then the ErrDenied marker. A deny whose
// (commitment, reason) is already archived writes only the marker, which is
// a no-op when present and repairs one that failed before.
func (a *archivingGate) privateDeny(ctx context.Context, res gate.Result, reason string, validUntil uint64, marker *archive.RejectionRecord) {
	marker.Error = privateDenyMarker
	k := denyKey{h: res.CommitmentHash, reason: reason}
	if !a.pol.denies.reserve(k, validUntil, uint64(a.clock.Now().Unix())) {
		a.w.write(ctx, marker)
		return
	}
	part, err := a.pol.partRecord(res.PrivatePart)
	if err != nil {
		a.w.log.Error("edictad: the PrivatePart of a deny cannot be sealed; only the marker is written", "err", err)
		a.pol.denies.release(k)
		a.w.write(ctx, marker)
		return
	}
	recs := []archive.Record{part, &archive.PolicyDenyRecord{SignedVerdict: res.PolicyVerdict}, marker}
	if a.w.writeChain(ctx, &chain{recs: recs}) >= 2 {
		a.pol.denies.commit(k)
		return
	}
	a.pol.denies.release(k)
}
