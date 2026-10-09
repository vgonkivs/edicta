package archive

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

const formatV0 = 0

var errNilRecord = errors.New("archive: nil record")

// Decode strictly decodes one record. Every failure wraps ErrCorrupt and the
// cause. The result does not alias b.
func Decode(b []byte) (Record, error) {
	rec, err := decode(b, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return rec, nil
}

// Encode returns the canonical bytes of r, or an error if r would not decode.
func Encode(r Record) ([]byte, error) {
	b, err := encodeRaw(r)
	if err != nil {
		return nil, err
	}
	if _, err := decode(b, false); err != nil {
		return nil, fmt.Errorf("archive: invalid %s record: %w", r.Kind(), err)
	}
	return b, nil
}

type pmap struct {
	items map[uint64]*gitem
	subs  map[uint64]*pmap
	da    uint64
	hasDA bool
}

func decode(data []byte, clone bool) (Record, error) {
	if len(data) > MaxRecordSize {
		return nil, fmt.Errorf("%w: %d bytes", commitment.ErrTooLarge, len(data))
	}
	root, err := scanTop(data)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: record is not a map", commitment.ErrWrongType)
	}
	top := make(map[uint64]*gitem, len(root.pairs))
	for _, p := range root.pairs {
		top[p.key] = p.val
	}
	for _, c := range commonSchema {
		v, ok := top[c.key]
		if !ok {
			return nil, fmt.Errorf("%w: record.%s", commitment.ErrMissingField, c.name)
		}
		if v.major != majUint {
			return nil, fmt.Errorf("%w: record.%s", commitment.ErrWrongType, c.name)
		}
	}
	if top[1].u != formatV0 {
		return nil, fmt.Errorf("%w: format %d", commitment.ErrUnsupportedVersion, top[1].u)
	}
	kind := Kind(top[2].u)
	if !kind.valid() {
		return nil, fmt.Errorf("%w: kind %d", commitment.ErrInvalidEnum, top[2].u)
	}
	if len(data) > maxSizeOf(kind) {
		return nil, fmt.Errorf("%w: %s record of %d bytes", commitment.ErrTooLarge, kind, len(data))
	}
	defs := schemaOf(kind)
	pm, err := parseMap(root, defs, kind.String())
	if err != nil {
		return nil, err
	}
	if err := checkValues(pm, defs, kind); err != nil {
		return nil, err
	}
	rec := build(pm, kind, clone)
	if again, err := encodeRaw(rec); err != nil || !bytes.Equal(again, data) {
		return nil, fmt.Errorf("%w: re-encoding differs", commitment.ErrNonCanonical)
	}
	return rec, nil
}

func parseMap(it *gitem, defs []fdef, where string) (*pmap, error) {
	if it.major != majMap {
		return nil, fmt.Errorf("%w: %s is not a map", commitment.ErrWrongType, where)
	}
	pm := &pmap{items: map[uint64]*gitem{}, subs: map[uint64]*pmap{}}
	for _, p := range it.pairs {
		var d *fdef
		for i := range defs {
			if defs[i].key == p.key {
				d = &defs[i]
				break
			}
		}
		if d == nil {
			return nil, fmt.Errorf("%w: %s key %d", commitment.ErrUnknownKey, where, p.key)
		}
		path := where + "." + d.name
		if err := pm.checkDefined(d, path); err != nil {
			return nil, err
		}
		v := p.val
		want := [...]byte{majUint, majBstr, majTstr, majTstr, majMap}[d.typ]
		if v.major != want {
			return nil, fmt.Errorf("%w: %s has major type %d", commitment.ErrWrongType, path, v.major)
		}
		switch d.typ {
		case tBstr:
			if len(v.b) < d.lo || len(v.b) > d.hi {
				return nil, fmt.Errorf("%w: %s of %d bytes", commitment.ErrFieldSize, path, len(v.b))
			}
		case tTstr, tErrName:
			if len(v.b) < d.lo || len(v.b) > d.hi {
				return nil, fmt.Errorf("%w: %s of %d bytes", commitment.ErrFieldSize, path, len(v.b))
			}
			ok := true
			for _, c := range v.b {
				if d.typ == tTstr && !isIDChar(c) || d.typ == tErrName && !isNameChar(c) {
					ok = false
				}
			}
			if d.typ == tErrName && !bytes.HasPrefix(v.b, []byte("Err")) {
				ok = false
			}
			if !ok {
				return nil, fmt.Errorf("%w: %s outside its grammar", commitment.ErrInvalidString, path)
			}
		case tMap:
			sub, err := parseMap(v, d.sub, path)
			if err != nil {
				return nil, err
			}
			pm.subs[d.key] = sub
		}
		pm.items[d.key] = v
		if d.name == "da" {
			pm.da, pm.hasDA = v.u, true
		}
	}
	for i := range defs {
		d := &defs[i]
		if _, ok := pm.items[d.key]; !ok && pm.required(d) {
			return nil, fmt.Errorf("%w: %s.%s", commitment.ErrMissingField, where, d.name)
		}
	}
	return pm, nil
}

func (pm *pmap) checkDefined(d *fdef, path string) error {
	bad := false
	switch d.pres {
	case pReq1, pOpt1:
		bad = pm.hasDA && pm.da == 2
	case pReq2:
		bad = pm.hasDA && pm.da == 1
	case pTxIndex, pTxProof:
		_, ok := pm.items[8]
		bad = !ok
	}
	if bad {
		return fmt.Errorf("%w: %s is not defined here", commitment.ErrUnknownKey, path)
	}
	return nil
}

func (pm *pmap) required(d *fdef) bool {
	switch d.pres {
	case pReq:
		return true
	case pReq1, pReq1Opt2:
		return pm.hasDA && pm.da == 1
	case pReq2:
		return pm.hasDA && pm.da == 2
	case pTxIndex:
		_, ok := pm.items[8]
		return ok
	}
	return false
}

type namedUint struct {
	name string
	v    uint64
}

func collectUints(pm *pmap, defs []fdef, out []namedUint) []namedUint {
	for i := range defs {
		d := &defs[i]
		it, ok := pm.items[d.key]
		if !ok {
			continue
		}
		switch d.typ {
		case tMap:
			out = collectUints(pm.subs[d.key], d.sub, out)
		case tUint:
			out = append(out, namedUint{d.name, it.u})
		}
	}
	return out
}

var nonZero = map[string]bool{
	"intent_height": true, "height": true, "promise_height": true, "authorized_at": true,
	"rejected_at": true, "checked_at": true, "block_time": true, "blob_retention_s": true,
	"retention_latest_s": true, "retention_at_height_s": true, "promise_created": true,
}

func checkValues(pm *pmap, defs []fdef, kind Kind) error {
	uints := collectUints(pm, defs, nil)
	for _, u := range uints {
		if u.v > math.MaxInt64 {
			return fmt.Errorf("%w: %s", commitment.ErrIntRange, u.name)
		}
		if u.name == "tx_code" && u.v != 0 {
			return fmt.Errorf("%w: tx_code %d, only 0 is archived", commitment.ErrIntRange, u.v)
		}
	}
	maps := []*pmap{pm}
	if k2, ok := pm.subs[5]; ok && kind == KindAuthorization {
		maps = append(maps, k2)
	}
	for _, m := range maps {
		if m.hasDA && m.da != 1 && m.da != 2 {
			return fmt.Errorf("%w: da %d", commitment.ErrInvalidEnum, m.da)
		}
	}
	if k2, ok := pm.subs[5]; ok && kind == KindAuthorization {
		if it, ok := k2.items[7]; ok && (it.u < 1 || it.u > 3) {
			return fmt.Errorf("%w: retention_source %d", commitment.ErrInvalidEnum, it.u)
		}
	}
	if kind == KindRejection && !verdicts[string(pm.items[4].b)] {
		return fmt.Errorf("%w: %s is not a verdict", commitment.ErrInvalidEnum, pm.items[4].b)
	}
	for _, u := range uints {
		if u.v == 0 && nonZero[u.name] {
			return fmt.Errorf("%w: %s", commitment.ErrZeroValue, u.name)
		}
	}
	if it, ok := pm.items[5]; ok && it.major == majBstr && (kind == KindPayload || kind == KindEvidence) && !namespaceOK(it.b) {
		return fmt.Errorf("%w: %x", commitment.ErrInvalidNamespace, it.b)
	}
	switch kind {
	case KindMandate, KindPolicyAllow, KindPolicyDeny, KindPolicyBucket, KindPolicyClosed:
		return checkPolicyBody(kind, pm.items[3].b)
	case KindDecision:
		if _, err := commitment.DecodeSigned(pm.items[3].b); err != nil {
			return err
		}
	case KindAuthorization:
		sa, _, err := commitment.DecodeSignedAuthorization(pm.items[3].b)
		if err != nil {
			return err
		}
		a := &sa.Authorization
		if err := commitment.ValidateAuthorization(a, nil); err != nil {
			return err
		}
		// A fast-mode Authorization needs its window in the K2 inputs, a key
		// this codec does not define yet.
		if a.Mode == commitment.ModeFast {
			return fmt.Errorf("%w: fast_window of a fast-mode authorization", commitment.ErrMissingField)
		}
	}
	return nil
}

// checkPolicyBody strictly decodes the nested structure of a policy record.
// A verdict must match the kind: an allow in a policy_deny record, or the
// reverse, is an invalid enum.
func checkPolicyBody(kind Kind, b []byte) error {
	switch kind {
	case KindMandate:
		_, _, err := policy.DecodeSignedMandate(b)
		return err
	case KindPolicyAllow, KindPolicyDeny:
		sv, _, err := policy.DecodeSignedVerdict(b)
		if err != nil {
			return err
		}
		want := uint64(policy.OutcomeAllow)
		if kind == KindPolicyDeny {
			want = policy.OutcomeDeny
		}
		if sv.Verdict.Outcome != want {
			return fmt.Errorf("%w: %s record holds outcome %d", commitment.ErrInvalidEnum, kind, sv.Verdict.Outcome)
		}
	case KindPolicyBucket:
		_, err := policy.DecodeBucket(b)
		return err
	case KindPolicyClosed:
		_, err := policy.DecodeClosedSet(b)
		return err
	}
	return nil
}

// namespaceOK accepts a version-0 user namespace: 18 zero bytes after the
// version and a non-zero sub-id prefix, which excludes the reserved range.
func namespaceOK(ns []byte) bool {
	if len(ns) != 29 || ns[0] != 0 || !allZero(ns[1:19]) {
		return false
	}
	return !allZero(ns[19:28])
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func build(pm *pmap, kind Kind, clone bool) Record {
	bs := func(m *pmap, key uint64) []byte {
		it, ok := m.items[key]
		if !ok {
			return nil
		}
		if clone {
			return bytes.Clone(it.b)
		}
		return it.b
	}
	u := func(m *pmap, key uint64) uint64 {
		if it, ok := m.items[key]; ok {
			return it.u
		}
		return 0
	}
	switch kind {
	case KindPayload:
		return &PayloadRecord{
			DA: commitment.DA(u(pm, 3)), Commitment: bs(pm, 4), Namespace: bs(pm, 5),
			Signer: bs(pm, 6), Blob: bs(pm, 7), IntentHeight: u(pm, 8),
		}
	case KindEvidence:
		return &EvidenceRecord{
			DA: commitment.DA(u(pm, 3)), Commitment: bs(pm, 4), Namespace: bs(pm, 5),
			Height: u(pm, 6), Header: bs(pm, 7), AnchorTx: bs(pm, 8), AnchorTxIndex: u(pm, 9),
			AnchorTxProof: bs(pm, 10), BlobProof: bs(pm, 11), TxCode: u(pm, 12),
			SystemBlob: bs(pm, 13), SystemBlobProof: bs(pm, 14), PromiseHeight: u(pm, 15),
			PromiseHeader: bs(pm, 16), HistoricalInfo: bs(pm, 17), PromiseValset: bs(pm, 18),
		}
	case KindDecision:
		return &DecisionRecord{Envelope: bs(pm, 3), Action: bs(pm, 4)}
	case KindAuthorization:
		r := &AuthorizationRecord{SignedAuthorization: bs(pm, 3), AuthorizedAt: u(pm, 4)}
		if k := pm.subs[5]; k != nil {
			r.K2 = &K2Inputs{
				DA: commitment.DA(u(k, 1)), CheckedAt: u(k, 2), BlockTime: u(k, 3),
				BlobRetentionS: u(k, 4), RetentionLatestS: u(k, 5), RetentionAtHeightS: u(k, 6),
				RetentionSource: RetentionSource(u(k, 7)), PromiseCreated: u(k, 8),
			}
		}
		return r
	case KindMandate:
		return &MandateRecord{SignedMandate: bs(pm, 3)}
	case KindPolicyAllow:
		return &PolicyAllowRecord{SignedVerdict: bs(pm, 3)}
	case KindPolicyDeny:
		return &PolicyDenyRecord{SignedVerdict: bs(pm, 3)}
	case KindPolicyBucket:
		return &PolicyBucketRecord{Bucket: bs(pm, 3)}
	case KindPolicyClosed:
		return &PolicyClosedRecord{ClosedSet: bs(pm, 3)}
	case KindPolicySuccessor:
		return &PolicySuccessorRecord{
			GateID: string(pm.items[3].b), CounterKey: bs(pm, 4), StateHash: bs(pm, 5), CommitmentHash: bs(pm, 6),
		}
	}
	r := &RejectionRecord{
		Error: string(pm.items[4].b), GateID: string(pm.items[5].b), RejectedAt: u(pm, 6),
	}
	copy(r.CommitmentHash[:], pm.items[3].b)
	return r
}

type mapWriter struct {
	n int
	b []byte
}

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n < 1<<8:
		return append(b, m|24, byte(n))
	case n < 1<<16:
		return append(b, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func (w *mapWriter) uint(key, v uint64) {
	w.b = appendHead(appendHead(w.b, majUint, key), majUint, v)
	w.n++
}

func (w *mapWriter) bytes(key uint64, v []byte) {
	w.b = appendHead(appendHead(w.b, majUint, key), majBstr, uint64(len(v)))
	w.b = append(w.b, v...)
	w.n++
}

func (w *mapWriter) text(key uint64, v string) {
	w.b = appendHead(appendHead(w.b, majUint, key), majTstr, uint64(len(v)))
	w.b = append(w.b, v...)
	w.n++
}

func (w *mapWriter) opt(key uint64, v []byte) {
	if v != nil {
		w.bytes(key, v)
	}
}

func (w *mapWriter) sub(key uint64, s *mapWriter) {
	w.b = appendHead(w.b, majUint, key)
	w.b = append(appendHead(w.b, majMap, uint64(s.n)), s.b...)
	w.n++
}

func (w *mapWriter) finish() []byte {
	out := appendHead(make([]byte, 0, len(w.b)+9), majMap, uint64(w.n))
	return append(out, w.b...)
}

// encodeRaw writes the canonical bytes without validating values. A field
// that is absent when zero is written when a decoder would need to see it to
// refuse the record.
func encodeRaw(r Record) ([]byte, error) {
	w := &mapWriter{}
	w.uint(1, formatV0)
	switch r := r.(type) {
	case *PayloadRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPayload))
		w.uint(3, uint64(r.DA))
		w.bytes(4, r.Commitment)
		w.opt(5, r.Namespace)
		w.opt(6, r.Signer)
		w.bytes(7, r.Blob)
		w.uint(8, r.IntentHeight)
	case *EvidenceRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindEvidence))
		w.uint(3, uint64(r.DA))
		w.bytes(4, r.Commitment)
		w.bytes(5, r.Namespace)
		w.uint(6, r.Height)
		w.bytes(7, r.Header)
		w.opt(8, r.AnchorTx)
		if r.AnchorTx != nil || r.AnchorTxIndex != 0 {
			w.uint(9, r.AnchorTxIndex)
		}
		w.opt(10, r.AnchorTxProof)
		w.opt(11, r.BlobProof)
		if r.DA == commitment.DAFibre || r.TxCode != 0 {
			w.uint(12, r.TxCode)
		}
		w.opt(13, r.SystemBlob)
		w.opt(14, r.SystemBlobProof)
		if r.DA == commitment.DAFibre || r.PromiseHeight != 0 {
			w.uint(15, r.PromiseHeight)
		}
		w.opt(16, r.PromiseHeader)
		w.opt(17, r.HistoricalInfo)
		w.opt(18, r.PromiseValset)
	case *DecisionRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindDecision))
		w.bytes(3, r.Envelope)
		w.bytes(4, r.Action)
	case *AuthorizationRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindAuthorization))
		w.bytes(3, r.SignedAuthorization)
		w.uint(4, r.AuthorizedAt)
		if k := r.K2; k != nil {
			s := &mapWriter{}
			s.uint(1, uint64(k.DA))
			s.uint(2, k.CheckedAt)
			s.uint(3, k.BlockTime)
			for i, v := range []uint64{k.BlobRetentionS, k.RetentionLatestS, k.RetentionAtHeightS, uint64(k.RetentionSource), k.PromiseCreated} {
				if v != 0 {
					s.uint(uint64(4+i), v)
				}
			}
			w.sub(5, s)
		}
	case *RejectionRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindRejection))
		w.bytes(3, r.CommitmentHash[:])
		w.text(4, r.Error)
		w.text(5, r.GateID)
		w.uint(6, r.RejectedAt)
	case *MandateRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindMandate))
		w.bytes(3, r.SignedMandate)
	case *PolicyAllowRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPolicyAllow))
		w.bytes(3, r.SignedVerdict)
	case *PolicyDenyRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPolicyDeny))
		w.bytes(3, r.SignedVerdict)
	case *PolicyBucketRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPolicyBucket))
		w.bytes(3, r.Bucket)
	case *PolicyClosedRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPolicyClosed))
		w.bytes(3, r.ClosedSet)
	case *PolicySuccessorRecord:
		if r == nil {
			return nil, errNilRecord
		}
		w.uint(2, uint64(KindPolicySuccessor))
		w.text(3, r.GateID)
		w.bytes(4, r.CounterKey)
		w.bytes(5, r.StateHash)
		w.bytes(6, r.CommitmentHash)
	default:
		return nil, errNilRecord
	}
	return w.finish(), nil
}

// KeyPath returns the canonical slash-separated path of the record's key.
func KeyPath(r Record) (string, error) {
	switch r := r.(type) {
	case *PayloadRecord:
		if r != nil {
			return DataPath(KindPayload, r.DA, r.Commitment)
		}
	case *EvidenceRecord:
		if r != nil {
			return DataPath(KindEvidence, r.DA, r.Commitment)
		}
	case *DecisionRecord:
		if r != nil {
			s, err := commitment.DecodeSigned(r.Envelope)
			if err != nil {
				return "", fmt.Errorf("archive: decision envelope: %w", err)
			}
			h, err := commitment.HashOf(&s.Commitment)
			if err != nil {
				return "", fmt.Errorf("archive: decision hash: %w", err)
			}
			return HashPath(KindDecision, h), nil
		}
	case *AuthorizationRecord:
		if r != nil {
			s, _, err := commitment.DecodeSignedAuthorization(r.SignedAuthorization)
			if err != nil {
				return "", fmt.Errorf("archive: signed authorization: %w", err)
			}
			var h commitment.Hash
			copy(h[:], s.Authorization.CommitmentHash)
			return HashPath(KindAuthorization, h), nil
		}
	case *RejectionRecord:
		if r != nil {
			return RejectionPath(r.CommitmentHash, r.Error)
		}
	default:
		if p, ok, err := policyKeyPath(r); ok {
			return p, err
		}
	}
	return "", errNilRecord
}

// policyKeyPath returns the key of a policy record, computed from the nested
// bytes or fields. ok is false for any other record.
func policyKeyPath(r Record) (path string, ok bool, err error) {
	switch r := r.(type) {
	case *MandateRecord:
		if r == nil {
			return "", false, nil
		}
		_, h, err := policy.DecodeSignedMandate(r.SignedMandate)
		if err != nil {
			return "", true, fmt.Errorf("archive: signed mandate: %w", err)
		}
		return PolicyHashPath(KindMandate, h), true, nil
	case *PolicyAllowRecord:
		if r == nil {
			return "", false, nil
		}
		sv, _, err := policy.DecodeSignedVerdict(r.SignedVerdict)
		if err != nil {
			return "", true, fmt.Errorf("archive: signed verdict: %w", err)
		}
		return PolicyHashPath(KindPolicyAllow, commitment.Hash(sv.Verdict.CommitmentHash)), true, nil
	case *PolicyDenyRecord:
		if r == nil {
			return "", false, nil
		}
		sv, _, err := policy.DecodeSignedVerdict(r.SignedVerdict)
		if err != nil {
			return "", true, fmt.Errorf("archive: signed verdict: %w", err)
		}
		p, err := PolicyDenyPath(commitment.Hash(sv.Verdict.CommitmentHash), sv.Verdict.Reason)
		return p, true, err
	case *PolicyBucketRecord:
		if r == nil {
			return "", false, nil
		}
		return PolicyHashPath(KindPolicyBucket, policy.HashBucketBytes(r.Bucket)), true, nil
	case *PolicyClosedRecord:
		if r == nil {
			return "", false, nil
		}
		return PolicyHashPath(KindPolicyClosed, policy.HashClosedSetBytes(r.ClosedSet)), true, nil
	case *PolicySuccessorRecord:
		if r == nil {
			return "", false, nil
		}
		if len(r.CounterKey) != 32 || len(r.StateHash) != 32 {
			return "", true, fmt.Errorf("archive: successor key fields: %w", commitment.ErrFieldSize)
		}
		var ck [32]byte
		copy(ck[:], r.CounterKey)
		return PolicyHashPath(KindPolicySuccessor, policy.SuccessorKey(r.GateID, ck, commitment.Hash(r.StateHash))), true, nil
	}
	return "", false, nil
}

// DataPath is the path of a payload or evidence record.
func DataPath(k Kind, da commitment.DA, commit []byte) (string, error) {
	if k != KindPayload && k != KindEvidence {
		return "", fmt.Errorf("archive: %s has no (da, commitment) key", k)
	}
	if da != commitment.DAFibre && da != commitment.DACelestiaBlob {
		return "", fmt.Errorf("archive: da %d: %w", da, commitment.ErrInvalidEnum)
	}
	if len(commit) != 32 {
		return "", fmt.Errorf("archive: commitment of %d bytes: %w", len(commit), commitment.ErrFieldSize)
	}
	return k.String() + "/" + strconv.FormatUint(uint64(da), 10) + "/" + hex.EncodeToString(commit), nil
}

// HashPath is the path of a decision or Authorization record.
func HashPath(k Kind, h commitment.Hash) string {
	return k.String() + "/" + hex.EncodeToString(h[:])
}

// policyDirs are the first path segments of the policy kinds.
var policyDirs = map[Kind]string{
	KindMandate: "mandate", KindPolicyAllow: "policy-allow", KindPolicyDeny: "policy-deny",
	KindPolicyBucket: "policy-bucket", KindPolicyClosed: "policy-closed", KindPolicySuccessor: "policy-successor",
}

// PolicyHashPath is the path of a mandate, policy_allow, policy_bucket,
// policy_closed or policy_successor record; h is the key of the kind.
func PolicyHashPath(k Kind, h commitment.Hash) string {
	return policyDirs[k] + "/" + hex.EncodeToString(h[:])
}

// PolicyDenyPath is the path of a policy_deny record; reason must be one of
// the policy deny names.
func PolicyDenyPath(h commitment.Hash, reason string) (string, error) {
	if !IsPolicyDeny(reason) {
		return "", fmt.Errorf("archive: %q is not a policy deny name: %w", reason, commitment.ErrInvalidEnum)
	}
	return policyDirs[KindPolicyDeny] + "/" + hex.EncodeToString(h[:]) + "/" + reason, nil
}

// RejectionPath is the path of a marker; name must be a verdict.
func RejectionPath(h commitment.Hash, name string) (string, error) {
	if !verdicts[name] {
		return "", fmt.Errorf("archive: %q is not a verdict: %w", name, commitment.ErrInvalidEnum)
	}
	return "rejection/" + hex.EncodeToString(h[:]) + "/" + name, nil
}

// IsVerdict reports whether name may be carried by a rejection marker.
func IsVerdict(name string) bool { return verdicts[name] }

// SameIdentity reports whether a and b are the same record for write-once
// purposes: the fields that would change a verdict, not the first-write-wins
// ones. Records of different kinds are never the same.
func SameIdentity(a, b Record) bool {
	switch a := a.(type) {
	case *PayloadRecord:
		b, ok := b.(*PayloadRecord)
		return ok && a.DA == b.DA && bytes.Equal(a.Commitment, b.Commitment) &&
			bytes.Equal(a.Namespace, b.Namespace) && bytes.Equal(a.Signer, b.Signer) &&
			bytes.Equal(a.Blob, b.Blob)
	case *EvidenceRecord:
		b, ok := b.(*EvidenceRecord)
		return ok && a.DA == b.DA && bytes.Equal(a.Commitment, b.Commitment) &&
			bytes.Equal(a.Namespace, b.Namespace) && a.Height == b.Height
	case *DecisionRecord:
		b, ok := b.(*DecisionRecord)
		return ok && bytes.Equal(a.Envelope, b.Envelope) && bytes.Equal(a.Action, b.Action)
	case *AuthorizationRecord:
		b, ok := b.(*AuthorizationRecord)
		return ok && bytes.Equal(a.SignedAuthorization, b.SignedAuthorization)
	case *RejectionRecord:
		b, ok := b.(*RejectionRecord)
		return ok && a.CommitmentHash == b.CommitmentHash && a.Error == b.Error
	case *MandateRecord:
		b, ok := b.(*MandateRecord)
		return ok && bytes.Equal(a.SignedMandate, b.SignedMandate)
	case *PolicyAllowRecord:
		b, ok := b.(*PolicyAllowRecord)
		return ok && bytes.Equal(a.SignedVerdict, b.SignedVerdict)
	case *PolicyDenyRecord:
		// The first write stays: two denies of one key are the same record.
		b, ok := b.(*PolicyDenyRecord)
		if !ok {
			return false
		}
		pa, erra := KeyPath(a)
		pb, errb := KeyPath(b)
		return erra == nil && errb == nil && pa == pb
	case *PolicyBucketRecord:
		b, ok := b.(*PolicyBucketRecord)
		return ok && bytes.Equal(a.Bucket, b.Bucket)
	case *PolicyClosedRecord:
		b, ok := b.(*PolicyClosedRecord)
		return ok && bytes.Equal(a.ClosedSet, b.ClosedSet)
	case *PolicySuccessorRecord:
		// Whole record, so a second commitment under one key is a conflict.
		b, ok := b.(*PolicySuccessorRecord)
		return ok && a.GateID == b.GateID && bytes.Equal(a.CounterKey, b.CounterKey) &&
			bytes.Equal(a.StateHash, b.StateHash) && bytes.Equal(a.CommitmentHash, b.CommitmentHash)
	}
	return false
}
