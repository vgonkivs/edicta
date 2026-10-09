package absence

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

// Record is an archived absence proof for one height (archive kind 14).
// Results and NextHeader are present together, only for da = 1, when the
// height holds a candidate whose result code must be proven.
type Record struct {
	DA            uint64
	Commitment    []byte
	Namespace     []byte
	Height        uint64
	Header        []byte // protobuf SignedHeader at Height
	DAH           []byte // protobuf DataAvailabilityHeader
	NamespaceData []byte // shwap NamespaceData stream; empty when no row holds the namespace
	Results       []byte // JSON result object of /block_results at Height
	NextHeader    []byte // protobuf SignedHeader at Height + 1
}

// Path is the archive path of the record, derived from its key.
func (r Record) Path() string {
	return PathPrefix + "/" + strconv.FormatUint(r.DA, 10) + "/" + hex.EncodeToString(r.Commitment) + "/" +
		strconv.FormatUint(r.Height, 10)
}

type fieldType int

const (
	typUint fieldType = iota
	typBytes
)

type fieldDef struct {
	key      uint64
	name     string
	typ      fieldType
	min, max int
	// fibreOnly fields are not defined for da = 2, and optional for da = 1.
	fibreOnly bool
}

var schema = []fieldDef{
	{key: keyDA, name: "da", typ: typUint},
	{key: keyCommitment, name: "commitment", typ: typBytes, min: commitmentSize, max: commitmentSize},
	{key: keyNamespace, name: "namespace", typ: typBytes, min: namespaceSize, max: namespaceSize},
	{key: keyHeight, name: "height", typ: typUint},
	{key: keyHeader, name: "header", typ: typBytes, min: 1, max: maxProofPart},
	{key: keyDAH, name: "dah", typ: typBytes, min: 1, max: maxProofPart},
	{key: keyNamespaceData, name: "namespace_data", typ: typBytes, min: 0, max: maxNamespaceData},
	{key: keyResults, name: "results", typ: typBytes, min: 1, max: maxProofPart, fibreOnly: true},
	{key: keyNextHeader, name: "next_header", typ: typBytes, min: 1, max: maxProofPart, fibreOnly: true},
}

func fieldByKey(k uint64) (fieldDef, bool) {
	for _, d := range schema {
		if d.key == k {
			return d, true
		}
	}
	return fieldDef{}, false
}

// DecodeRecord strictly decodes a kind 14 record. Every failure wraps
// archive.ErrCorrupt and the decoding cause. The result does not alias b.
func DecodeRecord(b []byte) (Record, error) {
	r, err := decodeRecord(b)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %w", archive.ErrCorrupt, err)
	}
	return r, nil
}

// DecodeRecordAt decodes a record read from path and requires the path to be
// the one its key gives, so that a proof for one height can never be served
// as another's.
func DecodeRecordAt(path string, b []byte) (Record, error) {
	r, err := DecodeRecord(b)
	if err != nil {
		return Record{}, err
	}
	if p := r.Path(); p != path {
		return Record{}, fmt.Errorf("%w: record read from %s has key %s", archive.ErrCorrupt, path, p)
	}
	return r, nil
}

// EncodeRecord returns the canonical bytes of r, or an error if they would
// not decode.
func EncodeRecord(r Record) ([]byte, error) {
	b := encodeRecord(r)
	if _, err := decodeRecord(b); err != nil {
		return nil, fmt.Errorf("absence: invalid record: %w", err)
	}
	return b, nil
}

func decodeRecord(b []byte) (Record, error) {
	if len(b) > maxArchiveRecordSize {
		return Record{}, fmt.Errorf("%w: %d bytes", commitment.ErrTooLarge, len(b))
	}
	top, err := scanTop(b)
	if err != nil {
		return Record{}, err
	}
	if top.major != majMap {
		return Record{}, fmt.Errorf("%w: record is not a map", commitment.ErrWrongType)
	}
	vals := make(map[uint64]item, len(top.pairs))
	for _, p := range top.pairs {
		vals[p.key] = p.val
	}
	for _, f := range []struct {
		key  uint64
		name string
	}{{keyFormat, "format"}, {keyKind, "kind"}} {
		v, ok := vals[f.key]
		if !ok {
			return Record{}, fmt.Errorf("%w: record.%s", commitment.ErrMissingField, f.name)
		}
		if v.major != majUint {
			return Record{}, fmt.Errorf("%w: record.%s", commitment.ErrWrongType, f.name)
		}
	}
	if vals[keyFormat].u != RecordFormat {
		return Record{}, fmt.Errorf("%w: format %d", commitment.ErrUnsupportedVersion, vals[keyFormat].u)
	}
	if k := vals[keyKind].u; k != KindAbsenceProof {
		return Record{}, fmt.Errorf("%w: kind %d is not an absence proof", commitment.ErrInvalidEnum, k)
	}
	if len(b) > MaxRecordSize {
		return Record{}, fmt.Errorf("%w: absence_proof record of %d bytes", commitment.ErrTooLarge, len(b))
	}

	var (
		r    Record
		da   uint64
		have = map[uint64]bool{}
	)
	for _, p := range top.pairs {
		if p.key == keyFormat || p.key == keyKind {
			continue
		}
		d, ok := fieldByKey(p.key)
		if !ok {
			return Record{}, fmt.Errorf("%w: absence_proof: key %d", commitment.ErrUnknownKey, p.key)
		}
		path := "absence_proof." + d.name
		if d.fibreOnly && have[keyDA] && da == DACelestiaBlob {
			return Record{}, fmt.Errorf("%w: %s: not defined for da = 2", commitment.ErrUnknownKey, path)
		}
		want := byte(majUint)
		if d.typ == typBytes {
			want = majBytes
		}
		if p.val.major != want {
			return Record{}, fmt.Errorf("%w: %s: major %d, want %d", commitment.ErrWrongType, path, p.val.major, want)
		}
		if d.typ == typBytes && (len(p.val.b) < d.min || len(p.val.b) > d.max) {
			return Record{}, fmt.Errorf("%w: %s: %d bytes", commitment.ErrFieldSize, path, len(p.val.b))
		}
		if p.key == keyDA {
			da = p.val.u
		}
		have[p.key] = true
	}
	for _, d := range schema {
		if !d.fibreOnly && !have[d.key] {
			return Record{}, fmt.Errorf("%w: absence_proof.%s", commitment.ErrMissingField, d.name)
		}
	}

	r.DA, r.Height = vals[keyDA].u, vals[keyHeight].u
	for _, v := range []struct {
		name string
		u    uint64
	}{{"format", vals[keyFormat].u}, {"kind", vals[keyKind].u}, {"da", r.DA}, {"height", r.Height}} {
		if v.u > math.MaxInt64 {
			return Record{}, fmt.Errorf("%w: %s = %d", commitment.ErrIntRange, v.name, v.u)
		}
	}
	if r.DA != DAFibre && r.DA != DACelestiaBlob {
		return Record{}, fmt.Errorf("%w: da = %d", commitment.ErrInvalidEnum, r.DA)
	}
	if r.Height == 0 {
		return Record{}, fmt.Errorf("%w: height", commitment.ErrZeroValue)
	}
	r.Namespace = bytes.Clone(vals[keyNamespace].b)
	if !namespaceOK(r.Namespace) {
		return Record{}, fmt.Errorf("%w: %x", commitment.ErrInvalidNamespace, r.Namespace)
	}
	if have[keyResults] != have[keyNextHeader] {
		if have[keyResults] {
			return Record{}, fmt.Errorf("%w: absence_proof.next_header: present iff results", commitment.ErrMissingField)
		}
		return Record{}, fmt.Errorf("%w: absence_proof.next_header: present iff results", commitment.ErrUnknownKey)
	}
	r.Commitment = bytes.Clone(vals[keyCommitment].b)
	r.Header = bytes.Clone(vals[keyHeader].b)
	r.DAH = bytes.Clone(vals[keyDAH].b)
	r.NamespaceData = bytes.Clone(vals[keyNamespaceData].b)
	if have[keyResults] {
		r.Results = bytes.Clone(vals[keyResults].b)
		r.NextHeader = bytes.Clone(vals[keyNextHeader].b)
	}
	if !bytes.Equal(encodeRecord(r), b) {
		return Record{}, fmt.Errorf("%w: absence_proof", commitment.ErrNonCanonical)
	}
	return r, nil
}

// encodeRecord writes deterministic CBOR: keys ascending, shortest heads.
func encodeRecord(r Record) []byte {
	n := uint64(9)
	if r.Results != nil || r.NextHeader != nil {
		n = 11
	}
	b := make([]byte, 0, 64+len(r.Header)+len(r.DAH)+len(r.NamespaceData)+len(r.Results)+len(r.NextHeader))
	b = appendHead(b, majMap, n)
	putUint := func(k, v uint64) {
		b = appendHead(b, majUint, k)
		b = appendHead(b, majUint, v)
	}
	putBytes := func(k uint64, v []byte) {
		b = appendHead(b, majUint, k)
		b = appendHead(b, majBytes, uint64(len(v)))
		b = append(b, v...)
	}
	putUint(keyFormat, RecordFormat)
	putUint(keyKind, KindAbsenceProof)
	putUint(keyDA, r.DA)
	putBytes(keyCommitment, r.Commitment)
	putBytes(keyNamespace, r.Namespace)
	putUint(keyHeight, r.Height)
	putBytes(keyHeader, r.Header)
	putBytes(keyDAH, r.DAH)
	putBytes(keyNamespaceData, r.NamespaceData)
	if n == 11 {
		putBytes(keyResults, r.Results)
		putBytes(keyNextHeader, r.NextHeader)
	}
	return b
}

// namespaceOK accepts a version-0 user blob namespace: 18 zero bytes after
// the version and a non-zero sub-id prefix, which excludes the reserved
// range.
func namespaceOK(ns []byte) bool {
	if len(ns) != namespaceSize || ns[0] != 0 {
		return false
	}
	for _, c := range ns[1:19] {
		if c != 0 {
			return false
		}
	}
	for _, c := range ns[19:28] {
		if c != 0 {
			return true
		}
	}
	return false
}
