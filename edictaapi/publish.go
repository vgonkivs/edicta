package edictaapi

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// TagPublishRequest is the domain tag of the publish message (section 17.1).
const TagPublishRequest = "edicta/v1/publish-request"

const (
	maxUint63 = uint64(1)<<63 - 1
	// requestOverhead is the slack of the request limit over max_blob_bytes.
	requestOverhead = 256
)

// PublishRequest is the decoded body of POST /v1/publish.
type PublishRequest struct {
	Blob        []byte // aliases the decoded input
	AgentID     string
	RequestedAt uint64
	Signature   []byte
}

// PublishMessage returns the 70 to 196 bytes an agent signs (section 17.1):
// 0x19 || tag || len(gate_id) || gate_id || len(agent_id) || agent_id ||
// u64be(requested_at) || SHA-256(blob).
func PublishMessage(gateID, agentID string, requestedAt uint64, blob []byte) ([]byte, error) {
	if !validID(gateID) {
		return nil, fmt.Errorf("%w: gate_id", idErr(gateID))
	}
	if !validID(agentID) {
		return nil, fmt.Errorf("%w: agent_id", idErr(agentID))
	}
	if err := checkRequestedAt(requestedAt); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	msg := make([]byte, 0, 1+len(TagPublishRequest)+2+len(gateID)+len(agentID)+8+32)
	msg = append(msg, byte(len(TagPublishRequest)))
	msg = append(msg, TagPublishRequest...)
	msg = append(msg, byte(len(gateID)))
	msg = append(msg, gateID...)
	msg = append(msg, byte(len(agentID)))
	msg = append(msg, agentID...)
	msg = append(msg,
		byte(requestedAt>>56), byte(requestedAt>>48), byte(requestedAt>>40), byte(requestedAt>>32),
		byte(requestedAt>>24), byte(requestedAt>>16), byte(requestedAt>>8), byte(requestedAt))
	msg = append(msg, sum[:]...)
	return msg, nil
}

func idErr(s string) error {
	if len(s) < 1 || len(s) > 64 {
		return commitment.ErrFieldSize
	}
	return commitment.ErrInvalidString
}

func checkRequestedAt(v uint64) error {
	if v == 0 {
		return fmt.Errorf("%w: requested_at", commitment.ErrZeroValue)
	}
	if v > maxUint63 {
		return fmt.Errorf("%w: requested_at", commitment.ErrIntRange)
	}
	return nil
}

// EncodePublishRequest returns the canonical wire form of r (section 17.2).
// It refuses a request DecodePublishRequest would refuse, except for the
// server-side blob limit.
func EncodePublishRequest(r PublishRequest) ([]byte, error) {
	if len(r.Blob) < 1 {
		return nil, fmt.Errorf("%w: blob is empty", commitment.ErrFieldSize)
	}
	if !validID(r.AgentID) {
		return nil, fmt.Errorf("%w: agent_id", idErr(r.AgentID))
	}
	if err := checkRequestedAt(r.RequestedAt); err != nil {
		return nil, err
	}
	if len(r.Signature) != 64 {
		return nil, fmt.Errorf("%w: signature length %d", commitment.ErrFieldSize, len(r.Signature))
	}
	return encodeMap(
		kv{key: 1, kind: fBytes, b: r.Blob},
		kv{key: 2, kind: fText, s: r.AgentID},
		kv{key: 3, kind: fUint, u: r.RequestedAt},
		kv{key: 4, kind: fBytes, b: r.Signature},
	), nil
}

var publishRequestSchema = []fspec{
	{key: 1, name: "blob", kind: fBytes, min: 1, max: unbounded, required: true},
	{key: 2, name: "agent_id", kind: fText, min: 1, max: 64, charset: isID, required: true},
	{key: 3, name: "requested_at", kind: fUint, required: true},
	{key: 4, name: "signature", kind: fBytes, min: 64, max: 64, required: true},
}

// DecodePublishRequest applies rules PR1 and PR2 of section 17.3: the size
// limit max_blob_bytes + 256, strict decoding, len(blob) <= maxBlob and
// requested_at in 1..2^63-1. Errors wrap the sentinels of package commitment.
// The blob and signature alias b.
func DecodePublishRequest(b []byte, maxBlob uint64) (PublishRequest, error) {
	if uint64(len(b)) > maxBlob+requestOverhead {
		return PublishRequest{}, fmt.Errorf("%w: request of %d bytes", commitment.ErrTooLarge, len(b))
	}
	f, err := decodeFields(b, publishRequestSchema)
	if err != nil {
		return PublishRequest{}, err
	}
	if uint64(len(f[1].b)) > maxBlob {
		return PublishRequest{}, fmt.Errorf("%w: blob of %d bytes", commitment.ErrTooLarge, len(f[1].b))
	}
	if err := checkRequestedAt(f[3].u); err != nil {
		return PublishRequest{}, err
	}
	req := PublishRequest{Blob: f[1].b, AgentID: string(f[2].b), RequestedAt: f[3].u, Signature: f[4].b}
	again, err := EncodePublishRequest(req)
	if err != nil {
		return PublishRequest{}, err
	}
	if !bytes.Equal(again, b) {
		return PublishRequest{}, fmt.Errorf("%w: publish request", commitment.ErrNonCanonical)
	}
	return req, nil
}
