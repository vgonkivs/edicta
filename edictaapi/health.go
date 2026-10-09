package edictaapi

import "fmt"

// HealthInfo is the answer of GET /v1/health (section 18.2). It is
// informational: a caller must not take keys or namespaces from it as trusted
// configuration.
type HealthInfo struct {
	Status         uint64 // 1 ok, 2 degraded
	ChainID        string
	HeadHeight     uint64
	HeadTime       uint64
	GateID         string
	GatePubKey     []byte
	RecorderSigner []byte // empty when the Recorder is disabled
	Namespace      []byte // empty when the Recorder is disabled
	AllowedDA      []uint64
}

var healthSchema = []fspec{
	{key: 1, name: "status", kind: fUint, required: true},
	{key: 2, name: "chain_id", kind: fText, min: 1, max: 50, required: true},
	{key: 3, name: "head_height", kind: fUint, required: true},
	{key: 4, name: "head_time", kind: fUint, required: true},
	{key: 5, name: "gate_id", kind: fText, min: 1, max: 64, charset: isID, required: true},
	{key: 6, name: "gate_pubkey", kind: fBytes, min: 32, max: 32, required: true},
	{key: 7, name: "recorder_signer", kind: fBytes, min: 20, max: 20},
	{key: 8, name: "namespace", kind: fBytes, min: 29, max: 29},
	{key: 9, name: "allowed_da", kind: fUintArray, min: 1, max: 2, required: true},
}

func encodeHealth(h HealthInfo) []byte {
	items := []kv{
		{key: 1, kind: fUint, u: h.Status},
		{key: 2, kind: fText, s: h.ChainID},
		{key: 3, kind: fUint, u: h.HeadHeight},
		{key: 4, kind: fUint, u: h.HeadTime},
		{key: 5, kind: fText, s: h.GateID},
		{key: 6, kind: fBytes, b: h.GatePubKey},
	}
	if len(h.RecorderSigner) > 0 {
		items = append(items, kv{key: 7, kind: fBytes, b: h.RecorderSigner})
	}
	if len(h.Namespace) > 0 {
		items = append(items, kv{key: 8, kind: fBytes, b: h.Namespace})
	}
	items = append(items, kv{key: 9, kind: fUintArray, arr: h.AllowedDA})
	return encodeMap(items...)
}

func decodeHealth(b []byte) (HealthInfo, error) {
	f, err := decodeFields(b, healthSchema)
	if err != nil {
		return HealthInfo{}, fmt.Errorf("edictaapi: health response: %w", err)
	}
	h := HealthInfo{
		Status: f[1].u, ChainID: string(f[2].b), HeadHeight: f[3].u, HeadTime: f[4].u,
		GateID: string(f[5].b), GatePubKey: append([]byte(nil), f[6].b...),
	}
	if n := f[7]; n != nil {
		h.RecorderSigner = append([]byte(nil), n.b...)
	}
	if n := f[8]; n != nil {
		h.Namespace = append([]byte(nil), n.b...)
	}
	for _, e := range f[9].entries {
		h.AllowedDA = append(h.AllowedDA, e.val.u)
	}
	return h, nil
}
