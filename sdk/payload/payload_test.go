package payload_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

var all = []error{payload.ErrMalformed, payload.ErrVersion, payload.ErrTooLarge}

func requireOnly(t *testing.T, err, want error) {
	t.Helper()
	sdkfix.RequireOnly(t, err, want, all)
}

func TestConstants(t *testing.T) {
	assert.EqualValues(t, 0, payload.Version)
}

// Every valid vector: Encode gives the spec plaintext byte for byte, Decode
// accepts it and the decoded value encodes back to the same bytes.
func TestVectorCases(t *testing.T) {
	v := sdkfix.Load(t)
	require.GreaterOrEqual(t, len(v.Cases), 4)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := payload.Encode(c.Payload)
			require.NoError(t, err)
			require.Equal(t, c.Plaintext, got)

			p, err := payload.Decode(c.Plaintext)
			require.NoError(t, err)
			assert.Equal(t, c.Payload.Context.MediaType, p.Context.MediaType)
			assert.Equal(t, c.Payload.Action, p.Action)
			assert.Equal(t, c.Payload.Metadata != nil, p.Metadata != nil)

			back, err := payload.Encode(p)
			require.NoError(t, err)
			assert.Equal(t, c.Plaintext, back)
		})
	}
}

// The action sits at payload key 5 as {3: type, 4: data}, and the retired
// constraints key 6 is absent. The data is the cleartext action bytes whose
// hash the commitment carries.
func TestActionEncodesAsTypeAndData(t *testing.T) {
	v := sdkfix.Load(t)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var m map[uint64]cbor.RawMessage
			require.NoError(t, cbor.Unmarshal(c.Plaintext, &m))
			assert.NotContains(t, m, uint64(6), "retired constraints key present")

			var act map[uint64]any
			require.NoError(t, cbor.Unmarshal(m[5], &act))
			assert.Len(t, act, 2)
			assert.Equal(t, c.ActionType, act[3])
			assert.Equal(t, c.Action, act[4])
			assert.Equal(t, c.ActionType, c.Payload.Action.Type)
			assert.Equal(t, c.Action, c.Payload.Action.Data)

			h, err := commitment.ActionHash(c.Payload.Action.Type, c.Payload.Action.Data)
			require.NoError(t, err)
			assert.Equal(t, c.ActionHash, h)
		})
	}
}

// The payload carries no constraints and the action has exactly a type and
// the bytes.
func TestPayloadShape(t *testing.T) {
	names := func(v any) []string {
		rt := reflect.TypeOf(v)
		out := make([]string, 0, rt.NumField())
		for i := 0; i < rt.NumField(); i++ {
			out = append(out, rt.Field(i).Name)
		}
		return out
	}
	assert.ElementsMatch(t, []string{"Version", "Model", "Policy", "Context", "Action", "Metadata"}, names(payload.Payload{}))
	assert.ElementsMatch(t, []string{"Type", "Data"}, names(payload.Action{}))
}

// The plaintext-stage vectors that name a payload sentinel, decoded after the
// blob layer opened them.
func TestVectorPlaintextRejects(t *testing.T) {
	v := sdkfix.Load(t)
	n := 0
	for _, r := range v.Rejects {
		if r.Stage != "plaintext" || !strings.HasPrefix(r.Expect, "payload.") {
			continue
		}
		n++
		t.Run(r.ID, func(t *testing.T) {
			want, ok := sdkfix.Sentinel(r.Expect)
			require.True(t, ok, "unknown sentinel %s", r.Expect)
			_, pt := v.OpenPlaintext(t, r)
			_, err := payload.Decode(pt)
			requireOnly(t, err, want)
		})
	}
	require.GreaterOrEqual(t, n, 16)
}

// A required context with no bytes is an empty byte string on the wire, not
// null and not absent.
func TestEmptyContextBytes(t *testing.T) {
	v := sdkfix.Load(t)
	p := sdkfix.ClonePayload(v.Cases[3].Payload)
	require.Empty(t, p.Context.Bytes)
	want, err := payload.Encode(p)
	require.NoError(t, err)
	p.Context.Bytes = nil
	got, err := payload.Encode(p)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	d, err := payload.Decode(got)
	require.NoError(t, err)
	assert.Empty(t, d.Context.Bytes)
}

func longType(n int) string { return "application/" + strings.Repeat("a", n-len("application/")) }

func mediaTypes() (valid, invalid []string) {
	valid = []string{
		"application/json", "text/plain", "application/vnd.edicta.dca.v0+cbor", "a/b", "x-y/z.w+v",
		"application/octet-stream", "0/0", "a!#$&^_.+-/b" + "0", strings.Repeat("a", 31) + "/" + strings.Repeat("b", 32),
	}
	invalid = []string{
		"", "Application/json", "application/JSON", "application/json; charset=utf-8", "application/json;",
		"applicationjson", "a/b/c", " a/b", "a/b ", "a /b", "/b", "a/", "/", "-a/b", "a/-b", ".a/b", "a/.b",
		"a/b\n", "a\t/b", "é/b", "a/é", "a/b,c", "a/b(c", "a/b*", "a/b%", "a/b=",
		strings.Repeat("a", 32) + "/" + strings.Repeat("b", 32),
	}
	return
}

func TestMediaTypeEncode(t *testing.T) {
	v := sdkfix.Load(t)
	valid, invalid := mediaTypes()
	for _, mt := range valid {
		t.Run("valid context "+mt, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			p.Context.MediaType = mt
			_, err := payload.Encode(p)
			require.NoError(t, err)
		})
		t.Run("valid metadata "+mt, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			p.Metadata = &payload.Data{MediaType: mt, Bytes: []byte("x")}
			_, err := payload.Encode(p)
			require.NoError(t, err)
		})
	}
	for _, mt := range invalid {
		t.Run("invalid context "+mt, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			p.Context.MediaType = mt
			_, err := payload.Encode(p)
			requireOnly(t, err, payload.ErrMalformed)
		})
		t.Run("invalid metadata "+mt, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			p.Metadata = &payload.Data{MediaType: mt, Bytes: []byte("x")}
			_, err := payload.Encode(p)
			requireOnly(t, err, payload.ErrMalformed)
		})
	}
}

// generic decodes a plaintext into nested maps with uint keys, so a test can
// break one field and re-encode the rest canonically.
func generic(t *testing.T, pt []byte) map[uint64]any {
	t.Helper()
	dm, err := cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[uint64]any{})}.DecMode()
	require.NoError(t, err)
	var m map[uint64]any
	require.NoError(t, dm.Unmarshal(pt, &m))
	return m
}

func canonical(t *testing.T, m map[uint64]any) []byte {
	t.Helper()
	em, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	b, err := em.Marshal(m)
	require.NoError(t, err)
	return b
}

func sub(m map[uint64]any, k uint64) map[uint64]any { return m[k].(map[uint64]any) }

// The decoder side of every rule: bytes that are valid CBOR but break the
// plaintext schema, limits or profile.
func TestDecodeRejects(t *testing.T) {
	v := sdkfix.Load(t)
	base := v.Cases[1].Plaintext // every optional field present
	require.NotNil(t, v.Cases[1].Payload.Metadata)

	mut := func(f func(m map[uint64]any)) []byte {
		m := generic(t, base)
		f(m)
		return canonical(t, m)
	}
	valid, invalid := mediaTypes()
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"nil", nil, payload.ErrMalformed},
		{"empty", []byte{}, payload.ErrMalformed},
		{"truncated", base[:len(base)-1], payload.ErrMalformed},
		{"trailing byte", append(append([]byte{}, base...), 0x00), payload.ErrMalformed},
		{"non-minimal map head", append([]byte{0xb8, 0x07}, base[1:]...), payload.ErrMalformed},
		{"version 1", mut(func(m map[uint64]any) { m[1] = uint64(1) }), payload.ErrVersion},
		{"version 2", mut(func(m map[uint64]any) { m[1] = uint64(2) }), payload.ErrVersion},
		{"version float", mut(func(m map[uint64]any) { m[1] = float64(0) }), payload.ErrMalformed},
		{"version text", mut(func(m map[uint64]any) { m[1] = "0" }), payload.ErrMalformed},
		{"unknown key", mut(func(m map[uint64]any) { m[8] = uint64(0) }), payload.ErrMalformed},
		{"missing model", mut(func(m map[uint64]any) { delete(m, 2) }), payload.ErrMalformed},
		{"missing policy", mut(func(m map[uint64]any) { delete(m, 3) }), payload.ErrMalformed},
		{"missing context", mut(func(m map[uint64]any) { delete(m, 4) }), payload.ErrMalformed},
		{"missing action", mut(func(m map[uint64]any) { delete(m, 5) }), payload.ErrMalformed},
		{"retired constraints key", mut(func(m map[uint64]any) { m[6] = map[uint64]any{1: uint64(1)} }), payload.ErrMalformed},
		{"model id empty", mut(func(m map[uint64]any) { sub(m, 2)[1] = "" }), payload.ErrMalformed},
		{"model id 129", mut(func(m map[uint64]any) { sub(m, 2)[1] = strings.Repeat("a", 129) }), payload.ErrMalformed},
		{"model id 128 ok shape", mut(func(m map[uint64]any) { sub(m, 2)[1] = strings.Repeat("a", 128) }), nil},
		{"model id non-ascii", mut(func(m map[uint64]any) { sub(m, 2)[1] = "mé" }), payload.ErrMalformed},
		{"model id control", mut(func(m map[uint64]any) { sub(m, 2)[1] = "m\x1f" }), payload.ErrMalformed},
		{"model id del", mut(func(m map[uint64]any) { sub(m, 2)[1] = "m\x7f" }), payload.ErrMalformed},
		{"model id with spaces ok shape", mut(func(m map[uint64]any) { sub(m, 2)[1] = "a b" }), nil},
		{"model version empty", mut(func(m map[uint64]any) { sub(m, 2)[2] = "" }), payload.ErrMalformed},
		{"model version 65", mut(func(m map[uint64]any) { sub(m, 2)[2] = strings.Repeat("v", 65) }), payload.ErrMalformed},
		{"model digest 31", mut(func(m map[uint64]any) { sub(m, 2)[3] = make([]byte, 31) }), payload.ErrMalformed},
		{"model digest 33", mut(func(m map[uint64]any) { sub(m, 2)[3] = make([]byte, 33) }), payload.ErrMalformed},
		{"model unknown key", mut(func(m map[uint64]any) { sub(m, 2)[4] = "x" }), payload.ErrMalformed},
		{"policy id empty", mut(func(m map[uint64]any) { sub(m, 3)[1] = "" }), payload.ErrMalformed},
		{"policy digest 31", mut(func(m map[uint64]any) { sub(m, 3)[3] = make([]byte, 31) }), payload.ErrMalformed},
		{"policy text empty", mut(func(m map[uint64]any) { sub(m, 3)[4] = []byte{} }), payload.ErrMalformed},
		{"policy unknown key", mut(func(m map[uint64]any) { sub(m, 3)[5] = "x" }), payload.ErrMalformed},
		{"context missing media type", mut(func(m map[uint64]any) { delete(sub(m, 4), 1) }), payload.ErrMalformed},
		{"context missing data", mut(func(m map[uint64]any) { delete(sub(m, 4), 2) }), payload.ErrMalformed},
		{"context data is text", mut(func(m map[uint64]any) { sub(m, 4)[2] = "x" }), payload.ErrMalformed},
		{"context unknown key", mut(func(m map[uint64]any) { sub(m, 4)[3] = "x" }), payload.ErrMalformed},
		{"metadata missing media type", mut(func(m map[uint64]any) { delete(sub(m, 7), 1) }), payload.ErrMalformed},
		{"metadata empty data", mut(func(m map[uint64]any) { sub(m, 7)[2] = []byte{} }), payload.ErrMalformed},
		{"metadata null", mut(func(m map[uint64]any) { m[7] = nil }), payload.ErrMalformed},
		{"action retired kind key", mut(func(m map[uint64]any) { sub(m, 5)[1] = "ibkr.order.v0" }), payload.ErrMalformed},
		{"action retired params key", mut(func(m map[uint64]any) { sub(m, 5)[2] = map[uint64]any{} }), payload.ErrMalformed},
		{"action unknown key", mut(func(m map[uint64]any) { sub(m, 5)[5] = uint64(1) }), payload.ErrMalformed},
		{"action missing type", mut(func(m map[uint64]any) { delete(sub(m, 5), 3) }), payload.ErrMalformed},
		{"action missing data", mut(func(m map[uint64]any) { delete(sub(m, 5), 4) }), payload.ErrMalformed},
		{"action type uppercase", mut(func(m map[uint64]any) { sub(m, 5)[3] = "Application/json" }), payload.ErrMalformed},
		{"action type empty", mut(func(m map[uint64]any) { sub(m, 5)[3] = "" }), payload.ErrMalformed},
		{"action type no slash", mut(func(m map[uint64]any) { sub(m, 5)[3] = "applicationjson" }), payload.ErrMalformed},
		{"action type parameter", mut(func(m map[uint64]any) { sub(m, 5)[3] = "application/json; charset=utf-8" }), payload.ErrMalformed},
		{"action type 129", mut(func(m map[uint64]any) { sub(m, 5)[3] = longType(129) }), payload.ErrMalformed},
		{"action type 128", mut(func(m map[uint64]any) { sub(m, 5)[3] = longType(128) }), nil},
		{"action type is bytes", mut(func(m map[uint64]any) { sub(m, 5)[3] = []byte("a/b") }), payload.ErrMalformed},
		{"action data empty", mut(func(m map[uint64]any) { sub(m, 5)[4] = []byte{} }), payload.ErrMalformed},
		{"action data is text", mut(func(m map[uint64]any) { sub(m, 5)[4] = "x" }), payload.ErrMalformed},
		{"action data one byte ok", mut(func(m map[uint64]any) { sub(m, 5)[4] = []byte{0} }), nil},
		{"action data max ok", mut(func(m map[uint64]any) { sub(m, 5)[4] = make([]byte, commitment.MaxActionSize) }), nil},
		{"action data over max", mut(func(m map[uint64]any) { sub(m, 5)[4] = make([]byte, commitment.MaxActionSize+1) }), payload.ErrMalformed},
	}
	for _, mt := range valid {
		tests = append(tests, struct {
			name string
			in   []byte
			want error
		}{"context media type ok " + mt, mut(func(m map[uint64]any) { sub(m, 4)[1] = mt }), nil})
	}
	for _, mt := range invalid {
		tests = append(tests, struct {
			name string
			in   []byte
			want error
		}{"context media type " + mt, mut(func(m map[uint64]any) { sub(m, 4)[1] = mt }), payload.ErrMalformed})
		tests = append(tests, struct {
			name string
			in   []byte
			want error
		}{"metadata media type " + mt, mut(func(m map[uint64]any) { sub(m, 7)[1] = mt }), payload.ErrMalformed})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := payload.Decode(tt.in)
			if tt.want == nil {
				require.NoError(t, err)
				require.NotNil(t, p)
				return
			}
			requireOnly(t, err, tt.want)
			assert.Nil(t, p)
		})
	}
}

// The accepted set is exactly the canonical encodings: a padded length head
// and an indefinite-length map fail even when the values are fine.
func TestDecodeRejectsNonCanonical(t *testing.T) {
	v := sdkfix.Load(t)
	base := v.Cases[0].Plaintext
	indef := append([]byte{0xbf}, base[1:]...)
	indef = append(indef, 0xff)
	for name, in := range map[string][]byte{
		"indefinite map": indef,
		"padded head":    append([]byte{0xb9, 0x00, 0x06}, base[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := payload.Decode(in)
			requireOnly(t, err, payload.ErrMalformed)
		})
	}
}

func TestEncodeRejects(t *testing.T) {
	v := sdkfix.Load(t)
	str := func(s string) *string { return &s }
	tests := []struct {
		name string
		mod  func(p *payload.Payload)
		want error
	}{
		{"version 1", func(p *payload.Payload) { p.Version = 1 }, payload.ErrVersion},
		{"model id empty", func(p *payload.Payload) { p.Model.ID = "" }, payload.ErrMalformed},
		{"model id 129", func(p *payload.Payload) { p.Model.ID = strings.Repeat("a", 129) }, payload.ErrMalformed},
		{"model id non-ascii", func(p *payload.Payload) { p.Model.ID = "mé" }, payload.ErrMalformed},
		{"model version empty", func(p *payload.Payload) { p.Model.Version = str("") }, payload.ErrMalformed},
		{"model digest short", func(p *payload.Payload) { p.Model.Digest = make([]byte, 31) }, payload.ErrMalformed},
		{"policy id empty", func(p *payload.Payload) { p.Policy.ID = "" }, payload.ErrMalformed},
		{"policy digest long", func(p *payload.Payload) { p.Policy.Digest = make([]byte, 33) }, payload.ErrMalformed},
		{"policy text empty slice", func(p *payload.Payload) { p.Policy.Text = []byte{} }, payload.ErrMalformed},
		{"context media type empty", func(p *payload.Payload) { p.Context.MediaType = "" }, payload.ErrMalformed},
		{"metadata empty data", func(p *payload.Payload) { p.Metadata = &payload.Data{MediaType: "text/plain"} }, payload.ErrMalformed},
		{"metadata without media type", func(p *payload.Payload) { p.Metadata = &payload.Data{Bytes: []byte("x")} }, payload.ErrMalformed},
		{"action type empty", func(p *payload.Payload) { p.Action.Type = "" }, payload.ErrMalformed},
		{"action type uppercase", func(p *payload.Payload) { p.Action.Type = "Application/json" }, payload.ErrMalformed},
		{"action type parameter", func(p *payload.Payload) { p.Action.Type = "text/plain; charset=utf-8" }, payload.ErrMalformed},
		{"action type 129", func(p *payload.Payload) { p.Action.Type = longType(129) }, payload.ErrMalformed},
		{"action data nil", func(p *payload.Payload) { p.Action.Data = nil }, payload.ErrMalformed},
		{"action data empty", func(p *payload.Payload) { p.Action.Data = []byte{} }, payload.ErrMalformed},
		{"action data over max", func(p *payload.Payload) { p.Action.Data = make([]byte, commitment.MaxActionSize+1) }, payload.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			tt.mod(p)
			b, err := payload.Encode(p)
			requireOnly(t, err, tt.want)
			assert.Nil(t, b)
		})
	}
	t.Run("nil payload", func(t *testing.T) {
		_, err := payload.Encode(nil)
		require.Error(t, err)
	})
}

func TestEncodeAcceptsActionLimits(t *testing.T) {
	v := sdkfix.Load(t)
	tests := []struct {
		name string
		typ  string
		data []byte
	}{
		{"one byte", "a/b", []byte{0}},
		{"128 byte type", longType(128), []byte{1}},
		{"max data", "application/octet-stream", make([]byte, commitment.MaxActionSize)},
		{"json bytes", "application/json", []byte(`{"to":"0x01"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sdkfix.ClonePayload(v.Cases[0].Payload)
			p.Action = payload.Action{Type: tt.typ, Data: tt.data}
			b, err := payload.Encode(p)
			require.NoError(t, err)
			d, err := payload.Decode(b)
			require.NoError(t, err)
			assert.Equal(t, p.Action, d.Action)
		})
	}
}

// Encode never changes its input and is deterministic.
func TestEncodeIsPureAndDeterministic(t *testing.T) {
	v := sdkfix.Load(t)
	p := sdkfix.ClonePayload(v.Cases[1].Payload)
	a, err := payload.Encode(p)
	require.NoError(t, err)
	b, err := payload.Encode(p)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Equal(t, v.Cases[1].Payload.Action, p.Action)
}

// The decoded payload owns its bytes: a caller that wipes the decrypted input
// afterwards leaves the result intact.
func TestDecodeDoesNotAliasItsInput(t *testing.T) {
	v := sdkfix.Load(t)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			in := append([]byte{}, c.Plaintext...)
			p, err := payload.Decode(in)
			require.NoError(t, err)
			clear(in)
			assert.Equal(t, c.Action, p.Action.Data)
			back, err := payload.Encode(p)
			require.NoError(t, err)
			assert.Equal(t, c.Plaintext, back)
		})
	}
}
