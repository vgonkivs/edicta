package commitment_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

const ibkrType = "application/vnd.edicta.ibkr.order.v0+cbor"

// testSalt is a fixed 32-byte action salt for tests that need any salt.
var testSalt = bytes.Repeat([]byte{0x5a}, commitment.ActionSaltSize)

// preimage rebuilds the action hash input from the layout alone.
func preimage(actionType string, salt, action []byte) []byte {
	out := []byte{byte(len(commitment.TagAction))}
	out = append(out, commitment.TagAction...)
	out = append(out, byte(len(actionType)))
	out = append(out, actionType...)
	out = append(out, salt...)
	return append(out, action...)
}

func TestActionHashLayout(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		action []byte
	}{
		{"one byte", "a/b", []byte{0}},
		{"ibkr type", ibkrType, []byte("order")},
		{"json bytes", "application/json", []byte(`{"to":"0x01","value":"1"}`)},
		{"128 byte type", "application/vnd.test." + strings.Repeat("a", 128-len("application/vnd.test.")), []byte{1, 2, 3}},
		{"max action", "application/octet-stream", bytes.Repeat([]byte{0xa5}, commitment.MaxActionSize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := commitment.ActionHash(tt.typ, testSalt, tt.action)
			require.NoError(t, err)
			want := sha256.Sum256(preimage(tt.typ, testSalt, tt.action))
			assert.Equal(t, hex.EncodeToString(want[:]), hex.EncodeToString(got[:]))
		})
	}
}

func TestActionHashSeparatesTypeAndBytes(t *testing.T) {
	action := []byte{1, 2, 3, 4}
	base, err := commitment.ActionHash("application/json", testSalt, action)
	require.NoError(t, err)

	t.Run("other type same bytes", func(t *testing.T) {
		h, err := commitment.ActionHash("application/octet-stream", testSalt, action)
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})
	t.Run("type suffix moved into the bytes", func(t *testing.T) {
		h1, err := commitment.ActionHash("a/bc", testSalt, []byte("d"))
		require.NoError(t, err)
		h2, err := commitment.ActionHash("a/b", testSalt, []byte("cd"))
		require.NoError(t, err)
		assert.NotEqual(t, h1, h2, "type and bytes do not split one way only")
	})
	t.Run("one flipped bit", func(t *testing.T) {
		b := bytes.Clone(action)
		b[2] ^= 1
		h, err := commitment.ActionHash("application/json", testSalt, b)
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})
	t.Run("trailing zero byte", func(t *testing.T) {
		h, err := commitment.ActionHash("application/json", testSalt, append(bytes.Clone(action), 0))
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})
	t.Run("other salt", func(t *testing.T) {
		other := bytes.Clone(testSalt)
		other[31] ^= 1
		h, err := commitment.ActionHash("application/json", other, action)
		require.NoError(t, err)
		assert.NotEqual(t, base, h)
	})
	t.Run("salt bytes moved into the action", func(t *testing.T) {
		h, err := commitment.ActionHash("application/json", testSalt[:31], append([]byte{testSalt[31]}, action...))
		require.Error(t, err, "the salt has one width, so the split is unique")
		assert.Equal(t, commitment.Hash{}, h)
	})
	t.Run("bare sha256 is not the action hash", func(t *testing.T) {
		bare := sha256.Sum256(action)
		assert.NotEqual(t, base, commitment.Hash(bare))
	})
	t.Run("deterministic", func(t *testing.T) {
		again, err := commitment.ActionHash("application/json", testSalt, action)
		require.NoError(t, err)
		assert.Equal(t, base, again)
	})
	t.Run("does not modify its input", func(t *testing.T) {
		in := bytes.Clone(action)
		_, err := commitment.ActionHash("application/json", testSalt, in)
		require.NoError(t, err)
		assert.Equal(t, action, in)
	})
}

func TestActionHashRejects(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		action []byte
		want   string
	}{
		{"nil action", "application/json", nil, "ErrActionSize"},
		{"empty action", "application/json", []byte{}, "ErrActionSize"},
		{"action one over max", "application/json", make([]byte, commitment.MaxActionSize+1), "ErrActionSize"},
		{"empty type", "", []byte{1}, "ErrInvalidString"},
		{"uppercase type", "Application/json", []byte{1}, "ErrInvalidString"},
		{"type without slash", "applicationjson", []byte{1}, "ErrInvalidString"},
		{"type with parameter", "application/json; charset=utf-8", []byte{1}, "ErrInvalidString"},
		{"type with space", "application/ json", []byte{1}, "ErrInvalidString"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := commitment.ActionHash(tt.typ, testSalt, tt.action)
			assertSentinel(t, err, tt.want)
			assert.Equal(t, commitment.Hash{}, h, "hash returned with an error")
		})
	}
	for _, tt := range []struct {
		name string
		salt []byte
		want string
	}{
		{"nil salt", nil, "ErrMissingField"},
		{"empty salt", []byte{}, "ErrMissingField"},
		{"31-byte salt", make([]byte, 31), "ErrFieldSize"},
		{"33-byte salt", make([]byte, 33), "ErrFieldSize"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, err := commitment.ActionHash("application/json", tt.salt, []byte{1})
			assertSentinel(t, err, tt.want)
			assert.Equal(t, commitment.Hash{}, h)
		})
	}
	t.Run("type longer than 128 bytes", func(t *testing.T) {
		typ := "application/" + strings.Repeat("a", 129-len("application/"))
		_, err := commitment.ActionHash(typ, testSalt, []byte{1})
		require.Error(t, err)
		assert.True(t, matchesAnySentinel(err), "no sentinel: %v", err)
	})
}

func TestValidMediaType(t *testing.T) {
	long := func(n int) string { return "application/" + strings.Repeat("a", n-len("application/")) }
	tests := []struct {
		name string
		s    string
		max  int
		want bool
	}{
		{"shortest", "a/b", 128, true},
		{"digits", "0/9", 128, true},
		{"json", "application/json", 128, true},
		{"ibkr", ibkrType, 128, true},
		{"all punctuation", "x/y!#$&^_.+-", 128, true},
		{"exactly max 128", long(128), 128, true},
		{"one over max 128", long(129), 128, false},
		{"exactly max 64", long(64), 64, true},
		{"one over max 64", long(65), 64, false},
		{"empty", "", 128, false},
		{"two bytes", "a/", 128, false},
		{"no slash", "abc", 128, false},
		{"leading slash", "/ab", 128, false},
		{"trailing slash", "ab/", 128, false},
		{"empty subtype", "a/ ", 128, false},
		{"two slashes", "a/b/c", 128, false},
		{"uppercase type", "A/b", 128, false},
		{"uppercase subtype", "a/B", 128, false},
		{"parameter", "text/plain; charset=utf-8", 128, false},
		{"space", "a/b c", 128, false},
		{"trailing space", "a/b ", 128, false},
		{"tab", "a/b\t", 128, false},
		{"newline", "a/b\n", 128, false},
		{"nul", "a/b\x00", 128, false},
		{"leading hyphen type", "-a/b", 128, false},
		{"leading hyphen subtype", "a/-b", 128, false},
		{"leading dot subtype", "a/.b", 128, false},
		{"leading plus subtype", "a/+b", 128, false},
		{"unicode", "a/é", 128, false},
		{"greek lookalike", "a/\u03bf", 128, false},
		{"comma", "a/b,c", 128, false},
		{"semicolon", "a/b;c", 128, false},
		{"equals", "a/b=c", 128, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, commitment.ValidMediaType(tt.s, tt.max))
		})
	}
}

// Retired fields must not come back under another name.
func TestSchemaShape(t *testing.T) {
	names := func(v any) []string {
		rt := reflect.TypeOf(v)
		out := make([]string, 0, rt.NumField())
		for i := 0; i < rt.NumField(); i++ {
			if rt.Field(i).IsExported() {
				out = append(out, rt.Field(i).Name)
			}
		}
		return out
	}
	assert.ElementsMatch(t, []string{
		"Version", "AgentID", "AgentPubKey", "Nonce", "IssuedAt", "ValidUntil",
		"Scope", "Action", "PayloadRef", "CiphertextHash", "PlaintextHash", "PayloadSize", "MandateRef",
	}, names(commitment.Commitment{}))
	assert.ElementsMatch(t, []string{"GateID"}, names(commitment.Scope{}))
	assert.ElementsMatch(t, []string{"Type", "Hash"}, names(commitment.Action{}))
	assert.ElementsMatch(t, []string{"GateID", "ActionTypes"}, names(commitment.GateScope{}))
	assert.ElementsMatch(t, []string{"Version", "CommitmentHash", "GateID", "GatePubKey", "RailRef", "RecordedAt", "ExecutorPubKey", "ExecutorSignature"}, names(commitment.Receipt{}))
	assert.ElementsMatch(t, []string{"Version", "CommitmentHash", "ActionHash", "GateID", "Expires", "Path", "Mode", "AnchorDeadline"}, names(commitment.Authorization{}))
}

// The wire keys: action is {3: type, 4: hash}, scope is {1: gate_id}, and no
// retired key (action 1 and 2, scope 2 to 4, constraints 9) is ever written.
func TestWireKeys(t *testing.T) {
	c, _, _ := baseCommitment(t)
	b, err := commitment.Encode(c)
	require.NoError(t, err)

	var top map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(b, &top))
	keys := func(m map[uint64]cbor.RawMessage) []uint64 {
		out := make([]uint64, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	assert.ElementsMatch(t, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13}, keys(top))

	var action, scope map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(top[8], &action))
	require.NoError(t, cbor.Unmarshal(top[7], &scope))
	assert.ElementsMatch(t, []uint64{3, 4}, keys(action))
	assert.ElementsMatch(t, []uint64{1}, keys(scope))

	var typ string
	var hash []byte
	require.NoError(t, cbor.Unmarshal(action[3], &typ))
	require.NoError(t, cbor.Unmarshal(action[4], &hash))
	assert.Equal(t, c.Action.Type, typ)
	assert.Equal(t, c.Action.Hash, hash)
}
