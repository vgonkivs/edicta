package commitment_test

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

// baseCommitment is the minimal_lmt vector input: issued_at 1791000000,
// valid_until 1791000900, DA celestia_blob, no optional fields.
func baseCommitment(t *testing.T) (*commitment.Commitment, commitment.GateScope, commitment.Params) {
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	return toCommitment(t, vc.Input), toGate(t, vf.Gate), toParams(t, vf.Params)
}

func TestCheckTime(t *testing.T) {
	const issued, validUntil = uint64(1791000000), uint64(1791000900)
	tests := []struct {
		name string
		skew uint64
		now  uint64
		want string
	}{
		{"mid window", 30, issued + 60, ""},
		{"issued_at exactly now+skew", 30, issued - 30, ""},
		{"issued_at one past now+skew", 30, issued - 31, "ErrNotYetValid"},
		{"zero skew issued_at equals now", 0, issued, ""},
		{"zero skew issued_at in future", 0, issued - 1, "ErrNotYetValid"},
		{"last valid second with skew", 30, validUntil - 31, ""},
		{"now+skew equals valid_until is expired", 30, validUntil - 30, "ErrExpired"},
		{"zero skew last valid second", 0, validUntil - 1, ""},
		{"zero skew now equals valid_until", 0, validUntil, "ErrExpired"},
		{"far past expiry", 30, validUntil + 100000, "ErrExpired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, p := baseCommitment(t)
			p.SkewS = tt.skew
			err := commitment.CheckTime(c, tt.now, p)
			if tt.want == "" {
				require.NoError(t, err, "unexpected error")
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestCheckScope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(g *commitment.GateScope, c *commitment.Commitment)
		want   string
	}{
		{"identical", func(*commitment.GateScope, *commitment.Commitment) {}, ""},
		{"gate id", func(g *commitment.GateScope, _ *commitment.Commitment) { g.GateID = "gate-paper-2" }, "ErrScopeMismatch"},
		{"gate id case", func(g *commitment.GateScope, _ *commitment.Commitment) { g.GateID = "GATE-PAPER-1" }, "ErrScopeMismatch"},
		{"gate id prefix", func(g *commitment.GateScope, _ *commitment.Commitment) { g.GateID = "gate-paper-" }, "ErrScopeMismatch"},
		{"action type only in the middle of the set", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ActionTypes = []string{"application/json", c.Action.Type, "application/octet-stream"}
		}, ""},
		{"action type is the only one", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ActionTypes = []string{c.Action.Type}
		}, ""},
		{"action type not configured", func(g *commitment.GateScope, _ *commitment.Commitment) {
			g.ActionTypes = []string{"application/json"}
		}, "ErrActionTypeNotAllowed"},
		{"empty allowlist allows nothing", func(g *commitment.GateScope, _ *commitment.Commitment) { g.ActionTypes = nil }, "ErrActionTypeNotAllowed"},
		{"suffix differs", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ActionTypes = []string{c.Action.Type + "x"}
		}, "ErrActionTypeNotAllowed"},
		{"prefix of the committed type", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ActionTypes = []string{c.Action.Type[:len(c.Action.Type)-1]}
		}, "ErrActionTypeNotAllowed"},
		{"case is not folded", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ActionTypes = []string{strings.ToUpper(c.Action.Type)}
		}, "ErrActionTypeNotAllowed"},
		{"gate id checked before action type", func(g *commitment.GateScope, _ *commitment.Commitment) {
			g.GateID = "gate-paper-2"
			g.ActionTypes = nil
		}, "ErrScopeMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, g, _ := baseCommitment(t)
			tt.mutate(&g, c)
			err := commitment.CheckScope(c, g)
			if tt.want == "" {
				require.NoError(t, err, "unexpected error")
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestCheckAction(t *testing.T) {
	c, _, _ := baseCommitment(t)
	vf := loadValid(t)
	vc := validCaseByID(t, vf, "minimal_lmt")
	action, salt := actionBytes(t, vc.actionSpec), actionSalt(t, vc.actionSpec)
	require.NoError(t, commitment.CheckAction(c, action, salt), "control")

	tests := []struct {
		name   string
		action func() []byte
		want   string
	}{
		{"identical", func() []byte { return bytes.Clone(action) }, ""},
		{"first byte flipped", func() []byte { b := bytes.Clone(action); b[0] ^= 1; return b }, "ErrActionMismatch"},
		{"last byte flipped", func() []byte { b := bytes.Clone(action); b[len(b)-1] ^= 1; return b }, "ErrActionMismatch"},
		{"truncated by one", func() []byte { return bytes.Clone(action[:len(action)-1]) }, "ErrActionMismatch"},
		{"one byte appended", func() []byte { return append(bytes.Clone(action), 0) }, "ErrActionMismatch"},
		{"one byte prepended", func() []byte { return append([]byte{0}, action...) }, "ErrActionMismatch"},
		{"one byte", func() []byte { return []byte{0} }, "ErrActionMismatch"},
		{"empty", func() []byte { return nil }, "ErrActionSize"},
		{"empty non-nil", func() []byte { return []byte{} }, "ErrActionSize"},
		{"max size plus one", func() []byte { return make([]byte, commitment.MaxActionSize+1) }, "ErrActionSize"},
		{"max size of wrong bytes", func() []byte { return make([]byte, commitment.MaxActionSize) }, "ErrActionMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := commitment.CheckAction(c, tt.action(), salt)
			if tt.want == "" {
				require.NoError(t, err, "unexpected error")
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}

	for _, st := range []struct {
		name string
		salt []byte
		want string
	}{
		{"salt missing", nil, "ErrMissingField"},
		{"salt empty", []byte{}, "ErrMissingField"},
		{"salt 31 bytes", salt[:31], "ErrFieldSize"},
		{"salt 33 bytes", append(bytes.Clone(salt), 0), "ErrFieldSize"},
		{"salt flipped", func() []byte { b := bytes.Clone(salt); b[0] ^= 1; return b }(), "ErrActionMismatch"},
		{"salt of another vector", actionSalt(t, validCaseByID(t, vf, "fibre_small_payload").actionSpec), "ErrActionMismatch"},
	} {
		t.Run(st.name, func(t *testing.T) {
			assertSentinel(t, commitment.CheckAction(c, action, st.salt), st.want)
		})
	}
	t.Run("size before salt", func(t *testing.T) {
		assertSentinel(t, commitment.CheckAction(c, nil, nil), "ErrActionSize")
	})
	t.Run("committed type decides the preimage", func(t *testing.T) {
		d := *c
		d.Action.Type = "application/json"
		assertSentinel(t, commitment.CheckAction(&d, action, salt), "ErrActionMismatch")
	})
	t.Run("committed hash decides the match", func(t *testing.T) {
		d := *c
		d.Action.Hash = bytes.Clone(c.Action.Hash)
		d.Action.Hash[31] ^= 1
		assertSentinel(t, commitment.CheckAction(&d, action, salt), "ErrActionMismatch")
	})
	t.Run("sha256 of the bytes alone is not the action hash", func(t *testing.T) {
		sum := sha256.Sum256(action)
		d := *c
		d.Action.Hash = sum[:]
		assertSentinel(t, commitment.CheckAction(&d, action, salt), "ErrActionMismatch")
	})
}

// Boundary behaviour of stage S that vectors pin only at a single point.
func TestValidateStaticBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *commitment.Commitment, p *commitment.Params)
		want   string
	}{
		{"baseline", func(*commitment.Commitment, *commitment.Params) {}, ""},
		{"ttl equals max", func(c *commitment.Commitment, _ *commitment.Params) { c.ValidUntil = c.IssuedAt + 3600 }, ""},
		{"ttl one over max", func(c *commitment.Commitment, _ *commitment.Params) { c.ValidUntil = c.IssuedAt + 3601 }, "ErrTTLTooLong"},
		{"ttl uses blob retention for celestia_blob", func(c *commitment.Commitment, p *commitment.Params) {
			p.BlobRetentionS = 400
			p.FibreRetentionS = 14400
			c.ValidUntil = c.IssuedAt + 101
		}, "ErrTTLTooLong"},
		{"ttl ignores fibre retention for celestia_blob", func(c *commitment.Commitment, p *commitment.Params) {
			p.BlobRetentionS = 14400
			p.FibreRetentionS = 400
			c.ValidUntil = c.IssuedAt + 900
		}, ""},
		{"ttl uses fibre retention for fibre", func(c *commitment.Commitment, p *commitment.Params) {
			c.PayloadRef.DA = commitment.DAFibre
			c.PayloadRef.Signer = nil
			p.FibreRetentionS = 400
			p.BlobRetentionS = 14400
			c.ValidUntil = c.IssuedAt + 101
		}, "ErrTTLTooLong"},
		{"valid_until equals issued_at", func(c *commitment.Commitment, _ *commitment.Params) { c.ValidUntil = c.IssuedAt }, "ErrTimeOrder"},
		{"payload_size at max", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadSize = commitment.MaxPayloadSize }, ""},
		{"payload_size one over max", func(c *commitment.Commitment, _ *commitment.Params) {
			c.PayloadSize = commitment.MaxPayloadSize + 1
		}, "ErrPayloadTooLarge"},
		{"issued_at zero", func(c *commitment.Commitment, _ *commitment.Params) { c.IssuedAt = 0 }, "ErrZeroValue"},
		{"version 2", func(c *commitment.Commitment, _ *commitment.Params) { c.Version = 2 }, "ErrUnsupportedVersion"},
		{"height 2^63", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadRef.Height = 1 << 63 }, "ErrIntRange"},
		{"height zero", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadRef.Height = 0 }, "ErrZeroValue"},
		{"payload_size zero", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadSize = 0 }, "ErrZeroValue"},
		{"unknown da", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadRef.DA = 3 }, "ErrInvalidEnum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, p := baseCommitment(t)
			tt.mutate(c, &p)
			err := commitment.ValidateStatic(c, p)
			if tt.want == "" {
				require.NoError(t, err, "unexpected error")
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}
