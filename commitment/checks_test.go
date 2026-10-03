package commitment_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
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
		name     string
		deadline *uint64
		skew     uint64
		now      uint64
		want     string
	}{
		{"mid window", nil, 30, issued + 60, ""},
		{"issued_at exactly now+skew", nil, 30, issued - 30, ""},
		{"issued_at one past now+skew", nil, 30, issued - 31, "ErrNotYetValid"},
		{"zero skew issued_at equals now", nil, 0, issued, ""},
		{"zero skew issued_at in future", nil, 0, issued - 1, "ErrNotYetValid"},
		{"last valid second with skew", nil, 30, validUntil - 31, ""},
		{"now+skew equals valid_until is expired", nil, 30, validUntil - 30, "ErrExpired"},
		{"zero skew last valid second", nil, 0, validUntil - 1, ""},
		{"zero skew now equals valid_until", nil, 0, validUntil, "ErrExpired"},
		{"far past expiry", nil, 30, validUntil + 100000, "ErrExpired"},
		{"deadline earlier than valid_until wins", ptr(issued + 300), 30, issued + 270, "ErrExpired"},
		{"before deadline", ptr(issued + 300), 30, issued + 269, ""},
		{"deadline equal to valid_until", ptr(validUntil), 30, validUntil - 31, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, p := baseCommitment(t)
			c.Constraints.Deadline = tt.deadline
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
		{"rail", func(g *commitment.GateScope, _ *commitment.Commitment) { g.Rail = 2 }, "ErrScopeMismatch"},
		{"account", func(g *commitment.GateScope, _ *commitment.Commitment) { g.Account = "DU7654321" }, "ErrScopeMismatch"},
		{"gate has chain id, commitment none", func(g *commitment.GateScope, _ *commitment.Commitment) { g.ChainID = ptr("celestia") }, "ErrScopeMismatch"},
		{"commitment has chain id, gate none", func(_ *commitment.GateScope, c *commitment.Commitment) { c.Scope.ChainID = ptr("celestia") }, "ErrScopeMismatch"},
		{"both chain ids equal", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ChainID = ptr("celestia")
			c.Scope.ChainID = ptr("celestia")
		}, ""},
		{"chain ids differ", func(g *commitment.GateScope, c *commitment.Commitment) {
			g.ChainID = ptr("celestia")
			c.Scope.ChainID = ptr("mocha-4")
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
	tests := []struct {
		name   string
		mutate func(o *commitment.IBKROrderV0)
		want   string
	}{
		{"identical", func(*commitment.IBKROrderV0) {}, ""},
		{"symbol ignored when different", func(o *commitment.IBKROrderV0) { o.Symbol = ptr("MSFT") }, ""},
		{"symbol ignored when present", func(o *commitment.IBKROrderV0) { o.Symbol = ptr("AAPL") }, ""},
		{"account", func(o *commitment.IBKROrderV0) { o.Account = "DU7654321" }, "ErrActionMismatch"},
		{"conid", func(o *commitment.IBKROrderV0) { o.ConID++ }, "ErrActionMismatch"},
		{"side", func(o *commitment.IBKROrderV0) { o.Side = 2 }, "ErrActionMismatch"},
		{"qty up", func(o *commitment.IBKROrderV0) { o.Qty++ }, "ErrActionMismatch"},
		{"qty down", func(o *commitment.IBKROrderV0) { o.Qty-- }, "ErrActionMismatch"},
		{"order type", func(o *commitment.IBKROrderV0) { o.OrderType = 2 }, "ErrActionMismatch"},
		{"limit price up", func(o *commitment.IBKROrderV0) { *o.LimitPrice++ }, "ErrActionMismatch"},
		{"limit price down", func(o *commitment.IBKROrderV0) { *o.LimitPrice-- }, "ErrActionMismatch"},
		{"limit price absent", func(o *commitment.IBKROrderV0) { o.LimitPrice = nil }, "ErrActionMismatch"},
		{"currency", func(o *commitment.IBKROrderV0) { o.Currency = "EUR" }, "ErrActionMismatch"},
		{"tif", func(o *commitment.IBKROrderV0) { o.TIF = 2 }, "ErrActionMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := baseCommitment(t)
			req := *c.Action.IBKROrder
			lp := *req.LimitPrice
			req.LimitPrice = &lp
			tt.mutate(&req)
			err := commitment.CheckAction(c, req)
			if tt.want == "" {
				require.NoError(t, err, "unexpected error")
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
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
		{"notional exactly at bound", func(c *commitment.Commitment, _ *commitment.Params) {
			o := c.Action.IBKROrder
			c.Constraints.MaxNotional = o.Qty * *o.LimitPrice / commitment.QtyScale
		}, ""},
		{"notional one unit over bound", func(c *commitment.Commitment, _ *commitment.Params) {
			o := c.Action.IBKROrder
			c.Constraints.MaxNotional = o.Qty**o.LimitPrice/commitment.QtyScale - 1
		}, "ErrNotionalExceeded"},
		{"buy at price bound", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice)
		}, ""},
		{"buy one over price bound", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice - 1)
		}, "ErrPriceBound"},
		{"sell at price bound", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Action.IBKROrder.Side = 2
			c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice)
		}, ""},
		{"sell one under price bound", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Action.IBKROrder.Side = 2
			c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice + 1)
		}, "ErrPriceBound"},
		{"market order with no price is rejected as unsupported", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Action.IBKROrder.OrderType = 2
			c.Action.IBKROrder.LimitPrice = nil
		}, "ErrUnsupportedOrderType"},
		{"limit order without price", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Action.IBKROrder.LimitPrice = nil
		}, "ErrLimitPrice"},
		{"chain id on ibkr", func(c *commitment.Commitment, _ *commitment.Params) { c.Scope.ChainID = ptr("celestia") }, "ErrChainIDRule"},
		{"scope account differs from params account", func(c *commitment.Commitment, _ *commitment.Params) { c.Scope.Account = "DU7654321" }, "ErrAccountMismatch"},
		{"deadline equals issued_at", func(c *commitment.Commitment, _ *commitment.Params) { c.Constraints.Deadline = ptr(c.IssuedAt) }, "ErrDeadlineRange"},
		{"deadline one past valid_until", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Constraints.Deadline = ptr(c.ValidUntil + 1)
		}, "ErrDeadlineRange"},
		{"deadline equals valid_until", func(c *commitment.Commitment, _ *commitment.Params) {
			c.Constraints.Deadline = ptr(c.ValidUntil)
		}, ""},
		{"payload_size at max", func(c *commitment.Commitment, _ *commitment.Params) { c.PayloadSize = commitment.MaxPayloadSize }, ""},
		{"payload_size one over max", func(c *commitment.Commitment, _ *commitment.Params) {
			c.PayloadSize = commitment.MaxPayloadSize + 1
		}, "ErrPayloadTooLarge"},
		{"issued_at zero", func(c *commitment.Commitment, _ *commitment.Params) { c.IssuedAt = 0 }, "ErrZeroValue"},
		{"max_notional zero", func(c *commitment.Commitment, _ *commitment.Params) { c.Constraints.MaxNotional = 0 }, "ErrZeroValue"},
		{"price_bound zero", func(c *commitment.Commitment, _ *commitment.Params) { c.Constraints.PriceBound = ptr(uint64(0)) }, "ErrZeroValue"},
		{"conid zero", func(c *commitment.Commitment, _ *commitment.Params) { c.Action.IBKROrder.ConID = 0 }, "ErrZeroValue"},
		{"version 1", func(c *commitment.Commitment, _ *commitment.Params) { c.Version = 1 }, "ErrUnsupportedVersion"},
		{"qty above 2^63-1", func(c *commitment.Commitment, _ *commitment.Params) { c.Action.IBKROrder.Qty = 1 << 63 }, "ErrIntRange"},
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
