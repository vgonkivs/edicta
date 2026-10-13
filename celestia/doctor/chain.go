package doctor

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/celestia/clearerr"
	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

const (
	// maxHeadLag is how far the head may trail the clock before the chain is
	// called stalled; it is the lag the gate itself tolerates at start.
	maxHeadLag = node.DefaultMaxHeadLagS * time.Second

	// assumedBlobGas is the gas of one pay-for-blob or pay-for-fibre tx, used
	// to size the account balance. It is an estimate; the node's own price
	// decides the real fee.
	assumedBlobGas = 250_000
)

type chainCheck struct{ env *Env }

func (chainCheck) Name() string { return "chain" }

func (k chainCheck) Run(ctx context.Context, c config.Config) Result {
	ch, err := k.env.chainFor(ctx, c.Network)
	if err != nil {
		if errors.Is(err, ErrNotAvailable) {
			return fail("no chain probe in this run", "report this as a bug")
		}
		return fail(fmt.Sprintf("cannot open the node connections: %v", clearerr.Dial(c.Network.ConsensusGRPC.Addr, "", c.Network.ConsensusGRPC.TLS, err)),
			"check network.bridge and network.consensus_grpc")
	}
	want := c.Network.ChainID
	got, err := ch.ConsensusChainID(ctx)
	if err != nil {
		return fail(fmt.Sprintf("network.consensus_grpc: %v", clearerr.Dial(c.Network.ConsensusGRPC.Addr, "", c.Network.ConsensusGRPC.TLS, err)),
			"check network.consensus_grpc.addr and tls")
	}
	if got != want {
		return Result{Status: Fail, Cause: clearerr.WrongChain(c.Network.ConsensusGRPC.Addr, got, want).Error(),
			Fix: "point network.consensus_grpc at a node of " + want + ", or change network.celestia"}
	}
	head, err := ch.BridgeHead(ctx)
	if err != nil {
		return fail(fmt.Sprintf("network.bridge: %v", clearerr.Dial(c.Network.Bridge.Addr, "", c.Network.Bridge.TLS, err)), "check network.bridge.addr, tls and the token file")
	}
	if head.ChainID != want {
		return Result{Status: Fail, Cause: clearerr.WrongChain(c.Network.Bridge.Addr, head.ChainID, want).Error(),
			Fix: "point network.bridge at a bridge node of " + want}
	}
	lo, hi := uint64(node.DefaultMinAppVersion), uint64(node.DefaultMaxAppVersion)
	if c.Recorder != nil && c.Recorder.DA == config.DAFibre {
		lo, hi = node.FibreAppVersion, node.FibreAppVersion
	}
	if head.AppVersion < lo || head.AppVersion > hi {
		return fail(fmt.Sprintf("node app version %d is outside the pinned %d..%d", head.AppVersion, lo, hi),
			"use a node on a supported app version, or a binary built for this one")
	}
	lag := k.env.now().Sub(head.Time)
	if lag < 0 {
		lag = -lag
	}
	if lag > maxHeadLag {
		return fail(fmt.Sprintf("bridge head %d is %s off the local clock: the node is not moving or the clock is wrong", head.Height, lag.Round(time.Second)),
			"use a synced node; check the clock with the clock check")
	}
	if cons, err := ch.LatestHeight(ctx); err == nil && cons+10 < head.Height {
		return warn(fmt.Sprintf("consensus node at height %d is behind the bridge head %d", cons, head.Height), "use a consensus node that keeps up with the chain")
	}
	if msg := k.cometChainIDs(ctx, c); msg != "" {
		return fail(msg, "point network.comet_rpc at nodes of "+want)
	}
	return ok("%s at height %d, app version %d", got, head.Height, head.AppVersion)
}

func (k chainCheck) cometChainIDs(ctx context.Context, c config.Config) string {
	if k.env.Net == nil {
		return ""
	}
	for i, u := range c.Network.CometRPC {
		e, err := parseURLEndpoint("", u, epComet, false)
		if err != nil {
			continue
		}
		info, err := cometStatus(ctx, k.env.Net, e)
		if err != nil {
			continue // the endpoints check reports an unreachable RPC
		}
		if info.Network != c.Network.ChainID {
			return fmt.Sprintf("network.comet_rpc[%d]: %s", i, clearerr.WrongChain(u, info.Network, c.Network.ChainID))
		}
		if info.CatchingUp {
			return fmt.Sprintf("network.comet_rpc[%d] at %s is still catching up", i, u)
		}
	}
	return ""
}

// accountOf opens a file keyring non-interactively and returns the account
// address of its key. The error is already in plain words.
func (e *Env) accountOf(ctx context.Context, dir, name, passFile string) (string, error) {
	if e.Keyring == nil {
		return "", errNoProbe("keyring")
	}
	addr, err := e.Keyring.Address(ctx, dir, name, passFile)
	if err != nil {
		if errors.Is(err, node.ErrBadPassphrase) {
			return "", clearerr.KeyringPassphrase(passFile, name)
		}
		return "", err
	}
	return addr, nil
}

type fibreCheck struct{ env *Env }

func (fibreCheck) Name() string { return "fibre" }

func (k fibreCheck) Run(ctx context.Context, c config.Config) Result {
	r := c.Recorder
	if r == nil || r.DA != config.DAFibre {
		return ok("recorder.da is not fibre: Fibre is not used")
	}
	ch, err := k.env.chainFor(ctx, c.Network)
	if err != nil {
		return fail(fmt.Sprintf("cannot open the node connections: %v", err), "see the chain check")
	}
	params, err := ch.FibreParams(ctx)
	switch {
	case errors.Is(err, node.ErrNotFound):
		return fail("the chain has no x/fibre module", `use recorder.da = "celestia_blob", or a chain with Fibre`)
	case err != nil:
		return fail(fmt.Sprintf("x/fibre params unreadable: %v", err), "check network.consensus_grpc; the node must serve the fibre query")
	}
	addr, err := k.env.accountOf(ctx, r.KeyringDir, r.KeyName, r.PassphraseFile)
	if err != nil {
		return fail(fmt.Sprintf("cannot tell the Recorder account: %v", err), "see the keyring check")
	}
	esc, err := ch.Escrow(ctx, addr)
	if err != nil {
		return fail(fmt.Sprintf("escrow of %s unreadable: %v", addr, err), "check network.consensus_grpc")
	}
	need, err := EscrowNeed(r.MaxBlobBytes, r.EscrowHeadroomUtia)
	if err != nil {
		return fail(fmt.Sprintf("recorder.max_blob_bytes: %v", err), "lower recorder.max_blob_bytes")
	}
	if esc.AvailableUtia < need {
		return Result{Status: Fail, Cause: clearerr.EscrowLow(esc.AvailableUtia, need).Error(),
			Fix: fmt.Sprintf("deposit at least %d utia more into the Fibre escrow of %s", need-esc.AvailableUtia, addr)}
	}
	return ok("x/fibre readable (retention %ds); escrow %d utia covers %d utia", params.RetentionS, esc.AvailableUtia, need)
}

// EscrowNeed is what the escrow must hold for a Recorder: the cost of one
// upload of maxBlobBytes plus the configured headroom.
func EscrowNeed(maxBlobBytes, headroom uint64) (uint64, error) {
	us, err := fibrecommit.UploadSize(maxBlobBytes)
	if err != nil {
		return 0, err
	}
	cost := recorder.FibreCostUtia(us)
	if cost+headroom < cost {
		return 0, errors.New("headroom overflows")
	}
	return cost + headroom, nil
}

type feesCheck struct{ env *Env }

func (feesCheck) Name() string { return "fees" }

func (k feesCheck) Run(ctx context.Context, c config.Config) Result {
	ch, err := k.env.chainFor(ctx, c.Network)
	if err != nil {
		return fail(fmt.Sprintf("cannot open the node connections: %v", err), "see the chain check")
	}
	price, err := ch.MinGasPrice(ctx)
	if err != nil {
		return fail(fmt.Sprintf("the node's minimum gas price is unreadable: %v", err), "check network.consensus_grpc; fees are read from the node, never guessed")
	}
	perBlob := feeOf(price, assumedBlobGas)
	var notes []string
	var low []string
	type acct struct {
		label, dir, name, pass string
		perDay                 uint64
	}
	var accts []acct
	if r := c.Recorder; r != nil {
		accts = append(accts, acct{"recorder", r.KeyringDir, r.KeyName, r.PassphraseFile, r.BlobsPerDay})
	}
	if p := c.Publisher; p != nil {
		accts = append(accts, acct{"publisher", p.KeyringDir, p.KeyName, p.PassphraseFile, p.BlobsPerDay})
	}
	for _, a := range accts {
		addr, err := k.env.accountOf(ctx, a.dir, a.name, a.pass)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s balance not checked: %v", a.label, err))
			continue
		}
		bal, err := ch.Balance(ctx, addr, "utia")
		if err != nil {
			return fail(fmt.Sprintf("balance of %s unreadable: %v", addr, err), "check network.consensus_grpc")
		}
		need := satMul(perBlob, a.perDay)
		if bal < need {
			low = append(low, fmt.Sprintf("%s %s holds %d utia, one day of %d blobs needs about %d", a.label, addr, bal, a.perDay, need))
		}
	}
	switch {
	case len(low) > 0:
		return fail(strings.Join(low, "; "), "fund the address from the faucet or lower blobs_per_day")
	case len(notes) > 0:
		return warn(strings.Join(notes, "; "), "fix the keyring, then run doctor again")
	}
	return ok("minimum gas price %s utia/gas; balances cover one day", price.FloatString(6))
}

// feeOf is price times gas, rounded up.
func feeOf(price *big.Rat, gas uint64) uint64 {
	f := new(big.Rat).Mul(price, new(big.Rat).SetUint64(gas))
	q, m := new(big.Int).QuoRem(f.Num(), f.Denom(), new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() {
		return ^uint64(0) / 1_000_000
	}
	return q.Uint64()
}

func satMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}
