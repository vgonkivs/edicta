package edictad

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// IntentSourceArchive is the one source of anchor intents: the archive the
// Recorder writes them to before it broadcasts.
const IntentSourceArchive = "archive"

// FastConfig is the optional [gate.fast] table. Enabled, the gate authorizes
// a pending payload reference on its archived anchor intent, before the
// anchor lands. Off, every key must stay zero, so a half-switched file never
// starts.
type FastConfig struct {
	Enabled bool `toml:"enabled"`
	// IntentSource is where anchor intents are read; only "archive".
	IntentSource string `toml:"intent_source"`
	// OwnNode attests that the consensus endpoint is the operator's own. The
	// gate looks intents up and broadcasts them there, and a node that lies
	// about mempool acceptance is equivalent to the gate lying.
	OwnNode bool `toml:"own_node"`
	// PendingNamespaces are hex, 29 bytes each: the namespaces a pending
	// reference may name.
	PendingNamespaces      []string `toml:"pending_namespaces"`
	FastWindowBlocks       uint64   `toml:"fast_window_blocks"`
	MaxH0AgeBlocks         uint64   `toml:"max_h0_age_blocks"`
	MinFastSlackBlocks     uint64   `toml:"min_fast_slack_blocks"`
	MinPromiseSlackSeconds uint64   `toml:"min_promise_slack_seconds"`
	// RebroadcastIntent re-sends a da = 1 intent; absent means true.
	RebroadcastIntent *bool `toml:"rebroadcast_intent"`
}

func (f FastConfig) isZero() bool {
	return !f.Enabled && f.IntentSource == "" && !f.OwnNode && len(f.PendingNamespaces) == 0 &&
		f.FastWindowBlocks == 0 && f.MaxH0AgeBlocks == 0 && f.MinFastSlackBlocks == 0 &&
		f.MinPromiseSlackSeconds == 0 && f.RebroadcastIntent == nil
}

// WithDefaults fills the zero keys of an enabled table with the gate's
// defaults; a disabled table is left as is.
func (f FastConfig) WithDefaults() FastConfig {
	if !f.Enabled {
		return f
	}
	d := gate.DefaultConfig()
	if f.IntentSource == "" {
		f.IntentSource = IntentSourceArchive
	}
	if f.FastWindowBlocks == 0 {
		f.FastWindowBlocks = d.FastWindowBlocks
	}
	if f.MaxH0AgeBlocks == 0 {
		f.MaxH0AgeBlocks = d.MaxH0AgeBlocks
	}
	if f.MinFastSlackBlocks == 0 {
		f.MinFastSlackBlocks = d.MinFastSlackBlocks
	}
	if f.MinPromiseSlackSeconds == 0 {
		f.MinPromiseSlackSeconds = d.MinPromiseSlackSeconds
	}
	return f
}

func (f FastConfig) namespaces() ([][]byte, error) {
	out := make([][]byte, 0, len(f.PendingNamespaces))
	for i, s := range f.PendingNamespaces {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 29 {
			return nil, cfgErr("gate.fast.pending_namespaces[%d] must be 58 hex characters", i)
		}
		if slices.ContainsFunc(out, func(o []byte) bool { return bytes.Equal(o, b) }) {
			return nil, cfgErr("gate.fast.pending_namespaces[%d] is a duplicate", i)
		}
		out = append(out, b)
	}
	return out, nil
}

// applyTo copies the table into the gate configuration.
func (f FastConfig) applyTo(g *gate.Config) error {
	if !f.Enabled {
		return nil
	}
	ns, err := f.namespaces()
	if err != nil {
		return err
	}
	g.FastMode = true
	g.PendingNamespaces = ns
	g.FastWindowBlocks = f.FastWindowBlocks
	g.MaxH0AgeBlocks = f.MaxH0AgeBlocks
	g.MinFastSlackBlocks = f.MinFastSlackBlocks
	g.MinPromiseSlackSeconds = f.MinPromiseSlackSeconds
	if f.RebroadcastIntent != nil {
		v := *f.RebroadcastIntent
		g.RebroadcastIntent = &v
	}
	return nil
}

// validateFastNeeds runs before the archive table is checked, so that a
// fast-mode file without an archive is refused for that reason by name.
func (c Config) validateFastNeeds() error {
	f := c.Gate.Fast
	if !f.Enabled {
		if !f.isZero() {
			return cfgErr("the [gate.fast] keys need gate.fast.enabled")
		}
		return nil
	}
	if c.Archive.Dir == "" {
		return cfgErr("gate.fast.enabled needs the archive: archive.dir is required")
	}
	if !c.Policy.Enabled() {
		return cfgErr("gate.fast.enabled needs a mandate: policy.mandate_file is required")
	}
	return nil
}

// validateFast checks an enabled table, the gate's bounds included, once the
// gate table itself is valid.
func (c Config) validateFast() error {
	f := c.Gate.Fast
	if !f.Enabled {
		return nil
	}
	if f.IntentSource != IntentSourceArchive {
		return cfgErr("gate.fast.intent_source must be archive")
	}
	if !f.OwnNode {
		return cfgErr("gate.fast.own_node must be true: the gate looks anchor intents up and broadcasts them only through the operator's own consensus node")
	}
	if len(f.PendingNamespaces) == 0 {
		return cfgErr("gate.fast.pending_namespaces is empty")
	}
	if f.RebroadcastIntent != nil && !*f.RebroadcastIntent && c.Network.DA != DAConfigFibre {
		return cfgErr(`gate.fast.rebroadcast_intent applies to da = "fibre" only: with celestia_blob the gate always looks the intent up and broadcasts it`)
	}
	g := gate.DefaultConfig()
	g.Scope = commitment.GateScope{GateID: c.Gate.GateID, ActionTypes: slices.Clone(c.Gate.ActionTypes)}
	if err := f.applyTo(&g); err != nil {
		return err
	}
	if err := g.ValidateBasic(); err != nil {
		return cfgErr("gate.fast: %v", err)
	}
	return nil
}

// intentReader refuses a store that cannot serve anchor intents: fast mode
// would otherwise answer every pending reference with an unavailable intent.
func intentReader(store archive.Store) (archive.IntentReader, error) {
	ir, ok := store.(archive.IntentReader)
	if !ok || isNil(ir) {
		return nil, cfgErr("gate.fast.enabled needs an archive store that serves anchor intents; this one cannot")
	}
	return ir, nil
}

// fastDeps fills the stage K-fast dependencies of the gate: intents from the
// archive, a verifier for the one da of this instance, and the broadcaster on
// the operator's own consensus node.
func fastDeps(cfg Config, d Deps, store archive.Store, chainID string, gd *gate.Deps) error {
	ir, err := intentReader(store)
	if err != nil {
		return err
	}
	var v gate.IntentVerifier
	if cfg.DA() == commitment.DAFibre {
		v, err = gatechain.NewFibreIntents(fibreIntentChain{FibreChainReader: d.Fibre.Chain, cons: d.Consensus}, chainID)
	} else {
		v, err = gatechain.NewBlobIntents(d.Reader)
	}
	if err != nil {
		return fmt.Errorf("edictad: intent verifier: %w", err)
	}
	b, err := gatechain.NewBroadcaster(d.Consensus)
	if err != nil {
		return fmt.Errorf("edictad: intent broadcaster: %w", err)
	}
	gd.Intents = archive.NewIntentSource(ir)
	gd.IntentVerifiers = map[commitment.DA]gate.IntentVerifier{cfg.DA(): v}
	gd.Broadcaster = b
	return nil
}

// fibreIntentChain reads the da = 1 intent evidence: blocks from the Fibre
// chain reader, the head and the x/fibre parameters from the consensus
// client. Both are the same consensus endpoint.
type fibreIntentChain struct {
	node.FibreChainReader
	cons node.Consensus
}

func (c fibreIntentChain) LatestHeight(ctx context.Context) (uint64, error) {
	return c.cons.LatestHeight(ctx)
}

func (c fibreIntentChain) FibreParamsAt(ctx context.Context, height uint64) (node.FibreParams, error) {
	return c.cons.FibreParamsAt(ctx, height)
}
