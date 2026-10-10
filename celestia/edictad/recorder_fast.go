package edictad

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

// defaultFastTimeoutBlocks is the recorder's own default, repeated here so the
// configuration can be checked against the gate's bounds before start.
const defaultFastTimeoutBlocks = 100

// fastBlobCloseTimeoutS bounds the shutdown wait for the confirmation loops of
// a celestia_blob fast Recorder; one loop step is bounded by the recorder.
const fastBlobCloseTimeoutS = 30

func (r RecorderConfig) hasFastKeys() bool {
	return r.Fast || r.FastTimeoutBlocks != 0 || r.FastDedicatedAccount || r.FastUploadAddr != "" || r.FastEscrowHeadroomUtia != 0
}

func (r RecorderConfig) withFastDefaults(da string) RecorderConfig {
	if r.Fast && da == DAConfigBlob && r.FastTimeoutBlocks == 0 {
		r.FastTimeoutBlocks = defaultFastTimeoutBlocks
	}
	return r
}

// validateRecorderFast checks the fast keys of [recorder]. Off, every one of
// them must stay zero, so a half-switched file never starts.
func (c Config) validateRecorderFast() error {
	r := c.Recorder
	if !r.Fast {
		if r.hasFastKeys() {
			return cfgErr("recorder.fast_timeout_blocks, fast_dedicated_account, fast_upload_addr and fast_escrow_headroom_utia need recorder.fast")
		}
		return nil
	}
	if !r.Enabled {
		return cfgErr("recorder.fast needs recorder.enabled")
	}
	// The pending references this Recorder returns are only of use to a gate
	// that accepts them, and the fast gate is what attests the consensus
	// endpoint the anchor txs go through is the operator's own node.
	if !c.Gate.Fast.Enabled {
		return cfgErr("recorder.fast needs gate.fast.enabled: the anchor txs go out through the operator's own node, and this gate must accept the pending references")
	}
	ns, err := r.namespace()
	if err != nil {
		return err
	}
	pending, err := c.Gate.Fast.namespaces()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(pending, func(p []byte) bool { return bytes.Equal(p, ns) }) {
		return cfgErr("recorder.fast needs recorder.namespace in gate.fast.pending_namespaces")
	}
	if !r.FastDedicatedAccount {
		return cfgErr("recorder.fast_dedicated_account must be true: the account of recorder.key_name must sign nothing but this Recorder's anchor txs; any other sender on it (another process, a strict Recorder, an executor, manual txs) makes pending references stale")
	}
	if c.Network.DA == DAConfigFibre {
		return c.validateRecorderFastFibre()
	}
	if r.FastUploadAddr != "" || r.FastEscrowHeadroomUtia != 0 {
		return cfgErr(`recorder.fast_upload_addr and fast_escrow_headroom_utia need network.da = "fibre"`)
	}
	rc := recorder.Config{Namespace: ns, FastTimeoutBlocks: r.FastTimeoutBlocks}
	if err := rc.ValidateBasic(); err != nil {
		return cfgErr("recorder.fast_timeout_blocks: %v", err)
	}
	f := c.Gate.Fast
	if r.FastTimeoutBlocks <= f.MaxH0AgeBlocks+f.MinFastSlackBlocks {
		return cfgErr("recorder.fast_timeout_blocks must exceed gate.fast.max_h0_age_blocks + gate.fast.min_fast_slack_blocks, or the gate refuses every pending reference for lack of slack")
	}
	return nil
}

func (c Config) validateRecorderFastFibre() error {
	r := c.Recorder
	if r.FastTimeoutBlocks != 0 {
		return cfgErr(`recorder.fast_timeout_blocks does not apply to da = "fibre": the promise height window bounds the anchor`)
	}
	if r.FastUploadAddr == "" {
		return cfgErr(`recorder.fast_upload_addr is required with recorder.fast and da = "fibre"`)
	}
	// The uploader is dialled with the consensus endpoint's token, so another
	// address is refused before anything is dialled.
	if normAddr(r.FastUploadAddr) != normAddr(c.Network.ConsensusGRPC.Addr) {
		return cfgErr("recorder.fast_upload_addr must be network.consensus_grpc.addr: promises are uploaded through the node the Recorder reads and broadcasts through")
	}
	need, err := oneUploadCost(r.maxBlob())
	if err != nil {
		return cfgErr("recorder.max_blob_bytes: %v", err)
	}
	if r.FastEscrowHeadroomUtia < need {
		return cfgErr("recorder.fast_escrow_headroom_utia must be at least %d utia, the cost of one upload of recorder.max_blob_bytes: escrow reservations are lost on restart while earlier promises can still be charged", need)
	}
	return nil
}

// oneUploadCost is what the escrow pays for one upload of n bytes.
func oneUploadCost(n uint64) (uint64, error) {
	us, err := fibrecommit.UploadSize(n)
	if err != nil {
		return 0, err
	}
	return recorder.FibreCostUtia(us), nil
}

// escrowMargin is what a fibre Recorder keeps in the escrow beyond the cost of
// an upload: the configured margin plus, in fast mode, the headroom for the
// promises of an earlier process that may still be charged.
func (r RecorderConfig) escrowMargin() uint64 {
	m := r.EscrowMarginUtia
	if r.Fast {
		if m+r.FastEscrowHeadroomUtia < m {
			return ^uint64(0)
		}
		m += r.FastEscrowHeadroomUtia
	}
	return m
}

func normAddr(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// sameAccount requires the anchor signer to be the account whose escrow pays
// for the promises: the uploader signs them with that key, and the escrow
// checks read that account.
func sameAccount(ctx context.Context, s node.AnchorSigner, escrowOwner []byte) error {
	a, err := s.Address(ctx)
	if err != nil {
		return fmt.Errorf("edictad: anchor signer: %w", err)
	}
	if !bytes.Equal(a, escrowOwner) {
		return cfgErr("the anchor signer is not the account of the fibre submitter: both must be recorder.key_name")
	}
	return nil
}

// recorderIsNotPrincipal refuses a mandate whose principal is the Recorder's
// own secp256k1 key. The key is compared, not the (sig_type, bytes) pair: one
// private key signing anchors and mandates is the hazard whether the mandate
// names it as a Cosmos key or as the Ethereum address of the same point. A
// signer that cannot show its key cannot be cleared against an Ethereum
// principal, so that is refused too.
func recorderIsNotPrincipal(ctx context.Context, s node.AnchorSigner, m *policy.Mandate) error {
	scheme, err := m.Scheme()
	if err != nil {
		return err
	}
	var pub []byte
	if pk, ok := s.(node.AnchorPublicKey); ok {
		if pub, err = pk.PublicKey(ctx); err != nil {
			return fmt.Errorf("edictad: anchor signer public key: %w", err)
		}
		if err := shownKeyIsTheAccount(ctx, s, pub); err != nil {
			return err
		}
	}
	if scheme == principalsig.Ed25519 {
		return nil
	}
	same := false
	switch scheme {
	case principalsig.CosmosADR036:
		principal, err := principalsig.CosmosAddress(m.Principal, m.PrincipalHRP)
		if err != nil {
			return fmt.Errorf("edictad: mandate principal: %w", err)
		}
		if pub != nil {
			own, err := principalsig.CosmosAddress(pub, m.PrincipalHRP)
			if err != nil {
				return fmt.Errorf("edictad: anchor signer public key: %w", err)
			}
			same = own == principal
		} else {
			addr, err := s.Address(ctx)
			if err != nil {
				return fmt.Errorf("edictad: anchor signer: %w", err)
			}
			_, a, err := principalsig.ParseCosmosAddress(principal)
			if err != nil {
				return fmt.Errorf("edictad: mandate principal: %w", err)
			}
			same = bytes.Equal(a[:], addr)
		}
	case principalsig.EIP712:
		if pub == nil {
			return cfgErr("recorder.fast: the anchor signer does not show its public key, so it cannot be told apart from the mandate's eip712 principal")
		}
		own, err := principalsig.EthereumAddress(pub)
		if err != nil {
			return fmt.Errorf("edictad: anchor signer public key: %w", err)
		}
		same = bytes.Equal(own[:], m.Principal)
	}
	if same {
		return cfgErr("the recorder key is the mandate's %s principal; the Recorder and the principal must hold different keys", scheme)
	}
	return nil
}

// shownKeyIsTheAccount refuses an injected signer whose shown key is not a
// compressed secp256k1 key of its own account: the principal check compares
// that key, so it must be the one that signs.
func shownKeyIsTheAccount(ctx context.Context, s node.AnchorSigner, pub []byte) error {
	bech, err := principalsig.CosmosAddress(pub, "celestia")
	if err != nil {
		return cfgErr("recorder.fast: the anchor signer's public key is not a compressed secp256k1 key: %v", err)
	}
	_, own, err := principalsig.ParseCosmosAddress(bech)
	if err != nil {
		return fmt.Errorf("edictad: anchor signer public key: %w", err)
	}
	addr, err := s.Address(ctx)
	if err != nil {
		return fmt.Errorf("edictad: anchor signer: %w", err)
	}
	if !bytes.Equal(own[:], addr) {
		return cfgErr("recorder.fast: the anchor signer's public key is not the key of its account")
	}
	return nil
}

// logRecorderFast names the account and the bounds of fast mode, never a key.
func logRecorderFast(log *slog.Logger, cfg Config, account []byte) {
	attrs := []any{"account", hex.EncodeToString(account), "da", cfg.Network.DA}
	if cfg.Network.DA == DAConfigFibre {
		attrs = append(attrs, "escrow_headroom_utia", cfg.Recorder.FastEscrowHeadroomUtia)
	} else {
		attrs = append(attrs, "fast_timeout_blocks", cfg.Recorder.FastTimeoutBlocks)
	}
	log.Info("edictad: recorder fast mode on; this account must sign nothing else", attrs...)
}
