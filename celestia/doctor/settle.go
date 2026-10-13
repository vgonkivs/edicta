package doctor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/principalsig"
)

// PayerAddress derives the 0x address of the secp256k1 payer key in a raw
// 32-byte file (mode 0600). It reuses the signer of principalsig, so the
// address rule is the one the principal keys already use.
func PayerAddress(path string) (string, error) {
	s, err := secret.FromFile(path)
	if err != nil {
		return "", err
	}
	defer s.Zero()
	return PayerAddressOf(s)
}

// PayerAddressOf derives the 0x address from a payer scalar. A key file of
// hex text is accepted as well as 32 raw bytes.
func PayerAddressOf(s secret.Secret) (string, error) {
	raw := s.Reveal()
	defer clear(raw)
	if len(raw) != 32 {
		h, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		clear(raw)
		if err != nil || len(h) != 32 {
			return "", errors.New("the payer key must be 32 bytes, raw or as 64 hex characters")
		}
		raw = h
	}
	sg, err := principalsig.NewSecp256k1Signer(principalsig.EIP712, raw, "")
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(sg.Principal()), nil
}

type signerCheck struct{ env *Env }

func (signerCheck) Name() string { return "signer" }

func (k signerCheck) Run(ctx context.Context, c config.Config) Result {
	s := c.Signer
	if s == nil {
		return ok("no signer configured")
	}
	var p problems
	var payer string
	if s.PayerBackend == config.BackendFile {
		addr, err := PayerAddress(s.PayerKeyFile)
		switch {
		case err != nil:
			p.fail(fmt.Sprintf("signer.payer_key_file: %v", err), "create the payer key with edicta init, mode 0600")
		case s.PayerAddress != "" && !strings.EqualFold(addr, s.PayerAddress):
			p.fail(fmt.Sprintf("signer.payer_address %s is not the address of the payer key, %s", s.PayerAddress, addr), "set signer.payer_address to "+addr+", or use the matching key file")
		default:
			payer = addr
		}
	}
	// The pins must equal the preset the settlement section names.
	if sp, err := k.env.presets().Settlement(c.Network.Settlement); err == nil && sp.EVMChainID != 0 {
		if s.PinnedChainID != sp.EVMChainID {
			p.fail(fmt.Sprintf("signer.pinned_chain_id %d is not the preset's %d", s.PinnedChainID, sp.EVMChainID), "set signer.pinned_chain_id to the preset's chain id")
		}
		if !strings.EqualFold(s.PinnedUSDC, sp.USDC.Address) {
			p.fail(fmt.Sprintf("signer.pinned_usdc %s is not the preset's %s", s.PinnedUSDC, sp.USDC.Address), "set signer.pinned_usdc to the preset's token")
		}
	}
	k.localGate(&p, c)
	if k.env.Signer != nil {
		info, err := k.env.Signer.Info(ctx, s.Listen)
		switch {
		case errors.Is(err, ErrNotAvailable):
			p.warn("the signer service is not running or not available in this build", "start the signer, then run doctor again")
		case err != nil:
			p.fail(fmt.Sprintf("the signer at %s is not reachable: %v", s.Listen, err), "start the signer, or fix signer.listen")
		default:
			k.compare(&p, s, info, payer)
		}
	} else {
		p.warn("the signer service was not probed", "run doctor with a signer probe")
	}
	return p.result(fmt.Sprintf("payer %s; pins equal the preset", payer))
}

// localGate compares the signer's pinned gate keys with the gate's own key
// when both run from this config.
func (k signerCheck) localGate(p *problems, c config.Config) {
	if c.Gate == nil {
		return
	}
	pub, err := pubOfSeedFile(c.Gate.KeyFile, "gate")
	if err != nil {
		return // the gate check reports it
	}
	want := hex.EncodeToString(pub)
	if !slices.ContainsFunc(c.Signer.PinnedGateKeys, func(s string) bool { return strings.EqualFold(s, want) }) {
		p.fail("signer.pinned_gate_keys does not contain this gate's public key "+want, "pin the gate's public key in signer.pinned_gate_keys")
		return
	}
	if len(c.Signer.PinnedGateKeys) > 1 {
		p.warn("signer.pinned_gate_keys pins more than the local gate", "remove pins of gates you do not run")
	}
}

func (k signerCheck) compare(p *problems, s *config.Signer, info SignerInfo, payer string) {
	norm := func(in []string) []string {
		out := make([]string, len(in))
		for i, x := range in {
			out[i] = strings.ToLower(x)
		}
		slices.Sort(out)
		return out
	}
	if !slices.Equal(norm(info.PinnedGateKeys), norm(s.PinnedGateKeys)) {
		p.fail("the running signer pins other gate keys than signer.pinned_gate_keys", "restart the signer with this config")
	}
	if info.ChainID != s.PinnedChainID || !strings.EqualFold(info.USDC, s.PinnedUSDC) {
		p.fail("the running signer pins another chain or token than the config", "restart the signer with this config")
	}
	if payer != "" && !strings.EqualFold(info.PayerAddress, payer) {
		p.fail(fmt.Sprintf("the signer's payer %s is not the address of the payer key, %s", info.PayerAddress, payer), "point the signer at the payer key file")
	}
}

// evmProviders returns the usable settlement RPCs and the findings about the
// rest.
func (e *Env) evmProviders(ctx context.Context, c config.Config) (good []string, bad []string, wrong []string) {
	for _, u := range c.Network.EVM.RPC {
		id, err := e.EVM.ChainID(ctx, u)
		switch {
		case err != nil:
			bad = append(bad, fmt.Sprintf("%s: %v", host(u), err))
		case id != c.Network.EVM.ChainID:
			wrong = append(wrong, fmt.Sprintf("%s answers chain %d, config expects %d", host(u), id, c.Network.EVM.ChainID))
		default:
			good = append(good, u)
		}
	}
	return good, bad, wrong
}

func host(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

type settlementCheck struct{ env *Env }

func (settlementCheck) Name() string { return "settlement" }

func (k settlementCheck) Run(ctx context.Context, c config.Config) Result {
	if c.Network.Settlement == config.SettlementNone {
		return ok("no settlement chain configured")
	}
	if k.env.EVM == nil {
		return fail("no settlement probe in this run", "report this as a bug")
	}
	good, bad, wrong := k.env.evmProviders(ctx, c)
	if len(wrong) > 0 {
		return fail(strings.Join(wrong, "; "), "point network.evm.rpc at providers of chain "+fmt.Sprint(c.Network.EVM.ChainID))
	}
	if len(good) == 0 {
		return fail("no settlement RPC answered: "+strings.Join(bad, "; "), "check network.evm.rpc; public RPCs are rate-limited, try again or add a provider")
	}
	hosts := map[string]bool{}
	for _, u := range good {
		hosts[host(u)] = true
	}
	if len(hosts) < 2 {
		return warn(fmt.Sprintf("only one settlement provider answers (%s): L1 results are single-source", host(good[0])),
			"add a second, independent provider to network.evm.rpc")
	}
	if len(bad) > 0 {
		return warn("some providers did not answer: "+strings.Join(bad, "; "), "replace or remove them")
	}
	return ok("%d providers answer chain %d", len(hosts), c.Network.EVM.ChainID)
}

type facilitatorCheck struct{ env *Env }

func (facilitatorCheck) Name() string { return "facilitator" }

func (k facilitatorCheck) Run(ctx context.Context, c config.Config) Result {
	e := c.Network.EVM
	if c.Network.Settlement == config.SettlementNone || e.FacilitatorURL == "" {
		return ok("no facilitator configured")
	}
	if k.env.Net == nil {
		return fail("no network probe in this run", "report this as a bug")
	}
	resp, err := k.env.Net.HTTPGet(ctx, strings.TrimSuffix(e.FacilitatorURL, "/")+"/supported")
	if err != nil {
		return fail(fmt.Sprintf("%s/supported: %v", e.FacilitatorURL, err), "check network.evm.facilitator_url")
	}
	if resp.Status != 200 {
		return fail(fmt.Sprintf("%s/supported answered HTTP %d", e.FacilitatorURL, resp.Status), "check network.evm.facilitator_url; the facilitator may be down")
	}
	var doc struct {
		Kinds []struct {
			Scheme  string `json:"scheme"`
			Network string `json:"network"`
		} `json:"kinds"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return fail("the facilitator's /supported is not the expected JSON", "check network.evm.facilitator_url")
	}
	for _, kd := range doc.Kinds {
		if kd.Scheme == "exact" && kd.Network == e.FacilitatorNetwork {
			return ok("lists exact on %s", e.FacilitatorNetwork)
		}
	}
	return fail(fmt.Sprintf("the facilitator does not list scheme exact on %s", e.FacilitatorNetwork),
		"use a facilitator that supports it, or change network.settlement")
}

type balancesCheck struct{ env *Env }

func (balancesCheck) Name() string { return "balances" }

func (k balancesCheck) Run(ctx context.Context, c config.Config) Result {
	s := c.Signer
	if s == nil || c.Network.Settlement == config.SettlementNone {
		return ok("no payer configured")
	}
	payer := s.PayerAddress
	if payer == "" && s.PayerBackend == config.BackendFile {
		a, err := PayerAddress(s.PayerKeyFile)
		if err != nil {
			return warn(fmt.Sprintf("payer address unknown: %v", err), "see the signer check")
		}
		payer = a
	}
	if payer == "" {
		return warn("payer address unknown", "set signer.payer_address")
	}
	if k.env.EVM == nil {
		return fail("no settlement probe in this run", "report this as a bug")
	}
	good, _, _ := k.env.evmProviders(ctx, c)
	var lastErr error
	for _, u := range good {
		bal, err := k.env.EVM.USDCBalance(ctx, u, c.Network.EVM.USDC.Address, payer)
		if err != nil {
			lastErr = err
			continue
		}
		if bal.Sign() == 0 {
			fix := "send USDC on " + c.Network.Settlement + " to " + payer + "; no ETH is needed, the facilitator pays gas"
			if sp, err := k.env.presets().Settlement(c.Network.Settlement); err == nil && sp.FaucetURL != "" {
				fix += "; testnet faucet: " + sp.FaucetURL
			}
			return warn("payer "+payer+" holds 0 USDC", fix)
		}
		return ok("payer %s holds %s USDC base units", payer, formatInt(bal))
	}
	if lastErr != nil {
		return warn("payer USDC balance unreadable: "+lastErr.Error(), "check network.evm.rpc")
	}
	return warn("no settlement RPC answered: the payer balance was not read", "see the settlement check")
}

func formatInt(b *big.Int) string { return b.String() }
