package initcmd

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// WriteText prints what the run created or found and the addresses to fund.
// It prints public keys and addresses only.
func (r Result) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "home %s\n", r.Home)
	for _, k := range []Ed25519Key{r.Agent, r.Gate, r.Executor} {
		if k.Status == "" {
			continue
		}
		fmt.Fprintf(&b, "%-8s %-9s key %s  ed25519 %s\n", k.Status, k.Role, k.Path, hex.EncodeToString(k.Public))
	}
	for _, a := range []Account{r.Recorder, r.Publisher} {
		if a.Status == "" {
			continue
		}
		fmt.Fprintf(&b, "%-8s %-9s keyring %s (key %q, passphrase file %s)  %s\n", a.Status, a.Role, a.KeyringDir, a.KeyName, a.PassphraseFile, a.Address)
	}
	if r.Payer != nil {
		fmt.Fprintf(&b, "%-8s %-9s key %s  %s\n", r.Payer.Status, "payer", r.Payer.Path, r.Payer.Address)
	}
	if r.RecorderNamespace != "" {
		fmt.Fprintf(&b, "namespaces (new on every run until the config file records them): recorder %s, publisher %s\n", r.RecorderNamespace, r.PublisherNamespace)
	}

	var fund []string
	tia := "TIA on " + r.Network.ChainID
	if r.CelestiaFaucet != "" {
		tia += " (faucet: " + r.CelestiaFaucet + ")"
	}
	for _, a := range []Account{r.Recorder, r.Publisher} {
		if a.Address != "" {
			fund = append(fund, fmt.Sprintf("  %-9s %s  %s", a.Role, a.Address, tia))
		}
	}
	if r.Payer != nil && r.Payer.Address != "" {
		usdc := fmt.Sprintf("USDC on %s (chain %d)", r.Network.Settlement, r.Network.EVM.ChainID)
		if r.SettlementFaucet != "" {
			usdc += " (faucet: " + r.SettlementFaucet + ")"
		}
		fund = append(fund, fmt.Sprintf("  %-9s %s  %s; no ETH needed, the facilitator pays the gas", "payer", r.Payer.Address, usdc))
	}
	if len(fund) > 0 {
		b.WriteString("fund these addresses:\n")
		b.WriteString(strings.Join(fund, "\n"))
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
