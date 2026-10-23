package doctor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/keyfile"
)

// The Ed25519 known answer of RFC 8032, test 1: a broken or swapped crypto
// library fails it before any real key is trusted.
const (
	katSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	katPub  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	katSig  = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)

func ed25519KnownAnswer() error {
	seed, _ := hex.DecodeString(katSeed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := hex.DecodeString(katPub)
	sig, _ := hex.DecodeString(katSig)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		return fmt.Errorf("public key derivation differs from the known answer")
	}
	if !bytes.Equal(ed25519.Sign(priv, nil), sig) || !ed25519.Verify(pub, nil, sig) {
		return fmt.Errorf("signature differs from the known answer")
	}
	return nil
}

// problems collects findings of a check; the worst one decides the status.
type problems struct {
	fails, warns, fixes []string
}

func (p *problems) fail(cause, fix string) {
	p.fails = append(p.fails, cause)
	p.fixes = append(p.fixes, fix)
}

func (p *problems) warn(cause, fix string) {
	p.warns = append(p.warns, cause)
	p.fixes = append(p.fixes, fix)
}

func (p *problems) result(okMsg string) Result {
	switch {
	case len(p.fails) > 0:
		return fail(strings.Join(append(p.fails, p.warns...), "; "), strings.Join(uniq(p.fixes), "; "))
	case len(p.warns) > 0:
		return warn(strings.Join(p.warns, "; "), strings.Join(uniq(p.fixes), "; "))
	}
	return ok("%s", okMsg)
}

type gateCheck struct{ env *Env }

func (gateCheck) Name() string { return "gate" }

func (k gateCheck) Run(_ context.Context, c config.Config) Result {
	g := c.Gate
	if g == nil {
		return ok("no gate configured")
	}
	var p problems
	if err := ed25519KnownAnswer(); err != nil {
		p.fail("Ed25519 known-answer check: "+err.Error(), "rebuild the binary; do not run a gate on this build")
		return p.result("")
	}
	gatePub, err := pubOfSeedFile(g.KeyFile, "gate")
	if err != nil {
		p.fail(err.Error(), "create the key with edicta init, or fix the mode to 0600 and the length to 32 bytes")
	}
	var agentPub ed25519.PublicKey
	if c.Agent != nil {
		if agentPub, err = pubOfSeedFile(c.Agent.KeyFile, "agent"); err != nil {
			p.fail(err.Error(), "create the key with edicta init, or fix the mode to 0600 and the length to 32 bytes")
		}
	}
	for i, hexKey := range g.ExecutorKeys {
		b, _ := hex.DecodeString(hexKey)
		switch {
		case gatePub != nil && bytes.Equal(b, gatePub):
			p.fail(fmt.Sprintf("gate.executor_keys[%d] is the gate's own key", i), "the executor and the gate are different roles: use the executor's own key")
		case agentPub != nil && bytes.Equal(b, agentPub):
			p.fail(fmt.Sprintf("gate.executor_keys[%d] is the agent's key", i), "the executor and the agent are different roles: use the executor's own key")
		}
	}
	if gatePub != nil && agentPub != nil && bytes.Equal(gatePub, agentPub) {
		p.fail("the gate and the agent use one key", "give each role its own key file")
	}
	k.allowlist(&p, g, c.Agent, agentPub)
	k.mandate(&p, c, agentPub)
	return p.result(fmt.Sprintf("gate key %s known-answer ok; allowlist and mandate checked", short(gatePub)))
}

func short(pub []byte) string {
	h := hex.EncodeToString(pub)
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}

func pubOfSeedFile(path, what string) (ed25519.PublicKey, error) {
	priv, err := keyfile.ReadSeed(path, what)
	if err != nil {
		return nil, err
	}
	defer clear(priv)
	pub := priv.Public().(ed25519.PublicKey)
	// A sign and verify round trip proves the key is usable, not just 32 bytes.
	msg := []byte("edicta doctor")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		return nil, fmt.Errorf("%s key does not sign", what)
	}
	return pub, nil
}

type agentsFile struct {
	Agents []struct {
		AgentID string `toml:"agent_id"`
		PubKey  string `toml:"pubkey"`
	} `toml:"agents"`
}

func (k gateCheck) allowlist(p *problems, g *config.Gate, a *config.Agent, agentPub ed25519.PublicKey) {
	data, err := os.ReadFile(g.AllowlistFile)
	if err != nil {
		p.fail(fmt.Sprintf("gate.allowlist_file: %v", err), "create the allowlist with edicta init, or point gate.allowlist_file at it")
		return
	}
	var f agentsFile
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&f); err != nil {
		p.fail("gate.allowlist_file is not [[agents]] with agent_id and pubkey", "fix the file; unknown keys are refused")
		return
	}
	if a == nil || agentPub == nil {
		return
	}
	for _, e := range f.Agents {
		if e.AgentID == a.ID {
			if !strings.EqualFold(e.PubKey, hex.EncodeToString(agentPub)) {
				p.fail(fmt.Sprintf("allowlist lists agent %s with another public key than agent.key_file", a.ID), "replace the pubkey in the allowlist with the agent's current public key")
			}
			return
		}
	}
	p.fail(fmt.Sprintf("agent %s is not in the allowlist", a.ID), "add agent_id and pubkey to gate.allowlist_file")
}

func (k gateCheck) mandate(p *problems, c config.Config, agentPub ed25519.PublicKey) {
	g := c.Gate
	if g.MandateFile == "" {
		if g.FastMode {
			p.fail("gate.fast_mode needs a mandate that allows it, and gate.mandate_file is empty", "set gate.mandate_file to a mandate with fast_mode_max_delay")
		}
		if g.Sessions {
			p.fail("gate.sessions needs a mandate with a session limit, and gate.mandate_file is empty", "set gate.mandate_file")
		}
		return
	}
	b, err := os.ReadFile(g.MandateFile)
	if err != nil {
		p.fail(fmt.Sprintf("gate.mandate_file: %v", err), "create the mandate with edicta init, or fix gate.mandate_file")
		return
	}
	sm, _, err := policy.VerifyMandate(b)
	if err != nil {
		p.fail(fmt.Sprintf("the mandate does not decode and verify: %v", err), "regenerate and sign the mandate")
		return
	}
	m := &sm.Mandate
	if m.GateID != g.GateID {
		p.fail(fmt.Sprintf("the mandate is bound to gate %q, not gate.gate_id %q", m.GateID, g.GateID), "sign a mandate for this gate_id")
	}
	if agentPub != nil && !m.Covers(agentPub) {
		p.fail("the mandate does not cover the agent's key", "sign a mandate that lists the agent's public key")
	}
	now := uint64(k.env.now().Unix())
	switch {
	case now < m.NotBefore:
		p.fail(fmt.Sprintf("the mandate starts at %s", time.Unix(int64(m.NotBefore), 0).UTC().Format(time.RFC3339)), "wait, or sign a mandate that is in force now")
	case now >= m.NotAfter:
		p.fail(fmt.Sprintf("the mandate expired at %s", time.Unix(int64(m.NotAfter), 0).UTC().Format(time.RFC3339)), "sign a new mandate version")
	case m.NotAfter-now < 24*3600:
		p.warn(fmt.Sprintf("the mandate expires in %s", (time.Duration(m.NotAfter-now)*time.Second).Round(time.Minute)), "sign a new mandate version soon")
	}
	if g.FastMode && m.FastModeMaxDelay == 0 {
		p.fail("gate.fast_mode is on but the mandate gives no fast_mode_max_delay: fast mode needs the principal's consent", "sign a mandate with fast_mode_max_delay, or turn gate.fast_mode off")
	}
	if g.Sessions {
		k.sessions(p, m)
	}
}

func (k gateCheck) sessions(p *problems, m *policy.Mandate) {
	s := k.env.Sessions
	if s == nil || !s.Supported() {
		p.fail("gate.sessions is on but this build has no sessions", "turn gate.sessions off, or use a build with sessions")
		return
	}
	delay, has := s.MaxDelay(m)
	min := s.MinPublishSlackBlocks() + 1
	switch {
	case !has:
		p.fail("gate.sessions is on but the mandate has no session_max_delay", "sign a mandate with session_max_delay")
	case delay < min:
		p.fail(fmt.Sprintf("session_max_delay %d is below MinPublishSlackBlocks + 1 = %d", delay, min), "sign a mandate with a larger session_max_delay")
	}
}
