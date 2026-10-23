package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/vgonkivs/edicta/celestia/clearerr"
	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/internal/secret"
)

type epKind int

const (
	// epConnect only needs a transport connection.
	epConnect epKind = iota
	// epComet is a CometBFT RPC: it must answer /status.
	epComet
)

type endpoint struct {
	label    string
	raw      string
	kind     epKind
	host     string
	port     string
	tls      bool
	required bool
	// scheme is the one the config used: http, https or "" for host:port.
	scheme string
}

func (e endpoint) hostPort() string { return net.JoinHostPort(e.host, e.port) }

// parseURLEndpoint reads an http or https URL.
func parseURLEndpoint(label, raw string, kind epKind, required bool) (endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return endpoint{}, fmt.Errorf("%s: %q is not an http or https URL", label, clearerr.RedactURL(raw))
	}
	port := u.Port()
	tls := u.Scheme == "https"
	if port == "" {
		port = "80"
		if tls {
			port = "443"
		}
	}
	return endpoint{label: label, raw: raw, kind: kind, host: u.Hostname(), port: port, tls: tls, required: required, scheme: u.Scheme}, nil
}

// parseHostPort reads host:port with an optional scheme and a TLS flag.
func parseHostPort(label, raw string, tls bool, required bool) (endpoint, error) {
	scheme := ""
	addr := raw
	if s, rest, found := strings.Cut(raw, "://"); found {
		scheme, addr = s, rest
		switch s {
		case "https":
			tls = true
		case "http":
			tls = false
		default:
			return endpoint{}, fmt.Errorf("%s: scheme %q, want http or https", label, s)
		}
	}
	addr = strings.TrimSuffix(addr, "/")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
		if !tls {
			port = "80"
		}
	}
	if host == "" {
		return endpoint{}, fmt.Errorf("%s: %q has no host", label, clearerr.RedactURL(raw))
	}
	return endpoint{label: label, raw: raw, kind: epConnect, host: host, port: port, tls: tls, required: required, scheme: scheme}, nil
}

// endpointsOf lists every endpoint the config names. Config errors in an
// endpoint are returned separately: they are reported as failures.
func endpointsOf(c config.Config) ([]endpoint, []error) {
	var (
		out  []endpoint
		errs []error
		seen = map[string]bool{}
	)
	add := func(e endpoint, err error) {
		if err != nil {
			errs = append(errs, err)
			return
		}
		key := e.hostPort() + "|" + e.scheme + "|" + fmt.Sprint(e.kind, e.tls)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}
	n := c.Network
	if n.Bridge.Addr != "" {
		add(parseHostPort("network.bridge", n.Bridge.Addr, n.Bridge.TLS, true))
	}
	if n.ConsensusGRPC.Addr != "" {
		add(parseHostPort("network.consensus_grpc", n.ConsensusGRPC.Addr, n.ConsensusGRPC.TLS, true))
	}
	for i, u := range n.CometRPC {
		add(parseURLEndpoint(fmt.Sprintf("network.comet_rpc[%d]", i), u, epComet, i == 0))
	}
	for i, u := range n.EVM.RPC {
		add(parseURLEndpoint(fmt.Sprintf("network.evm.rpc[%d]", i), u, epConnect, false))
	}
	if n.EVM.FacilitatorURL != "" {
		add(parseURLEndpoint("network.evm.facilitator_url", n.EVM.FacilitatorURL, epConnect, true))
	}
	if c.Agent != nil {
		if c.Agent.RecorderURL != "" {
			add(parseURLEndpoint("agent.recorder_url", c.Agent.RecorderURL, epConnect, true))
		}
		if c.Agent.GateURL != "" {
			add(parseURLEndpoint("agent.gate_url", c.Agent.GateURL, epConnect, true))
		}
	}
	if c.Archive.URL != "" {
		add(parseURLEndpoint("archive.url", c.Archive.URL, epConnect, true))
	}
	for i, u := range c.Archive.MirrorURLs {
		add(parseURLEndpoint(fmt.Sprintf("archive.mirror_urls[%d]", i), u, epConnect, false))
	}
	if c.Capture != nil && c.Capture.CometRPC != "" {
		add(parseURLEndpoint("capture.comet_rpc", c.Capture.CometRPC, epComet, true))
	}
	if v := c.Verify; v != nil {
		if v.HeadersRPC != "" {
			add(parseURLEndpoint("verify.headers_rpc", v.HeadersRPC, epComet, true))
		}
		if v.TxRPC != "" {
			add(parseURLEndpoint("verify.tx_rpc", v.TxRPC, epComet, true))
		}
		for i, u := range v.CheckpointRPC {
			add(parseURLEndpoint(fmt.Sprintf("verify.checkpoint_rpc[%d]", i), u, epComet, false))
		}
		for i, u := range v.CrossCheckRPC {
			add(parseURLEndpoint(fmt.Sprintf("verify.cross_check_rpc[%d]", i), u, epComet, false))
		}
	}
	return out, errs
}

type endpointsCheck struct{ env *Env }

func (endpointsCheck) Name() string { return "endpoints" }

func (k endpointsCheck) Run(ctx context.Context, c config.Config) Result {
	if k.env.Net == nil {
		return fail("no network probe in this run", "report this as a bug")
	}
	eps, cfgErrs := endpointsOf(c)
	var failed, warned []string
	var fix []string
	for _, e := range cfgErrs {
		failed = append(failed, e.Error())
		fix = append(fix, "write the endpoint as an http or https URL")
	}
	reached := 0
	for _, e := range eps {
		err := k.probe(ctx, e)
		switch {
		case err == nil:
			reached++
		case e.required:
			failed = append(failed, fmt.Sprintf("%s: %v", e.label, err))
			fix = append(fix, fixFor(err))
		default:
			warned = append(warned, fmt.Sprintf("%s: %v", e.label, err))
		}
	}
	if msg, f := k.tokenFiles(c); msg != "" {
		failed = append(failed, msg)
		fix = append(fix, f)
	}
	if len(failed) == 0 {
		if msg, f := k.nodeLevel(ctx, c); msg != "" {
			failed = append(failed, msg)
			fix = append(fix, f)
		}
	}
	switch {
	case len(failed) > 0:
		return fail(strings.Join(failed, "; "), strings.Join(uniq(fix), "; "))
	case len(warned) > 0:
		return warn(strings.Join(warned, "; "), "optional endpoints are skipped when down; fix them to keep the redundancy")
	}
	return ok("%d endpoints reachable", reached)
}

func fixFor(err error) string {
	switch clearerr.KindOf(err) {
	case clearerr.KindScheme:
		return "correct the scheme or the tls flag as the message says"
	case clearerr.KindTLS:
		return "fix the certificate, or set tls = false for a local node"
	}
	return "check the address, the DNS name and the firewall"
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// probe resolves the host, connects (with TLS when the endpoint uses it) and
// for a CometBFT RPC reads /status.
func (k endpointsCheck) probe(ctx context.Context, e endpoint) error {
	n := k.env.Net
	if net.ParseIP(e.host) == nil {
		if addrs, err := n.LookupHost(ctx, e.host); err != nil || len(addrs) == 0 {
			return fmt.Errorf("DNS: cannot resolve %s", e.host)
		}
	}
	var err error
	if e.tls {
		err = n.DialTLS(ctx, e.hostPort(), e.host)
	} else {
		err = n.DialTCP(ctx, e.hostPort())
	}
	if err != nil {
		return clearerr.Dial(e.hostPort(), e.scheme, e.tls, err)
	}
	if e.kind != epComet {
		return nil
	}
	_, err = cometStatus(ctx, n, e)
	return err
}

type cometInfo struct {
	Network    string
	Height     uint64
	CatchingUp bool
}

// cometStatus reads /status of a CometBFT RPC.
func cometStatus(ctx context.Context, n Net, e endpoint) (cometInfo, error) {
	resp, err := n.HTTPGet(ctx, strings.TrimSuffix(e.raw, "/")+"/status")
	if err != nil {
		return cometInfo{}, clearerr.Dial(e.hostPort(), e.scheme, e.tls, err)
	}
	if resp.Status == 400 && strings.Contains(string(resp.Body), "HTTPS server") {
		return cometInfo{}, clearerr.Dial(e.hostPort(), e.scheme, e.tls, errors.New("Client sent an HTTP request to an HTTPS server"))
	}
	if resp.Status != 200 {
		return cometInfo{}, fmt.Errorf("/status answered HTTP %d, want a CometBFT RPC", resp.Status)
	}
	var doc struct {
		Result struct {
			NodeInfo struct {
				Network string `json:"network"`
			} `json:"node_info"`
			SyncInfo struct {
				Height     string `json:"latest_block_height"`
				CatchingUp bool   `json:"catching_up"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &doc); err != nil || doc.Result.NodeInfo.Network == "" {
		return cometInfo{}, errors.New("/status is not a CometBFT status document")
	}
	var h uint64
	_, _ = fmt.Sscan(doc.Result.SyncInfo.Height, &h)
	return cometInfo{Network: doc.Result.NodeInfo.Network, Height: h, CatchingUp: doc.Result.SyncInfo.CatchingUp}, nil
}

// tokenFiles checks that every token file the network section names opens.
func (k endpointsCheck) tokenFiles(c config.Config) (string, string) {
	for _, t := range []struct{ label, path string }{
		{"network.bridge.token_file", c.Network.Bridge.TokenFile},
		{"network.consensus_grpc.token_file", c.Network.ConsensusGRPC.TokenFile},
	} {
		if t.path == "" {
			continue
		}
		s, err := secret.FromFile(t.path)
		if err != nil {
			return fmt.Sprintf("%s: %v", t.label, err), "make the file readable by you only (chmod 600) and non-empty"
		}
		s.Zero()
	}
	return "", ""
}

// nodeLevel opens the gRPC and bridge connections of the config and asks
// each one a question, so a refused auth token shows up here.
func (k endpointsCheck) nodeLevel(ctx context.Context, c config.Config) (string, string) {
	ch, err := k.env.chainFor(ctx, c.Network)
	if err != nil {
		if errors.Is(err, ErrNotAvailable) {
			return "", ""
		}
		return fmt.Sprintf("node connection: %v", clearerr.Dial(c.Network.ConsensusGRPC.Addr, "", c.Network.ConsensusGRPC.TLS, err)),
			"check network.consensus_grpc and network.bridge, and their token files"
	}
	if _, err := ch.ConsensusChainID(ctx); err != nil {
		return fmt.Sprintf("network.consensus_grpc: gRPC: %v", clearerr.Dial(c.Network.ConsensusGRPC.Addr, "", c.Network.ConsensusGRPC.TLS, err)),
			"check network.consensus_grpc.addr and tls; a TLS endpoint needs tls = true"
	}
	if _, err := ch.BridgeHead(ctx); err != nil {
		if isAuthError(err) {
			return fmt.Sprintf("network.bridge: the bridge node rejected the auth token (%v)", clearerr.RedactErr(err, c.Network.Bridge.Addr)),
				"set network.bridge.token_file to a file with a valid bridge auth token"
		}
		return fmt.Sprintf("network.bridge: %v", clearerr.Dial(c.Network.Bridge.Addr, "", c.Network.Bridge.TLS, err)),
			"check network.bridge.addr and tls"
	}
	return "", ""
}

func isAuthError(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "401") || strings.Contains(s, "403") || strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "forbidden") || strings.Contains(s, "permission denied")
}
