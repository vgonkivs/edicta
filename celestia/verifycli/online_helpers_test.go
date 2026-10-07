package verifycli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/bankvec"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// serveArchive serves the scenario's archive directory over HTTP with the
// real handler; wrap may replace answers.
func (s *scenario) serveArchive(t *testing.T, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	ro, err := fsarchive.OpenReadOnly(s.archiveDir, map[commitment.DA]gate.DACommitter{
		commitment.DACelestiaBlob: blobv1.New(),
	})
	require.NoError(t, err)
	h := http.Handler(httparchive.NewHandler(ro))
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// hide answers the listed URL paths with a status and passes the rest on.
func hide(answers map[string]int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if code, ok := answers[r.URL.Path]; ok {
				w.WriteHeader(code)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *scenario) path(kind string) string { return "/" + kind + "/" + hex.EncodeToString(s.hash[:]) }

func (s *scenario) cometChain() *cometfake.Chain {
	return &cometfake.Chain{ChainID: chainID, Hdrs: s.chain.hdrs}
}

// forkAt is the scenario's chain with one header replaced, as a lying node
// would serve it.
func (s *scenario) forkAt(h uint64) *cometfake.Chain {
	hdrs := make(map[uint64]core.Header, len(s.chain.hdrs))
	for k, v := range s.chain.hdrs {
		hdrs[k] = v
	}
	hd := hdrs[h]
	hd.AppHash = filler("fork", h)
	hdrs[h] = hd
	return &cometfake.Chain{ChainID: chainID, Hdrs: hdrs}
}

// forkFrom is a different history from h on, relinked, so that its hashes
// at and above h differ from the real ones.
func (s *scenario) forkFrom(h uint64) *cometfake.Chain {
	hdrs := make(map[uint64]core.Header, len(s.chain.hdrs))
	for k, v := range s.chain.hdrs {
		hdrs[k] = v
	}
	before := hdrs[h-1]
	prev := before.Hash()
	for k := h; k <= checkpointH; k++ {
		hd := hdrs[k]
		hd.AppHash = filler("fork", k)
		hd.LastBlockID.Hash = prev
		hdrs[k] = hd
		prev = hd.Hash()
	}
	return &cometfake.Chain{ChainID: chainID, Hdrs: hdrs}
}

func (s *scenario) rpc(t *testing.T, c *cometfake.Chain, id string) *cometfake.Server {
	t.Helper()
	return cometfake.New(t, c, checkpointH, id)
}

func nodeID(n int) string {
	return hex.EncodeToString(sha256.New().Sum([]byte{byte(n)}))[:40]
}

func (s *scenario) onlineArgs(cmd string, archiveURL string, extra ...string) []string {
	a := []string{cmd, hex.EncodeToString(s.hash[:]), "--gate-key", s.gateKey, "--archive-url", archiveURL}
	return append(a, extra...)
}

func (s *scenario) explicitCheckpoint() string {
	return strconv.FormatUint(checkpointH, 10) + ":" + hex.EncodeToString(s.chain.hash(checkpointH))
}

// bank transaction and receipt

func (s *scenario) bankTx(t testing.TB, timeout uint64) []byte {
	t.Helper()
	var signed bankvec.Signed
	for _, x := range bankvec.Txs(t).Signed {
		if x.ID == "signed_minimal_mocha" {
			signed = x
		}
	}
	raw := bankvec.Hex(t, signed.TxRawHex)
	var auth, sig []byte
	for rest := raw; len(rest) > 0; {
		num, _, n := protowire.ConsumeTag(rest)
		rest = rest[n:]
		v, n := protowire.ConsumeBytes(rest)
		rest = rest[n:]
		switch num {
		case 2:
			auth = v
		case 3:
			sig = v
		}
	}
	body, err := bankaction.Body(s.msg, s.hash, timeout)
	require.NoError(t, err)
	field := func(num protowire.Number, b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), b)
	}
	var tx []byte
	for _, f := range [][]byte{field(1, body), field(2, auth), field(3, sig)} {
		tx = append(tx, f...)
	}
	return tx
}

func refOf(tx []byte) string {
	h := sha256.Sum256(tx)
	return hex.EncodeToString(h[:])
}

func (s *scenario) receipt(t testing.TB, railRef string) []byte {
	t.Helper()
	ek := gatefix.ExecutorKey(t, "executor1")
	req, err := commitment.RecordRequestMessage(s.hash, gatefix.GateID, railRef)
	require.NoError(t, err)
	gk := gatefix.Key(t, "gate1")
	r := commitment.Receipt{
		CommitmentHash:    append([]byte(nil), s.hash[:]...),
		GateID:            gatefix.GateID,
		GatePubKey:        gk.Public().(ed25519.PublicKey),
		RailRef:           railRef,
		RecordedAt:        authorizedAt + 5,
		ExecutorPubKey:    ek.Public().(ed25519.PublicKey),
		ExecutorSignature: ed25519.Sign(ek, req),
	}
	canon, err := commitment.EncodeReceipt(&r)
	require.NoError(t, err)
	h := commitment.HashReceipt(canon)
	b, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{
		Receipt:   r,
		Signature: ed25519.Sign(gk, commitment.ReceiptSigningMessage(h)),
	})
	require.NoError(t, err)
	return b
}

func writeReceipt(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "receipt.cbor")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

func (s *scenario) commitmentBytes(t testing.TB) []byte {
	t.Helper()
	return gatefix.Template(t).PayloadRef.Commitment
}
