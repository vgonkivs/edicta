package edictad_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

const testActionType = "application/vnd.edicta.test.v0+cbor"

var errArchiveDown = errors.New("archive down")

// faultStore wraps a real archive and fails or observes Put by record kind.
type faultStore struct {
	archive.Store
	mu   sync.Mutex
	fail map[archive.Kind]error
	hook map[archive.Kind]func()
	puts []archive.Kind
	recs []archive.Record
}

func newFaultStore(inner archive.Store) *faultStore {
	return &faultStore{Store: inner, fail: map[archive.Kind]error{}, hook: map[archive.Kind]func(){}}
}

func (f *faultStore) failKind(k archive.Kind, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.fail, k)
		return
	}
	f.fail[k] = err
}

func (f *faultStore) failAll(err error) {
	for _, k := range []archive.Kind{archive.KindDecision, archive.KindAuthorization, archive.KindRejection, archive.KindPayload, archive.KindEvidence} {
		f.failKind(k, err)
	}
}

func (f *faultStore) onPut(k archive.Kind, fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook[k] = fn
}

func (f *faultStore) putCount(k archive.Kind) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.puts {
		if p == k {
			n++
		}
	}
	return n
}

func (f *faultStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	f.mu.Lock()
	f.puts = append(f.puts, r.Kind())
	f.recs = append(f.recs, r)
	err, hook := f.fail[r.Kind()], f.hook[r.Kind()]
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return 0, err
	}
	return f.Store.Put(ctx, r)
}

func (f *faultStore) authorizationPuts() []*archive.AuthorizationRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*archive.AuthorizationRecord
	for _, r := range f.recs {
		if a, ok := r.(*archive.AuthorizationRecord); ok {
			out = append(out, a)
		}
	}
	return out
}

// withArchive opens a real filesystem archive in the configured directory and
// hands it to edictad wrapped in a faultStore.
func (e *env) withArchive() (*faultStore, *fsarchive.Store) {
	e.t.Helper()
	real, err := fsarchive.Open(e.path("archive"), map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(e.t, err)
	fs := newFaultStore(real)
	e.deps.Archive = fs
	return fs, real
}

// stage puts the blob of the decision template on the fake chain: a header
// before issuance, the blob with the real commitment and a proof for it.
func (e *env) stage() *commitment.Commitment {
	e.t.Helper()
	c := gatefix.Template(e.t)
	ref := c.PayloadRef
	hd := blockAt(ref.Height, 8)
	hd.Time = t0.Add(-1000 * time.Second)
	e.chain.AddHeader(hd)
	e.chain.AddBlob(ref.Height, node.Blob{Namespace: bytes.Clone(ref.Namespace), Data: gatefix.Blob(e.t), ShareVersion: 1,
		Signer: bytes.Clone(ref.Signer), Commitment: bytes.Clone(ref.Commitment)}, rootProof{root: hd.DataRoot})
	// A newer head keeps the compatibility check on a fresh block.
	head := blockAt(ref.Height+1, 8)
	e.chain.AddHeader(head)
	// The registry epoch must lie before every decision's issued_at.
	reg, err := boltreg.Open(e.path("registry.db"), uint64(t0.Unix())-3600)
	require.NoError(e.t, err)
	require.NoError(e.t, reg.Close())
	return c
}

// decision is a signed commitment for the staged blob and its action bytes.
type decision struct {
	env    []byte
	action []byte
	hash   commitment.Hash
	c      *commitment.Commitment
}

func (e *env) decision(base *commitment.Commitment, tag byte, mods ...func(*commitment.Commitment)) decision {
	return e.decisionAct(base, tag, []byte{0xa1, tag, 0x01, 0x02}, mods...)
}

// decisionAct commits to the given action bytes; mods run before signing.
func (e *env) decisionAct(base *commitment.Commitment, tag byte, action []byte, mods ...func(*commitment.Commitment)) decision {
	e.t.Helper()
	c := gatefix.Fresh(base, tag)
	sum, err := commitment.ActionHash(testActionType, action)
	require.NoError(e.t, err)
	c.AgentID, c.AgentPubKey = "agent-1", bytes.Clone(e.agentPub)
	c.Scope.GateID = "gate-test-1"
	c.Action.Type, c.Action.Hash = testActionType, sum[:]
	c.IssuedAt, c.ValidUntil = uint64(t0.Unix())-5, uint64(t0.Unix())+600
	for _, m := range mods {
		m(c)
	}
	b, h := gatefix.SignWith(e.t, e.agentPrv, c)
	return decision{env: b, action: action, hash: h, c: c}
}

func (d decision) sum() [32]byte { return sha256.Sum256(d.env) }

func (e *env) authorizeRaw(d decision) (int, string, []byte) {
	e.t.Helper()
	resp := post(e.t, e.srv, "/v0/authorize", "", authorizeBody(string(d.env), string(d.action)))
	var b bytes.Buffer
	_, err := b.ReadFrom(resp.Body)
	require.NoError(e.t, err)
	return resp.StatusCode, resp.Header.Get("Retry-After"), b.Bytes()
}

// authorizeStatus is authorizeRaw for goroutines: it never fails the test.
func (e *env) authorizeStatus(d decision) (int, error) {
	req, err := http.NewRequest(http.MethodPost, "http://"+e.srv.Addr()+"/v0/authorize",
		bytes.NewReader(authorizeBody(string(d.env), string(d.action))))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// registryKeys closes the server and lists the registry file.
func (e *env) registryKeys() []registry.Entry {
	e.t.Helper()
	require.NoError(e.t, e.srv.Shutdown(bg))
	reg, err := boltreg.Open(e.path("registry.db"), 1)
	require.NoError(e.t, err)
	defer reg.Close()
	out, err := reg.List(bg, nil, 100)
	require.NoError(e.t, err)
	return out
}

func removeFile(path string) error { return os.Remove(path) }
