package edictaapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

const window = skewVec + 300*time.Second

func (e *env) rebuild() {
	var p sdk.Publisher
	if e.pub != nil {
		p = e.pub
	}
	e.h = edictaapi.NewHandler(e.gate, p, e.allow, e.quota, e.health, e.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func statusOf(t testing.TB, code string) (int, bool) {
	for _, r := range loadErrVectors(t).Errors {
		if r.Code == code {
			return int(u64(t, r.Status)), r.Retryable == "1"
		}
	}
	t.Fatalf("no row for %s", code)
	return 0, false
}

func TestPublishMessageVectors(t *testing.T) {
	pv := loadPubVectors(t)
	for _, c := range pv.Cases {
		t.Run(c.ID, func(t *testing.T) {
			blob := c.blob(t)
			require.Equal(t, c.BlobSHA, hex.EncodeToString(sha(blob)))
			msg, err := edictaapi.PublishMessage(pv.Server.GateID, c.AgentID, u64(t, c.RequestedAt), blob)
			require.NoError(t, err)
			require.Equal(t, c.MessageHex, hex.EncodeToString(msg))
			require.GreaterOrEqual(t, len(msg), 70)
			require.LessOrEqual(t, len(msg), 196)
			key := unhex(t, pv.Server.Allowlist[c.AgentID])
			require.True(t, ed25519.Verify(key, msg, unhex(t, c.SigHex)))
			if c.RequestSHA != "" {
				sum := sha256.Sum256(c.request(t))
				require.Equal(t, c.RequestSHA, hex.EncodeToString(sum[:]))
			}
		})
	}
}

func TestPublishMessageRejectsBadInputs(t *testing.T) {
	blob := []byte("b")
	for name, c := range map[string]struct {
		gate, agent string
		at          uint64
	}{
		"empty agent":   {"g", "", 1},
		"agent 65":      {"g", strings.Repeat("a", 65), 1},
		"agent charset": {"g", "agent id", 1},
		"empty gate":    {"", "a", 1},
		"gate 65":       {strings.Repeat("g", 65), "a", 1},
		"at zero":       {"g", "a", 0},
		"at 2^63":       {"g", "a", 1 << 63},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := edictaapi.PublishMessage(c.gate, c.agent, c.at, blob)
			require.Error(t, err)
		})
	}
	msgA, err := edictaapi.PublishMessage("g", "a", 1, blob)
	require.NoError(t, err)
	msgB, err := edictaapi.PublishMessage("h", "a", 1, blob)
	require.NoError(t, err)
	require.NotEqual(t, msgA, msgB, "the server's gate_id is bound into the message")
	require.Equal(t, byte(0x19), msgA[0])
}

func TestPublishAcceptedVectors(t *testing.T) {
	pv := loadPubVectors(t)
	for _, c := range pv.Cases {
		t.Run(c.ID, func(t *testing.T) {
			e := newEnv(t, nil)
			var want []byte
			e.pub.result, want = testRef(t)
			blob := c.blob(t)
			rec := e.post("/v0/publish", c.request(t))
			require.Equal(t, 200, rec.Code, "%x", rec.Body.Bytes())
			require.Equal(t, cborType, rec.Header().Get("Content-Type"))
			require.Equal(t, want, rec.Body.Bytes())
			require.Equal(t, 1, e.pub.count())
			require.Equal(t, blob, e.pub.blobs[0], "blob is published byte-exact")
			require.Equal(t, 1, e.fq.count())
			require.Equal(t, []string{c.AgentID}, e.fq.seen)
		})
	}
}

func TestPublishRejectVectors(t *testing.T) {
	pv := loadPubVectors(t)
	for _, c := range pv.Reject {
		t.Run(c.ID, func(t *testing.T) {
			var allow map[string]string
			if c.Server != nil && c.Server.Allowlist != nil {
				allow = c.Server.Allowlist
			}
			e := newEnv(t, allow)
			if c.Server != nil && c.Server.MaxBlobBytes != "" {
				e.cfg.MaxBlobBytes = u64(t, c.Server.MaxBlobBytes)
				e.rebuild()
			}
			status, retry := statusOf(t, c.Expect)
			requireErr(t, e.post("/v0/publish", c.request(t)), status, c.Expect, retry)
			require.Zero(t, e.pub.count(), "nothing is submitted")
			require.Zero(t, e.fq.count(), "nothing is charged")
		})
	}
}

func TestDecodePublishRequestVectors(t *testing.T) {
	pv := loadPubVectors(t)
	for _, c := range pv.Cases {
		if c.RequestHex == "" {
			continue
		}
		t.Run("accept/"+c.ID, func(t *testing.T) {
			raw := c.request(t)
			req, err := edictaapi.DecodePublishRequest(raw, maxBlobVec)
			require.NoError(t, err)
			require.Equal(t, c.blob(t), req.Blob)
			require.Equal(t, c.AgentID, req.AgentID)
			require.Equal(t, u64(t, c.RequestedAt), req.RequestedAt)
			require.Equal(t, unhex(t, c.SigHex), req.Signature)
			again, err := edictaapi.EncodePublishRequest(req)
			require.NoError(t, err)
			require.Equal(t, raw, again, "round trip is byte-exact")
		})
	}
	for _, c := range pv.Reject {
		if c.Rule != "PR1" && c.Rule != "PR2" {
			continue
		}
		t.Run("reject/"+c.ID, func(t *testing.T) {
			max := maxBlobVec
			if c.Server != nil && c.Server.MaxBlobBytes != "" {
				max = u64(t, c.Server.MaxBlobBytes)
			}
			_, err := edictaapi.DecodePublishRequest(c.request(t), max)
			want, ok := sentinelFor(c.Expect)
			require.True(t, ok)
			require.ErrorIs(t, err, want)
		})
	}
}

func TestPublishUnknownAgentEqualsBadSignature(t *testing.T) {
	sk, pubHex := testKey(1)
	other, _ := testKey(2)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	blob := []byte("some blob")
	unknown := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-zzz", sk, nowVec, blob))
	badSig := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", other, nowVec, blob))
	requireErr(t, unknown, 401, "edictaapi.ErrPublishSignature", false)
	requireErr(t, badSig, 401, "edictaapi.ErrPublishSignature", false)
	require.Equal(t, unknown.Body.Bytes(), badSig.Body.Bytes(), "no allowlist oracle: identical bodies")
	require.Equal(t, unknown.Header(), badSig.Header())
	require.Zero(t, e.pub.count())
}

func TestPublishSignatureBoundToServerGateID(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	rec := e.post("/v0/publish", signedPublish(t, "other-gate", "agent-a", sk, nowVec, []byte("b")))
	requireErr(t, rec, 401, "edictaapi.ErrPublishSignature", false)
	rec = e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("b")))
	require.Equal(t, 200, rec.Code)
}

func TestPublishGateKeyAsAgentKeyRefused(t *testing.T) {
	sk, pubHex := testKey(9)
	e := newEnv(t, map[string]string{"agent-g": pubHex})
	e.cfg.GateKeys = append(e.cfg.GateKeys, sk.Public().(ed25519.PublicKey))
	e.rebuild()
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-g", sk, nowVec, []byte("b")))
	requireErr(t, rec, 403, "ErrAgentKeyIsGateKey", false)
	require.Zero(t, e.pub.count())
	require.Zero(t, e.fq.count())
}

func TestPublishStaleWindow(t *testing.T) {
	sk, pubHex := testKey(1)
	w := uint64(window / time.Second)
	require.Equal(t, uint64(330), w)
	cases := []struct {
		name string
		at   uint64
		ok   bool
	}{
		{"past edge", nowVec - w, true},
		{"past edge +1", nowVec - w - 1, false},
		{"future edge", nowVec + w, true},
		{"future edge +1", nowVec + w + 1, false},
		{"now", nowVec, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, map[string]string{"agent-a": pubHex})
			rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, c.at, []byte("blob")))
			if c.ok {
				require.Equal(t, 200, rec.Code)
				return
			}
			requireErr(t, rec, 410, "edictaapi.ErrPublishStale", false)
			require.Zero(t, e.pub.count())
			require.Zero(t, e.fq.count(), "stale requests are not charged")
		})
	}
	t.Run("stale precedes quota", func(t *testing.T) {
		e := newEnv(t, map[string]string{"agent-a": pubHex})
		e.fq.err = edictaapi.ErrQuotaExceeded
		rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec-w-1, []byte("b")))
		requireErr(t, rec, 410, "edictaapi.ErrPublishStale", false)
	})
}

func TestPublishDedupeByBlobHash(t *testing.T) {
	skA, pubA := testKey(1)
	skB, pubB := testKey(2)
	e := newEnv(t, map[string]string{"agent-a": pubA, "agent-b": pubB})
	e.pub.result, _ = testRef(t)
	blob := []byte("one blob, many requests")

	first := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec, blob))
	require.Equal(t, 200, first.Code)
	retry := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec+5, blob))
	require.Equal(t, 200, retry.Code)
	require.Equal(t, first.Body.Bytes(), retry.Body.Bytes(), "same payload_ref, block_time, retention_start")
	other := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-b", skB, nowVec+6, blob))
	require.Equal(t, 200, other.Code)
	require.Equal(t, first.Body.Bytes(), other.Body.Bytes(), "two agents, same bytes, same ref")
	require.Equal(t, 1, e.pub.count(), "submitted once")
	require.Equal(t, 1, e.fq.count(), "deduplicated answers are not charged")

	// Entries live at least 2*(skew+300) after publication.
	e.clock.Advance(2 * window)
	now := nowVec + uint64(2*window/time.Second)
	again := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, now, blob))
	require.Equal(t, 200, again.Code)
	require.Equal(t, first.Body.Bytes(), again.Body.Bytes())
	require.Equal(t, 1, e.pub.count())
	require.Equal(t, 1, e.fq.count())

	// A different blob is a different publication and is charged.
	e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, now, []byte("a different blob")))
	require.Equal(t, 2, e.pub.count())
	require.Equal(t, 2, e.fq.count())
}

func TestPublishFailureIsNotRemembered(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	e.pub.result, _ = testRef(t)
	e.pub.err = gate.ErrChainUnavailable
	blob := []byte("blob")
	requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, blob)), 503, "ErrChainUnavailable", true)
	e.pub.mu.Lock()
	e.pub.err = nil
	e.pub.mu.Unlock()
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec+1, blob))
	require.Equal(t, 200, rec.Code)
	require.Equal(t, 2, e.pub.count())
}

func TestPublishConcurrentSameBlobSubmitsOnce(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	ref, _ := testRef(t)
	entered, release := make(chan struct{}, 16), make(chan struct{})
	e.pub.fn = func(_ context.Context, blob []byte) (sdk.Published, error) {
		entered <- struct{}{}
		<-release
		return ref, nil
	}
	blob := []byte("racing blob")
	type res struct {
		code int
		body []byte
	}
	out := make(chan res, 6)
	var wg sync.WaitGroup
	fire := func(i int) {
		defer wg.Done()
		rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec+uint64(i), blob))
		out <- res{rec.Code, rec.Body.Bytes()}
	}
	wg.Add(1)
	go fire(0)
	<-entered
	for i := 1; i < 6; i++ {
		wg.Add(1)
		go fire(i)
	}
	close(release)
	wg.Wait()
	close(out)
	var ok []byte
	for r := range out {
		switch r.code {
		case 200:
			if ok == nil {
				ok = r.body
			}
			require.Equal(t, ok, r.body)
		case 503:
			eb := parseErr(t, r.body)
			require.Equal(t, uint64(1), eb.Retryable, "an in-flight duplicate may answer retryable")
		default:
			t.Fatalf("unexpected status %d", r.code)
		}
	}
	require.Equal(t, 1, e.pub.count())
	final := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec+9, blob))
	require.Equal(t, 200, final.Code)
	require.Equal(t, 1, e.pub.count())
}

func TestPublishQuotas(t *testing.T) {
	skA, pubA := testKey(1)
	skB, pubB := testKey(2)
	allow := map[string]string{"agent-a": pubA, "agent-b": pubB}
	t.Run("blobs per hour", func(t *testing.T) {
		e := newEnv(t, allow, withRealQuota(edictaapi.QuotaConfig{BlobsPerHour: 2, BytesPerDay: 1 << 20}))
		for i := 0; i < 2; i++ {
			rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec, []byte("blob"+strconv.Itoa(i))))
			require.Equal(t, 200, rec.Code)
		}
		rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec, []byte("blob-3")))
		requireErr(t, rec, 429, "edictaapi.ErrQuotaExceeded", true)
		n, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		require.NoError(t, err)
		require.Positive(t, n)
		require.Equal(t, 2, e.pub.count(), "no fee is spent over quota")
		// Quotas are per agent.
		rec = e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-b", skB, nowVec, []byte("blob-b")))
		require.Equal(t, 200, rec.Code)
		// A deduplicated request over quota is still answered: it spends nothing.
		rec = e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec+1, []byte("blob0")))
		require.Equal(t, 200, rec.Code)
		// After the window tokens return.
		e.clock.Advance(time.Hour)
		rec = e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec+3600, []byte("blob-4")))
		require.Equal(t, 200, rec.Code)
	})
	t.Run("bytes per day", func(t *testing.T) {
		e := newEnv(t, allow, withRealQuota(edictaapi.QuotaConfig{BlobsPerHour: 100, BytesPerDay: 10}))
		require.Equal(t, 200, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec, []byte("12345678"))).Code)
		rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skA, nowVec, []byte("abcdefgh")))
		requireErr(t, rec, 429, "edictaapi.ErrQuotaExceeded", true)
		require.Equal(t, 1, e.pub.count())
	})
	t.Run("quota only after a valid signature", func(t *testing.T) {
		e := newEnv(t, allow)
		e.fq.err = edictaapi.ErrQuotaExceeded
		// bad signature: 401, not 429, and the quota is never consulted
		rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", skB, nowVec, []byte("b")))
		requireErr(t, rec, 401, "edictaapi.ErrPublishSignature", false)
		require.Zero(t, e.fq.count())
	})
}

func TestPublisherErrorsAreMapped(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	e.pub.err = errRecOutcomeUnk
	requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("a"))), 503, "recorder.ErrOutcomeUnknown", true)
	e.pub.err = errRecTooLarge
	requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("b"))), 413, "recorder.ErrTooLarge", false)
	e.pub.err = errors.New("secret-detail")
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("c")))
	eb := requireErr(t, rec, 500, "edictaapi.ErrInternal", false)
	require.NotContains(t, eb.Message, "secret-detail")
}

func TestPublishBlobAtLimit(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	e.cfg.MaxBlobBytes = 64
	e.rebuild()
	e.pub.result, _ = testRef(t)
	require.Equal(t, 200, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, make([]byte, 64))).Code)
	requireErr(t, e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, make([]byte, 65))), 413, "ErrTooLarge", false)
}

func TestPublishInvalidRefFromRecorderIsInternal(t *testing.T) {
	sk, pubHex := testKey(1)
	e := newEnv(t, map[string]string{"agent-a": pubHex})
	e.pub.result.Ref.Commitment = e.pub.result.Ref.Commitment[:31] // invalid ref: never served
	rec := e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("blob")))
	eb := requireErr(t, rec, 500, "edictaapi.ErrInternal", false)
	require.NotContains(t, eb.Message, "commitment")
	e.pub.result = sdk.Published{}
	rec = e.post("/v0/publish", signedPublish(t, gateIDVec, "agent-a", sk, nowVec, []byte("blob2")))
	requireErr(t, rec, 500, "edictaapi.ErrInternal", false)
}
