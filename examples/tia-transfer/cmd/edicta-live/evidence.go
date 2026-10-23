package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Evidence is what a live run proves, collected from values the run has
// already verified one by one. Check re-derives the cross-item claims
// (ordering and binding) from the printed fields themselves, so a reader of
// the JSON can repeat them. It holds no secret.
type Evidence struct {
	DryRun bool `json:"dry_run"`

	ChainID   string `json:"chain_id"`
	Namespace string `json:"namespace"`
	// AnchorDA is "fibre" for da = 1, where the height is that of the
	// PayForFibre tx and there is no signer; empty for a blob.
	AnchorDA        string `json:"anchor_da,omitempty"`
	BlobHeight      uint64 `json:"blob_height"`
	BlobTime        uint64 `json:"blob_time"`
	BlobTimeRFC3339 string `json:"blob_time_rfc3339"`
	ShareCommitment string `json:"share_commitment"`
	SignerHex       string `json:"signer_hex"`
	SignerBech32    string `json:"signer_bech32"`
	InclusionLevel  string `json:"inclusion_check"`

	CommitmentHash string `json:"commitment_hash"`
	AgentPubKey    string `json:"agent_pubkey"`
	IssuedAt       uint64 `json:"issued_at"`
	ValidUntil     uint64 `json:"valid_until"`

	Authorization AuthorizationEvidence `json:"authorization"`
	Transfer      TransferEvidence      `json:"transfer"`
	Receipt       ReceiptEvidence       `json:"receipt"`

	Hints []string `json:"hints"`
}

// AuthorizationEvidence is the gate's Authorization, verified under the
// gate key the run pinned.
type AuthorizationEvidence struct {
	Hash           string `json:"hash"`
	CommitmentHash string `json:"commitment_hash"`
	GateID         string `json:"gate_id"`
	GatePubKey     string `json:"gate_pubkey"`
	GateKeyPinned  bool   `json:"gate_key_pinned"` // false: taken from the server's health answer
	Expires        uint64 `json:"expires"`
	Verified       bool   `json:"verified"`
}

// TransferEvidence is the executor's transaction. In a dry run it was signed
// but never broadcast, and Height is zero.
type TransferEvidence struct {
	TxHash        string `json:"tx_hash"`
	Height        uint64 `json:"height"`
	Code          uint32 `json:"code"`
	Memo          string `json:"memo"`
	TimeoutHeight uint64 `json:"timeout_height"`
	From          string `json:"from"`
	To            string `json:"to"`
	Denom         string `json:"denom"`
	Amount        uint64 `json:"amount"`
	Broadcast     bool   `json:"broadcast"`
}

// ReceiptEvidence is the gate's receipt for the transfer.
type ReceiptEvidence struct {
	Verified       bool   `json:"verified"`
	CommitmentHash string `json:"commitment_hash"`
	RailRef        string `json:"rail_ref"`
	ExecutorKey    string `json:"executor_pubkey"`
	RecordedAt     uint64 `json:"recorded_at"`
}

// ErrEvidence means an evidence item does not hold.
var ErrEvidence = errors.New("evidence check failed")

// Check verifies the claims that tie the items together. It returns every
// failed claim in one error.
func (e *Evidence) Check() error {
	var bad []string
	fail := func(format string, a ...any) { bad = append(bad, fmt.Sprintf(format, a...)) }

	if e.BlobHeight == 0 {
		fail("blob height is zero")
	}
	if !validHash(e.CommitmentHash) {
		fail("commitment_hash is not 64 hex characters")
	}
	if !e.Authorization.Verified {
		fail("Authorization not verified")
	}
	if e.Authorization.CommitmentHash != e.CommitmentHash {
		fail("Authorization is for another commitment")
	}
	if e.Transfer.Memo != e.CommitmentHash {
		fail("transfer memo %q is not the commitment_hash", e.Transfer.Memo)
	}
	if e.Transfer.TimeoutHeight == 0 {
		fail("transfer has no timeout_height")
	}
	if !validHash(e.Transfer.TxHash) {
		fail("transfer tx hash is not 64 hex characters")
	}
	if !e.DryRun {
		if !e.Transfer.Broadcast {
			fail("transfer was not broadcast")
		}
		if e.Transfer.Height <= e.BlobHeight {
			fail("transfer height %d is not above blob height %d", e.Transfer.Height, e.BlobHeight)
		}
		if e.Transfer.Code != 0 {
			fail("transfer failed on chain with code %d", e.Transfer.Code)
		}
		r := e.Receipt
		switch {
		case !r.Verified:
			fail("receipt not verified")
		case r.CommitmentHash != e.CommitmentHash:
			fail("receipt is for another commitment")
		case r.RailRef != e.Transfer.TxHash:
			fail("receipt rail_ref is not the transfer tx hash")
		case r.ExecutorKey == "":
			fail("receipt has no executor key")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: %s", ErrEvidence, strings.Join(bad, "; "))
	}
	return nil
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}

// JSON is the indented JSON form.
func (e *Evidence) JSON() ([]byte, error) { return json.MarshalIndent(e, "", "  ") }

// Text is the plain-text form.
func (e *Evidence) Text() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	title := "EVIDENCE"
	if e.DryRun {
		title = "EVIDENCE (DRY RUN: the transfer was signed but NOT broadcast)"
	}
	w("==== %s ====", title)
	w("chain_id:          %s", e.ChainID)
	w("-- decision published before the action --")
	w("namespace:         %s", e.Namespace)
	if e.fibre() {
		w("PFF at height H:   %d", e.BlobHeight)
	} else {
		w("blob height H:     %d", e.BlobHeight)
	}
	w("block time at H:   %s (%d)", e.BlobTimeRFC3339, e.BlobTime)
	if e.fibre() {
		w("blob commitment:   %s", e.ShareCommitment)
	} else {
		w("share commitment:  %s", e.ShareCommitment)
		w("signer:            %s (%s)", e.SignerBech32, e.SignerHex)
	}
	w("inclusion check:   %s", e.InclusionLevel)
	w("-- commitment --")
	w("commitment_hash:   %s", e.CommitmentHash)
	w("agent pubkey:      %s", e.AgentPubKey)
	w("issued_at:         %d", e.IssuedAt)
	w("valid_until:       %d", e.ValidUntil)
	w("-- Authorization (gate) --")
	w("gate_id:           %s", e.Authorization.GateID)
	w("gate pubkey:       %s (%s)", e.Authorization.GatePubKey, pinned(e.Authorization.GateKeyPinned))
	w("hash:              %s", e.Authorization.Hash)
	w("expires:           %d", e.Authorization.Expires)
	w("verified:          %s", okText(e.Authorization.Verified))
	w("-- transfer --")
	w("from -> to:        %s -> %s", e.Transfer.From, e.Transfer.To)
	w("amount:            %d %s", e.Transfer.Amount, e.Transfer.Denom)
	w("tx hash:           %s", e.Transfer.TxHash)
	if e.Transfer.Broadcast {
		w("tx height:         %d (%s than H)", e.Transfer.Height, cmpText(e.Transfer.Height, e.BlobHeight))
		w("tx code:           %d", e.Transfer.Code)
	} else {
		w("tx height:         not broadcast")
	}
	w("timeout_height:    %d", e.Transfer.TimeoutHeight)
	w("memo:              %s (%s)", e.Transfer.Memo, memoText(e.Transfer.Memo == e.CommitmentHash))
	if !e.DryRun {
		w("-- receipt (gate) --")
		w("verified:          %s", okText(e.Receipt.Verified))
		w("rail_ref:          %s", e.Receipt.RailRef)
		w("executor key:      %s", e.Receipt.ExecutorKey)
		w("recorded_at:       %d", e.Receipt.RecordedAt)
	}
	w("-- how to look it up yourself --")
	for _, h := range e.Hints {
		w("  %s", h)
	}
	return b.String()
}

func (e *Evidence) fibre() bool { return e.AnchorDA == "fibre" }

func okText(ok bool) string {
	if ok {
		return "OK"
	}
	return "FAILED"
}

func pinned(p bool) string {
	if p {
		return "pinned by flag"
	}
	return "NOT pinned: learned from the server, pass --gate-pubkey to pin it"
}

func memoText(ok bool) string {
	if ok {
		return "equals commitment_hash"
	}
	return "DOES NOT equal commitment_hash"
}

func cmpText(tx, blob uint64) string {
	if tx > blob {
		return "above"
	}
	return "NOT above"
}

// hintsFor returns look-up instructions that name no explorer.
func hintsFor(e *Evidence) []string {
	anchor := fmt.Sprintf("blob: ask a bridge node for blob.Get(height=%d, namespace=%s, commitment=%s); its signer must be %s",
		e.BlobHeight, e.Namespace, e.ShareCommitment, e.SignerBech32)
	if e.fibre() {
		anchor = fmt.Sprintf("anchor: the PayForFibre tx of namespace %s and commitment %s is in the block at height %d; edicta-verify checks it from the archived evidence",
			e.Namespace, e.ShareCommitment, e.BlobHeight)
	}
	return []string{
		fmt.Sprintf("transfer: query tx %s on chain %s with any explorer or node (tx query by hash)", e.Transfer.TxHash, e.ChainID),
		anchor,
		"binding: the transfer memo is the commitment_hash; search transactions by memo to find it",
	}
}

func rfc3339(unix uint64) string {
	if unix > 1<<62 {
		return ""
	}
	return time.Unix(int64(unix), 0).UTC().Format(time.RFC3339)
}

// bodyOfTxRaw returns body_bytes, the first field of a TxRaw.
func bodyOfTxRaw(txRaw []byte) ([]byte, error) {
	num, typ, n := protowire.ConsumeTag(txRaw)
	if n < 0 || num != 1 || typ != protowire.BytesType {
		return nil, errors.New("tx has no body_bytes first")
	}
	v, m := protowire.ConsumeBytes(txRaw[n:])
	if m < 0 {
		return nil, errors.New("tx body_bytes is truncated")
	}
	return v, nil
}

// memoOfBody returns the memo of a TxBody (field 2); the body must carry
// exactly one.
func memoOfBody(body []byte) (string, error) {
	var memo string
	seen := false
	for rest := body; len(rest) > 0; {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return "", errors.New("tx body: bad tag")
		}
		rest = rest[n:]
		m := protowire.ConsumeFieldValue(num, typ, rest)
		if m < 0 {
			return "", errors.New("tx body: bad field")
		}
		if num == 2 {
			if typ != protowire.BytesType || seen {
				return "", errors.New("tx body: bad or repeated memo")
			}
			v, _ := protowire.ConsumeBytes(rest)
			memo, seen = string(v), true
		}
		rest = rest[m:]
	}
	if !seen {
		return "", errors.New("tx body has no memo")
	}
	return memo, nil
}
