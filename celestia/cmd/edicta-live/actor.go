package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/examples/tia-transfer/agent"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
)

const (
	modelID  = "edicta-live/price-band-agent"
	policyID = "edicta-live/price-band-v0"
)

// decisionError marks a failure of a decision's act step. It ends the run:
// the agent never retries a half-done decision.
type decisionError struct{ err error }

func (e *decisionError) Error() string { return e.err.Error() }
func (e *decisionError) Unwrap() error { return e.err }

// actor is the demo's act step: commit (publish, verify inclusion, sign),
// authorize, execute, record.
type actor struct {
	cfg       Config
	log       func(string, ...any)
	out       io.Writer
	collected func(*Evidence)

	builder *sdk.Builder
	api     *edictaapi.Client // publish and authorize
	rec     *edictaapi.Client // record
	exec    *transfer.Executor
	store   *transfer.MemStore
	rail    *railtx.Rail
	dom     transfer.Domain

	gateID, level  string
	gateKey        []byte
	keyPinned      bool
	execPub        []byte
	recorderSigner []byte
}

var _ agent.Actor = (*actor)(nil)

// Act implements agent.Actor.
func (a *actor) Act(ctx context.Context, d agent.Decision) error {
	ev, err := a.act(ctx, d)
	switch {
	case ev != nil && (err == nil || errors.Is(err, ErrEvidence)):
		a.emit(ev)
	case ev != nil:
		a.log("decision failed after: commitment_hash %s, blob height %d, tx hash %q", ev.CommitmentHash, ev.BlobHeight, ev.Transfer.TxHash)
	}
	if err != nil {
		return &decisionError{err: err}
	}
	return nil
}

func (a *actor) emit(ev *Evidence) {
	if a.collected != nil {
		a.collected(ev)
	}
	if a.out == nil {
		return
	}
	var text []byte
	if a.cfg.JSONOut {
		j, err := ev.JSON()
		if err != nil {
			a.log("cannot encode the evidence: %v", err)
			return
		}
		text = append(j, '\n')
	} else {
		text = []byte(ev.Text())
	}
	_, _ = a.out.Write(text)
	if a.cfg.EvidenceFile != "" {
		j, err := ev.JSON()
		if err == nil {
			err = writeFile(a.cfg.EvidenceFile, append(j, '\n'))
		}
		if err != nil {
			a.log("cannot write the evidence file: %v", err)
		}
	}
}

func (a *actor) act(ctx context.Context, d agent.Decision) (*Evidence, error) {
	p := &payload.Payload{
		Version: payload.Version,
		Model:   payload.Model{ID: modelID},
		Policy:  payload.Policy{ID: policyID},
		Context: payload.Data{MediaType: pricetrigger.MediaType, Bytes: d.Context},
		Action:  payload.Action{Type: bankaction.ActionType, Data: d.Action},
	}
	a.log("decision: %s branch, move %d bp; publishing through edictad before any action", d.Payload.Branch.Name, d.Payload.MoveBP)
	res, err := a.builder.Commit(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("publish and commit: %w", err)
	}
	ev := a.baseEvidence(res)
	a.log("published: blob at height %d, commitment_hash %s, inclusion verified", ev.BlobHeight, ev.CommitmentHash)

	authBytes, err := a.api.Authorize(ctx, res.Envelope, res.Action)
	if err != nil {
		return nil, fmt.Errorf("gate authorize: %w", err)
	}
	sa, ah, err := commitment.VerifyAuthorization(authBytes, commitment.AuthorizationCheck{
		GatePubKey: a.gateKey, GateID: a.gateID, ActionType: bankaction.ActionType,
		Action: res.Action, Now: uint64(time.Now().Unix()), SkewS: a.cfg.SkewS,
	})
	if err != nil {
		return nil, fmt.Errorf("Authorization does not verify: %w", err)
	}
	ev.Authorization = AuthorizationEvidence{
		Hash: hex.EncodeToString(ah[:]), CommitmentHash: hex.EncodeToString(sa.Authorization.CommitmentHash),
		GateID: sa.Authorization.GateID, GatePubKey: hex.EncodeToString(a.gateKey), GateKeyPinned: a.keyPinned,
		Expires: sa.Authorization.Expires, Verified: true,
	}
	a.log("Authorization verified, expires %d", sa.Authorization.Expires)

	_, msg, err := bankaction.CheckExecution(res.Action, bankaction.Domain(a.dom), bankaction.Limits{})
	if err != nil {
		return ev, fmt.Errorf("authorized action: %w", err)
	}
	ev.Transfer = TransferEvidence{From: msg.From, To: msg.To, Denom: msg.Denom, Amount: msg.Amount}

	var txRaw []byte
	if a.cfg.DryRun {
		a.log("dry run: signing the transfer without broadcasting it")
		var hash [32]byte
		if txRaw, hash, ev.Transfer.TimeoutHeight, err = a.dryRunSign(ctx, res, sa.Authorization.Expires); err != nil {
			return ev, err
		}
		ev.Transfer.TxHash = hex.EncodeToString(hash[:])
	} else {
		a.log("executing the transfer (rebroadcasting the same signed bytes until included or timed out)")
		r, err := a.exec.Execute(ctx, authBytes, res.Action)
		ev.Transfer.TxHash = hex.EncodeToString(r.TxHash[:])
		if err != nil {
			return ev, fmt.Errorf("transfer: %w", err)
		}
		rec, err := a.store.Get(ctx, res.CommitmentHash)
		if err != nil {
			return ev, fmt.Errorf("executor record: %w", err)
		}
		txRaw = rec.Prepared.TxRaw
		if sha256.Sum256(txRaw) != r.TxHash {
			return ev, errors.New("stored signed transaction does not hash to the transfer tx hash")
		}
		ev.Transfer.Height, ev.Transfer.Code, ev.Transfer.Broadcast = r.Height, r.Code, true
		ev.Transfer.TimeoutHeight = rec.Prepared.TimeoutHeight
		a.log("transfer %s included at height %d", ev.Transfer.TxHash, r.Height)
	}
	body, err := bodyOfTxRaw(txRaw)
	if err != nil {
		return ev, err
	}
	ev.Transfer.Memo, err = memoOfBody(body)
	if err != nil {
		return ev, err
	}
	// The body must be exactly the authorized message plus the memo and the
	// timeout, and nothing else.
	act, err := bankaction.Decode(res.Action)
	if err != nil {
		return ev, err
	}
	th, err := bankaction.CheckBody(act, res.CommitmentHash, body)
	if err != nil {
		return ev, fmt.Errorf("signed transaction: %w", err)
	}
	if th != ev.Transfer.TimeoutHeight {
		return ev, errors.New("signed transaction timeout_height differs from the executor's record")
	}

	if !a.cfg.DryRun {
		if err := a.record(ctx, res, ev); err != nil {
			return ev, err
		}
	}
	ev.Hints = hintsFor(ev)
	return ev, ev.Check()
}

func (a *actor) baseEvidence(res *sdk.Result) *Evidence {
	ref := res.Published.Ref
	signer, _ := bankmsg.EncodeAddress(a.dom.HRP, ref.Signer)
	return &Evidence{
		DryRun: a.cfg.DryRun, ChainID: a.dom.ChainID,
		Namespace: hex.EncodeToString(ref.Namespace), BlobHeight: ref.Height,
		BlobTime: res.Published.BlockTime, BlobTimeRFC3339: rfc3339(res.Published.BlockTime),
		ShareCommitment: hex.EncodeToString(ref.Commitment),
		SignerHex:       hex.EncodeToString(ref.Signer), SignerBech32: signer,
		InclusionLevel: a.level,
		CommitmentHash: hex.EncodeToString(res.CommitmentHash[:]),
		AgentPubKey:    hex.EncodeToString(res.Commitment.AgentPubKey),
		IssuedAt:       res.Validity.IssuedAt, ValidUntil: res.Validity.ValidUntil,
	}
}

// dryRunSign builds and signs the transaction the executor would send, by the
// same rules, and stops there.
func (a *actor) dryRunSign(ctx context.Context, res *sdk.Result, expires uint64) ([]byte, [32]byte, uint64, error) {
	var zero [32]byte
	act, err := bankaction.Decode(res.Action)
	if err != nil {
		return nil, zero, 0, err
	}
	height, headTime, interval, err := a.rail.Head(ctx)
	if err != nil {
		return nil, zero, 0, fmt.Errorf("dry run: head: %w", err)
	}
	th, err := bankaction.TimeoutHeight(bankaction.TimeoutInput{
		HeadHeight: height, HeadTime: headTime, TauMs: uint64((interval + time.Millisecond - 1) / time.Millisecond),
		Expires: expires, SkewS: a.cfg.SkewS, MaxBlocks: 200, Now: uint64(time.Now().Unix()),
	})
	if err != nil {
		return nil, zero, 0, fmt.Errorf("dry run: timeout height: %w", err)
	}
	body, err := bankaction.Body(act.Msg, res.CommitmentHash, th)
	if err != nil {
		return nil, zero, 0, err
	}
	raw, err := a.rail.Sign(ctx, body, act.ChainID, a.cfg.MaxFee)
	if err != nil {
		return nil, zero, 0, fmt.Errorf("dry run: sign: %w", err)
	}
	return raw, sha256.Sum256(raw), th, nil
}

// record asks the gate for the receipt and verifies it.
func (a *actor) record(ctx context.Context, res *sdk.Result, ev *Evidence) error {
	ref := ev.Transfer.TxHash
	pub, sig, err := a.exec.RecordRequest(res.CommitmentHash, ref)
	if err != nil {
		return fmt.Errorf("record request: %w", err)
	}
	raw, err := a.rec.Record(ctx, res.Envelope, ref, pub, sig)
	if err != nil {
		return fmt.Errorf("gate record: %w", err)
	}
	sr, _, err := commitment.VerifyReceipt(raw)
	if err != nil {
		return fmt.Errorf("receipt does not verify: %w", err)
	}
	r := sr.Receipt
	switch {
	case !bytes.Equal(r.GatePubKey, a.gateKey) || r.GateID != a.gateID:
		return errors.New("receipt is signed by another gate")
	case !bytes.Equal(r.CommitmentHash, res.CommitmentHash[:]):
		return errors.New("receipt is for another commitment")
	case r.RailRef != ref:
		return errors.New("receipt rail_ref is not the transfer tx hash")
	case !bytes.Equal(r.ExecutorPubKey, ed25519.PublicKey(a.execPub)):
		return errors.New("receipt names another executor key")
	}
	ev.Receipt = ReceiptEvidence{
		Verified: true, CommitmentHash: hex.EncodeToString(r.CommitmentHash), RailRef: r.RailRef,
		ExecutorKey: hex.EncodeToString(r.ExecutorPubKey), RecordedAt: r.RecordedAt,
	}
	a.log("receipt verified")
	return nil
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
