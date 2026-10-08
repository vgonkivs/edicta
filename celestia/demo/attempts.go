package demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/verifier"
)

const rogueWait = 120 * time.Second

// attempts is step 7. The executor's rail is locked first, so attempts 1 to 3
// cannot move funds; the rogue executor of attempt 4 runs last.
func (r *Runner) attempts(ctx context.Context, d *decision) error {
	sc := r.deps.Screen
	r.rail.Lock()
	var wrong, inconclusive bool
	add := func(a AttemptResult, soft bool) {
		r.out.Attempts = append(r.out.Attempts, a)
		sc.Attempt(a)
		switch {
		case a.Skipped:
			inconclusive = true
		case !a.AsExpected && soft:
			inconclusive = true
		case !a.AsExpected:
			wrong = true
		}
	}

	sc.Layer(1, "the gate prevents")
	add(r.attemptDifferentAmount(ctx, d), false)
	a2 := r.attemptReuse(ctx, d)
	add(a2, false)
	ol, err := r.attemptOverLimit(ctx)
	if err != nil {
		return err
	}
	add(ol, false)

	sc.Layer(2, "sources cannot frame an honest agent")
	if r.haveRoot {
		a, soft := r.attemptTamper(ctx, d)
		add(a, soft)
	} else {
		add(AttemptResult{Layer: 2, Name: "tampered-archive", Skipped: true, Got: "skipped: needs a trust root"}, false)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	sc.Layer(3, "bypass is detected")
	if r.haveRoot {
		a, soft, err := r.attemptRogue(ctx, d)
		if err != nil {
			return err
		}
		add(a, soft)
	} else {
		add(AttemptResult{Layer: 3, Name: "rogue-executor", Skipped: true, Got: "skipped: needs a trust root"}, false)
	}

	switch {
	case wrong:
		return coded(ExitWrong, ErrAttemptUnexpected)
	case inconclusive || r.step5Inconclusive:
		r.out.Code = ExitInconclusive
	default:
		r.out.Code = ExitOK
	}
	return nil
}

func (r *Runner) msgAction(amount uint64) ([]byte, error) {
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: r.dom.Sender, To: r.funder.addr, Denom: r.dom.Denom, Amount: amount}, r.dom.HRP)
	if err != nil {
		return nil, err
	}
	return bankaction.Encode(bankaction.Action{ChainID: r.dom.ChainID, Msg: msg})
}

func (r *Runner) attemptDifferentAmount(ctx context.Context, d *decision) AttemptResult {
	a := AttemptResult{Layer: 1, Name: "different-amount", Expected: "gate ErrActionMismatch; executor ErrActionMismatch"}
	tampered, err := r.msgAction(d.amount * 1000)
	if err != nil {
		a.Got = err.Error()
		return a
	}
	_, gerr := r.authClient.Authorize(ctx, d.res.Envelope, tampered)
	_, eerr := r.exec.Execute(ctx, d.authBytes, tampered)
	gok, eok := errors.Is(gerr, commitment.ErrActionMismatch), errors.Is(eerr, commitment.ErrActionMismatch)
	a.AsExpected = gok && eok
	a.Got = fmt.Sprintf("gate %s; executor %s", errName(gerr, "ErrActionMismatch"), errName(eerr, "ErrActionMismatch"))
	a.Why = fmt.Sprintf("the agent committed %d utia; the bytes for %d utia hash to something else", d.amount, d.amount*1000)
	return a
}

func (r *Runner) attemptReuse(ctx context.Context, d *decision) AttemptResult {
	a := AttemptResult{Layer: 1, Name: "reuse-decision",
		Expected: "gate ErrNonceUsed, no new Authorization; executor ErrSeen; new commitment with the same nonce ErrNonceUsed"}
	_, gerr := r.authClient.Authorize(ctx, d.res.Envelope, d.res.Action)
	var stored []byte
	if apiErr := asAPIError(gerr); apiErr != nil {
		stored = apiErr.Stored
	}
	gateOK := errors.Is(gerr, gate.ErrNonceUsed) && string(stored) == string(d.authBytes)
	_, eerr := r.exec.Execute(ctx, d.authBytes, d.res.Action)
	execOK := errors.Is(eerr, transfer.ErrSeen)
	newOK, nerr := r.reuseNonceWithNewCommitment(ctx, d)
	a.AsExpected = gateOK && execOK && newOK
	a.Got = fmt.Sprintf("gate %s (stored Authorization returned: %t); executor %s; new commitment %s",
		errName(gerr, "ErrNonceUsed"), string(stored) == string(d.authBytes), errName(eerr, "ErrSeen"), errName(nerr, "ErrNonceUsed"))
	a.Why = "one Authorization per nonce, and the executor runs a decision once"
	return a
}

// reuseNonceWithNewCommitment signs a second commitment for the same payload
// and nonce with a later issued_at, so the refusal can only be the nonce.
func (r *Runner) reuseNonceWithNewCommitment(ctx context.Context, d *decision) (bool, error) {
	c := d.res.Commitment
	c.IssuedAt++
	h, err := commitment.HashOf(&c)
	if err != nil {
		return false, err
	}
	sig, err := r.signer.SignCommitment(ctx, h)
	if err != nil {
		return false, err
	}
	env, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: c, Signature: sig})
	if err != nil {
		return false, err
	}
	_, aerr := r.authClient.Authorize(ctx, env, d.res.Action)
	return errors.Is(aerr, gate.ErrNonceUsed), aerr
}

// attemptTamper serves a copy of the archive with one flipped byte in the
// payload record and verifies against it. soft reports an inconclusive result
// that is not the expected one, which is not a wrong verdict.
func (r *Runner) attemptTamper(ctx context.Context, d *decision) (a AttemptResult, soft bool) {
	a = AttemptResult{Layer: 2, Name: "tampered-archive", Expected: "INCONCLUSIVE, payload unchecked source_corrupt",
		Why: "Tampered data cannot frame an honest agent. The archive is only a source: bytes that do not match the anchored commitment prove this copy is bad, not that the agent or executor did anything wrong."}
	dst := filepath.Join(r.runDir, "tampered-archive")
	if err := tamperArchive(ctx, filepath.Join(r.runDir, "archive"), dst, d.res.Published.Ref); err != nil {
		a.Got = "could not prepare the copy: " + err.Error()
		return a, false
	}
	srv, err := openArchiveServer(dst)
	if err != nil {
		a.Got = err.Error()
		return a, false
	}
	defer srv.Close()
	res, err := r.verify(ctx, d.res.CommitmentHash, srv.url, filepath.Join(r.runDir, "receipt.cbor"), r.root, d.txHeight)
	r.writeVerifyFile("verify-attempt3.json", res)
	if err != nil {
		a.Got = err.Error()
		return a, true
	}
	a.Got = fmt.Sprintf("%s (verify exit %d)", strings.ToUpper(string(res.Verdict)), res.Code)
	var payloadOK, anyFail bool
	for _, c := range res.Checks {
		if c.Status == "fail" {
			anyFail = true
		}
		if c.Check == string(verifier.CheckPayload) && c.Status == "unchecked" && c.Reason == string(verifier.ReasonSourceCorrupt) {
			payloadOK = true
			a.Got += fmt.Sprintf("; payload: unchecked, reason=source_corrupt, source=%s", hostOf(srv.url))
		}
	}
	a.AsExpected = res.Verdict == VerdictInconclusive && payloadOK && !anyFail
	return a, !a.AsExpected && res.Verdict == VerdictInconclusive
}

func hostOf(u string) string { return strings.TrimPrefix(u, "http://") }

// tamperArchive copies src to dst and flips one byte of the payload blob,
// re-encoding the record so it still decodes.
func tamperArchive(ctx context.Context, src, dst string, ref commitment.PayloadRef) error {
	if err := copyTree(src, dst); err != nil {
		return err
	}
	st, err := fsarchive.OpenReadOnly(dst, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	if err != nil {
		return err
	}
	rec, err := st.Payload(ctx, ref.DA, ref.Commitment)
	if err != nil {
		return err
	}
	if len(rec.Blob) == 0 {
		return errors.New("empty payload blob")
	}
	rec.Blob[len(rec.Blob)/2] ^= 0x01
	enc, err := archive.Encode(rec)
	if err != nil {
		return err
	}
	rel, err := archive.KeyPath(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, filepath.FromSlash(rel)), enc, 0o600)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case e.IsDir():
			return os.MkdirAll(target, 0o700)
		case !e.Type().IsRegular():
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, cerr := io.Copy(out, in)
		if err := out.Close(); cerr == nil {
			cerr = err
		}
		return cerr
	})
}

// attemptRogue is the finale: a second decision gets a genuine Authorization,
// and an executor that skips its own checks signs a different amount.
func (r *Runner) attemptRogue(ctx context.Context, first *decision) (a AttemptResult, soft bool, err error) {
	a = AttemptResult{Layer: 3, Name: "rogue-executor", Expected: "INVALID, execution fails with bankaction.ErrBodyMismatch",
		Why: "The gate authorized only the committed bytes; enforcing them is the executor's job, and the verifier proves when it was skipped."}
	d, err := r.newDecision(ctx, r.cfg.AmountUTIA)
	if err != nil {
		return a, false, err
	}
	if err := r.commit(ctx, d); err != nil {
		return a, false, err
	}
	if err := r.authorize(ctx, d); err != nil {
		return a, false, err
	}
	txHash, height, err := r.rogueSend(ctx, d)
	if err != nil {
		return a, false, err
	}
	ref := hex.EncodeToString(txHash[:])
	pub, sig, err := r.exec.RecordRequest(d.res.CommitmentHash, ref)
	if err != nil {
		return a, false, coded(ExitUsage, err)
	}
	receipt, err := r.recordWith(ctx, d, ref, pub, sig)
	if err != nil {
		return a, false, err
	}
	rpath := filepath.Join(r.runDir, "rogue-receipt.cbor")
	if err := os.WriteFile(rpath, receipt, 0o600); err != nil {
		return a, false, coded(ExitUsage, err)
	}
	root, err := r.trustRoot(ctx, height)
	if err != nil {
		if errors.Is(err, ErrTrustRootUnavailable) {
			a.Skipped, a.Got = true, "skipped: needs a trust root"
			return a, false, nil
		}
		return a, false, err
	}
	res, err := r.verify(ctx, d.res.CommitmentHash, r.archive.url, rpath, root, height)
	r.writeVerifyFile("verify-attempt4.json", res)
	if err != nil {
		return a, false, err
	}
	a.Got = fmt.Sprintf("%s (verify exit %d)", strings.ToUpper(string(res.Verdict)), res.Code)
	for _, c := range res.Checks {
		if c.Check == string(verifier.CheckExecution) && c.Status == "fail" && strings.Contains(c.Detail, bankaction.ErrBodyMismatch.Error()) {
			a.AsExpected = res.Verdict == VerdictInvalid
			a.Got += fmt.Sprintf("; execution: FAIL %s", bankaction.ErrBodyMismatch.Error())
		}
	}
	a.Why = fmt.Sprintf("The gate-signed receipt names tx %s; those bytes hash to it and send %d utia where the agent committed %d. %s", ref, d.amount+1, d.amount, a.Why)
	return a, !a.AsExpected && res.Verdict == VerdictInconclusive, nil
}

// rogueSend signs a transfer of amount + 1 under the genuine Authorization,
// without the executor's checks, and broadcasts it once.
func (r *Runner) rogueSend(ctx context.Context, d *decision) (hash [32]byte, height uint64, err error) {
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: r.dom.Sender, To: r.funder.addr, Denom: r.dom.Denom, Amount: d.amount + 1}, r.dom.HRP)
	if err != nil {
		return hash, 0, coded(ExitUsage, err)
	}
	head, headTime, interval, err := r.rawRail.Head(ctx)
	if err != nil {
		return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: rogue head: %w", err))
	}
	th, err := bankaction.TimeoutHeight(bankaction.TimeoutInput{
		HeadHeight: head, HeadTime: headTime, TauMs: uint64((interval + time.Millisecond - 1) / time.Millisecond),
		Expires: d.authExpires, SkewS: skewS, MaxBlocks: 200, Now: uint64(r.deps.now().Unix()),
	})
	if err != nil {
		return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: rogue timeout height: %w", err))
	}
	body, err := bankaction.Body(msg, d.res.CommitmentHash, th)
	if err != nil {
		return hash, 0, coded(ExitUsage, err)
	}
	raw, err := r.rawRail.Sign(ctx, body, r.dom.ChainID, r.preset.Funding.MaxFee)
	if err != nil {
		return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: rogue sign: %w", err))
	}
	hash = sha256.Sum256(raw)
	rogue := GuardRailOnce(r.rawRail, r.consent)
	if err := rogue.Broadcast(ctx, raw); err != nil {
		return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: rogue broadcast: %w", err))
	}
	r.deps.Screen.Info(fmt.Sprintf("rogue executor sent %d utia (decision committed %d): tx %s", d.amount+1, d.amount, hex.EncodeToString(hash[:])))
	deadline := r.deps.now().Add(rogueWait)
	for {
		st, err := r.rawRail.Status(ctx, hash)
		if err == nil && st.State == transfer.TxCommitted {
			if st.Code != 0 {
				return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: the rogue transaction failed on chain with code %d", st.Code))
			}
			return hash, st.Height, nil
		}
		if ctx.Err() != nil {
			return hash, 0, ctx.Err()
		}
		if !r.deps.now().Before(deadline) {
			return hash, 0, coded(ExitInconclusive, fmt.Errorf("demo: the rogue transaction %s was not included in time", hex.EncodeToString(hash[:])))
		}
		if err := r.deps.sleep(ctx, 3*time.Second); err != nil {
			return hash, 0, err
		}
	}
}
