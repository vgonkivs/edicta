package demo

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/celestia/railtx"
)

const (
	maxStaleRetries    = 5
	maxRejectedRetries = 3
	maxReadFailures    = 12
)

// fundingLoop moves funds from the funder with railtx.Funder. Every balance
// read follows a Settle that returned without error in the same iteration,
// and the amount of a Send is thrown away whenever Send reports ErrSettled.
type fundingLoop struct {
	f       Funding
	ab      Abandoner
	chain   Chain
	console Console
	screen  Screen
	denom   string
	explore Explorer
	poll    time.Duration
	timeout time.Duration
	sleep   func(context.Context, time.Duration) error
	now     func() time.Time

	seen  uint64
	sends []FundingSend
}

// Explorer renders links.
type Explorer interface {
	Tx(hash string) string
	Block(height uint64) string
	Address(addr string) string
}

func (l *fundingLoop) wait(ctx context.Context) error { return l.sleep(ctx, l.poll) }

// settle runs Settle and records the height at which a cleared send was seen
// committed. A nil error means the funder has no send in flight and the
// state may be read.
func (l *fundingLoop) settle(ctx context.Context) error {
	ph, th, had := l.f.Pending()
	for {
		cleared, err := l.f.Settle(ctx)
		switch {
		case err == nil:
			if cleared && had {
				if st, serr := l.f.Status(ctx, ph); serr == nil && st.Found && st.Height > 0 {
					l.seen = max(l.seen, st.Height)
					l.markHeight(ph, st.Height)
				}
			}
			return nil
		case errors.Is(err, railtx.ErrSequenceAdvanced):
			done, aerr := l.offerAbandon(ctx, ph, th)
			if aerr != nil {
				return aerr
			}
			if done {
				continue
			}
			return err
		case errors.Is(err, railtx.ErrSendInFlight):
			l.screen.Wait(fmt.Sprintf("funding send %s may land until height %d", short(ph), th), "")
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
			ph, th, had = l.f.Pending()
		default:
			return err
		}
	}
}

func (l *fundingLoop) markHeight(h [32]byte, height uint64) {
	hs := hex.EncodeToString(h[:])
	for i := range l.sends {
		if l.sends[i].Hash == hs {
			l.sends[i].Height = height
		}
	}
}

// ensure sends to addr until its balance is at least need.
func (l *fundingLoop) ensure(ctx context.Context, label, addr string, need uint64) error {
	var stale, rejected, readFails int
	for {
		if err := l.settle(ctx); err != nil {
			return err
		}
		bal, _, err := l.chain.BalanceAt(ctx, addr, l.denom, l.seen)
		if err != nil {
			if readFails++; readFails > maxReadFailures {
				return fmt.Errorf("demo: balance of %s: %w", label, err)
			}
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
			continue
		}
		readFails = 0
		if bal >= need {
			return nil
		}
		hash, th, err := l.f.Send(ctx, addr, need-bal)
		switch {
		case err == nil:
			l.record(hash, addr, need-bal, th)
			l.screen.Info(fmt.Sprintf("funding %s: sent %d utia, tx %s, includable until height %d", label, need-bal, short(hash), th))
		case errors.Is(err, railtx.ErrSettled):
			// The send just cleared; the shortfall computed above predates it.
		case errors.Is(err, railtx.ErrSendInFlight):
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
		case errors.Is(err, railtx.ErrStaleSequence):
			if stale++; stale > maxStaleRetries {
				return coded(ExitInconclusive, err)
			}
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
		case errors.Is(err, railtx.ErrSequenceBound):
			done, aerr := l.offerBinding(ctx)
			if aerr != nil {
				return aerr
			}
			if !done {
				return coded(ExitInconclusive, err)
			}
		case errors.Is(err, railtx.ErrRejected):
			l.screen.Warn(fmt.Sprintf("funding send rejected by the node: %v", err))
			if rejected++; rejected > maxRejectedRetries {
				return coded(ExitInconclusive, err)
			}
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
		case errors.Is(err, railtx.ErrTotalAboveMax):
			return coded(ExitInconclusive, fmt.Errorf("%w: %w; raise it with --max-total-funding", ErrFundingCap, err))
		case errors.Is(err, railtx.ErrAmountAboveMax), errors.Is(err, railtx.ErrFeeAboveMax):
			return coded(ExitUsage, err)
		case errors.Is(err, railtx.ErrNotStarted):
			return coded(ExitWrong, err)
		case th > 0:
			l.record(hash, addr, need-bal, th)
			l.screen.Warn(fmt.Sprintf("funding send %s may still land until height %d (it stays pending): %v", short(hash), th, err))
			if werr := l.wait(ctx); werr != nil {
				return werr
			}
		default:
			return err
		}
	}
}

func (l *fundingLoop) record(h [32]byte, to string, amount, th uint64) {
	l.sends = append(l.sends, FundingSend{Hash: hex.EncodeToString(h[:]), To: to, Amount: amount, TimeoutHeight: th})
}

// waitFor polls the funder's balance until it holds need, asking the
// operator whether to keep waiting after each timeout round.
func (l *fundingLoop) waitFor(ctx context.Context, addr string, need uint64) error {
	start := l.now()
	for {
		if err := l.settle(ctx); err != nil {
			return err
		}
		bal, _, err := l.chain.BalanceAt(ctx, addr, l.denom, l.seen)
		if err == nil && bal >= need {
			return nil
		}
		elapsed := l.now().Sub(start)
		l.screen.Wait("waiting for funds...", fmt.Sprintf("%d / %d utia (%d:%02d)", bal, need, int(elapsed.Minutes()), int(elapsed.Seconds())%60))
		if elapsed >= l.timeout {
			ans, qerr := l.console.WaitEnter(ctx, fmt.Sprintf("Funds for %s did not arrive in %s. Enter = keep waiting, q = quit", addr, l.timeout))
			if qerr != nil {
				return qerr
			}
			if ans == AnswerQuit {
				return coded(ExitInconclusive, fmt.Errorf("%w: %w", ErrOperatorQuit, ErrFundTimeout))
			}
			start = l.now()
		}
		if werr := l.wait(ctx); werr != nil {
			return werr
		}
	}
}

// offerAbandon is the only caller of Abandoner.Abandon. It acts only if the
// operator types the exact word for this send. done reports that the send was
// abandoned or settled by itself, so the loop may go on.
func (l *fundingLoop) offerAbandon(ctx context.Context, hash [32]byte, th uint64) (done bool, err error) {
	word := "abandon " + hex.EncodeToString(hash[:4])
	floor, _ := l.f.Guards()
	seq := ""
	if floor != nil {
		seq = fmt.Sprintf(" (last sequence seen used: %d)", *floor)
	}
	l.screen.Warn(fmt.Sprintf("Funding send %s (includable until %d) is unresolved%s.\n"+
		"      The funder's sequence moved past it and no lookup shows which transaction used it. It may have landed.\n"+
		"      If you abandon it and it did land, the demo sends again, at most the per-send maximum now and never more than the lifetime cap in total.\n"+
		"      Check %s", hex.EncodeToString(hash[:]), th, seq, l.explore.Address(l.f.Address())))
	ok, cerr := l.console.Confirm(ctx, fmt.Sprintf("Type %q to abandon it, or q to quit", word), word)
	if cerr != nil {
		return false, cerr
	}
	if !ok {
		return false, nil
	}
	aerr := l.ab.Abandon(ctx, hash)
	switch {
	case aerr == nil, errors.Is(aerr, railtx.ErrSettled):
		return true, nil
	default:
		return false, coded(ExitInconclusive, fmt.Errorf("abandon: %w", aerr))
	}
}

func (l *fundingLoop) offerBinding(ctx context.Context) (done bool, err error) {
	_, binding := l.f.Guards()
	if binding == nil {
		return false, nil
	}
	seq := *binding
	word := fmt.Sprintf("abandon-binding %d", seq)
	l.screen.Warn(fmt.Sprintf("The next funding send must reuse sequence %d, but the node offers another.\n"+
		"      Abandoning the binding lets the demo sign at the node's sequence. If the earlier send did land,\n"+
		"      the demo may send again: at most the per-send maximum now and the lifetime cap in total.\n"+
		"      Check %s", seq, l.explore.Address(l.f.Address())))
	ok, cerr := l.console.Confirm(ctx, fmt.Sprintf("Type %q to abandon it, or q to quit", word), word)
	if cerr != nil {
		return false, cerr
	}
	if !ok {
		return false, nil
	}
	if aerr := l.ab.AbandonBinding(ctx, seq); aerr != nil {
		return false, coded(ExitInconclusive, fmt.Errorf("abandon binding: %w", aerr))
	}
	return true, nil
}

func short(h [32]byte) string { return hex.EncodeToString(h[:4]) + "..." }
