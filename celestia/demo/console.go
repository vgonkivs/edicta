package demo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/vgonkivs/edicta/celestia/secret"
)

// TerminalConsole reads the operator's answers from a terminal. A line read
// that outlives its context is kept for the next prompt, so no input is lost.
type TerminalConsole struct {
	in      *os.File
	out     io.Writer
	rd      *bufio.Reader
	pending chan lineResult
	// stale marks a read that started before a Flush; its line is dropped.
	stale bool
}

type lineResult struct {
	s   string
	err error
}

// NewTerminalConsole refuses an input that is not a terminal: the start of
// the demo is always an Enter typed by a person.
func NewTerminalConsole(in *os.File, out io.Writer) (*TerminalConsole, error) {
	if in == nil || !term.IsTerminal(int(in.Fd())) {
		return nil, ErrNoTerminal
	}
	return &TerminalConsole{in: in, out: out, rd: bufio.NewReader(in)}, nil
}

func (c *TerminalConsole) line(ctx context.Context) (string, error) {
	if c.pending == nil {
		ch := make(chan lineResult, 1)
		c.pending = ch
		go func() {
			s, err := c.rd.ReadString('\n')
			ch <- lineResult{strings.TrimRight(s, "\r\n"), err}
		}()
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-c.pending:
		c.pending = nil
		if c.stale {
			c.stale = false
			return c.line(ctx)
		}
		if res.err != nil && res.s == "" {
			return "", fmt.Errorf("demo: reading the terminal: %w", res.err)
		}
		return res.s, nil
	}
}

// Flush drops everything typed so far, so an early keystroke is never taken
// as the answer to a prompt shown later. It fails if the input cannot be
// flushed, and the caller must then not ask for consent.
func (c *TerminalConsole) Flush() error {
	if err := flushInput(int(c.in.Fd())); err != nil {
		return fmt.Errorf("demo: flushing the terminal input: %w", err)
	}
	c.rd.Reset(c.in)
	if c.pending != nil {
		c.stale = true
	}
	return nil
}

func (c *TerminalConsole) WaitEnter(ctx context.Context, prompt string) (Answer, error) {
	for {
		fmt.Fprintf(c.out, "\n  > %s\n", prompt)
		s, err := c.line(ctx)
		if err != nil {
			return 0, err
		}
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "":
			return AnswerContinue, nil
		case "q":
			return AnswerQuit, nil
		}
		fmt.Fprintln(c.out, "  Press Enter to continue or type q to quit.")
	}
}

func (c *TerminalConsole) Confirm(ctx context.Context, prompt, want string) (bool, error) {
	fmt.Fprintf(c.out, "\n  > %s\n", prompt)
	s, err := c.line(ctx)
	if err != nil {
		return false, err
	}
	return s == want, nil
}

func (c *TerminalConsole) ReadLine(ctx context.Context, prompt string) (string, error) {
	fmt.Fprintf(c.out, "\n  > %s\n", prompt)
	return c.line(ctx)
}

func (c *TerminalConsole) Passphrase(prompt string) (secret.Secret, error) {
	if c.pending != nil {
		return secret.Secret{}, errors.New("demo: a read is pending")
	}
	fmt.Fprint(c.out, prompt)
	b, err := term.ReadPassword(int(c.in.Fd()))
	fmt.Fprintln(c.out)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("demo: reading the passphrase: %w", err)
	}
	defer clear(b)
	if len(b) == 0 {
		return secret.Secret{}, errors.New("demo: empty passphrase")
	}
	return secret.New(b), nil
}
