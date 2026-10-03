package commitment_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

func TestNilCommitment(t *testing.T) {
	_, _, p := baseCommitment(t)
	rows := []struct {
		name string
		call func() error
		want error
	}{
		{"ValidateStatic", func() error { return commitment.ValidateStatic(nil, p) }, commitment.ErrUnsupportedActionKind},
		{"CheckTime", func() error { return commitment.CheckTime(nil, edgeNow, p) }, commitment.ErrExpired},
		{"CheckScope", func() error { return commitment.CheckScope(nil, commitment.GateScope{}) }, commitment.ErrScopeMismatch},
		{"CheckAction", func() error { return commitment.CheckAction(nil, commitment.IBKROrderV0{}) }, commitment.ErrActionMismatch},
		{"CheckPayload", func() error { return commitment.CheckPayload(nil, []byte("x")) }, commitment.ErrPayloadSizeMismatch},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					if v := recover(); v != nil {
						t.Fatalf("panic: %v", v)
					}
				}()
				err = r.call()
			}()
			if err == nil {
				t.Fatal("nil error")
			}
			if !errors.Is(err, r.want) {
				t.Fatalf("want %v, got %v", r.want, err)
			}
			if !strings.Contains(err.Error(), "nil commitment") {
				t.Fatalf("message lacks \"nil commitment\": %v", err)
			}
		})
	}
}

func TestTagLengths(t *testing.T) {
	tags := map[string]string{
		"TagCommitment": commitment.TagCommitment,
		"TagSig":        commitment.TagSig,
		"TagReceipt":    commitment.TagReceipt,
	}
	for name, v := range tags {
		if n := len(v); n < 1 || n > 255 {
			t.Errorf("%s length %d outside 1..255", name, n)
		}
	}
}

func TestSignDoesNotAliasCaller(t *testing.T) {
	c, _, _ := baseCommitment(t)
	s, h, err := commitment.Sign(loadKey(t, "agent1"), c)
	if err != nil {
		t.Fatal(err)
	}
	wantNonce := bytes.Clone(s.Commitment.Nonce)
	wantKey := bytes.Clone(s.Commitment.AgentPubKey)
	for i := range c.Nonce {
		c.Nonce[i] ^= 0xff
	}
	for i := range c.AgentPubKey {
		c.AgentPubKey[i] ^= 0xff
	}
	if !bytes.Equal(s.Commitment.Nonce, wantNonce) || !bytes.Equal(s.Commitment.AgentPubKey, wantKey) {
		t.Fatal("envelope changed after caller mutation")
	}
	hh, err := commitment.HashOf(&s.Commitment)
	if err != nil {
		t.Fatal(err)
	}
	if hh != h {
		t.Fatal("envelope no longer matches returned hash")
	}
	if err := verifyErr(s); err != nil {
		t.Fatalf("envelope no longer verifies: %v", err)
	}
}

func TestNilCommitmentEncoding(t *testing.T) {
	priv := loadKey(t, "agent1")
	rows := []struct {
		name string
		call func() error
	}{
		{"Sign", func() error { _, _, err := commitment.Sign(priv, nil); return err }},
		{"Encode", func() error { _, err := commitment.Encode(nil); return err }},
		{"HashOf", func() error { _, err := commitment.HashOf(nil); return err }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Fatalf("panic: %v", v)
				}
			}()
			err := r.call()
			if err == nil {
				t.Fatal("nil error")
			}
			if !strings.Contains(err.Error(), "nil commitment") {
				t.Fatalf("message lacks \"nil commitment\": %v", err)
			}
		})
	}
}
