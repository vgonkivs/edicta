package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/secret"
)

const plain = "hunter2-token"

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestFromFileModes(t *testing.T) {
	tests := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true}, {0o400, true},
		{0o640, false}, {0o604, false}, {0o644, false}, {0o660, false}, {0o666, false}, {0o700 | 0o010, false},
	}
	for _, tc := range tests {
		t.Run(tc.mode.String(), func(t *testing.T) {
			s, err := secret.FromFile(writeFile(t, plain, tc.mode))
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, plain, s.RevealString())
				return
			}
			require.ErrorIs(t, err, secret.ErrPermissions)
			assert.False(t, s.IsSet())
			assert.NotContains(t, err.Error(), plain)
		})
	}
}

func TestFromFileContent(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", plain, plain},
		{"one newline", plain + "\n", plain},
		{"crlf", plain + "\r\n", plain},
		{"only one newline trimmed", plain + "\n\n", plain + "\n"},
		{"inner newline kept", "a\nb\n", "a\nb"},
		{"leading space kept", " " + plain, " " + plain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := secret.FromFile(writeFile(t, tc.in, 0o600))
			require.NoError(t, err)
			assert.Equal(t, tc.want, s.RevealString())
		})
	}
}

func TestFromFileErrors(t *testing.T) {
	_, err := secret.FromFile(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)

	for _, in := range []string{"", "\n", "\r\n"} {
		_, err = secret.FromFile(writeFile(t, in, 0o600))
		assert.ErrorIs(t, err, secret.ErrEmpty)
	}

	_, err = secret.FromFile(t.TempDir())
	require.Error(t, err)

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(writeFile(t, plain, 0o644), link))
	_, err = secret.FromFile(link)
	assert.ErrorIs(t, err, secret.ErrPermissions)
}

func TestRevealIsACopy(t *testing.T) {
	in := []byte(plain)
	s := secret.New(in)
	in[0] = 'X'
	assert.Equal(t, plain, s.RevealString())
	out := s.Reveal()
	out[0] = 'Y'
	assert.Equal(t, plain, s.RevealString())
	assert.True(t, bytes.Equal([]byte(plain), s.Reveal()))
}

func TestZeroValueAndZero(t *testing.T) {
	var z secret.Secret
	assert.False(t, z.IsSet())
	assert.Nil(t, z.Reveal())
	assert.Equal(t, "[redacted]", fmt.Sprint(z))

	s := secret.New([]byte(plain))
	assert.True(t, s.IsSet())
	s.Zero()
	assert.False(t, s.IsSet())
	assert.Empty(t, s.Reveal())
}

type holder struct {
	Public string
	s      secret.Secret
	list   []secret.Secret
	m      map[string]secret.Secret
	ptr    *secret.Secret
}

type Exported struct {
	S secret.Secret
	L []secret.Secret
	M map[string]secret.Secret
}

func TestRedactionEverywhere(t *testing.T) {
	s := secret.New([]byte(plain))
	h := holder{Public: "p", s: s, list: []secret.Secret{s}, m: map[string]secret.Secret{"k": s}, ptr: &s}
	e := Exported{S: s, L: []secret.Secret{s}, M: map[string]secret.Secret{"k": s}}

	values := map[string]any{
		"value": s, "pointer": &s, "unexported holder": h, "holder pointer": &h,
		"exported": e, "exported pointer": &e, "slice": []secret.Secret{s},
		"map": map[string]secret.Secret{"k": s}, "any slice": []any{s, &s},
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T", "%p", "%10.3s", "%#x", "% x", "%t"}
	for name, v := range values {
		for _, verb := range verbs {
			out := fmt.Sprintf(verb, v)
			assert.NotContains(t, out, plain, "%s %s", name, verb)
			assert.NotContains(t, out, fmt.Sprintf("%x", plain), "%s %s", name, verb)
		}
		assert.NotContains(t, fmt.Sprint(v), plain, name)
		assert.NotContains(t, fmt.Sprintln(v), plain, name)
	}

	assert.Equal(t, "[redacted]", fmt.Sprintf("%v", s))
	assert.Equal(t, "[redacted]", fmt.Sprintf("%#v", s))
	assert.Equal(t, "[redacted]", fmt.Sprintf("%s", s))
	assert.Equal(t, "[redacted]", s.String())
	assert.Equal(t, "[redacted]", s.GoString())
}

func TestRedactionJSON(t *testing.T) {
	s := secret.New([]byte(plain))
	e := Exported{S: s, L: []secret.Secret{s}, M: map[string]secret.Secret{"k": s}}
	for _, v := range []any{s, &s, e, &e, []secret.Secret{s}, map[string]secret.Secret{"k": s}, holder{s: s}} {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.NotContains(t, string(b), plain)
	}
	b, err := json.Marshal(s)
	require.NoError(t, err)
	assert.JSONEq(t, `"[redacted]"`, string(b))

	b, err = json.MarshalIndent(e, "", " ")
	require.NoError(t, err)
	assert.NotContains(t, string(b), plain)
}

func TestRedactionSlog(t *testing.T) {
	s := secret.New([]byte(plain))
	h := holder{s: s, list: []secret.Secret{s}, m: map[string]secret.Secret{"k": s}}
	e := Exported{S: s, L: []secret.Secret{s}, M: map[string]secret.Secret{"k": s}}

	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(mk(&buf))
		l.Info("m", "s", s, "p", &s, "h", h, "e", e, "l", []secret.Secret{s},
			"m", map[string]secret.Secret{"k": s}, slog.Group("g", "s", s), "a", slog.AnyValue(s))
		assert.NotContains(t, buf.String(), plain, name)
		assert.Contains(t, buf.String(), "[redacted]", name)
	}
}
