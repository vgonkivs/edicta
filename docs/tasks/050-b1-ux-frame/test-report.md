# 050 B1.5 test report

Run: `go test -race -count=1 -p 2` over config, clearerr, doctor, keyfile, initcmd, cmd/edicta, cmd/edictad, edictad, verifycli: all green
(after fixing one error in my own new test: agent.id rejects '=', so the '=' case uses agent.key_file).
task.md is absent from the worktree; acceptance was taken from impl-notes.md and the brief.

Existing programmer tests cover: strict parse, overrides, presets/mainnet refusal, all 13 doctor checks (fakes), secret/URL-key leakage,
init (0600/0700, no overwrite, idempotent, failed preflight writes nothing, partial home, symlinks, locking), FromEdicta, verify defaults.

Added edge cases:
- config: override value containing '=', duplicate keys/tables refused, override through a non-table or empty key, FuzzParse (10s, -parallel 2, no finding; errors always wrap ErrConfig).
- cmd/edicta: `doctor --set key=a=b`, `doctor --json` with every check failing (ok=false, all fail, exit non-zero).
- initcmd: canceled context before preflight writes nothing; read-only home errors and stays empty.
- edictad: FromEdicta with recorder.da=fibre and own_node=false names own_node.

Findings (production bugs): none. No t.Skip tests.
Not covered: doctor SystemKeyring/openChain system tests (listed as missing in impl-notes), real network probes.
