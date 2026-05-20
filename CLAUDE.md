# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## The spec is the contract

`SPEC.md` is the authoritative contract for this server. **Read it before writing or modifying code, and do not deviate.** Section numbers (e.g. "§5", "§13.5") referenced in code comments, commit messages, and this file point into that document. When in doubt, the spec wins over inference from existing code.

## Commands

```
make test         # unit + integration with -short, target < 10s
make test-slow    # full suite including the ~16s ratelimit backoff test
make test-race    # everything under -race (with -short)
make e2e          # E2E suite, spawns the built binary against /usr/bin/{ssh,sftp,scp}
make coverage     # merged unit + integration + E2E coverage; fails if < 90%
```

Run a single test: `go test ./internal/<pkg>/ -run TestName` (add `-tags=e2e` for `./test/e2e/...`).

Required gates before claiming work is done:
- `go vet ./...`
- `gofmt -l .` (must print nothing)
- `go mod tidy` after adding/removing imports
- The relevant `make` target(s) for what changed

## Architecture

The binary is `cmd/minisshd`. Startup flow (spec §2): parse flags/env → resolve user+password (`internal/auth.Resolve`) → load or generate host key (`internal/hostkey`) → bind listener → print the `Password: XXXXXX` banner once to stdout (the **only** non-`logging` write in the program) → enter `server.Serve`.

Request flow per connection:

1. `internal/server` (`server.go`, `auth.go`) terminates the SSH handshake using `golang.org/x/crypto/ssh`. Password auth runs `subtle.ConstantTimeCompare` against the resolved credentials; failures feed `internal/ratelimit` (per-IP exponential backoff, §5).
2. `internal/server/dispatch.go` accepts channels and routes requests. The §7 rejection list (port forwarding, agent forwarding, X11, env, etc.) lives here — additions or changes to allowed request types belong in this file.
3. `internal/session` runs the accepted session: `service.go` is the entry point, `pty.go` wraps `github.com/creack/pty`, `sysproc.go` carries the platform-specific `SysProcAttr` for shell/exec, and SFTP is handled via `github.com/pkg/sftp`. Signal forwarding and exit-status semantics for interactive shell, one-shot exec, and SFTP all live in this package (§8).
4. `internal/logging` is the only sanctioned output sink for the program (the §2 step 8 password banner in `cmd/minisshd/main.go` is the single documented exception). It emits structured logfmt events and **actively scrubs the configured password from every emitted line** at runtime — preserve that scrub when touching the package; it is what keeps the password out of logs even if a future call site is careless.
5. `internal/version` holds build-time constants only and is excluded from the coverage threshold.

## Conventions

- Crypto and timing primitives are mandated by the spec: `crypto/rand` (never `math/rand`), `subtle.ConstantTimeCompare` for credential checks, and `time.Now()`'s monotonic reading for any duration measurement.
- Tests use Go's standard `testing` package only — no `testify`, no `ginkgo`.
- Test file naming determines what `make` target picks them up:
  - `*_test.go` next to source — unit, runs under `make test`.
  - `*_integration_test.go` — integration, runs under `make test`/`test-slow`/`test-race`.
  - `test/e2e/*_test.go` with `//go:build e2e` — E2E, only `make e2e` / coverage with the system ssh clients present.
- The coverage threshold is a single Makefile variable, `COVERAGE_THRESHOLD := 90.0`. Raise it over time; never carve out additional package exclusions beyond `internal/version`.
- macOS and Linux are both supported. PTY, SFTP, and signal behaviour must work on both. Gate platform-specific test paths with `runtime.GOOS` only when truly necessary, and prefer assertions that hold on both OSes.
- The password value must never appear in any structured log event. Any new log call site goes through `internal/logging`, which applies the runtime scrub.
- This server is not meant to face the public internet, and no code-level check enforces that. Don't add one without a spec change — operator responsibility is intentional.
