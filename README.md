# minisshd

A minimal, single-user SSH server for macOS and Linux. Listens on a TCP port, authenticates one user with a password (auto-generated 6-digit if none is configured), and supports interactive shell, one-off `exec`, and SFTP — enough for the system `ssh`, `sftp`, and `scp` clients to work unmodified.

The full contract lives in [`minisshd-spec.md`](./minisshd-spec.md). **This server is not meant to face the public internet.** No code-level check enforces that — it's the operator's responsibility.

## Usage

```
minisshd [--port N] [--bind IP] [--pass XXXXXX] [--user NAME] [--shell PATH] [--host-key PATH]
```

`MINISSHD_PASS` and `MINISSHD_USER` environment variables are honored when the matching flags are unset. If no password is configured, a fresh 6-digit numeric password is generated on startup and printed once to stdout — only after the listener has successfully bound.

## Build and test

```
make test         # unit + integration (-short), fast (target <10s)
make test-slow    # full suite incl. ~16s backoff timing test
make e2e          # build the binary, run E2E against /usr/bin/ssh|sftp|scp
make test-race    # everything under -race
make coverage     # merged unit + integration + E2E coverage, fails <90%
```

Coverage is enforced at **≥ 90.0 %** across `cmd/` and `internal/` (per spec §13.5). The threshold value lives as a single variable in the Makefile so it can be raised over time.

## Supported platforms

macOS and Linux. PTY, SFTP, and signal semantics work on both. Windows is not supported.
