# minisshd project conventions

- The contract is `minisshd-spec.md`. Read it before writing code. Do not deviate.
- All Go code must pass `go vet ./...` and `gofmt -l .` (the latter must print nothing).
- Use `crypto/rand`, `subtle.ConstantTimeCompare`, and `time.Now()` (monotonic) as the spec mandates.
- Tests use Go's standard `testing` package — no `testify`, no `ginkgo`.
- Package-local unit tests live next to source: `internal/<pkg>/*_test.go`.
- Integration tests use the `_integration_test.go` filename suffix.
- E2E tests live under `test/e2e/` and are gated by the `e2e` Go build tag.
- Logging always goes through `internal/logging`. The only exception is the `Password: XXXXXX` banner in `cmd/minisshd/main.go`, which writes directly to stdout per spec §2 step 8.
- The password value never appears in any structured log event. The `logging` package enforces this with an active runtime scrub of the configured password from every emitted line.
- The coverage threshold lives in the Makefile as a single variable (`COVERAGE_THRESHOLD := 90.0`) so it can be raised over time.
- `internal/version` is excluded from the coverage threshold (constants only). No other exclusions are permitted.
- After adding new imports, run `go mod tidy` to keep `go.mod`/`go.sum` aligned.
- macOS and Linux are supported runtimes. PTY/SFTP/signal semantics must work on both; gate platform-specific tests with `runtime.GOOS` only when truly required, and prefer assertions that hold on both OSes.
