# minissh project conventions

- The contract is `minissh-spec.md`. Read it before writing code. Do not deviate.
- All Go code must pass `go vet ./...` and `gofmt -l .` (the latter must print nothing).
- Use `crypto/rand`, `subtle.ConstantTimeCompare`, and `time.Now()` (monotonic) as the spec mandates.
- Tests use Go's standard `testing` package — no `testify`, no `ginkgo`.
- Package-local unit tests live next to source: `internal/<pkg>/*_test.go`.
- Integration tests use the `_integration_test.go` filename suffix. **These are written exclusively by `test-impl` — even when they live inside another teammate's package directory, the suffix carves them out of that teammate's ownership.**
- E2E tests live under `test/e2e/` and are gated by the `e2e` Go build tag.
- Logging always goes through `internal/logging`. The only exception is the `Password: XXXXXX` banner in `cmd/minissh/main.go`, which writes directly to stdout per spec §2 step 8.
- The password value never appears in any structured log event. The `logging` package enforces this with an active runtime scrub of the configured password from every emitted line.
- File ownership: each teammate edits implementation files (`.go`) and **package-local unit tests** (`*_test.go` that are not `*_integration_test.go`) only inside their assigned directories. `*_integration_test.go` files anywhere belong to `test-impl`. The `test/e2e/` directory and the `Makefile` body belong to `test-impl`. Coordinate cross-package interface changes via the mailbox before changing signatures.
- The coverage threshold lives in the Makefile as a single variable (`COVERAGE_THRESHOLD := 90.0`) so it can be raised over time.
- `internal/version` is excluded from the coverage threshold (constants only). No other exclusions are permitted.
- After adding new imports, run `go mod tidy` to keep `go.mod`/`go.sum` aligned.
- macOS is the supported runtime. Linux is acceptable for development but PTY/SFTP/signal semantics must match macOS; gate platform-specific tests with `runtime.GOOS == "darwin"` or `// +build darwin` only when truly required.
