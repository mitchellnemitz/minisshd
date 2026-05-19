COVERAGE_THRESHOLD := 90.0

GO ?= go
# §13.5: coverage is measured across cmd/ and internal/. internal/version is
# excluded from the threshold (constants only) but is still listed here so
# spawned-binary coverage data can attribute lines to it without warnings.
COVERPKG := ./cmd/...,./internal/...

# Install destination for `make install`. Override on the command line, e.g.
# `make install MINISSHD_INSTALL_DIR=/usr/local/bin`.
MINISSHD_INSTALL_DIR ?= $(HOME)/.local/bin

.PHONY: build install test test-slow e2e test-race coverage clean-coverage

# Build a single-platform binary at build/minisshd using the same flags as the
# release workflow (.github/workflows/release.yml): CGO disabled, -trimpath,
# and -s -w to strip the symbol/DWARF tables.
build:
	@mkdir -p build
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w' -o build/minisshd ./cmd/minisshd

# Install the locally-built binary into MINISSHD_INSTALL_DIR (default
# ~/.local/bin). Uses `install` so the binary lands with mode 0755 on both
# macOS and Linux.
install: build
	@mkdir -p $(MINISSHD_INSTALL_DIR)
	install -m 0755 build/minisshd $(MINISSHD_INSTALL_DIR)/minisshd
	@echo "installed: $(MINISSHD_INSTALL_DIR)/minisshd"

# §13.6: fast target, < 10 s. Skips the ~16 s ratelimit backoff timing test
# via testing.Short().
test:
	$(GO) test -short ./...

# §13.6: full integration suite (includes the slow backoff test).
test-slow:
	$(GO) test ./...

# §13.6: full integration suite under the race detector.
test-race:
	$(GO) test -short -race ./...

# §13.6: end-to-end suite, only runs when the system ssh/sftp/scp clients
# are all present. Skips with a non-failing message otherwise.
e2e:
	@if ! command -v /usr/bin/ssh >/dev/null || ! command -v /usr/bin/sftp >/dev/null || ! command -v /usr/bin/scp >/dev/null; then \
		echo "make e2e: skipping — /usr/bin/{ssh,sftp,scp} not all present"; \
		exit 0; \
	fi
	$(GO) test -tags=e2e -count=1 -timeout 600s ./test/e2e/...

clean-coverage:
	rm -rf .coverage

# §13.5: combined coverage from unit + integration + (when available) E2E.
#   (a) unit + integration with -coverpkg.
#   (b) E2E with `go build -cover` + GOCOVERDIR.
#   (c) merge the two via `go tool covdata textfmt`.
#   (d) print per-package breakdown.
#   (e) fail if merged total < COVERAGE_THRESHOLD.
coverage: clean-coverage
	@mkdir -p .coverage/unit .coverage/e2e
	$(GO) test -coverpkg=$(COVERPKG) -coverprofile=.coverage/unit/cover.out ./...
	@# The E2E layer doesn't use -coverpkg because the test binary
	@# itself doesn't import internal/... — coverage comes from the
	@# spawned binary (built with go build -cover in TestMain), which
	@# writes covdata to GOCOVERDIR on graceful exit.
	@if command -v /usr/bin/ssh >/dev/null && command -v /usr/bin/sftp >/dev/null && command -v /usr/bin/scp >/dev/null; then \
		GOCOVERDIR=$(PWD)/.coverage/e2e $(GO) test -tags=e2e -count=1 -timeout 600s ./test/e2e/... || exit $$?; \
	else \
		echo "make coverage: skipping E2E layer — /usr/bin/{ssh,sftp,scp} not all present"; \
	fi
	@# Merge the E2E covdata (which is the GOCOVERDIR binary format
	@# emitted by the spawned binary) into textfmt, then concatenate
	@# with the unit/integration cover.out.
	@if [ -n "$$(ls .coverage/e2e 2>/dev/null)" ]; then \
		$(GO) tool covdata textfmt -i .coverage/e2e -o .coverage/e2e/textfmt.out 2>/dev/null || true; \
	fi
	@cat .coverage/unit/cover.out > .coverage/merged.out
	@if [ -s .coverage/e2e/textfmt.out ]; then \
		grep -v '^mode:' .coverage/e2e/textfmt.out >> .coverage/merged.out; \
	fi
	@# Per-package breakdown (also the source of the merged total).
	@$(GO) tool cover -func=.coverage/merged.out | tee .coverage/summary.txt
	@total=$$($(GO) tool cover -func=.coverage/merged.out | tail -1 | awk '{print $$3}' | tr -d '%'); \
		echo "Merged coverage: $$total% (threshold: $(COVERAGE_THRESHOLD)%)"; \
		awk -v t=$$total -v th=$(COVERAGE_THRESHOLD) 'BEGIN{ if (t+0 < th+0) { print "FAIL: merged coverage below threshold"; exit 1 } else { print "OK: merged coverage meets threshold"; exit 0 } }'
