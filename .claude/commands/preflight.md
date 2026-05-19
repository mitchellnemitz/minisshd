---
description: Run vet + gofmt check + make test and report
---

Run the required pre-completion gates from CLAUDE.md and report concisely.

go vet:
!`go vet ./... 2>&1; echo "[exit $?]"`

gofmt (any output above the marker is a failure):
!`gofmt -l . 2>&1; echo "[end]"`

make test:
!`make test 2>&1; echo "[exit $?]"`

Summarise: which gates passed and which failed. For any failure, show the
relevant output. If all three passed, say so in one line and stop.
