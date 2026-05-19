#!/bin/sh
# PreToolUse hook: enforce CLAUDE.md's required gates before any `git commit`.
# Runs `go vet ./...` and `gofmt -l .`; exits 2 to block the commit if either
# reports a problem. Other Bash calls pass through untouched.
set -eu

cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')

case "$cmd" in
  *"git commit"*) ;;
  *) exit 0 ;;
esac

if ! vet_out=$(go vet ./... 2>&1); then
  printf 'blocked: go vet ./... failed:\n%s\n' "$vet_out" >&2
  exit 2
fi

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  printf 'blocked: gofmt would reformat these files (run `gofmt -w .`):\n%s\n' "$unformatted" >&2
  exit 2
fi
