#!/bin/sh
# PostToolUse hook: run `gofmt -w` on any .go file the agent just wrote.
# Receives the tool-call JSON on stdin and extracts tool_input.file_path.
set -eu

file=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))')

case "$file" in
  *.go) exec gofmt -w "$file" ;;
esac
