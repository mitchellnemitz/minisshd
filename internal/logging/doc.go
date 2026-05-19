// Package logging emits the structured logfmt and JSON-Lines events listed in
// spec §9, and scrubs the configured password from every emitted line.
//
// Two output formats are supported, selectable via ParseFormat:
//
//   - FormatLogfmt (default): RFC3339-timestamp LEVEL event key=value ...
//   - FormatJSON: one JSON object per line (JSONL/NDJSON), per RFC 8259.
//
// Field names are identical across formats. Use ParseFormat to resolve the
// --log-format flag and MINISSHD_LOG_FORMAT env var at startup.
package logging
