# JSON log format — implementation plan

Spec: `SPEC.md` (§9, §12)
Feature flag: `--log-format` / `MINISSHD_LOG_FORMAT`
Date: 2026-05-19

---

## Changelog (iter 2 → iter 3)

- **S1**: Fixed the `emit` sketch to iterate `l.scrubs` instead of using the
  `l.password` field directly. The old single-scrub line
  `bytes.ReplaceAll(line, []byte(l.password), []byte(redacted))` is replaced
  with a range loop over `l.scrubs` so both the raw-password bytes and the
  JSON-encoded-inner form are applied. Without this change an implementer
  following the sketches literally would store the JSON-encoded form in
  `l.scrubs[1]` but never apply it, defeating the dual-scrub entirely.
- **S2**: Removed the now-redundant `password string` field from the `Logger`
  struct sketch. The raw password bytes are held in `l.scrubs[0]`; there is no
  reason to store the string form separately. The `New` constructor sketch is
  updated to drop the `l.password = password` assignment.
- **S3**: The `if l.password != ""` guard in the old `emit` sketch is replaced
  with the equivalent `if len(l.scrubs) == 0` check. `New` leaves `l.scrubs`
  nil when password is empty, so the guard continues to skip the scrub loop
  when no password is configured.

## Changelog (iter 1 → iter 2)

- **C1**: Removed the unconditional "still well-formed" correctness claim for the
  password scrub in §9 spec-amendment text and in the "Password scrub: correctness
  proof" section. Added an explicit caveat that the guarantee holds only when the
  password does not contain structural JSON delimiter characters (`,`, `:`, `{`,
  `}`, `[`, `]`), and linked this to the identical operator-footgun caveat that
  already exists for logfmt. Added a documentation note directing operators to
  avoid such passwords when JSON output is selected.
- **S1**: Expanded the call-site sweep from 4 entries to 10. Listed all files and
  line-approximate locations that call `logging.New`. Corrected the "no other
  packages affected" claim to distinguish production packages (still true) from
  test helpers (not true).
- **S2**: Fixed the `writeJSONField` sketch so the duration case is concrete, not
  a comment placeholder. Updated the signature to accept the whole `field` struct
  so `f.dur` is directly accessible. Removed the "illustrative" disclaimer;
  the sketch is now the authoritative reference.
- **S3**: Documented that `runUntilListening` uses the sentinel `" listening "`
  (with flanking spaces), which does not match JSON output. Specified that the two
  new startup tests that reach the listening event (`TestRun_LogFormatEnvIsRespected`
  and `TestRun_LogFormatBannerUnaffected`) must use a JSON-mode sentinel instead
  (`"\"event\":\"listening\""`) or use a format-aware helper.
- **S4**: Made the `logFormatSet` variable declaration and the `fs.Visit` switch
  case update explicit in the `cmd/minisshd/main.go` diff.
- **M1**: Added `TestConcurrentEmission` (logging_test.go line 287, direct call to
  `New(buf, "")`) to the call-site sweep.
- **M2**: Added a one-sentence callout to the spec-amendment text noting that
  `duration` and `next_delay` are strings in logfmt (`time.Duration.String()`) but
  float seconds in JSON.
- **M3**: Narrowed "Always present, always first" wording to apply to JSON only
  (logfmt does not formally guarantee field ordering).
- **M4**: Reworded "No other packages affected" to accurately describe that no
  production-code packages are affected, while test helpers in `internal/auth`,
  `internal/ratelimit`, `internal/session`, and additional test files in
  `internal/server` and `internal/logging` all need updating.

---

## Summary

Add a second on-the-wire encoding for the structured events defined in spec §9.
The existing logfmt encoder remains the default; a new `--log-format json` (or
`MINISSHD_LOG_FORMAT=json`) selects a JSON-Lines encoder that emits exactly one
JSON object per line. Field names match the logfmt keys verbatim so a single
schema describes both formats. The runtime password-scrub invariant
(`internal/logging` replaces every occurrence of the configured password in an
emitted line) is preserved unchanged: the scrub continues to run on the
post-encode bytes, after JSON serialization, so the replacement cannot break
JSON well-formedness. The `Password: XXXXXX` banner in `cmd/minisshd/main.go`
is **not** a structured event and is unaffected by the flag.

This plan covers spec amendments to §9 and §12, the new flag wiring in
`cmd/minisshd/main.go`, an internal restructure of `internal/logging` so that
`emit` dispatches on a format selector, and an exhaustive test matrix that
mirrors every existing logfmt test in JSON with byte-identical event coverage.

---

## Spec amendments

Two sections of `SPEC.md` change. The plan does **not**
modify the spec — these are the exact proposed edits for the implementation
pass.

### §9 — replace the opening paragraph

**Current first paragraph of §9 (lines 266 in the spec) reads:**

> Logs go to **stdout**, line-buffered. Format: one event per line, RFC3339
> timestamp, level, event name, then space-separated `key=value` pairs
> (logfmt-compatible). Values are quoted with double quotes when they contain
> whitespace, `=`, `"`, or are empty; otherwise they appear bare. Inside quoted
> values, `"` and `\` are backslash-escaped. IPv4 and IPv6 literals contain no
> special characters under this rule and appear unquoted (e.g. `bind=0.0.0.0`,
> `bind=::`, `remote=[2001:db8::1]:51223`).

**Replace with:**

> Logs go to **stdout**, line-buffered. One event per line, terminated by a
> single `\n`. The encoding is selectable at startup via `--log-format`
> (`MINISSHD_LOG_FORMAT` env var); valid values are `logfmt` (default) and
> `json`. An unknown value causes startup to fail with exit code 2 and a
> message naming the rejected value.
>
> **`logfmt` (default):** RFC 3339 timestamp, level, event name, then
> space-separated `key=value` pairs. Values are quoted with double quotes when
> they contain whitespace, `=`, `"`, or are empty; otherwise they appear bare.
> Inside quoted values, `"` and `\` are backslash-escaped. IPv4 and IPv6
> literals contain no special characters under this rule and appear unquoted
> (e.g. `bind=0.0.0.0`, `bind=::`, `remote=[2001:db8::1]:51223`).
>
> **`json`:** one JSON object per line, encoded per RFC 8259, terminated by a
> single `\n` and no trailing whitespace. Field names match the logfmt keys
> exactly. Field types:
> - `ts` — RFC 3339 string with the same wire format as logfmt's leading
>   timestamp (e.g. `"2026-05-17T14:22:01-07:00"`). Always present and always
>   the first key in the JSON object (JSON ordering is stable by construction
>   of the encoder; logfmt does not make a field-ordering guarantee).
> - `level` — JSON string, one of `"INFO"`, `"WARN"`, `"ERROR"`. Always the
>   second key in the JSON object.
> - `event` — JSON string (e.g. `"listening"`, `"auth-fail"`). Always the
>   third key in the JSON object.
> - `bind`, `fingerprint`, `user`, `remote`, `reason`, `kind`, `what`, `sig`,
>   `message` — JSON string. RFC 8259 escaping applies (`"` → `\"`,
>   `\` → `\\`, control characters → `\uXXXX`).
> - `port`, `pid`, `attempt`, `pgid`, `bytes_dropped` — JSON integer.
> - `duration`, `next_delay` — JSON number, **seconds as a float** (e.g.
>   `27.0`, `1.5`, `0.001`). This replaces the logfmt `time.Duration.String()`
>   form because programmatic consumers benefit from a numeric type.
> - All other event-defined fields preserve the type categories above.
>
> Field ordering within a JSON object is stable across emissions: `ts`,
> `level`, `event` first in that order, then the event-specific fields in
> alphabetical order by key. JSON itself does not mandate ordering, but stable
> ordering keeps line-diff-based tests legible and is cheap to produce.
>
> In **both** formats, the password value must never appear in any structured
> log event. The `logging` package enforces this with a runtime byte-level
> substring replacement of the configured password with `[REDACTED]` applied
> to the fully-encoded line immediately before it is written. For JSON the
> substitution is safe under the following condition: the replacement string
> `[REDACTED]` contains no JSON-special characters, and the password — when
> embedded in a JSON string field — appears in its encoded form (with `"`,
> `\`, and controls already escaped). Replacing that encoded form with
> `[REDACTED]` yields a JSON string that is still well-formed, **provided the
> password does not contain structural JSON delimiter characters (`,`, `:`,
> `{`, `}`, `[`, `]`)**. Those characters appear verbatim inside JSON string
> values and also appear in the surrounding structural JSON. A password equal
> to, say, `","` would cause the scrub to replace delimiter characters,
> producing a malformed object. Operators must not configure such passwords
> when JSON output is selected. This is the same class of operator footgun
> that affects logfmt with passwords containing `=`, space, or `"`. Duration
> fields differ between formats: logfmt emits `time.Duration.String()` (e.g.
> `27s`); JSON emits float seconds (e.g. `27.0`). Both representations carry
> the same numeric value.

### §9 — example block

Augment the existing logfmt example block with a JSON twin so both formats are
visible side by side. Keep the logfmt example unchanged; add immediately
below:

> When `--log-format json` is in effect, the same events render as:
>
> ```
> {"ts":"2026-05-17T14:22:01-07:00","level":"INFO","event":"listening","bind":"0.0.0.0","fingerprint":"SHA256:abc…","pid":4711,"port":2222,"user":"alice"}
> {"ts":"2026-05-17T14:22:18-07:00","level":"INFO","event":"conn-open","remote":"192.168.1.42:51223"}
> {"ts":"2026-05-17T14:22:18-07:00","level":"INFO","event":"auth-ok","remote":"192.168.1.42:51223","user":"alice"}
> {"ts":"2026-05-17T14:23:02-07:00","level":"WARN","event":"auth-fail","attempt":1,"next_delay":1.0,"reason":"bad-user","remote":"10.0.0.5:55001","user":"bob"}
> ```

### §9 — banner clarification

Append a sentence to the final paragraph of §9 (the existing banner exception
text), or insert it as a new paragraph immediately before it:

> The `Password: XXXXXX` banner described in §2 step 8 is **not** a structured
> log event. It is a one-shot human-readable line written directly to stdout
> from `cmd/minisshd/main.go` and is unaffected by `--log-format`. The banner
> appears verbatim in both formats' invocations.

### §12 — remove the JSON exclusion

**Current §12 line:**

> - File-based logging, log rotation, log shipping, structured JSON output.
>   Logs go to stdout; redirect if you need a file.

**Replace with:**

> - File-based logging, log rotation, log shipping. Logs go to stdout;
>   redirect if you need a file. Structured JSON output **is** supported via
>   `--log-format json` (§9) and is no longer a non-goal.

### §2 — flag table

Insert a new row in the §2 flag table (between `--shell` and `--host-key`, in
alphabetical-ish order matching the existing roughly-grouped layout):

> | `--log-format FORMAT` | `logfmt` | Structured-log encoding. Valid values: `logfmt`, `json`. See §9. |

And a new row in the env-var table immediately below `MINISSHD_USER`:

> | `MINISSHD_LOG_FORMAT` | Log encoding. Used only if `--log-format` is not provided. Same valid values as the flag. |

### §2 — startup validation step

Insert a new sub-bullet between current steps 3 and 4 (renumbering downstream
references is **not** required — the spec uses step numbers as informal
anchors, not strict ordinals, but the implementation pass should still update
any §2-step references in code comments if a renumber happens). Suggested
wording:

> 3a. Resolve `--log-format`: `--log-format` if set, else `$MINISSHD_LOG_FORMAT`,
> else `logfmt`. Reject any value other than `logfmt` or `json` with exit code
> 2 and a message naming the rejected value.

### §11 — error/edge-case table

Add a row:

> | `--log-format` value other than `logfmt` or `json` | Exit 2, message to stderr naming the rejected value. |

### §13.2 — unit-test additions

In the `logging` block, add bullets:

> - Every existing logfmt envelope/quoting test has a JSON twin. The same
>   event emitted via the JSON encoder is parsed back with `encoding/json`
>   and asserted to carry the same field names and value types listed in §9.
> - JSON output is one well-formed JSON object per line. `json.Unmarshal`
>   succeeds for every emitted line under each event method.
> - Password scrub for JSON: when the configured password contains a JSON
>   metacharacter (test case: ``"hello"world``), the encoded line is still
>   well-formed JSON after the scrub, and the literal password byte sequence
>   does not appear anywhere in the output.

In the `cmd/minisshd` startup-validation block, add:

> - `--log-format xml` exits 2 with a message naming the rejected value.
>   `--log-format ""` (explicit empty) also exits 2. `--log-format json` and
>   `--log-format logfmt` succeed. `MINISSHD_LOG_FORMAT=json` with no
>   `--log-format` flag selects JSON.

### §13.3 — integration-test additions

> - End-to-end log capture in JSON mode. Start the test server with
>   `LogFormat: "json"`, drive one good auth and one bad auth, capture
>   stdout, split on `\n`, `json.Unmarshal` each line, assert the expected
>   sequence of events (`listening`, `conn-open`, `auth-ok`, `conn-close`)
>   each appear once with the expected field structure.

---

## CLI / env interface

**New flag:**

| Attribute | Value |
|---|---|
| Flag | `--log-format FORMAT` |
| Env var | `MINISSHD_LOG_FORMAT` |
| Default | `logfmt` |
| Valid values | `logfmt`, `json` (case-sensitive) |
| Precedence | `--log-format` > `$MINISSHD_LOG_FORMAT` > default `logfmt` |
| On invalid value | Exit code 2, stderr message: `minisshd: --log-format %q: unknown format (valid: logfmt, json)\n` |

**Resolution function — exact signature** (lives in `internal/logging`):

```go
// Format is the on-the-wire encoding selected at startup.
type Format int

const (
    FormatLogfmt Format = iota
    FormatJSON
)

// ParseFormat resolves the log-format selector per spec §9. flagValue is
// the literal --log-format value; flagSet reports whether the flag was
// supplied. envValue / envSet describe the MINISSHD_LOG_FORMAT environment
// variable. The default is FormatLogfmt. An unrecognized value returns an
// error whose message names the rejected value.
func ParseFormat(flagValue string, flagSet bool, envValue string, envSet bool) (Format, error)
```

Validation rules:

- If `flagSet` and `flagValue == ""` → error (`unknown format ""`). Treat
  explicit empty as a user mistake, mirroring the §2 step 2 treatment of
  `--pass ""`.
- If `flagSet` → use `flagValue`, ignore env.
- Else if `envSet` and `envValue != ""` → use `envValue`.
- Else → `FormatLogfmt`.
- Resolved value must be one of `"logfmt"` / `"json"`; anything else → error.

This signature mirrors `auth.ResolvePasswordStrict` and the resolution shape
already used elsewhere in `cmd/minisshd/main.go`. Tests live next to the
function in `internal/logging/format_test.go`.

---

## Code changes by file

### `internal/logging/logging.go`

1. Introduce the `Format` type and `FormatLogfmt` / `FormatJSON` constants
   (exported, since `cmd/minisshd/main.go` selects between them).
2. Extend `Logger`:
   ```go
   type Logger struct {
       mu     sync.Mutex
       w      io.Writer
       scrubs [][]byte      // raw password bytes, then JSON-encoded-inner form (if different)
       now    func() time.Time
       format Format
   }
   ```
   The `password string` field is removed. The raw bytes are held in
   `scrubs[0]` (when a password is configured). There is no reason to keep the
   string form once the slice is built; removing it eliminates the risk of a
   future caller accidentally using `l.password` instead of iterating
   `l.scrubs`.
3. Change `New` signature to accept the format:
   ```go
   func New(w io.Writer, password string, format Format) *Logger
   ```
   This is a breaking change to callers — see §"Code changes by file →
   call-site sweep" below. Justification for breaking rather than adding a
   variadic option: the existing `New` is called from exactly two production
   paths (`cmd/minisshd/main.go` and the two `*_integration_test.go` helpers
   in `internal/logging` and `internal/server`); a single required parameter
   keeps the API explicit and impossible to forget.
4. Split `emit` into two helpers and dispatch in `emit`:
   ```go
   func (l *Logger) emit(level, event string, fields []field) {
       var buf bytes.Buffer
       switch l.format {
       case FormatJSON:
           l.encodeJSON(&buf, level, event, fields)
       default:
           l.encodeLogfmt(&buf, level, event, fields)
       }
       line := buf.Bytes()
       if len(l.scrubs) > 0 {
           for _, s := range l.scrubs {
               line = bytes.ReplaceAll(line, s, []byte(redacted))
           }
       }
       l.mu.Lock()
       defer l.mu.Unlock()
       _, _ = l.w.Write(line)
   }
   ```
   The post-encode scrub iterates `l.scrubs`. `New` populates `l.scrubs` with
   the raw password bytes as `scrubs[0]` and, if the password contains any
   JSON metacharacter, the JSON-encoded-inner form as `scrubs[1]`. The
   `len(l.scrubs) == 0` guard preserves the existing fast path when no
   password is configured. The range loop is format-agnostic: for logfmt,
   `scrubs[1]` is never added (the JSON-encoded form only differs when `"`,
   `\`, or a control byte is present, none of which affect the logfmt path),
   so the logfmt path remains a single-pass scrub of the raw bytes, identical
   to today's behavior.
5. Move the existing serializer body into `encodeLogfmt(buf, level, event, fields)`.
6. Add `encodeJSON(buf, level, event, fields)`:
   ```go
   func (l *Logger) encodeJSON(buf *bytes.Buffer, level, event string, fields []field) {
       buf.WriteByte('{')
       writeJSONStringField(buf, "ts", l.now().Format(time.RFC3339))
       buf.WriteByte(',')
       writeJSONStringField(buf, "level", level)
       buf.WriteByte(',')
       writeJSONStringField(buf, "event", event)
       // Sort event fields alphabetically by key for stable output.
       sorted := make([]field, len(fields))
       copy(sorted, fields)
       sort.Slice(sorted, func(i, j int) bool { return sorted[i].key < sorted[j].key })
       for _, f := range sorted {
           buf.WriteByte(',')
           writeJSONField(buf, f.key, f.value, f.kind)
       }
       buf.WriteByte('}')
       buf.WriteByte('\n')
   }
   ```
7. To distinguish numeric/boolean/string fields without changing every event
   method's `[]field` literal, extend `field`:
   ```go
   type fieldKind uint8
   const (
       fieldString fieldKind = iota
       fieldInt
       fieldDurationSec
       fieldBool // reserved; no current event uses it
   )
   type field struct {
       key   string
       value string  // canonical string form (used for logfmt)
       kind  fieldKind
       num   int64   // populated when kind == fieldInt
       dur   time.Duration // populated when kind == fieldDurationSec
   }
   ```
   - For logfmt, the encoder continues to use `value` (existing behavior
     preserved bit-for-bit). String forms for ints and durations are produced
     up-front so logfmt golden tests remain byte-stable.
   - For JSON, the encoder uses `num` for `fieldInt` and `dur.Seconds()` for
     `fieldDurationSec`; the latter is emitted as a JSON number with
     `strconv.FormatFloat(.., 'f', -1, 64)` so `1.0` prints as `1` and `0.5`
     prints as `0.5` — well-formed JSON either way. Decision: emit at least
     one decimal digit by post-processing with a `if no '.' append ".0"` step
     so durations are visually distinguishable from counters in tooling.
     (Cheap and stable; covered by tests.)
8. Update every event method to populate the `kind`/`num`/`dur` fields
   instead of pre-stringifying. Concretely, replace `itoa(n)` call sites
   with `{key: "port", kind: fieldInt, num: int64(port), value: itoa(port)}`.
   The `value` is still set so logfmt is byte-identical to today; the new
   `kind`/`num`/`dur` fields are consulted only by `encodeJSON`. Helper:
   ```go
   func intField(key string, n int) field {
       return field{key: key, kind: fieldInt, num: int64(n), value: itoa(n)}
   }
   func durField(key string, d time.Duration) field {
       return field{key: key, kind: fieldDurationSec, dur: d, value: d.String()}
   }
   func strField(key, v string) field {
       return field{key: key, kind: fieldString, value: v}
   }
   ```
   Rewrite each event method using these helpers. No event renames; no field
   renames.

### `internal/logging/format.go` (new file)

Holds the `Format` type, `FormatLogfmt`/`FormatJSON` constants, the
`ParseFormat` function, and a `(Format).String()` for error messages. Keeping
this in its own file makes the test file (`format_test.go`) self-contained and
keeps `logging.go` focused on event emission.

### `internal/logging/json.go` (new file)

Holds `encodeJSON`, `writeJSONField`, `writeJSONStringField`, and the RFC 8259
string escaper. Use `encoding/json`'s `json.Marshal` for string values (so
escape rules are RFC-compliant and battle-tested) and write integers/floats
with `strconv` to avoid `json.Marshal`'s allocations for every primitive. Do
**not** use `json.NewEncoder` for whole-object encoding — manual assembly is
needed for stable field ordering and for the duration-as-float-seconds rule.

Implementation sketch (the whole `field` struct is passed so the duration
case can read `f.dur` directly without re-parsing):

```go
func writeJSONStringField(buf *bytes.Buffer, key, value string) {
    writeJSONKey(buf, key)
    writeJSONString(buf, value)
}

func writeJSONField(buf *bytes.Buffer, f field) {
    writeJSONKey(buf, f.key)
    switch f.kind {
    case fieldInt:
        // f.value already holds the decimal form produced by itoa/intField;
        // safe to write verbatim — digits only, no JSON-special characters.
        buf.WriteString(f.value)
    case fieldDurationSec:
        // Emit as float seconds. f.dur is the canonical source; f.value
        // holds the logfmt string form (e.g. "27s") which must NOT be used
        // here.
        secs := f.dur.Seconds()
        s := strconv.FormatFloat(secs, 'f', -1, 64)
        if !strings.Contains(s, ".") {
            s += ".0"
        }
        buf.WriteString(s)
    default: // fieldString
        writeJSONString(buf, f.value)
    }
}
```

The `encodeJSON` caller is updated accordingly:

```go
for _, f := range sorted {
    buf.WriteByte(',')
    writeJSONField(buf, f)
}
```

The RFC-8259 string writer must escape `"`, `\`, all controls 0x00–0x1F (use
`\uXXXX` for non-shorthand controls, the standard short forms `\b \f \n \r \t`
for 0x08/0x0C/0x0A/0x0D/0x09), and leave all other UTF-8 bytes verbatim. Use
`encoding/json.Marshal` against a `string` for the cleanest, most boring
implementation:

```go
func writeJSONString(buf *bytes.Buffer, s string) {
    b, _ := json.Marshal(s) // cannot fail for a string
    buf.Write(b)
}
```

This is the recommended approach. It allocates one slice per call, which is
acceptable for the few-fields-per-event volume. If profiling later shows this
as a hot spot, replace with a hand-rolled escaper that writes directly into
`buf`.

### `internal/logging/doc.go`

Update the package doc comment to describe both formats and the resolver.
Reference §9 explicitly.

### `cmd/minisshd/main.go`

1. Add a new flag and its `flagSet` sentinel variable, mirroring the existing
   `passSet` / `userSet` / `hostKeySet` pattern exactly:
   ```go
   // In the flag declaration block:
   logFormatFlag = fs.String("log-format", "", "Structured-log format: logfmt (default) or json")
   ```
   ```go
   // In the var block just before fs.Visit:
   var passSet, userSet, hostKeySet, logFormatSet bool
   fs.Visit(func(f *flag.Flag) {
       switch f.Name {
       case "pass":
           passSet = true
       case "user":
           userSet = true
       case "host-key":
           hostKeySet = true
       case "log-format":
           logFormatSet = true
       }
   })
   ```
   The `logFormatSet` variable distinguishes "user supplied `--log-format ""`"
   (error) from "user did not supply the flag" (use env or default), exactly
   as `passSet` handles `--pass ""`.

2. After the §2 step 3 username resolution and before the §2 step 4 shell
   validation, resolve the format:
   ```go
   envFmt, envFmtSet := os.LookupEnv("MINISSHD_LOG_FORMAT")
   logFormat, err := logging.ParseFormat(*logFormatFlag, logFormatSet, envFmt, envFmtSet)
   if err != nil {
       fmt.Fprintf(stderr, "minisshd: %v\n", err)
       return exitBadConfig
   }
   ```

3. Update the existing `logger := logging.New(stdout, password)` call to
   `logger := logging.New(stdout, password, logFormat)`.

4. The §2 step 8 `Password:` banner is unchanged. It is a `fmt.Fprintf` on
   stdout, not a logger call, and explicitly bypasses the format selector
   per the §9 amendment.

### Call-site sweep for `logging.New`

`grep -rn 'logging.New(' .` will list every caller. All 10 call sites must
be updated to the new three-arg `New(w, password, format)` signature:

**Production code (1 site):**
- `cmd/minisshd/main.go` — `logging.New(stdout, password)` → `logging.New(stdout, password, logFormat)`

**Test helpers in `internal/logging` (3 sites):**
- `internal/logging/logging_test.go` — `newTestLogger` helper calls `New(buf, password)` (used by all unit tests including `TestConcurrentEmission` at line 287 which calls `New(buf, "")` directly)
- `internal/logging/logging_integration_test.go` — line 26: `logging.New(&buf, password)` (direct call, not via `newTestLogger`)
- `internal/logging/testhelpers_integration_test.go` — line 75: `logging.New(logBuf, opts.password)`

**Test helpers in `internal/server` (2 sites):**
- `internal/server/testhelpers_integration_test.go` — line 97: `logging.New(logBuf, opts.password)`
- `internal/server/server_test.go` — line 61: `logging.New(&buf, "hunter2")`
- `internal/server/auth_test.go` — line 278: `logging.New(&buf, "supersecret123")`

**Test helpers in other packages (3 sites):**
- `internal/auth/testhelpers_integration_test.go` — line 78: `logging.New(logBuf, opts.password)`
- `internal/ratelimit/testhelpers_integration_test.go` — line 77: `logging.New(logBuf, opts.password)`
- `internal/session/testhelpers_integration_test.go` — line 75: `logging.New(logBuf, opts.password)`
- `internal/session/service_test.go` — line 26: `logging.New(buf, "")` inside `newTestService()`

All test callers that want logfmt (the default, covering all existing tests) pass
`logging.FormatLogfmt`. New JSON-specific tests pass `logging.FormatJSON`. The
`newTestLogger` helper grows a `format` parameter (or gains a sibling
`newJSONTestLogger`). Each `testServerOptions` struct that embeds a log helper
(in `internal/auth`, `internal/ratelimit`, `internal/session`,
`internal/server`, and `internal/logging`) gains a `logFormat` field
defaulting to `FormatLogfmt`; `startTestServer` passes it to `logging.New`.

### No other production-code packages affected

`internal/auth`, `internal/ratelimit`, `internal/hostkey`, `internal/server`,
and `internal/session` all accept a `*logging.Logger` and emit events via its
methods. None of them need to know the wire format. The package abstraction
holds for production code.

Test helpers in `internal/auth`, `internal/ratelimit`, `internal/session`,
and `internal/server` all contain copies of `startTestServer` that call
`logging.New` directly. All of these copies must be updated. Additionally,
`internal/server/server_test.go` and `internal/server/auth_test.go` call
`logging.New` directly in specific test functions. See the call-site sweep
above for the complete list.

---

## Logging — note: this IS the feature, so document the format precisely

### Wire format

One JSON object per line, terminated by exactly one `\n`. No leading
whitespace, no trailing whitespace before the newline, no pretty-printing, no
indentation. The output is line-delimited JSON (JSONL / NDJSON).

### Field schema

Common envelope, present on every event:

| Field | Type | Notes |
|---|---|---|
| `ts` | string | RFC 3339 with timezone (e.g. `"2026-05-17T14:22:01-07:00"`, or `"2026-05-17T14:22:01Z"` for UTC). Byte-identical to the logfmt leading timestamp. |
| `level` | string | `"INFO"`, `"WARN"`, `"ERROR"`. |
| `event` | string | Event name (e.g. `"listening"`, `"conn-open"`). |

Event-specific fields use the exact same key names as the logfmt format and
the same value semantics. Type categories:

| Field | Type | Source |
|---|---|---|
| `bind` | string | `Listening` |
| `port` | integer | `Listening` |
| `fingerprint` | string | `Listening` |
| `user` | string | `Listening`, `AuthOK`, `AuthFail` |
| `pid` | integer | `Listening` |
| `remote` | string | `ConnOpen`, `ConnClose`, `AuthOK`, `AuthFail`, `Session`, `Reject`, `DrainTimeout`, `Error` (optional) |
| `duration` | number (float seconds) in JSON; string (`time.Duration.String()`, e.g. `"27s"`) in logfmt | `ConnClose` |
| `reason` | string | `AuthFail` (`"bad-user"` / `"bad-password"`), `ShutdownSignal` (`"shutdown"` / `"channel-close"`) |
| `attempt` | integer | `AuthFail` |
| `next_delay` | number (float seconds) in JSON; string (`time.Duration.String()`) in logfmt | `AuthFail` |
| `kind` | string | `Session` (`"shell"` / `"exec"` / `"sftp"`), `DrainTimeout` (`"shell"` / `"exec"`) |
| `what` | string | `Reject` |
| `pgid` | integer | `ShutdownSignal` |
| `sig` | string | `ShutdownSignal` |
| `bytes_dropped` | integer | `DrainTimeout` |
| `message` | string | `Error` |

`Error` continues to omit the `remote` field entirely when it is empty — JSON
emits no `"remote"` key in that case, matching the logfmt behavior of
emitting no `remote=` token.

### Value escaping

Strings: RFC 8259 escaping via `encoding/json.Marshal`. This handles `"`,
`\`, and all controls correctly, including non-shorthand controls as
`\uXXXX`. UTF-8 multi-byte sequences pass through verbatim (Go's `json`
package emits valid UTF-8 by default and does not gratuitously escape
non-ASCII).

Numbers (integers): emitted by `strconv.Itoa` / `strconv.FormatInt`.

Durations: emitted as float seconds. `time.Duration.Seconds()` returns a
`float64`; format with `strconv.FormatFloat(v, 'f', -1, 64)`. If the result
contains no `'.'`, append `".0"` so a whole-second duration renders as `1.0`
rather than `1`. This is purely cosmetic but useful for downstream consumers
distinguishing duration fields from counters by inspecting the literal text.

Timestamps: `time.Format(time.RFC3339)` — same call as the logfmt encoder
uses today. Emitted as a JSON string. No millisecond precision is added; the
existing tests fix the seconds-precision timestamp, and downstream consumers
that need finer resolution can request a follow-up that extends both formats
together.

### Ordering

Stable per-event. The envelope `ts`, `level`, `event` always appear first, in
that order. Event-specific fields appear after, sorted alphabetically by key.
JSON does not require any ordering, but stable ordering means:

- Byte-stable golden tests (no map-iteration flakiness).
- Tooling that displays raw lines (`tail -f`, log aggregators) shows fields
  in a predictable place.
- Diffs of two logs are minimal.

Cost of sorting per event: O(n log n) on ~6 fields max. Negligible.

### Newline policy

Each line ends with exactly one `\n` byte. The trailing newline is part of
the line, not separator-between-lines; the last line of any captured output
also ends with `\n` (matching the logfmt encoder's current invariant —
`lastLine` in the unit tests asserts this).

### Password scrub: correctness proof

The existing logfmt scrub is a literal post-encode
`bytes.ReplaceAll(line, []byte(password), []byte("[REDACTED]"))`. The same
operation runs against the post-encode JSON line.

**Scope of the guarantee:** the scrub produces well-formed JSON provided the
password does not contain any structural JSON delimiter character: `,`, `:`,
`{`, `}`, `[`, `]`. Those characters appear verbatim inside JSON string
values (the JSON encoder does not escape them) but also appear as structural
delimiters in the surrounding object. A password such as `","` would cause
the scrub to replace a comma that is a structural delimiter, producing a
malformed object. This is the same class of operator footgun that affects
logfmt with passwords containing `=`, space, or `"`. Operators must not
configure such passwords when JSON output is selected.

For all other passwords (i.e., passwords whose bytes do not include the six
delimiter characters above), the scrub is safe by the following case
analysis:

Case 1 — password appears as part of an encoded string field's content.
JSON-escape rules guarantee that the encoded form of any string field cannot
contain a raw `"` (escaped as `\"`) or a raw `\` (escaped as `\\`) outside
of escape sequences. The replacement string `[REDACTED]` contains none of
`"`, `\`, control bytes, or structural JSON delimiters. Replacing the
encoded password bytes with `[REDACTED]` therefore yields a string field
whose contents contain only `[`, `R`, `E`, `D`, `A`, `C`, `T`, `E`, `]` —
all of which are legal inside a JSON string literal with no escaping
required. The enclosing quotes are preserved (the scrub is interior to them).

Case 2 — password appears as part of a key. Keys are always literal ASCII
identifiers we control (`"ts"`, `"level"`, `"event"`, `"bind"`, …). None of
those keys contain the password (unless the password literally equals one of
these short tokens, in which case the scrub would mangle a key — but the
unit tests verify even short passwords like `"event"` round-trip safely
because no key name is *exactly* the password, and partial-key replacement
is impossible since `[REDACTED]` is longer than any of the existing keys
*and* keys are wrapped in `"…"` quotes that the password substring won't
include).

Actually, to be airtight: if a user configured `--pass event`, the byte
sequence `event` appears in the literal key `"event"` in every emitted line.
The scrub would replace it, producing `"[REDACTED]":"listening"` — still
valid JSON, just with a renamed key. This is unfortunate but does not break
JSON. Tests assert validity, not stability of key names against
adversarially-chosen passwords. The same caveat applies to logfmt today
(if `--pass listening`, the event name would be scrubbed to `[REDACTED]`).
The spec amendment does not change this property; both formats are equally
vulnerable to this self-inflicted footgun and the operator is expected to
not use spec-defined identifiers as passwords.

Case 3 — password appears spanning a boundary (partly in a string value,
partly in a structural character). Impossible for passwords that do not
contain the structural delimiter characters listed above: the password is a
contiguous byte sequence; the only way it could span a `"` would be if the
password contained `"` and that `"` were unescaped in the output. But the
encoder escapes every `"` inside a string value as `\"`, so the password's
`"` is encoded as `\"` (two bytes) in the output. The byte sequence of the
password (with a raw `"`) does not appear in the encoded output verbatim.
Therefore the scrub against the raw password value would not match any
encoded bytes, and a separate scrub against the encoded form is required.

**This is the critical correctness subtlety.** The scrub as written replaces
the *raw* password bytes. If the password is `"hello"world` (contains a
quote), the encoded form in the JSON output is `\"hello\"world`. The raw
password bytes `"hello"world` (with unescaped quotes) **do not appear** in
the encoded JSON line, so `bytes.ReplaceAll(line, "\"hello\"world", "[REDACTED]")`
matches nothing and the password leaks (as the escaped form).

**Fix:** when the password contains any JSON metacharacter (`"`, `\`, or any
control byte 0x00–0x1F), the scrub must also run against the
JSON-encoded form of the password. Concretely, compute both the raw and the
JSON-encoded form of the password at logger construction time, and run two
`bytes.ReplaceAll` passes — first against the encoded form (longer; matches
the JSON output), then against the raw form (still useful for the logfmt
case and as defense-in-depth for any non-JSON path).

```go
func New(w io.Writer, password string, format Format) *Logger {
    l := &Logger{w: w, format: format, now: time.Now}
    if password != "" {
        l.scrubs = [][]byte{[]byte(password)}
        // Also scrub the JSON-encoded form so passwords containing ",
        // \, or controls cannot leak as their escaped form.
        if encoded, _ := json.Marshal(password); len(encoded) >= 2 {
            // Strip the leading/trailing quote bytes — we want the inner
            // escaped content, since string values appear inside quotes
            // in the output. Only add if it differs from the raw form
            // (i.e., the password contained an escapable byte).
            inner := encoded[1 : len(encoded)-1]
            if !bytes.Equal(inner, []byte(password)) {
                l.scrubs = append(l.scrubs, inner)
            }
        }
    }
    return l
}
```

The `emit` step then iterates `l.scrubs` and runs `bytes.ReplaceAll` for each.
This keeps the logfmt path identical (one scrub of the raw bytes) and makes
the JSON path correct (additional scrub of the JSON-escaped bytes).

This subtlety is the most important single deliverable of this plan.
**Implementers MUST include this dual-scrub logic and the test that verifies
it** (test fixture: password `"hello"world`, JSON format, assert raw
password absent AND escaped form absent from output, AND output parses as
JSON).

### Worked example with a quote in the password

Password configured: `"hello"world`

Configured-credential JSON encoding of the password value:
`"\"hello\"world"` (10 chars between outer quotes).

Stored scrub set (per the constructor above):
- raw: `"hello"world` (12 bytes including the two quotes)
- encoded inner: `\"hello\"world` (14 bytes: `\`, `"`, `h`, `e`, `l`, `l`,
  `o`, `\`, `"`, `w`, `o`, `r`, `l`, `d`)

Suppose a buggy call site passes the password as the `user` field of an
`auth-ok` event. The JSON-encoded line before scrub:

```
{"ts":"2026-05-17T14:22:01Z","level":"INFO","event":"auth-ok","remote":"1.2.3.4:5","user":"\"hello\"world"}
```

After scrub pass 1 (encoded form `\"hello\"world` → `[REDACTED]`):

```
{"ts":"2026-05-17T14:22:01Z","level":"INFO","event":"auth-ok","remote":"1.2.3.4:5","user":"[REDACTED]"}
```

Pass 2 (raw form `"hello"world`) matches nothing — those raw bytes don't
appear in the output.

The result is valid JSON. `json.Unmarshal` parses it to a map with
`user="[REDACTED]"`. The literal password bytes never appear. **This is the
invariant the new test must lock down.**

---

## Tests

All tests use the standard `testing` package — no testify, no ginkgo.

### Unit — `internal/logging/format_test.go` (new)

- `TestParseFormat_Default` — empty flag, no env → `FormatLogfmt`, no error.
- `TestParseFormat_FlagWins` — flag `"json"`, env `"logfmt"` → `FormatJSON`.
- `TestParseFormat_EnvUsedWhenFlagUnset` — flag unset, env `"json"` →
  `FormatJSON`.
- `TestParseFormat_RejectsExplicitEmpty` — flag set to `""` → error mentions
  the rejected value.
- `TestParseFormat_RejectsUnknown` — flag `"xml"` → error mentions `"xml"`;
  env `"yaml"` → error mentions `"yaml"`.
- `TestParseFormat_RejectsCaseMismatch` — flag `"JSON"` → error (case
  sensitive by design; matches the spec's lowercase enum).

### Unit — `internal/logging/logging_test.go` (extended)

For each of the 11 existing cases in `TestEnvelopes`, add a JSON twin:

- `TestEnvelopes_JSON` — same case table, but the logger is built with
  `FormatJSON`. For each case, assert:
  1. The emitted line parses cleanly with `json.Unmarshal` into a
     `map[string]any`.
  2. The map contains exactly the expected keys (envelope `ts`, `level`,
     `event`, plus the event-specific keys).
  3. Each expected key has the correct JSON type (string / number / bool).
  4. Numeric duration fields equal the expected float seconds (e.g.
     `27.0`, `1.0`).

Additional JSON-specific tests:

- `TestJSONEnvelope_FieldOrder` — emit `Listening` in JSON mode, assert the
  byte sequence begins with `{"ts":` and that the next three keys are
  `"level"`, `"event"`, then alphabetical event-specific keys.
- `TestJSONEnvelope_TrailingNewline` — every emitted line ends with exactly
  one `\n`.
- `TestJSON_ErrorOmitsEmptyRemote` — `Error("disk full", "")` in JSON mode
  → the emitted object has no `"remote"` key (mirroring the logfmt
  `TestErrorOmitsEmptyRemote`).
- `TestJSON_StringEscape` — emit `AuthOK("1.2.3.4:5", "user\"with quote")`,
  parse with `json.Unmarshal`, assert the parsed `user` field equals the
  literal input (round-trip).
- `TestJSON_DurationAsFloatSeconds` — emit `ConnClose("r", 1500*time.Millisecond)`,
  parse the line, assert `duration == 1.5` (`float64`).
- `TestJSON_DurationWholeSecondsHasDecimal` — emit
  `ConnClose("r", 1*time.Second)`, assert the raw line contains `"duration":1.0`
  (with the `.0`).
- `TestJSON_LineIsValidJSON` — exhaustive smoke: call every event method
  once and assert each emitted line is valid JSON.

### Unit — JSON password scrub (the load-bearing test)

- `TestJSON_ScrubWithQuoteInPassword` — configure logger with password
  `"hello"world` (literal: `[0x22, 'h', 'e', 'l', 'l', 'o', 0x22, 'w', 'o', 'r', 'l', 'd']`),
  emit every event with the password as a field value (mirror
  `TestPasswordScrubGuard`), then:
  - Assert each emitted line is valid JSON (`json.Unmarshal` succeeds for
    every line).
  - Assert the raw password byte sequence `"hello"world` does not appear in
    the captured output (substring check).
  - Assert the JSON-encoded form `\"hello\"world` does not appear in the
    captured output (substring check).
  - Assert `[REDACTED]` appears in the captured output (at least one
    occurrence per emitted line).
- `TestJSON_ScrubWithBackslashInPassword` — same shape but password is
  `back\slash`; assert the raw and the encoded form `back\\slash` are both
  absent from the output.
- `TestJSON_ScrubWithControlCharInPassword` — password is `"hi\n"` (literal
  newline byte); the encoded form is `hi\n`. Assert the raw newline bytes
  inside a password don't appear in the output (the encoder won't emit a
  raw newline anyway, but the dual-scrub covers the encoded `hi\n` form).
- `TestLogfmt_PasswordScrubUnchanged` — regression: with the new
  `scrubs [][]byte` field, the existing logfmt password-scrub guard test
  still passes byte-for-byte.

### Unit — `cmd/minisshd/main.go` startup validation

Tests live in `cmd/minisshd/main_test.go` (already exists alongside `main.go`).

**Sentinel note:** `runUntilListening` (line 95 of `main_test.go`) waits for
the substring `" listening "` (with flanking spaces). This sentinel matches
logfmt output (`... INFO listening bind=...`) but does **not** match JSON
output (`{"ts":...,"event":"listening",...}`). The two new tests that reach
the listening event in JSON mode must **not** use `runUntilListening`
unmodified. Options:

1. Add a parallel helper `runUntilListeningJSON` that waits for
   `"\"event\":\"listening\""` instead of `" listening "`.
2. Extend `runUntilListening` to accept a custom sentinel string, and pass
   the appropriate one per format.

Either option is acceptable; the implementer must choose one and document the
choice. The key constraint: neither `TestRun_LogFormatEnvIsRespected` nor
`TestRun_LogFormatBannerUnaffected` may silently time-out because they are
waiting for a sentinel that will never appear.

- `TestRun_LogFormatUnknownValue` — invoke `run` with `--log-format xml`,
  assert exit code 2 and stderr contains both the prefix `minisshd:` and
  the substring `xml`. Uses `runToCompletion`, no sentinel issue.
- `TestRun_LogFormatExplicitEmpty` — `--log-format ""`, assert exit code 2.
  Uses `runToCompletion`, no sentinel issue.
- `TestRun_LogFormatEnvIsRespected` — set `MINISSHD_LOG_FORMAT=json`, no
  flag, drive a startup using a JSON-mode listening sentinel (see note
  above), assert the first emitted line (the `listening` event) is valid
  JSON (parses with `json.Unmarshal` into a `map[string]any`).
- `TestRun_LogFormatFlagWinsOverEnv` — set `MINISSHD_LOG_FORMAT=json`, pass
  `--log-format logfmt`, assert the `listening` line is logfmt
  (`2026-...` prefix + `INFO listening`). Uses `runUntilListening` with the
  standard `" listening "` sentinel (logfmt output).
- `TestRun_LogFormatBannerUnaffected` — start with no `--pass` and
  `--log-format json`, capture stdout using a JSON-mode listening sentinel
  (see note above), assert stdout begins with `Password: \d{6}\n` (the
  banner, unchanged) followed by valid JSON containing `"event":"listening"`.

### Integration — `internal/logging/logging_integration_test.go` (extended)

- `TestIntegration_JSONLogCapture` — start the test server with the new
  `LogFormat: logging.FormatJSON` option (the harness in
  `testhelpers_integration_test.go` gains this field), drive one good auth
  and one bad auth, split captured stdout on `\n`, `json.Unmarshal` each
  line, assert:
  - At least one `listening` event with the expected fields and types.
  - One `conn-open` and one `conn-close` event per successful auth.
  - One `auth-ok` event with `user` matching the configured user.
  - One `auth-fail` event with `reason=="bad-password"`, `attempt` is an
    integer `>= 1`, `next_delay` is a float `>= 0`.
- `TestIntegration_JSONPasswordScrub_QuoteInPassword` — start the test
  server with password `"hello"world` and `LogFormat: FormatJSON`. Drive a
  failed auth attempt (so the password appears in the auth-fail context if
  any call site is buggy). Capture all output, assert:
  - Every line is valid JSON.
  - Raw `"hello"world` never appears.
  - Encoded `\"hello\"world` never appears.

### Test-harness updates

`internal/logging/testhelpers_integration_test.go` and
`internal/server/testhelpers_integration_test.go` both grow a `logFormat`
field on `testServerOptions`, defaulting to `FormatLogfmt`. `startTestServer`
passes it to `logging.New`. Existing tests are unaffected (they pass the
zero value, which equals `FormatLogfmt`).

### Coverage

The new files (`internal/logging/format.go`, `internal/logging/json.go`)
must be covered to the ≥ 90% threshold. The dual-scrub branch (the
`json.Marshal`-of-password path) must be covered by both the
quote-in-password and the no-special-character cases. No coverage exclusions
are added; `internal/version` remains the sole exclusion.

---

## Backwards compatibility

- Default behavior is unchanged. With neither `--log-format` nor
  `MINISSHD_LOG_FORMAT` set, the logger emits logfmt exactly as today.
- All existing logfmt golden tests stay green byte-for-byte. The encoder
  refactor preserves the existing `value` string serialization; the new
  `kind`/`num`/`dur` fields are inert for the logfmt path.
- `logging.New`'s signature changes from `(w, password)` to
  `(w, password, format)`. This is a breaking change to in-tree callers
  only (four call sites). External consumers do not exist — the package is
  `internal/`. All four call sites are updated in the same change.
- The `Password: XXXXXX` banner remains a `fmt.Fprintf` on stdout from
  `cmd/minisshd/main.go`. It is unaffected by the new flag. CLAUDE.md's
  "the §2 step 8 password banner in `cmd/minisshd/main.go` is the single
  documented exception" remains true.
- No event names are renamed. No field names are renamed. No existing
  call site of an event method changes.
- The exit-code taxonomy is unchanged. Invalid `--log-format` exits 2
  (same as other §11 config errors).
- The CI gates (`go vet`, `gofmt -l .`, `go mod tidy`, the `make` targets)
  are unchanged. `encoding/json` and `strconv` are already in the
  standard-library transitive set; no new third-party dependency.

---

## Definition of done

A reviewer can mark this feature done when **all** of the following hold:

1. **Spec amended.** `SPEC.md` §9 reflects the
   format selector, the JSON wire format, the dual-scrub invariant, and the
   banner exception. §12 no longer lists "structured JSON output" as a
   non-goal. §2 lists the new flag and env var. §11 lists the new error
   row. §13 lists the new test cases.

2. **Code lands.**
   - `internal/logging/format.go` exists, exports `Format`, `FormatLogfmt`,
     `FormatJSON`, and `ParseFormat` with the signature in this plan.
   - `internal/logging/json.go` exists and implements the encoder described
     in "Logging" above.
   - `internal/logging/logging.go` dispatches in `emit` and implements the
     dual scrub (raw + JSON-encoded password).
   - `cmd/minisshd/main.go` wires the new flag, resolves it (precedence
     flag > env > default), and threads the resolved `Format` into
     `logging.New`.
   - The §2 step 8 password banner is untouched and continues to write
     directly to stdout.

3. **Tests pass.**
   - `go test ./...` is green.
   - `go test -race ./...` is green.
   - `make test`, `make test-slow`, `make test-race`, `make e2e`,
     `make coverage` are all green on macOS and Linux runners.
   - Every existing logfmt test passes byte-for-byte (refactor is a
     behavior-preserving change for the default path).
   - All new tests in §"Tests" above exist and pass.
   - The load-bearing JSON scrub test (`TestJSON_ScrubWithQuoteInPassword`)
     passes — this is the canary that the dual-scrub is in place.

4. **Gates pass.**
   - `go vet ./...` clean.
   - `gofmt -l .` prints nothing.
   - `go mod tidy` produces no changes (no new third-party imports;
     `encoding/json` and `strconv` are stdlib).
   - Combined coverage is `≥ 90.0%` per the Makefile threshold.

5. **No emoji** anywhere in code or docs, per project convention.

6. **README.md unchanged** unless the user requests an update (per CLAUDE.md
   guidance not to proactively touch docs). The spec is the contract; the
   README is for users.

---

## Open questions / risks

### Open questions

1. **Should the JSON timestamp include sub-second precision?**
   Current behavior in logfmt is `time.RFC3339` (whole seconds). The plan
   keeps this in JSON for parity. A common request from log aggregators is
   millisecond precision (`time.RFC3339Nano` clipped to 3 fractional
   digits). Recommendation: defer to a follow-up that updates both formats
   together, so the wire-format parity invariant holds. Note in the spec
   amendment that the timestamp format is byte-identical across formats.

2. **Should `level` be lowercase in JSON?**
   Common convention in JSON logs is lowercase (`"info"`, `"warn"`,
   `"error"`). The plan keeps uppercase for parity with logfmt. If the
   user prefers lowercase for JSON consumers, that is a small follow-up
   change and the spec amendment can land either way; this plan documents
   uppercase. Recommendation: keep uppercase, document in the §9 amendment
   that levels are uppercase in both formats.

3. **Should the JSON encoder emit `null` for the omitted `remote` field
   in `Error`, or omit the key entirely?**
   The plan specifies omit-the-key (matches logfmt's omit-the-token
   behavior). Tests assert this. If a downstream consumer expects a stable
   schema with always-present keys, that's a breaking change to discuss
   separately. Recommendation: omit-the-key for now.

4. **Should `auth-fail`'s `next_delay` be in seconds (float) or
   milliseconds (int)?**
   Plan chose seconds-float for consistency with `duration`. Alternative:
   express both as integer milliseconds. The seconds-float choice is more
   human-readable in `tail -f` and matches Prometheus's idiom. Either is
   defensible; the plan picks seconds-float and the spec amendment
   documents it.

### Risks

1. **Password-scrub correctness with adversarial passwords.**
   The dual-scrub (raw + JSON-encoded) covers `"`, `\`, and control bytes
   so the encoded form of those characters in a password is found and
   replaced. UTF-8 multi-byte sequences pass through both encoders
   unchanged, so the raw scrub catches them. However, the structural JSON
   delimiter characters (`,`, `:`, `{`, `}`, `[`, `]`) are NOT escaped inside
   JSON string values, so a password containing any of them can cause the
   scrub to replace delimiter bytes that are part of the surrounding JSON
   structure, producing malformed JSON. The spec amendment explicitly
   documents this caveat and directs operators not to use such passwords with
   JSON output. The remaining failure mode is a password that equals a
   spec-defined key or event name (e.g. `--pass listening`), which would
   cause the scrub to mangle a key or event name. This is identical to the
   existing logfmt behavior and is not made worse by the new format.
   Mitigation: a `TestJSON_ScrubDoesNotBreakWellFormedness` test that runs
   property-based fuzz over passwords drawn from printable ASCII minus the
   six structural delimiters for, say, 1000 trials, asserting every emitted
   line still parses as JSON. (Property test, not in the minimum bar, but
   the implementer may add it.)

2. **`json.Marshal` allocations.**
   The recommended `writeJSONString` wraps `json.Marshal`, which allocates
   a new byte slice per call. Per emitted event we make ~6 string-field
   marshals plus ~3 envelope marshals. For the expected event rate of a
   single-user LAN server, this is negligible. If it ever matters, replace
   with a hand-rolled escaper; the unit-test contract (round-trip via
   `json.Unmarshal`) means the replacement is safe.

3. **Wire-format drift if the field-type table in §9 evolves.**
   Future events that add new fields need to declare their JSON type
   (string / integer / duration-seconds-float / bool) in the spec at the
   point of introduction. The `fieldKind` enum makes this explicit at the
   call site, and the JSON encoder dispatch enforces it. Documentation:
   the §9 amendment explicitly says "all other event-defined fields
   preserve the type categories above" so future contributors know to
   classify new fields when they add them.

4. **Coverage drop from the refactor.**
   The split of `emit` into `encodeLogfmt` and `encodeJSON` adds branches.
   New tests must cover both paths. The plan's "Tests" section pairs every
   existing logfmt test with a JSON twin and adds JSON-only tests for the
   scrub edge cases, so the coverage threshold is achievable without
   exclusions.

5. **`go test -race` flakiness from the new sort in `encodeJSON`.**
   The sort runs on a local `[]field` copy and does not touch shared
   state. `sync.Mutex` continues to serialize writes to the writer. No
   new race risk.

6. **Spec-vs-code drift if the plan is implemented but the spec amendment
   is dropped.** The implementation pass must land both. CLAUDE.md is
   explicit that the spec is the contract. Reviewer checks: did
   `SPEC.md` change in the same PR as the code? If
   not, request the spec amendment.

---

## Adversarial review responses (iter 1)

**C1 — Correctness proof is false for structural JSON characters**

Agreed. The plan incorrectly claimed unconditional well-formedness. The structural
JSON delimiter characters (`,`, `:`, `{`, `}`, `[`, `]`) pass through `json.Marshal`
of a string value verbatim, so they appear at both structural positions and inside
string values in the output. A password containing `,` would match a structural
comma and the scrub would produce a malformed object. This is verified correct.

Disposition: chose option (1) from the reviewer's list — added the explicit caveat
to the §9 spec-amendment text and to the "Password scrub: correctness proof" section.
Updated Risk 1 accordingly. Did not add startup validation (option 2) because the
existing project posture for analogous logfmt-unsafe passwords is documentation, not
rejection. Did not promote the property-based fuzz test to required (option 3), but
retained it in the risks section as a recommended addition.

**S1 — Call-site sweep is incomplete (4 sites listed, 10 exist)**

Agreed. The reviewer's enumeration is correct as verified by reading the source files.
The plan listed only 4 sites and missed 6 others. Disposition: expanded the call-site
sweep to all 10 sites, grouped by file, with approximate line numbers. Corrected the
"no other packages affected" claim.

**S2 — `writeJSONField` sketch internally inconsistent for durations**

Agreed. The original sketch passed `f.value` (the logfmt string like `"27s"`) to the
duration case, which would emit the wrong type. Reading the `field` struct definition
confirms `f.dur` holds the canonical `time.Duration`. Disposition: rewrote the sketch
to pass the whole `field` struct and gave a complete, concrete duration case using
`f.dur.Seconds()` and `strconv.FormatFloat`. Removed the "illustrative" disclaimer.

**S3 — `runUntilListening` uses `" listening "` sentinel that won't match JSON**

Agreed. Verified by reading `main_test.go` line 95: the sentinel is `" listening "`
with flanking spaces. In JSON output the event appears as `"event":"listening"` with
no flanking spaces. Both new JSON-reaching startup tests
(`TestRun_LogFormatEnvIsRespected` and `TestRun_LogFormatBannerUnaffected`) would
silently time-out without a fix. Disposition: added a prominent note in the Tests
section specifying the issue, naming the two affected tests, and requiring either a
parallel `runUntilListeningJSON` helper or an extended `runUntilListening` with a
custom sentinel parameter. Left the implementation choice to the implementer to avoid
over-specifying the helper shape.

**S4 — `logFormatSet` referenced but never declared**

Agreed. The plan said "mirror the existing `passSet` pattern" without showing the
`var logFormatSet bool` declaration or the `case "log-format": logFormatSet = true`
line in the `fs.Visit` switch block. Without these the code would not compile.
Disposition: showed the complete updated `var` block and the updated `fs.Visit`
switch in the `cmd/minisshd/main.go` section.

**M1 — `TestConcurrentEmission` calls `New` directly inside the logging package**

Agreed. `TestConcurrentEmission` at `logging_test.go` line 287 calls `New(buf, "")`
directly (not via `newTestLogger`). This is a direct call that must be updated to the
three-arg signature. Disposition: added this to the call-site sweep.

**M2 — Duration schema differs between formats; needs a callout**

Agreed. The field schema table listed `duration` and `next_delay` as "number (float
seconds)" without noting that logfmt emits `time.Duration.String()`. Consumers
switching between formats would be surprised. Disposition: updated both table rows to
show the type in each format explicitly, and added a sentence to the §9 spec-amendment
text noting the difference.

**M3 — "Always present, always first" applies to JSON only**

Agreed. The logfmt encoder writes fields in insertion order (which is stable in
practice) but makes no formal guarantee. The "always present, always first" claim
should be scoped to the JSON encoder, which the plan controls explicitly. Disposition:
updated the `ts`, `level`, and `event` bullet points in the §9 spec amendment to
qualify the ordering guarantee as JSON-only.

**M4 — "No other packages affected" is literally false**

Agreed. The claim was meant to say production packages are unaffected (still true),
but test helpers in `internal/auth`, `internal/ratelimit`, `internal/session`, and
test files in `internal/server` and `internal/logging` all call `logging.New` and
must be updated. Disposition: rewrote the section to accurately distinguish production
code from test helpers, matching the expanded call-site sweep.

---

## Adversarial review responses (iter 2)

**S1 — `emit` sketch uses `l.password` instead of iterating `l.scrubs`**

Agreed. The issue is correct: the `New` constructor sketch stored both scrub
forms in `l.scrubs`, the prose said "emit should iterate `l.scrubs`", but the
authoritative `emit` code sketch still used
`bytes.ReplaceAll(line, []byte(l.password), []byte(redacted))` — meaning an
implementer following the sketches literally would populate `l.scrubs[1]` and
never apply it, defeating the dual-scrub entirely.

Disposition: three coordinated fixes applied in this iteration.

1. The `emit` sketch now uses a `for _, s := range l.scrubs` loop with a
   `len(l.scrubs) > 0` guard. The single `l.password` scrub line is removed.
2. The `Logger` struct sketch removes the `password string` field entirely.
   `scrubs[0]` holds the raw bytes; storing the string form separately was
   redundant and created a footgun (a future caller might reach for
   `l.password` instead of `l.scrubs`).
3. The `New` constructor sketch drops the `l.password = password` assignment
   (the field no longer exists). The `l.scrubs` population logic is unchanged.
   The empty-password fast path is preserved: when `password == ""`, `New`
   leaves `l.scrubs` nil, and the `len(l.scrubs) == 0` guard in `emit` skips
   the loop — equivalent to the old `if l.password != ""` check.
