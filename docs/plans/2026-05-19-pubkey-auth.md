# Plan: Public-key authentication for minisshd (2026-05-19)

## Changelog (iter 2 → iter 3)

- **Fix A**: Corrected the `publickeyCallback` doc comment. The library calls `PublicKeyCallback` unconditionally on the first encounter of a key (before the `isQuery` branch), then caches the result (size-1 cache per connection). The callback fires for both queries (`isQuery=true`) and real signatures (`isQuery=false`); it cannot distinguish between the two. Removed the false claim that the library filters queries before reaching the callback.
- **Fix B**: Rate-limiter design decision: Option (i) accepted — queries feed the rate limiter. The `lim.Acquire` call runs on every `PublicKeyCallback` invocation, including probes. This is a deliberate, tighter-than-OpenSSH posture; documented with a justification paragraph and flagged in tests.
- **Fix C**: MaxAuthTries math revised. Rejected-key queries (`isQuery=true`, `authErr != nil`) fall through to `authFailures++` in the library. A client probing N rejected keys before signing burns N `MaxAuthTries` slots. Raised `MaxAuthTries = 6` to provide ~3 real attempts even after 3 probes; updated `TestIntegration_MaxAuthTriesCombinedCounter` spec accordingly.
- **Fix D**: Acknowledged cache-size-1 subtlety. When a client probes key A (which fails, so NOT cached as an accept), then key B, then signs with key A — the cache misses on A's sign attempt and `PublicKeyCallback` fires again. Rate-limit `Acquire` runs twice for key A across that sequence. Documented and accepted.
- **Fix E**: Open question 6 rewritten to reflect that queries DO feed the rate limiter, with the chosen design decision and rationale inline.

## Changelog (iter 1 → iter 2)

- **C1**: Explicitly listed `passwordCallback` call-site update (pass `method="password"`, `fingerprint=""`) and the `recordingAuthLogger` stub update in the file-change steps for `internal/server/auth.go` and `auth_test.go`.
- **C2**: Clarified the `ok := userOK && keyOK` combination in `publickeyCallback`: `CheckUsername` returns `(bool, string)` (not `(int, string)`), so both results are pre-materialized before `&&` evaluates — no branch is possible. Added explicit comment in the proposed code and a note in spec §4 text. Also updated the "muddled" comment cited by the top-level accuracy note.
- **C3**: Added explicit reconciliation note in §2.1 spec text: `MaxAuthTries = 3` is a catch-up amendment (the code was already ahead of the spec) and requires `TestIntegration_MaxAuthTriesCombinedCounter` before the spec value is committed.
- **C4 / S7**: Removed the incorrect `--pass`/`MINISSHD_PASS` condition from the unauthenticable-configuration check (§2.2 step 2c and the code-changes section). The check is now: `methods == {publickey}` AND zero keys loaded — unconditionally.
- **C5**: Specified that `Config.Methods` nil/empty defaults to `["password"]` in `newServerConfig`, and explicitly listed `TestNewServerConfig_OnlyPasswordAuthOffered` and `newTestServer` as needing updates.
- **S1**: Added a doc-comment note in `publickeyCallback`'s description that the library invokes the callback only for real signature verifications, not for pubkey queries (`has_signature=false`).
- **S2**: Added context-gating to the SIGHUP goroutine: the loop exits when `ctx.Done()` fires, preventing a reload racing against a partially-torn-down logger during the drain phase.
- **S3**: Added compile-time assertion `var _ pubkeyLogger = (*logging.Logger)(nil)` in `internal/server/auth.go` alongside the existing assertions.
- **S4**: Specified the exact Go code pattern for the empty-keyset branch: `matched = 0` after the dummy compare, explicitly preventing a false positive on an all-zero presented key.
- **S6**: Added a sentence to the spec amendment's reload paragraph explicitly describing the zero-key-reload-treated-as-failure policy and the rationale.
- **M1**: Added a catch-up-amendment note next to `MaxAuthTries = 3` in the spec prose.
- **M5**: Rewrote the `CheckUsername` doc comment for clarity.
- **M7**: Changed "matched == 1" comment to "matched != 0" in `Keyset.Check` description.
- **Accuracy note 1**: Aligned `atomic.Pointer[Keyset]` usage — spec amendment prose now says `atomic.Pointer[Keyset]` consistently.
- **Accuracy note 2**: Rewrote the muddled comment in `publickeyCallback` step 5 for clarity.
- **M6**: Audited §12 for other "key-based auth" references; disposition documented in adversarial review responses.

## 1. Summary

Add SSH public-key authentication alongside the existing password
authentication, gated by a new `--auth` selector flag that lets the operator
pick `password`, `publickey`, or any comma-separated combination. Accepted
public keys are loaded from a project-specific authorized-keys file (default
`$XDG_CONFIG_HOME/minisshd/authorized_keys`, falling back to
`~/.config/minisshd/authorized_keys`), parsed with
`golang.org/x/crypto/ssh.ParseAuthorizedKey`, and reloaded on `SIGHUP`. Every
existing minisshd invariant is preserved: the configured username remains
independent of system users, password-path constant-time semantics are
untouched, the publickey path uses the same `subtle.ConstantTimeCompare`
discipline over SHA-256 digests with a non-short-circuiting iteration over the
keyset, per-IP rate-limit state covers pubkey failures, and the password scrub
in `internal/logging` continues to apply unconditionally.

## 2. Spec amendments

Every section below quotes the current wording verbatim and proposes the exact
replacement wording. This plan is the contract for the implementation pass;
spec text outside these blocks is unchanged.

### 2.1 §4 — Authentication (whole-section rewrite)

Current §4 reads (verbatim, lines 72-99 of `SPEC.md`):

> ## 4. Authentication
>
> ### Method
>
> Only the SSH **`password`** authentication method is offered. `publickey`, `keyboard-interactive`, and all others are not advertised. The `none` method is part of the SSH negotiation flow — the server responds to a `none` attempt by listing `password` as the only allowed method, then rejects it.
>
> The server must guarantee **3 real password attempts per connection** before disconnecting. Because `golang.org/x/crypto/ssh`'s `MaxAuthTries` counter increments on the mandatory `none` probe as well as on password failures, setting `MaxAuthTries = 3` would deliver only 2 password attempts. The spec therefore requires `MaxAuthTries = 4` (allowing one `none` + three passwords), with an integration test (§13.3) that proves a client offering 10 password attempts is disconnected on the third *password* failure, not earlier and not later. Implementers in other languages must implement the same guarantee: count password failures only.
>
> ### Credential check
>
> To prevent timing attacks that distinguish wrong-user from wrong-password (or reveal the configured password length), the check must:
>
> 1. Compute SHA-256 over the presented username and over the presented password. The implementation pre-computes and caches SHA-256 of the resolved configured username and password after the password is finalized (per §2 step 2 if supplied via `--pass` or `MINISSHD_PASS`, or §2 step 8 if auto-generated) and before the listener accepts its first connection, so every auth callback compares against cached digests. SHA-256 over arbitrary-length input always produces 32 bytes, so equal-length comparison is guaranteed.
> 2. Compare each presented hash to the configured hash with `subtle.ConstantTimeCompare`. **Both comparisons must always run** — do not short-circuit on the first mismatch. Use `subtle.ConstantTimeSelect` or two boolean ANDs to combine the results without branching.
> 3. Decide the result:
>    - both match → `(ok=true, reason="")`
>    - user-hash mismatch, password-hash match → `(ok=false, reason="bad-user")`
>    - user-hash match, password-hash mismatch → `(ok=false, reason="bad-password")`
>    - both mismatch → `(ok=false, reason="bad-user")` (user wins for logging — keeps the reason field decisive when both are wrong)
>
> The client sees a generic "Permission denied (password)" in all failure cases; only the logs distinguish the reasons (see §9).
>
> **Residual side-channel:** SHA-256 itself is not constant-time over input length — a password that fills two blocks (≥ 56 bytes) takes measurably more CPU than one that fits in one block. The leak is at the block-count level (a handful of cycles per block), far smaller than a byte-by-byte string compare, and dwarfed by network jitter and the rate-limit backoff in §5. For the threat model this spec targets (single-user LAN server, 60 s backoff cap, 6-digit auto-generated default), the residual leak is acceptable. Spec implementers must not claim "fully constant-time auth"; the claim is "constant-time given equal-length inputs, with sub-cycle differences between length classes."
>
> ### Failure semantics
>
> The 3-attempt-per-connection cap is described in §4 (Method). Cross-connection failures feed the rate limiter — see §5.

Proposed replacement §4 (whole section):

```markdown
## 4. Authentication

### Methods

The server advertises the SSH authentication methods listed by `--auth` (§2).
Valid values are `password`, `publickey`, or any comma-separated combination
(`password,publickey`, `publickey,password`). Order is significant only for the
order in which the server lists methods in the `SSH_MSG_USERAUTH_FAILURE`
methods list; semantics are **any-of** — the client must satisfy *at least one*
listed method, matching OpenSSH's behavior when both `PasswordAuthentication`
and `PubkeyAuthentication` are `yes`. The default is `password`, preserving
pre-pubkey behavior.

`keyboard-interactive` and all other methods are not advertised. The `none`
method is part of the SSH negotiation flow — the server responds to a `none`
attempt by listing the configured methods, then rejects it.

The configured username (§2 step 3) gates **every** method. For publickey
auth, the username supplied by the client in the `SSH_MSG_USERAUTH_REQUEST`
must match the configured username under the same constant-time check used
for password auth (see Credential check below).

The server allows up to **`MaxAuthTries = 6` combined auth failures per
connection** before disconnecting. A "failure" is any auth attempt the
server rejects — either a password attempt, a publickey signature failure,
or a rejected-key pubkey **query** (the probe where the client asks "would
you accept this key?" against an unknown key). Password failures, publickey
signature failures, and rejected-key queries all share a single combined
`authFailures` counter in `golang.org/x/crypto/ssh`. The spec sets
`MaxAuthTries = 6` (**breaking from the previous catch-up value of 3**;
rationale below). The current `golang.org/x/crypto/ssh` library (v0.51.0,
`ssh/server.go: serverAuthenticate`) exempts only the mandatory initial `none`
probe from this counter ("Allow initial attempt of 'none' without penalty");
every other failure — including rejected-key queries — increments
`authFailures`.

**Why `MaxAuthTries = 6`:** A typical SSH client (OpenSSH, PuTTY) probes
each key in its agent with a query before presenting a signature. If the
client holds 3 keys of which 2 are not in the server's authorized-keys file,
the client generates 2 rejected-key queries (`authFailures` +2) before
signing with the accepted key. With `MaxAuthTries = 3`, those two probes
consume two of the three slots, leaving only one real credential attempt.
Setting `MaxAuthTries = 6` accommodates up to 3 rejected-key probes plus 3
real credential attempts before disconnect — matching what a normal
multi-key agent session needs without sacrificing brute-force protection
(the rate-limiter's per-IP backoff is the primary brute-force defense).
The effective guarantee is therefore: "at most 6 `authFailures` before
disconnect, where both rejected queries and real failures count; the
rate-limiter enforces the real per-IP cap." The `TestIntegration_MaxAuthTriesCombinedCounter`
integration test (§13.3) must pass before this spec value is considered
committed, as it asserts the library's counter behavior matches this
description. Implementations in other languages must implement the same
semantics: exempt only `none`, count all other rejections.

**Note:** A previous revision of this spec stated `MaxAuthTries = 3` and
claimed that pubkey queries do not count toward `authFailures`. That claim
was incorrect. The library source shows that the `isQuery=true` path sets
`authErr = candidate.result` for rejected keys and then falls through to the
shared `authFailures++` block in `server.go: serverAuthenticate`. Only accepted
queries (`candidate.result == nil`) use `continue userAuthLoop` before
reaching that block.

### Credential check

#### Password

To prevent timing attacks that distinguish wrong-user from wrong-password (or
reveal the configured password length), the password check must:

1. Compute SHA-256 over the presented username and over the presented
   password. The implementation pre-computes and caches SHA-256 of the
   resolved configured username and password after the password is finalized
   (per §2 step 2 if supplied via `--pass` or `MINISSHD_PASS`, or §2 step 8 if
   auto-generated) and before the listener accepts its first connection, so
   every auth callback compares against cached digests. SHA-256 over
   arbitrary-length input always produces 32 bytes, so equal-length comparison
   is guaranteed.
2. Compare each presented hash to the configured hash with
   `subtle.ConstantTimeCompare`. **Both comparisons must always run** — do
   not short-circuit on the first mismatch. Store each `subtle.ConstantTimeCompare`
   return value (an `int`) in a separate variable, then combine with bitwise
   `&` (e.g. `okInt := userMatch & passMatch`). Using `&&` on the raw calls
   would allow the Go compiler or runtime to short-circuit on the first
   zero return; storing into variables first eliminates that possibility.
3. Decide the result:
   - both match → `(ok=true, reason="")`
   - user-hash mismatch, password-hash match → `(ok=false, reason="bad-user")`
   - user-hash match, password-hash mismatch → `(ok=false, reason="bad-password")`
   - both mismatch → `(ok=false, reason="bad-user")` (user wins for logging —
     keeps the reason field decisive when both are wrong)

The client sees a generic "Permission denied (password)" in all failure cases;
only the logs distinguish the reasons (see §9).

#### Publickey

The publickey check uses the same hash-then-`subtle.ConstantTimeCompare`
discipline so the timing envelope reveals only the **size** of the accepted
keyset, not which key matched (or whether any matched):

1. At startup (after §2 step 6, before accept), the authorized-keys file (§2
   step 5b, see also §6.1) is parsed with
   `golang.org/x/crypto/ssh.ParseAuthorizedKey`. For each accepted key, the
   server computes the SHA-256 digest of `key.Marshal()` (the wire-format
   bytes) and caches the resulting 32-byte digest. Marshal-format is the same
   shape OpenSSH uses for fingerprinting; any two keys that compare equal
   under the SSH protocol have identical Marshal output. The cached digests
   are sorted lexicographically so reload-induced reordering does not change
   the iteration pattern.
2. On every publickey callback, compute SHA-256 over the presented key's
   `Marshal()` bytes, then `subtle.ConstantTimeCompare` it against **every**
   cached digest. The iteration must not short-circuit on the first match —
   it walks the entire keyset on every call and ORs the results with
   `|` on the int returns. This leaks the cardinality of the keyset (each
   pubkey check takes ~N × 32-byte compare time) but not which key matched.
3. The presented username is hashed and compared to the configured-username
   digest with `subtle.ConstantTimeCompare` in the **same** way as the
   password path. The username comparison and the key comparison both always
   run; the combined `ok` is the bitwise AND of the two int results.
4. Decide the result:
   - username matches AND any key digest matches → `(ok=true, reason="")`
   - username matches, no key matches → `(ok=false, reason="bad-key")`
   - username mismatches, any key matches → `(ok=false, reason="bad-user")`
   - username mismatches, no key matches → `(ok=false, reason="bad-user")`
     (user wins for logging — mirrors the password rule)

A keyset of zero accepted keys is a special case: the SHA-256 loop runs zero
times but the *check* is still invoked (cannot short-circuit at the function
boundary; doing so would leak "no keys configured" via timing). The function
performs a single dummy `subtle.ConstantTimeCompare` against a 32-byte zero
buffer so the cost floor matches "one configured key", then returns `(ok=false,
reason="bad-key")`. The client sees a generic "Permission denied (publickey)"
either way.

**Residual side-channel:** SHA-256 itself is not constant-time over input
length — a key that fills two blocks (most modern keys; an ed25519 marshalled
public key is ~51 bytes, so it fits in one block, while RSA-4096 takes ~530
bytes and spans nine blocks) takes measurably more CPU than a one-block key.
Comparison is over the 32-byte digest, which is length-invariant; only the
hashing step varies. The leak is at the block-count level (a handful of cycles
per block), dwarfed by network jitter and the rate-limit backoff in §5. The
existing residual-leak caveat from the password path applies equally: spec
implementers must not claim "fully constant-time auth"; the claim is
"constant-time given equal-length inputs (i.e. same key algorithm and size),
with sub-cycle differences between length classes."

### Failure semantics

The `MaxAuthTries = 6` per-connection cap covers password failures, publickey
signature failures, AND rejected-key pubkey queries, all combined into a single
`authFailures` counter (library behavior, `ssh/server.go`). The initial `none`
probe is the only exempt event. Cross-connection failures feed the rate limiter
— see §5 — under the same per-IP key, with no distinction between
method-of-failure. The rate limiter fires inside `PublicKeyCallback` on every
invocation (including queries; see §4 Credential check, Publickey rate-limit
note), which is a deliberate departure from OpenSSH's behavior.

#### Authorized-keys file: format, options, and reload

The format is OpenSSH's standard `authorized_keys` syntax: one key per line,
with `#`-prefixed lines and blank lines ignored. Trailing
comments after the key are permitted. Key options (e.g. `command="..."`,
`from="..."`, `no-port-forwarding`, `no-pty`) are **parsed but ignored** at
this stage — the implementation logs a single `WARN` `pubkey-option-ignored`
event per line containing options at load time and accepts the key. This is
the right default for a single-user LAN tool: the spec already restricts the
server to one identity, so per-key restriction options have no surface to bite
on. Future spec revisions may honor a subset; this one explicitly does not.

Malformed lines (a parse error from `ssh.ParseAuthorizedKey`) cause a single
`WARN` `pubkey-parse-error` event naming the line number and ssh.ParseAuthorizedKey's
error message, and the line is skipped. A file that yields zero usable keys
is permitted at load time but means publickey auth will always fail — this is
not itself an error, but the startup `listening` event records
`pubkey_count=0` so an operator notices.

The server reloads the authorized-keys file on `SIGHUP`. Reload is atomic
with respect to in-flight publickey callbacks: the current keyset is held
in an `atomic.Pointer[Keyset]`, so any callback that started with the old
`*Keyset` continues to use it and any callback that starts after the swap
sees the new one. A reload that fails (file unreadable, all lines malformed,
etc.) logs a `WARN` `pubkey-reload-failed` event and leaves the previous
keyset in place — an operator's typo on rotation never knocks all clients
offline. Likewise, a reload that succeeds in parsing the file but yields
**zero usable keys** is treated as a failure when the previous keyset had
≥1 key: the previous keyset is preserved, and `pubkey-reload-failed` is
logged. This policy prevents an accidental empty-file rotation from
permanently locking all publickey clients out (they would have no recourse
until the operator corrects the file and sends another SIGHUP).

`SIGHUP` is otherwise a no-op (existing behavior; minisshd does not interpret
SIGHUP for anything else). On macOS and Linux the signal is captured via
`signal.Notify`. If the spec ever extends SIGHUP to other behaviors (log
rotation, etc.), the keyset reload remains.

```

### 2.2 §2 — Command-line interface (flags table, env table, validation steps)

Current §2 flags table is replaced with the following additions
(`--auth` and `--authorized-keys`):

```markdown
| Flag | Default | Description |
|---|---|---|
| `--port N` | `2222` | TCP port to listen on. |
| `--bind IP` | `0.0.0.0` | IP address to bind the listener to. Use `127.0.0.1` for loopback only, a specific LAN address to restrict to one interface, `::` for all IPv6 interfaces, etc. Both IPv4 and IPv6 literals are accepted. |
| `--pass XXXXXX` | random 6-digit | Password clients must present. Any non-empty string accepted as an SSH password is valid. Overrides `MINISSHD_PASS` if both are set. If neither is set, a random 6-digit numeric password is generated and printed at startup. Only consulted when `--auth` includes `password`. |
| `--user NAME` | current OS user | Username clients must present. Overrides `MINISSHD_USER` if both are set. |
| `--shell PATH` | `$SHELL` | Shell binary for interactive sessions. Falls back to `/bin/zsh` if `$SHELL` is unset. |
| `--host-key PATH` | `~/.minisshd/host_key` | Path to the persistent host key. Generated on first run if missing. |
| `--auth METHODS` | `password` | Comma-separated SSH auth methods to advertise. Valid values: `password`, `publickey`, `password,publickey`, `publickey,password`. Whitespace around items is trimmed. Duplicate items are an error. Empty string or an unknown method is an error. |
| `--authorized-keys PATH` | `$XDG_CONFIG_HOME/minisshd/authorized_keys` (else `~/.config/minisshd/authorized_keys`) | Path to the OpenSSH-format authorized-keys file. Read only when `--auth` includes `publickey`. A missing file is treated as zero accepted keys (with a single `WARN` log at startup); a present-but-unreadable file is a startup error. |
```

Current §2 env table gains a row:

```markdown
| Var | Purpose |
|---|---|
| `MINISSHD_PASS` | Password value. Used only if `--pass` is not provided. Preferred over `--pass` because command-line arguments are visible to any local user via `ps`; environment variables are less exposed (not visible in default `ps` output on macOS or Linux). |
| `MINISSHD_USER` | Expected username. Used only if `--user` is not provided. |
| `MINISSHD_AUTH` | Comma-separated auth methods. Used only if `--auth` is not provided. Same value grammar as `--auth`. |
| `MINISSHD_AUTHORIZED_KEYS` | Authorized-keys file path. Used only if `--authorized-keys` is not provided. |
```

Current §2 step 2 — no change to its wording, but a new step 2b is
inserted **between** step 2 and step 3:

```markdown
2b. Resolve `--auth`: `--auth` if set, else `$MINISSHD_AUTH`, else
    `"password"`. Parse the comma-separated value into a set of methods.
    Reject (exit code 2) on: empty string, unknown method, duplicate
    method. The order in the value is preserved and surfaces in the SSH
    `methods` list returned to clients.

2c. If the resolved method set includes `publickey`:
    - Resolve the authorized-keys path: `--authorized-keys` if set, else
      `$MINISSHD_AUTHORIZED_KEYS`, else
      `$XDG_CONFIG_HOME/minisshd/authorized_keys` (when
      `$XDG_CONFIG_HOME` is set and non-empty), else
      `$HOME/.config/minisshd/authorized_keys`.
    - If the file is present, attempt to parse it. A parse-level error
      from `os.Open` (other than `os.ErrNotExist`) exits with code 4
      and a message naming the path. Malformed key lines do **not**
      fail startup (they log `pubkey-parse-error` at WARN and are
      skipped, per §4).
    - If the file is absent, the keyset is empty and the server logs
      a single `WARN` `pubkey-keys-missing path=<path>` event at
      startup. Startup continues — this is the "publickey configured
      but no keys yet" state, which is valid (other methods can still
      authenticate, or the operator can drop keys in and `SIGHUP`
      reload).
    - If the resolved method set is exactly `{publickey}` AND no keys
      were loaded, exit with code 2: this is an unauthenticable
      configuration. The `--pass` / `MINISSHD_PASS` value is irrelevant
      here — when `--auth=publickey`, password auth is not offered
      regardless of whether a password was supplied, so a configured
      password cannot rescue the server from having zero accepted keys.
```

Current §2 step 8 gains one clarifying sentence at the end:

```markdown
8. **Only after the listener is successfully bound**, if no password was resolved in step 2, generate a fresh 6-digit numeric password using a cryptographically secure RNG (`crypto/rand` in Go) and print exactly one line to stdout: `Password: 482910`. This is the only path that writes the password to stdout. If a password was supplied via flag or env, no banner is printed. **A random password is only generated when the resolved `--auth` set includes `password` and no password was supplied; in `publickey`-only mode no password is generated and no banner is printed.**
```

Current §2 step 9 — the `listening` event payload gains two new
fields:

```markdown
9. Log a single structured `listening` event including the bind address, the
   **actually bound port** (which may differ from `--port` when `--port 0` was
   requested — read it from the listener's local address after bind), host
   key fingerprint, expected username, PID, the configured auth method list,
   and the count of accepted public keys. The new fields are named
   `auth_methods` (e.g. `auth_methods=password,publickey`) and `pubkey_count`
   (an integer; 0 when publickey is not configured).
```

### 2.3 §9 — Logging (event table)

Two new events are appended to the §9 required-events table, and the existing
`auth-ok` and `auth-fail` rows gain a `method` field and (for publickey paths)
a `fingerprint` field:

```markdown
| Event | Level | Fields |
|---|---|---|
| `listening` | INFO | bind, port, fingerprint, user, pid, auth_methods, pubkey_count |
| `conn-open` | INFO | remote |
| `conn-close` | INFO | remote, duration (Go `time.Duration.String()` form, e.g. `27s`, `1m3.5s`) |
| `auth-ok` | INFO | remote, user, method (`password` / `publickey`), fingerprint (publickey only; SHA-256 of the presented key in `SHA256:<base64>` form, identical to `ssh-keygen -lf`). For `method=password` the fingerprint field is omitted. |
| `auth-fail` | WARN | remote, user, method (`password` / `publickey`), reason (`bad-user` / `bad-password` / `bad-key`), attempt (per-IP cumulative `fail_count` after this failure), next_delay (sleep that the next attempt from this IP will incur), fingerprint (publickey only; SHA-256 of the *presented* key, identical to `ssh-keygen -lf`; omitted for `method=password`). |
| `session` | INFO | remote, kind (`shell` / `exec` / `sftp`) |
| `reject` | WARN | remote, what (`x11`, `tcpip`, `agent`, `subsystem`, `streamlocal`, etc.) |
| `shutdown-signal` | INFO | pgid, sig, reason |
| `drain-timeout` | WARN | remote, kind, bytes_dropped |
| `pubkey-option-ignored` | WARN | path (file), line (1-based line number), option (e.g. `command="..."`). Emitted once per options-bearing line at startup and at every reload. |
| `pubkey-parse-error` | WARN | path, line, error |
| `pubkey-keys-missing` | WARN | path. Emitted once at startup if publickey is configured and the file is absent. |
| `pubkey-reload-failed` | WARN | path, error. Emitted on SIGHUP when the new file cannot be opened or yielded zero usable keys after previously having ≥1. |
| `pubkey-reload-ok` | INFO | path, pubkey_count. Emitted on every successful SIGHUP reload. |
| `error` | ERROR | message, remote (if applicable) |
```

The closing paragraph "The password must **never** appear in any structured
log event…" is unchanged. The active password scrub in `internal/logging`
continues to apply to every emitted line, including all `pubkey-*` events.
SSH fingerprints (the new `fingerprint` field) are not passwords; the scrub
operates on byte-literal substring replacement of the configured password and
therefore cannot accidentally redact a fingerprint unless the configured
password happens to occur as a substring of a base64-encoded SHA-256 digest.
This is implausible for a 6-digit numeric password (vanishingly low
probability) and acceptable for operator-chosen passwords — the scrub is
defense in depth, not the primary guarantee.

### 2.4 §11 — Error and edge cases (new rows)

Append to the existing exit-code table:

```markdown
| `--auth` empty, unknown method, or duplicate method | Exit 2, message to stderr naming the rejected value. |
| `--auth=publickey` only AND no keys loaded | Exit 2, message to stderr instructing the operator to provide keys or add `password` to `--auth`. (Whether `--pass` was supplied is irrelevant — password auth is not offered in publickey-only mode.) |
| `--authorized-keys` path exists but is not readable | Exit 4, message naming the path. |
| `--authorized-keys` path absent when `--auth` includes `publickey` | Startup continues with empty keyset; WARN `pubkey-keys-missing` logged. |
| Client offers `publickey` when `--auth=password` only | Server advertises only `password`; client negotiates down. Behaves identically to today's spec. |
| Client offers `password` when `--auth=publickey` only | Server advertises only `publickey`; client either falls back if it has a key, or fails. |
| SIGHUP received | Reload authorized-keys file. On parse-or-open failure, keep previous keyset and log `pubkey-reload-failed`. On success log `pubkey-reload-ok`. |
```

### 2.5 §12 — Explicit non-goals

Current §12 bullet "Multiple users, key-based auth, certificates, or 2FA."
is replaced with:

```markdown
- Multiple users, SSH certificates, or 2FA. (Public-key auth alongside
  password is supported per §4; certificate-based auth, certificate
  authorities, and OpenSSH `cert-authority` directives remain out of scope.
  Multi-user mappings — different keys to different system users — are also
  out of scope; minisshd always runs as the invoking user, and the
  configured username gates all auth methods.)
```

### 2.6 §13 — Test suite (additions to subsections)

§13.2 (Unit tests) gains a new `pubkey` block immediately after the existing
`auth` block:

```markdown
**`auth` (publickey)**
- Parsing accepts a single ed25519 key, ignores `#` comments, ignores blank
  lines, accepts a key with options (`command="..."`) and emits a
  `pubkey-option-ignored` warning, rejects a malformed line and emits a
  `pubkey-parse-error`, and returns an empty keyset for a missing or empty file.
- Marshal-then-SHA-256 of a freshly generated ed25519 key matches
  `ssh.FingerprintSHA256` from `golang.org/x/crypto/ssh`.
- `KeysetCheck` returns (ok=false, reason="bad-key") for an empty keyset
  (covering the dummy-compare branch — see §4 publickey step 4) and runs in
  the same envelope (within 5x) as a 1-key keyset.
- `KeysetCheck` returns (ok=true) when the presented key matches one of 5
  loaded keys (test with each of the 5 in turn), with the constant-time
  invariant: the wall-clock per-call median across 1000 iterations does
  not vary by more than 30% across which-key-matched cases. (Loose envelope;
  the rigorous Mann-Whitney U test lives in the integration layer alongside
  the existing password-path timing test.)
- `KeysetCheck` always iterates the entire keyset: a wrapper-injected
  counter on the inner compare proves N compares per call regardless of
  match position.
- Reload swap: build a keyset, swap atomically to a new keyset, confirm
  the new keys validate and the old ones don't, with no observable
  intermediate state on a 100-goroutine concurrent reader.
```

§13.2 (Unit tests) also gains, under `cmd/minisshd` startup validation:

```markdown
- `--auth ""`, `--auth bogus`, `--auth password,bogus`, `--auth
  password,password` all exit 2.
- `--auth publickey` with no `--authorized-keys` file present produces
  a WARN `pubkey-keys-missing` and the startup proceeds.
- `--auth publickey` with `--pass` unset and no keys file present exits 2
  (unauthenticable).
- `--auth password` (default) suppresses pubkey-related WARN events.
- `MINISSHD_AUTH=publickey,password` with no flag set works identically to
  `--auth=publickey,password`.
- `MINISSHD_AUTHORIZED_KEYS` precedence: env consulted only when flag not
  set; otherwise flag wins.
```

§13.3 (Integration tests) gains the following scenarios appended to the bullet
list:

```markdown
- **Publickey-only succeeds**: server with `--auth publickey` and a single
  ed25519 key in the authorized-keys file. Client offers that key → `auth-ok
  method=publickey fingerprint=SHA256:…` event with the matching fingerprint.
- **Publickey-only wrong key fails**: server with one accepted key; client
  offers a different key → `auth-fail reason=bad-key method=publickey
  fingerprint=SHA256:…` event with the *presented* (wrong) key's
  fingerprint.
- **Publickey-only wrong user fails**: server with one accepted key; client
  offers the right key but the wrong username → `auth-fail reason=bad-user
  method=publickey` and the presented key's fingerprint.
- **Password-only still works** (regression): default `--auth=password`,
  drive the existing integration test fixture; passes unchanged.
- **Both methods allowed, password used**: `--auth password,publickey`,
  client uses password → `auth-ok method=password`.
- **Both methods allowed, publickey used**: `--auth password,publickey`,
  client uses publickey → `auth-ok method=publickey`.
- **No methods allowed is unreachable** (negative integration): startup with
  `--auth=""` does not produce a listening event; assert the binary exits 2
  before bind.
- **SIGHUP reload**: start with key A in the file; auth with A succeeds.
  Overwrite the file with key B; send SIGHUP to the process. Wait for the
  `pubkey-reload-ok` log event. Auth with A now fails (`bad-key`), auth
  with B succeeds. Then overwrite the file with malformed garbage and
  SIGHUP again; the `pubkey-reload-failed` event appears and key B still
  authenticates (previous keyset preserved).
- **Combined-counter disconnect with mixed methods**: server with
  `--auth password,publickey` and `MaxAuthTries = 6`. Client sends
  3 rejected-key probes (each increments `authFailures`), then a wrong
  password, then 2 more wrong passwords. After the 6th failure the
  server disconnects. Asserts (a) rejected-key queries count toward the
  counter, and (b) the value of 6 still permits real credential attempts
  after probe failures. A companion assertion verifies that a fresh
  connection with no prior probes disconnects after 6 real failures.
- **Pubkey failures feed the rate limiter**: same per-IP backoff regression
  as the password version of the test, but every failure is a pubkey
  signature failure.
- **Pubkey fingerprint matches ssh-keygen -lf**: out-of-band, compute
  the `SHA256:…` fingerprint for a fixture key via `ssh.FingerprintSHA256`
  in the test harness and assert the value emitted in `auth-ok` matches.
```

§13.4 (E2E tests) gains a new case (renumber the existing list shifting
nothing else; the new case is appended at the end as case 17):

```markdown
17. **System ssh with -i**: generate an ed25519 keypair into the test temp
    dir, write its public form into the server's authorized-keys file, start
    the server with `--auth publickey --authorized-keys <path>`. Drive
    `/usr/bin/ssh -i <privkey> -o IdentitiesOnly=yes -o
    PreferredAuthentications=publickey -o PasswordAuthentication=no -p PORT
    testuser@127.0.0.1 'echo PUBKEY_OK'`. Assert exit code 0 and stdout
    contains `PUBKEY_OK`. Stop the server and start it again with `--auth
    password,publickey`; rerun the same ssh invocation; assert it still
    works. Then add `-o PreferredAuthentications=password` and assert the
    client fails (since the wrong-or-no password causes the SSH negotiation
    to fall through; this is the cross-check that "password,publickey"
    means "any of" not "both required").
```

§13.5 (Coverage) — no wording change. The added code paths must hit the
existing ≥ 90.0 % threshold; the threshold variable in the Makefile is the
single dial.

## 3. CLI / env interface

### New flags

| Flag | Env var | Default | Validation |
|---|---|---|---|
| `--auth METHODS` | `MINISSHD_AUTH` | `password` | Non-empty after trimming. Each comma-split element must be exactly `password` or `publickey`. No duplicates. Order preserved. Implemented in `internal/auth.ResolveMethods(flag, flagSet bool, env string, envSet bool) (Methods, error)`. |
| `--authorized-keys PATH` | `MINISSHD_AUTHORIZED_KEYS` | `$XDG_CONFIG_HOME/minisshd/authorized_keys` (when XDG set) else `$HOME/.config/minisshd/authorized_keys` | Path resolution only; existence is **not** required at parse time. If `--auth` includes `publickey`, file is opened in §2 step 2c. Permissions on the file are not enforced (unlike `host_key`); the file contains only public material. |

### New env vars

Same names/semantics as the flags. Precedence everywhere in this codebase
is: flag-explicitly-set > env-explicitly-set > default. The existing
`ResolvePasswordStrict` / `ResolveUsername` precedence rules are mirrored —
see `internal/auth/resolve.go`.

### Defaults preserve existing behavior

Running `minisshd` with **no new flags and no new env vars** behaves
identically to today: `--auth=password`, the keys file is never read, the
listening event has `auth_methods=password pubkey_count=0`, and no new
events appear in logs. The existing integration and E2E tests pass
unmodified — this is asserted by leaving them in place and adding new tests
rather than retrofitting old ones.

### Validation rules

- `--auth=""` (explicit empty) → exit 2 (`auth methods must not be empty`).
- `--auth=foo` → exit 2 (`unknown auth method "foo"`).
- `--auth=password,publickey,password` → exit 2 (`duplicate auth method
  "password"`).
- `--auth=PASSWORD` (uppercase) → exit 2 (`unknown auth method "PASSWORD"`).
  Method names are case-sensitive matching `golang.org/x/crypto/ssh`'s
  protocol identifiers.
- `--authorized-keys=/nonexistent`, when `--auth` does not include
  `publickey` → ignored entirely (file is not opened). When `--auth`
  includes `publickey` → emit `pubkey-keys-missing` at WARN and proceed
  with an empty keyset.
- `--authorized-keys=/etc/shadow` (or any path that exists but is
  unreadable for the invoking user) AND `--auth` includes `publickey` →
  exit 4 with a message naming the path. (Open returns `os.ErrPermission`
  or `os.ErrNotExist`; the latter is the "missing" path, the former is
  fatal.)
- A keys file that parses to zero usable lines while every line is
  malformed (no comments, no blanks, all errors) is treated as "zero keys"
  with WARN events per malformed line, but is **not** fatal. The
  unauthenticable-configuration check in §2 step 2c catches the case
  where this leaves the server with no method to accept any client.

## 4. Code changes by file

### Existing files modified

#### `cmd/minisshd/main.go` (spec §2 steps 2b, 2c, 8, 9)

- Add flags: `authFlag := fs.String("auth", "", ...)`,
  `authorizedKeysFlag := fs.String("authorized-keys", "", ...)`. Track
  `authSet` and `authorizedKeysSet` via `fs.Visit`.
- After the existing §2 step 3 (username resolution) and before §2 step 4
  (shell validation), call
  `methods, err := auth.ResolveMethods(*authFlag, authSet, os.Getenv("MINISSHD_AUTH"), envAuthSet)`
  — `os.LookupEnv` is used to thread `envAuthSet` in.
- Conditionally suppress the random-password-generate branch when
  `!methods.Contains(auth.MethodPassword)`. In that case, if no `--pass` /
  `MINISSHD_PASS` was supplied, the cached password is the empty string and
  the server never accepts a password attempt. `auth.NewCredentials` is then
  constructed with a *random sentinel* password (32 bytes from
  `crypto/rand` formatted as hex) so the password-callback path, even if
  ever invoked, cannot succeed; this also keeps the password-scrub
  invariant simple by giving the scrub a non-empty needle.
- When `methods.Contains(auth.MethodPublickey)`:
  - Resolve `keysPath` via `auth.ResolveAuthorizedKeysPath(*authorizedKeysFlag, authorizedKeysSet, os.Getenv("MINISSHD_AUTHORIZED_KEYS"), envKeysSet)`.
  - Construct a `*auth.KeysetSource` backed by the file path and the
    logger; call `source.Load(ctx)` to populate the initial keyset.
  - Wire the source into the `server.Config`.
- The unauthenticable-configuration check: when `methods == {publickey}`
  AND the initial keyset is empty, exit with code 2 and a clear stderr
  message. The presence or absence of `--pass`/`MINISSHD_PASS` is
  irrelevant — password auth is not advertised in publickey-only mode so
  a supplied password cannot rescue the configuration.
- Install a `SIGHUP` handler in `main`: alongside the existing
  `signal.NotifyContext(ctx, SIGINT, SIGTERM)`, add a separate
  `sighupCh := make(chan os.Signal, 1); signal.Notify(sighupCh, syscall.SIGHUP)`
  and a goroutine that calls `source.Reload()` for every signal received.
  The goroutine's loop **must be gated on `ctx.Done()`** so it exits
  cleanly when the server shuts down — a SIGHUP arriving during the drain
  phase (after the main context is cancelled) must not touch the logger
  or the keyset source, which may be partially torn down:
  ```go
  go func() {
      for {
          select {
          case <-sighupCh:
              source.Reload()
          case <-ctx.Done():
              return
          }
      }
  }()
  ```
  This is gated on `methods.Contains(auth.MethodPublickey)` so non-publickey
  configurations do not register a SIGHUP handler at all (matches existing
  spec language that SIGHUP is otherwise a no-op).
- The `listening` event now passes `methods.String()` (e.g.
  `"password,publickey"`) and `source.Count()` (or 0 when nil) to
  `logger.Listening`. The `logging.Logger.Listening` signature gains two
  parameters — see §5 below.

#### `internal/auth/credentials.go` (spec §4 publickey)

- Add a new exported method on `*Credentials`:
  ```go
  // CheckUsername returns (ok, reason) for the publickey path. Only the
  // username comparison runs; the caller is responsible for combining this
  // result with the keyset check. Reason is "" on match, ReasonBadUser
  // otherwise.
  func (c *Credentials) CheckUsername(presentedUser string) (ok bool, reason string)
  ```
- No change to the existing `Check`: it remains password+user combined.
  The publickey path composes `CheckUsername` (which returns a `bool`)
  with a separate `Keyset.Check` call (which also returns a `bool`) and
  combines the results using `ok := userOK && keyOK`. Because both calls
  return before the `&&` evaluates (they are pre-materialized into
  variables, not inlined as call expressions), no short-circuit is
  possible — the compiler has no opportunity to skip either call.

#### `internal/auth/resolve.go` (spec §2 step 2b, 2c)

- Add `MethodPassword = "password"` and `MethodPublickey = "publickey"` constants.
- Add `type Methods []string` with methods `Contains(m string) bool`,
  `String() string` (comma-joined, preserves input order), `Names() []string`.
- Add `ResolveMethods(flagVal string, flagSet bool, envVal string, envSet bool) (Methods, error)`:
  - If `flagSet` use `flagVal`, else if `envSet` use `envVal`, else
    return `Methods{MethodPassword}, nil`.
  - Trim each comma-split token. Empty token → error. Unknown token →
    error. Duplicate → error.
- Add `ResolveAuthorizedKeysPath(flagVal string, flagSet bool, envVal string, envSet bool) (string, error)`:
  - Precedence: flag-set > env-set > XDG. Returns the resolved path.
    XDG fallback consults `os.Getenv("XDG_CONFIG_HOME")` first; on empty
    or unset, falls back to `os.UserHomeDir()` + `/.config/minisshd/authorized_keys`.
- New errors: `ErrEmptyAuthMethods`, `ErrUnknownAuthMethod`,
  `ErrDuplicateAuthMethod`.

#### `internal/auth/` (new file: `pubkey.go`)

- `type AcceptedKey struct { Marshal []byte; Digest [sha256.Size]byte; Fingerprint string; Comment string }`.
- `type Keyset struct { keys []AcceptedKey }` plus methods
  `Check(presentedKey ssh.PublicKey) (ok bool, reason string, fp string)`
  and `Count() int`. The `Check` implementation:
  - Compute presented digest = SHA-256 over `presentedKey.Marshal()`.
  - Compute presented fingerprint = `ssh.FingerprintSHA256(presentedKey)`.
  - Iterate **every** accepted key: `matched |= subtle.ConstantTimeCompare(presented[:], k.Digest[:])`.
  - If `len(keys) == 0`, run one dummy compare against a 32-byte zero
    buffer for timing-floor parity, then **explicitly set `matched = 0`**:
    ```go
    var zero [sha256.Size]byte
    _ = subtle.ConstantTimeCompare(presented[:], zero[:])
    matched = 0  // dummy compare result discarded; empty keyset never authenticates
    ```
    The explicit `matched = 0` is required: without it, a presented key
    whose SHA-256 happens to be all-zero bytes would produce a
    `subtle.ConstantTimeCompare` return of 1, incorrectly authenticating.
    (This is a constructed worst-case; no real key has an all-zero digest,
    but the code must not rely on that property.)
  - Return `(matched != 0, reasonFromMatch(matched), fingerprint)`.
    The `!= 0` form is preferred over `== 1` because OR-accumulation can
    produce values other than 0 or 1 if the implementation ever
    changes (e.g., if a different comparison primitive is substituted).
- `type KeysetSource struct { path string; log Logger; cur atomic.Pointer[Keyset] }`
  with `Load(ctx) error`, `Reload() error`, `Current() *Keyset`, `Count() int`.
  - `Load`: open the file, parse with `ssh.ParseAuthorizedKey` line-by-line,
    log per-line warnings (`pubkey-parse-error`, `pubkey-option-ignored`),
    swap `cur` to the new pointer. Errors only on open failures other
    than `os.ErrNotExist` (which produces the empty keyset and a
    `pubkey-keys-missing` event).
  - `Reload`: same as Load but logs `pubkey-reload-ok` on success;
    `pubkey-reload-failed` on open failure **or** when the new parse
    yields zero usable keys and the current keyset had ≥1 key (the
    zero-keys-from-having-keys transition). In both failure cases the
    previous `cur` is preserved. Rationale: an accidental empty-file
    rotation must not permanently lock out all publickey clients; the
    operator has to both fix the file and send another SIGHUP.
- Logger interface is narrow: `PubkeyParseError`, `PubkeyOptionIgnored`,
  `PubkeyKeysMissing`, `PubkeyReloadOK`, `PubkeyReloadFailed`. Implemented
  in `internal/logging` (see §5).

#### `internal/server/auth.go` (spec §4 publickey, §5 rate-limit feed)

- Add an interface `publickeyChecker` mirroring `credentialChecker`:
  ```go
  type publickeyChecker interface {
      Current() *auth.Keyset
  }
  ```
  with compile-time assertions:
  ```go
  var _ publickeyChecker = (*auth.KeysetSource)(nil)
  var _ pubkeyLogger     = (*logging.Logger)(nil)  // narrow Logger interface from auth package
  ```
  (`pubkeyLogger` is the narrow interface declared in `internal/auth/pubkey.go`
  and satisfied by `*logging.Logger`; the assertion lives here, in
  `internal/server/auth.go`, alongside the existing `var _ authLogger` and
  `var _ credentialChecker` checks, because this file is the one that sees
  both packages.)
- Add `publickeyCallback(lim rateLimiter, creds credentialChecker, source publickeyChecker, log authLogger, sleep sleeper) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)`.

  **Library semantics (authoritative, verified against v0.51.0 source):**
  `golang.org/x/crypto/ssh` calls `PublicKeyCallback` unconditionally on
  the **first** encounter of a (user, key) pair per connection — regardless
  of whether the client is probing (`isQuery=true`, no signature attached)
  or presenting a real signature (`isQuery=false`). The library uses a
  size-1 cache (`maxCachedPubKeys = 1` in `ssh/server.go: pubKeyCache`) to
  avoid calling the callback twice for the common probe-then-sign sequence
  with the same key. The callback has **no way to distinguish** a query
  from a real signature; it fires on first encounter and its result is
  cached for the subsequent signature attempt.

  **Rate-limiter design decision — Option (i): queries feed the rate limiter.**
  Because the callback fires on both queries and signatures, `lim.Acquire`
  runs for every first-seen (user, key) pair, including probe-only keys the
  client never signs with. This is a deliberate, tighter-than-OpenSSH
  posture: OpenSSH does not rate-limit per query; minisshd does. The
  benefit is that an attacker probing large key sets incurs backoff
  immediately, before presenting a signature. The cost is that a legitimate
  client with a large agent (many keys) also incurs probe-time backoff if
  prior connections from the same IP have burned rate-limit tokens. For
  single-user LAN use this is acceptable. The test
  `TestPublickeyCallback_QueryAndSignBothAcquire` documents this behavior
  explicitly by verifying that `lim.Acquire` is called once for a probe of
  an accepted key (cache hit on the sign attempt means no second Acquire)
  and once for a probe of a rejected key.

  **Cache-size-1 implication (Fix D):** If a client probes key A (rejected,
  result cached), then key B (probe, evicts A from the cache), then signs
  with key A — the cache misses on A's sign attempt and `PublicKeyCallback`
  fires a second time for key A. This means `lim.Acquire` runs twice for
  key A across that probe→evict→sign sequence. This is accepted: the
  key-set check is O(N) and idempotent; `Acquire` twice is conservative
  (more backoff, not less). The behavior is documented in
  `TestPublickeyCallback_CacheEvictionCausesDoubleAcquire`.

  The callback mirrors `passwordCallback`'s structure:
  1. `delay, release := lim.Acquire(ip)`
     (runs unconditionally — for both query-induced and signature-induced
     invocations; see rate-limiter design decision above)
  2. `sleep(delay)`
  3. `userOK, userReason := creds.CheckUsername(meta.User())`
     (always runs; never short-circuit)
  4. `keyOK, keyReason, fp := source.Current().Check(presentedKey)`
     (always runs; iterates the entire keyset)
  5. `ok := userOK && keyOK`
     Both `userOK` and `keyOK` are pre-materialized into variables before
     this line, so the `&&` evaluates two already-computed `bool` values —
     neither call is skipped. The constant-time guarantees were established
     inside `CheckUsername` and `Keyset.Check` respectively; no branching
     occurs between those returns and this combine.
  6. `release(ok)`
  7. Log via `log.AuthOK(remote, meta.User(), "publickey", fp)` or
     `log.AuthFail(remote, meta.User(), "publickey", reasonChoice, attempt,
     next, fp)`. `reasonChoice`: bad-user wins over bad-key per §4
     publickey step 4.
- The `authLogger` interface gains `method string` and `fingerprint string`
  parameters on both `AuthOK` and `AuthFail`:
  ```go
  type authLogger interface {
      AuthOK(remote, user, method, fingerprint string)
      AuthFail(remote, user, method, reason string, attempt int, nextDelay time.Duration, fingerprint string)
  }
  ```
  **Call-site impact:** `passwordCallback` must be updated to pass
  `method="password"` and `fingerprint=""` at the two `log.AuthOK` and
  `log.AuthFail` call sites. Empty `fingerprint` is omitted from the log
  output by `Logger.AuthOK`/`Logger.AuthFail` (consistent with how `Error`
  omits empty `remote`).
  The `recordingAuthLogger` stub in `internal/server/auth_test.go` must
  be updated to match the new interface signatures so existing tests
  compile and pass.

#### `internal/server/config.go` (spec §2 step 9, §4 wiring)

- `Config` struct gains:
  - `Methods auth.Methods`
  - `KeysetSource *auth.KeysetSource` (nil when publickey is not configured)
- `MaxAuthTries` is raised from `3` to `6`. The comment is updated to
  explain: (a) both password and publickey failures share a single counter;
  (b) rejected-key pubkey queries also count toward the limit (library
  behavior, per `ssh/server.go: serverAuthenticate` in v0.51.0); (c) the value
  of 6 accommodates up to 3 rejected-key probes plus 3 real credential
  attempts, which a multi-key SSH agent session requires. The previous
  value of 3 was a pre-pubkey choice that assumed only password failures
  counted; the revised understanding of `authFailures++` semantics requires
  the higher value.

#### `internal/server/server.go` — `newServerConfig` default-methods behavior

`newServerConfig` must handle the case where `Config.Methods` is nil or
empty. When nil/empty, it **defaults to `["password"]`**, preserving
pre-pubkey behavior. Concretely:

```go
methods := s.cfg.Methods
if len(methods) == 0 {
    methods = auth.Methods{auth.MethodPassword}
}
```

This ensures existing code paths that construct `Config` without a
`Methods` field (e.g. `newTestServer` in `server_test.go`) continue
to work correctly.

**Required test updates:**

- `newTestServer` in `internal/server/server_test.go` must either set
  `Methods: auth.Methods{auth.MethodPassword}` explicitly, or rely on
  the nil→default behavior above. Either approach is acceptable; the
  test comment should make the intent clear.
- `TestNewServerConfig_OnlyPasswordAuthOffered` currently asserts
  `PublicKeyCallback == nil`. After this change, that assertion remains
  valid **only** when `Config.Methods` is nil/empty or explicitly
  `["password"]`. The test should be updated to set
  `Methods: auth.Methods{auth.MethodPassword}` explicitly (or keep nil
  and rely on the default) and add a comment noting that it is testing
  the password-only configuration. A companion test
  `TestNewServerConfig_PublickeyCallbackSetWhenMethodIncludesPublickey`
  should be added to verify the opposite case.

#### `internal/server/server.go` (spec §4 wiring)

- `newServerConfig` builds `ssh.ServerConfig` (nil/empty `Methods` defaults
  to `["password"]` — see the `config.go` section above):
  - Always set `MaxAuthTries = 6` (see §4 counter explanation).
  - If `Methods.Contains(MethodPassword)`: set `PasswordCallback`.
  - If `Methods.Contains(MethodPublickey)`: set `PublicKeyCallback`.
  - Both can be set simultaneously; the library advertises both methods
    and the client picks. This is the "any-of" semantics from §4.

#### `internal/logging/logging.go` (spec §9)

- `Listening` signature change:
  ```go
  func (l *Logger) Listening(bind string, port int, fingerprint, user string, pid int, authMethods string, pubkeyCount int)
  ```
- `AuthOK` signature change:
  ```go
  func (l *Logger) AuthOK(remote, user, method, fingerprint string)
  ```
  `fingerprint` is the empty string for `method=password`, in which case
  the field is omitted from output (consistent with how `Error` already
  omits empty `remote`).
- `AuthFail` signature change:
  ```go
  func (l *Logger) AuthFail(remote, user, method, reason string, attempt int, nextDelay time.Duration, fingerprint string)
  ```
  Empty `fingerprint` omits the field.
- New methods:
  ```go
  func (l *Logger) PubkeyParseError(path string, line int, err string)
  func (l *Logger) PubkeyOptionIgnored(path string, line int, option string)
  func (l *Logger) PubkeyKeysMissing(path string)
  func (l *Logger) PubkeyReloadOK(path string, pubkeyCount int)
  func (l *Logger) PubkeyReloadFailed(path string, err string)
  ```
  All flow through `emit`, so the password scrub continues to apply.

#### `internal/server/auth_test.go`, `internal/server/server_test.go`

- The `recordingAuthLogger` stub in `auth_test.go` must be updated to
  match the new `authLogger` interface:
  ```go
  type recordingAuthLogger struct { /* ... */ }
  func (r *recordingAuthLogger) AuthOK(remote, user, method, fingerprint string) { ... }
  func (r *recordingAuthLogger) AuthFail(remote, user, method, reason string, attempt int, nextDelay time.Duration, fingerprint string) { ... }
  ```
- `passwordCallback` call sites in `internal/server/auth.go` must be
  updated to pass `method="password"` and `fingerprint=""`:
  ```go
  log.AuthOK(remote, meta.User(), "password", "")
  log.AuthFail(remote, meta.User(), "password", reason, attempt, next, "")
  ```
- Tests that currently assert against `AuthOK(remote, user)` and
  `AuthFail(remote, user, reason, attempt, next)` are updated to include
  `method="password"` and `fingerprint=""` in their expectations.
  Existing behavior assertions are otherwise unchanged — proving the
  password-path behavior is preserved.
- `newTestServer` in `server_test.go` should be updated to set
  `Methods: auth.Methods{auth.MethodPassword}` explicitly in the
  `Config` struct, making the password-only intent clear. Existing tests
  that call `newTestServer` need no other changes.

#### `internal/server/testhelpers_integration_test.go`

- `testServerOptions` gains `authMethods auth.Methods` (default
  `[password]`) and `acceptedPubkey ssh.PublicKey` (optional). When the
  pubkey is set, write it to a temp authorized-keys file and wire a
  `KeysetSource` into the server config.
- A helper `clientConfigPubkey(user string, signer ssh.Signer)` builds an
  `*ssh.ClientConfig` whose `Auth` is `ssh.PublicKeys(signer)`.

#### `cmd/minisshd/main_test.go`, `cmd/minisshd/main_integration_test.go`

- Add coverage for the new flag/env validation paths listed in §3.
- Add a "default behavior" snapshot test that asserts the existing
  integration scenario passes byte-for-byte unchanged when no new flags
  are provided.

### New files

- `internal/auth/pubkey.go` — `AcceptedKey`, `Keyset`, `KeysetSource`.
- `internal/auth/pubkey_test.go` — unit tests per §13.2 publickey block.
- `internal/auth/pubkey_integration_test.go` — file-level integration
  (load real OpenSSH-format files, reload-on-overwrite semantics) using
  `t.TempDir()`.
- `internal/server/pubkey_test.go` — `publickeyCallback` unit tests
  (mirrors the existing `auth_test.go` shape).
- `internal/server/pubkey_integration_test.go` — integration tests for
  the full handshake using `golang.org/x/crypto/ssh.PublicKeys(signer)`
  as the client.
- `test/e2e/pubkey_test.go` (`//go:build e2e`) — E2E case 17 driving
  `/usr/bin/ssh -i …`.

## 5. Logging

### Signature changes

- `Logger.Listening` adds `authMethods string, pubkeyCount int`.
- `Logger.AuthOK` adds `method, fingerprint string` (fingerprint may be empty).
- `Logger.AuthFail` adds `method, fingerprint string` (fingerprint may be empty).
  `reason` now accepts `bad-key` in addition to `bad-user` / `bad-password`.

### New methods

| Method | Event | Level | Fields |
|---|---|---|---|
| `PubkeyParseError(path, line, err)` | `pubkey-parse-error` | WARN | `path`, `line`, `error` |
| `PubkeyOptionIgnored(path, line, option)` | `pubkey-option-ignored` | WARN | `path`, `line`, `option` |
| `PubkeyKeysMissing(path)` | `pubkey-keys-missing` | WARN | `path` |
| `PubkeyReloadOK(path, count)` | `pubkey-reload-ok` | INFO | `path`, `pubkey_count` |
| `PubkeyReloadFailed(path, err)` | `pubkey-reload-failed` | WARN | `path`, `error` |

### Password-scrub invariant

Every new event flows through `emit`. The scrub is unchanged: it replaces the
literal configured-password byte sequence with `[REDACTED]` on each emitted
line. No new event passes the password as a field, and the configured
password is never embedded in any pubkey-related field. The scrub will, by
construction, not match the new `fingerprint` field unless the configured
password happens to be a substring of a base64-encoded SHA-256 digest — this
is a documented limitation of the byte-literal scrub, not a regression.

### Fingerprint format

`SHA256:<base64>` per RFC 4716 / `ssh-keygen -lf`. The Go helper is
`golang.org/x/crypto/ssh.FingerprintSHA256(key)` which returns this exact
format. The fingerprint is computed once per callback (on the **presented**
key) and emitted in both `auth-ok` and `auth-fail`. For success, it identifies
which accepted key was used; for failure, it identifies the rejected key (so
operators can correlate `auth-fail` events with attacker fingerprints).

## 6. Tests

### Unit tests (next to source)

| File | Test | Intent |
|---|---|---|
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_MatchingKeyAcceptsAndReturnsFingerprint` | Single accepted key; presented matching key → `(ok=true, reason="", fp=<fingerprint>)`. |
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_WrongKeyReturnsBadKey` | Single accepted key; presented different key → `(ok=false, reason="bad-key", fp=<presented-fingerprint>)`. |
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_EmptyKeysetReturnsBadKey` | Zero accepted keys; check returns `(false, "bad-key", fp)` and the dummy compare ran exactly once. |
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_NoShortCircuit` | 5 accepted keys; presented key matches key #1; injected counting wrapper sees 5 compares. Repeat with key #5; still 5 compares. |
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_TimingEnvelope` | Loose timing: 1000 iterations of "matches first", "matches last", "no match" all within 30% wall-clock median (skipped under `-short`). |
| `internal/auth/pubkey_test.go` | `TestKeyset_Check_FingerprintMatchesSSHKeygenFormat` | Marshal a fixture ed25519 key; assert `ssh.FingerprintSHA256` and our pipeline agree. |
| `internal/auth/pubkey_test.go` | `TestParseAuthorizedKeys_GoodFile` | Two ed25519 keys, one comment line, one blank line → 2 accepted keys. |
| `internal/auth/pubkey_test.go` | `TestParseAuthorizedKeys_OptionsAreIgnored` | `command="ls" ssh-ed25519 AAA…` → accepted, with a `PubkeyOptionIgnored` event recorded. |
| `internal/auth/pubkey_test.go` | `TestParseAuthorizedKeys_MalformedLineIsSkipped` | `not-a-key` line → skipped, `PubkeyParseError` event recorded, other valid lines accepted. |
| `internal/auth/pubkey_test.go` | `TestParseAuthorizedKeys_EmptyFile` | Empty file → empty keyset, no events. |
| `internal/auth/pubkey_test.go` | `TestKeysetSource_Load_MissingFile` | `os.ErrNotExist` → empty keyset, `PubkeyKeysMissing` event. |
| `internal/auth/pubkey_test.go` | `TestKeysetSource_Load_UnreadableFile` | Permission-denied file → returns error to caller. |
| `internal/auth/pubkey_test.go` | `TestKeysetSource_Reload_AtomicSwap` | 100 goroutines call `Current().Check(key)` while a single goroutine calls `Reload()` repeatedly; race detector clean and result is always either old-set or new-set. |
| `internal/auth/pubkey_test.go` | `TestKeysetSource_Reload_PreservesPreviousOnFailure` | Load good set → Reload with malformed file → `Current()` still returns the good set, `PubkeyReloadFailed` event recorded. |
| `internal/auth/resolve_test.go` | `TestResolveMethods_DefaultPassword` | No flag, no env → `Methods{"password"}`. |
| `internal/auth/resolve_test.go` | `TestResolveMethods_FlagBeatsEnv` | flagSet=true value `publickey`, env `password` → `Methods{"publickey"}`. |
| `internal/auth/resolve_test.go` | `TestResolveMethods_EnvUsedWhenFlagUnset` | flagSet=false, env `password,publickey` → 2 methods. |
| `internal/auth/resolve_test.go` | `TestResolveMethods_RejectsEmpty/Unknown/Duplicate` | Table of error cases. |
| `internal/auth/resolve_test.go` | `TestResolveAuthorizedKeysPath_XDG` | XDG_CONFIG_HOME set → uses XDG. Unset → falls back to `~/.config/minisshd/authorized_keys`. |
| `internal/auth/resolve_test.go` | `TestResolveAuthorizedKeysPath_FlagBeatsEnvBeatsXDG` | Precedence ladder. |
| `internal/auth/credentials_test.go` | `TestCredentials_CheckUsername_OnlyUsernamePath` | `CheckUsername("alice")` against `NewCredentials("alice", "pw")` → `(true, "")`; wrong user → `(false, ReasonBadUser)`. |
| `internal/auth/credentials_test.go` | `TestCredentials_CheckUsername_AlwaysHashes` | Counting wrapper sees exactly one ConstantTimeCompare per call. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_SuccessLogsAuthOK_ReleasesTrue` | Mirrors the password version: order of operations is Acquire → sleep → CheckUsername+Check → release(true) → AuthOK. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_BadKeyReleasesFalseLogsBadKey` | Username matches, key doesn't → `release(false)`, `AuthFail reason=bad-key fingerprint=<presented>`. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_BadUserReleasesFalseLogsBadUser` | Username doesn't match → `bad-user` wins over `bad-key`. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_SleepHappensBeforeCheck` | Non-zero `lim.delay`; sleeper observes 0 check calls when invoked. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_IPv4MappedV6Normalization` | Presented remote `::ffff:127.0.0.1` → snapshot key is `127.0.0.1`. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_LoggerDoesNotLeakPassword` | Defense-in-depth using a real `*logging.Logger`: configured password substring never appears in output even for pubkey flows. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_QueryAndSignBothAcquire` | Stub rate-limiter counts Acquire calls. Invoke the callback once for a rejected key (simulates a query); `Acquire` count = 1. Then invoke again for the same key (simulates a sign attempt after cache eviction or a second probe); `Acquire` count = 2. Documents that queries feed the rate limiter. |
| `internal/server/pubkey_test.go` | `TestPublickeyCallback_CacheEvictionCausesDoubleAcquire` | Invoke callback for key A (probe, rejected → `Acquire` #1), then key B (any result → `Acquire` #2, evicts A from library cache), then key A again (sign attempt, cache miss → `Acquire` #3). Asserts total `Acquire` = 3, documenting the cache-size-1 double-invocation behavior. |
| `internal/server/auth_test.go` | (update) `TestPasswordCallback_LogsMethodPassword` | The existing password tests are extended to assert `method=password` (and absent `fingerprint`) in the logged event. |
| `internal/logging/logging_test.go` | `TestLogger_Listening_NewFields` | `auth_methods` and `pubkey_count` fields appear, quoted/unquoted correctly. |
| `internal/logging/logging_test.go` | `TestLogger_AuthOK_OmitsFingerprintWhenEmpty` | Password path → no `fingerprint=` substring. |
| `internal/logging/logging_test.go` | `TestLogger_AuthFail_AllReasonsAndMethods` | Table of (`method`, `reason`) crosses including new `bad-key`. |
| `internal/logging/logging_test.go` | `TestLogger_PubkeyEvents_AllFiveEmit` | One assertion per new event method; each produces the expected logfmt line. |
| `internal/logging/logging_test.go` | `TestLogger_PubkeyEvents_PasswordScrubStillApplies` | Configured password set; emit each pubkey event with the password substring inside the `path` field (`/tmp/<password>/keys`); assert `[REDACTED]` appears in the output. |
| `cmd/minisshd/main_test.go` | `TestRun_AuthFlagValidation` | Table of `--auth ""`, `--auth bogus`, `--auth pw,pw` → exit 2 with matching stderr. |
| `cmd/minisshd/main_test.go` | `TestRun_AuthPublickeyOnlyNoKeysNoPasswordExitsBadConfig` | `--auth publickey` + no keys file + no password → exit 2. |
| `cmd/minisshd/main_test.go` | `TestRun_AuthPublickeyMissingKeysFileIsWarning` | `--auth publickey,password` + missing keys file → startup OK, `pubkey-keys-missing` in log, `Password: ` banner still appears (because password is configured). |
| `cmd/minisshd/main_test.go` | `TestRun_DefaultBehaviorMatchesBaseline` | No new flags → log contains `auth_methods=password pubkey_count=0` and no new event types. |

### Integration tests (`*_integration_test.go`)

| File | Test | Intent |
|---|---|---|
| `internal/auth/pubkey_integration_test.go` | `TestIntegration_LoadParsesOpenSSHFormat` | Load a fixture file written by `ssh-keygen` (generated in-test); confirm count and fingerprints. |
| `internal/auth/pubkey_integration_test.go` | `TestIntegration_ReloadObservesFileChange` | Write → load → overwrite → reload → assertions on Count() and Check(). |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PublickeyOnlyAuthenticates` | Server `--auth publickey`, client offers matching key → `auth-ok method=publickey fingerprint=<expected>`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PublickeyOnlyWrongKeyFails` | Wrong key → `auth-fail reason=bad-key`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PublickeyOnlyWrongUserFails` | Right key, wrong username → `auth-fail reason=bad-user method=publickey`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PasswordOnlyBaselinePreserved` | Default `--auth=password`; runs the existing fixture and asserts byte-for-byte the same log lines as before (regression). |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_BothMethodsPasswordPath` | `--auth password,publickey`; client uses password → `auth-ok method=password`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_BothMethodsPubkeyPath` | `--auth password,publickey`; client uses pubkey → `auth-ok method=publickey`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_NeitherMethodAllowedRejects` | (negative) start with `--auth=""` and assert run() returns exit 2 before binding. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_SIGHUPReload` | Live process; SIGHUP triggers reload; verify auth flips from key A to key B; finally a malformed file SIGHUP leaves key B working. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_MaxAuthTriesCombinedCounter` | Server `MaxAuthTries=6`, `--auth password,publickey`. Scenario A: client sends 3 rejected-key probes then 3 wrong passwords — disconnected on 6th failure; log has exactly 6 `auth-fail` lines. Scenario B: 6 password failures on a fresh connection — disconnected after 6. Asserts rejected-key queries increment the counter (library behavior, `server.go: serverAuthenticate`). |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PubkeyFailureFeedsRateLimit` | 5 separate connections, each one wrong-key, then a 6th with correct credentials; the 6th's auth wall-clock is in `[13s, 21s]`. Skipped under `-short`. |
| `internal/server/pubkey_integration_test.go` | `TestIntegration_PubkeyFingerprintMatchesSSHKeygen` | Generate a key in-test; capture the `auth-ok` fingerprint; compare to `ssh.FingerprintSHA256` directly. |

### E2E tests (`test/e2e/`, `e2e` build tag)

| File | Test | Intent |
|---|---|---|
| `test/e2e/pubkey_test.go` | `TestE2E_SystemSSHWithIdentityFile` | (Case 17) `/usr/bin/ssh -i <privkey> -o IdentitiesOnly=yes -o PreferredAuthentications=publickey` connects and runs `echo PUBKEY_OK`. Then restart server with `--auth password,publickey` and re-run; still works. |
| `test/e2e/pubkey_test.go` | `TestE2E_PubkeyOnlyRejectsPasswordOnlyClient` | Server `--auth publickey`, client with `-o PreferredAuthentications=password` → ssh exits non-zero, server logs no `auth-ok` and at least one `auth-fail method=` (whatever the library reports for the never-completed negotiation). |

### Coverage

The new files keep the threshold ≥ 90 %:

- `internal/auth/pubkey.go` is exercised by `pubkey_test.go` and
  `pubkey_integration_test.go`. Key paths: `Keyset.Check` (both
  match-found and match-not-found branches, plus the empty-keyset dummy
  branch), `KeysetSource.Load` (good, missing, options-ignored, parse-
  error), `KeysetSource.Reload` (success, failure-preserves-previous).
- `internal/auth/resolve.go` additions tested by `resolve_test.go`.
- `internal/server/auth.go` additions (`publickeyCallback`) tested by
  `pubkey_test.go`.
- `cmd/minisshd/main.go` additions tested by `main_test.go` table
  drivers and one integration test that drives a live SIGHUP.

`internal/version` remains the only excluded package. The Makefile's
`COVERAGE_THRESHOLD := 90.0` is unchanged.

## 7. Backwards compatibility

Default invocation (`minisshd` with no flags and no new env vars) is
byte-for-byte equivalent to today:

- `--auth` defaults to `password`. No public-key callback is registered;
  the SSH server advertises only `password` exactly as before.
- `--authorized-keys` is not read.
- The `listening` event gains two fields (`auth_methods=password
  pubkey_count=0`). This is the **one** observable change in default
  behavior. It is additive (no field is removed or renamed) and tests that
  asserted only on substring presence of the existing fields (the
  recommended assertion style in this codebase per
  `internal/logging/logging_test.go`) are unaffected. Tests that asserted
  exact line equality on a `listening` line — none exist in the current
  suite — would need updating; the plan explicitly leaves the existing
  test fixtures in place and adds new assertions for the new fields.
- `auth-ok` and `auth-fail` events gain `method=` and (for publickey)
  `fingerprint=` fields. The existing fields (`remote`, `user`, `reason`,
  `attempt`, `next_delay`) are unchanged in name, position, and format.
  Tests that asserted on substring presence pass unchanged.
- Existing tests pass without modification:
  - `TestIntegration_CorrectCredentialsAllowShell`
  - `TestIntegration_WrongUserLogsBadUser`
  - `TestIntegration_WrongPasswordLogsBadPassword`
  - `TestIntegration_ThreeWrongPasswordsCloseConnectionAfterThirdAttempt`
  - All `cmd/minisshd/main_*` tests.
  These are explicitly listed in the §6 "Password-only baseline preserved"
  integration test as the regression set.

### Logger signature change — call sites updated, not behavior

`Logger.AuthOK`, `Logger.AuthFail`, and `Logger.Listening` gain new
parameters. This is a source-level breaking change for the `*logging.Logger`
*type signature*, but every call site is inside this repository and is
updated as part of the implementation pass. The on-the-wire log format is
strictly additive — old fields keep their positions, new fields are appended
in event-table order.

### Flag set / env var

`--auth` and `--authorized-keys` are new; `MINISSHD_AUTH` and
`MINISSHD_AUTHORIZED_KEYS` are new. No existing flag or env var is
renamed, removed, or has its default changed.

### Breaking changes

- The two `logging` event payloads (`auth-ok`, `auth-fail`) and the
  `listening` event payload gain new fields. This is documented as
  additive in §9 (the field-order rule "key=value pairs in the order
  listed in the events table" preserves stability). Operators parsing
  logs with a strict positional schema would need to adjust; logfmt
  parsers that key on field names are unaffected.
- No other breaking changes.

## 8. Definition of done

The implementation pass is complete when **all** of the following hold:

1. `go vet ./...` — clean (no warnings).
2. `gofmt -l .` — prints nothing.
3. `go mod tidy` leaves `go.mod` / `go.sum` unchanged after the change is
   merged (i.e. all imports are accounted for and there are no stale
   entries; verify with a follow-up `go mod tidy` producing no diff).
4. `make test` — green; runs unit + integration with `-short` in < 10 s
   (the slow rate-limit and pubkey-rate-limit tests are skipped under
   `-short` per §13.6).
5. `make test-slow` — green; runs the full integration suite including
   `TestIntegration_PubkeyFailureFeedsRateLimit` and the existing
   ~16 s backoff test.
6. `make test-race` — green under `-race -short`.
7. `make e2e` — green where `/usr/bin/{ssh,sftp,scp}` are present; new
   `TestE2E_SystemSSHWithIdentityFile` and
   `TestE2E_PubkeyOnlyRejectsPasswordOnlyClient` pass.
8. `make coverage` — merged coverage ≥ 90.0 % (the existing threshold;
   not raised in this change).
9. The spec amendments listed in §2 of this plan are applied to
   `SPEC.md` verbatim. No code change lands without
   the corresponding spec change in the same commit (per the
   project-defining "spec is the contract" rule in `CLAUDE.md`).
10. The §9 password-scrub invariant is preserved: a unit test in
    `internal/logging/logging_test.go`
    (`TestLogger_PubkeyEvents_PasswordScrubStillApplies`) asserts the
    scrub fires on every new event method.
11. The `internal/version` exclusion remains the only coverage
    carve-out. Every new file in `internal/auth`, `internal/server`, and
    `cmd/minisshd` is counted toward the threshold.
12. The `Password: XXXXXX` banner in `cmd/minisshd/main.go` is the only
    non-`logging` write to stdout. The pubkey paths log via
    `internal/logging` exclusively.
13. The existing `TestIntegration_ThreeWrongPasswordsCloseConnectionAfterThirdAttempt`
    must be updated to reflect `MaxAuthTries = 6`: a password-only client can
    now send up to 6 wrong passwords before the server disconnects. The test
    name should be updated to `TestIntegration_SixWrongPasswordsCloseConnection`
    (or kept with the old name but its assertion updated to expect 6 failures
    before disconnect, not 3). The new
    `TestIntegration_MaxAuthTriesCombinedCounter` proves the combined counter
    including rejected-key queries when methods are mixed.

## 9. Open questions / risks

1. **Multiple host-key algorithms.** The current host key is Ed25519
   (§6). When a client offers a publickey of a different algorithm
   (ssh-rsa, ecdsa-sha2-nistp256), `golang.org/x/crypto/ssh` handles the
   signature verification — but only if the accepted-keys file contains
   keys of that algorithm. The plan does **not** restrict accepted-key
   algorithms; `ssh.ParseAuthorizedKey` returns whatever it parses.
   **Risk:** an operator could add an RSA-1024 key and the server would
   accept it. The plan position is: this is operator responsibility,
   matching OpenSSH's `authorized_keys` semantics. Worth flagging to the
   user for review.
2. **Key options policy.** The plan commits to "parse, ignore with
   WARN". An alternative is "reject any line with options". Ignore is
   the chosen default because it keeps drop-in compatibility with
   existing `~/.ssh/authorized_keys` files an operator might copy over.
   If the reviewer prefers strict rejection, change the position in
   §4 publickey "Authorized-keys file" subsection and in the
   `internal/auth/pubkey.go` parser.
3. **SIGHUP collision with operator habit.** Some operators send SIGHUP
   to processes expecting log rotation. minisshd does not write to a
   file, so this is moot here. The plan keeps SIGHUP narrowly scoped to
   keys reload; if the spec ever adds file logging, the SIGHUP handler
   becomes a fan-out.
4. **Constant-time iteration vs. early-exit perf.** Iterating the entire
   keyset on every callback is O(N) per attempt and leaks N via timing.
   For the threat model (single-user LAN with rate-limit backoff capping
   attempts at ~1/min after a handful of failures) the cost is
   negligible and the timing leak is acceptable. The plan documents this
   in the §4 publickey "Residual side-channel" paragraph; reviewer
   should confirm the position.
5. **Combined counter semantics.** The plan defines a countable failure as
   any `authFailures` increment in `golang.org/x/crypto/ssh` — that is,
   any rejected auth that is not the initial `none` probe. This includes
   password failures, publickey signature failures, AND rejected-key
   pubkey queries. A previous version of this plan claimed pubkey queries
   do not count; that was incorrect (see §4 MaxAuthTries rationale and
   the library source analysis at `server.go: serverAuthenticate`). The value
   `MaxAuthTries = 6` (changed from 3) reflects this corrected
   understanding. `TestIntegration_MaxAuthTriesCombinedCounter` is updated
   to assert the library increments `authFailures` for rejected-key
   queries, not only for real signatures.
6. **Rate-limit interaction with publickey query traffic.** A previous
   version of this plan stated that query-level failures do NOT feed the
   rate limiter. That was wrong.

   **Correct behavior:** `golang.org/x/crypto/ssh` calls `PublicKeyCallback`
   on the first encounter of every (user, key) pair per connection — for
   both probes and real signatures. Because `lim.Acquire` runs at the top
   of the callback, every first-seen key triggers an `Acquire/release`
   cycle, including probe-only keys. A client probing N keys before signing
   the right one causes N `Acquire` calls (modulo the size-1 cache — if
   probe and sign are back-to-back for the same key, only one Acquire
   occurs; if another key is probed in between, the cache evicts the first
   and the sign attempt causes a second Acquire).

   **Design decision:** Option (i) — accept that queries feed the rate
   limiter and document it. This is a deliberate departure from OpenSSH
   (which does not rate-limit per query). The rationale: minisshd's threat
   model is a single-user LAN server; any IP probing a large unknown-key
   set is unusual and conservative rate-limiting is acceptable. An operator
   who connects a multi-key agent from an IP with a prior failure history
   will see query-time backoff — this is the intended behavior. The
   alternative (option ii: move Acquire to a different layer) would require
   either a wrapper around the SSH library's internal isQuery flag (not
   exposed) or a separate per-connection failure counter that duplicates
   logic already in the rate limiter.

   **What was previously said about OpenSSH alignment:** The old wording
   ("This matches OpenSSH") is removed. minisshd explicitly differs from
   OpenSSH here; this is flagged in the implementation comments for operator
   awareness.
7. **Sentinel password when password method is disabled.** The plan uses
   a 32-byte random hex string as the cached password when `--auth`
   excludes `password`, so the password scrub has a non-empty needle and
   the password callback (if ever wired by mistake) cannot succeed. An
   alternative is to leave the cached password empty and disable the
   `PasswordCallback` entirely. Both are safe; the chosen approach keeps
   `auth.NewCredentials` total over its inputs and avoids a nil-check
   in the callback wiring.
8. **XDG fallback edge case.** If `XDG_CONFIG_HOME` is set but empty, the
   plan treats it as unset and falls back to `~/.config/minisshd/...`.
   This matches the XDG Base Directory Specification ("If
   $XDG_CONFIG_HOME is either not set or empty, a default equal to
   $HOME/.config should be used"). Worth flagging because some Linux
   distributions set it to empty in default profiles.
9. **Race between SIGHUP reload and in-flight callback.** The
   `atomic.Pointer[Keyset]` pattern means a callback that started with
   the old set never sees a half-loaded state. A consequence: a key
   removed from the file may still authenticate one in-flight attempt
   after SIGHUP. Reviewer should confirm this is acceptable — alternative
   is to grab a per-callback snapshot earlier, which has the same
   semantics. The plan does not propose stronger eviction.
10. **macOS vs. Linux file mode for the authorized-keys file.** Unlike
    `host_key` (which requires `0600` and exits 4 otherwise), the plan
    does **not** enforce a mode on the authorized-keys file. It contains
    only public material; the existing `~/.ssh/authorized_keys` is
    typically `0600` for OpenSSH but only as defense-in-depth. Reviewer
    should confirm we do not want a mode check here.

---

## Adversarial review responses (iter 1)

Each numbered issue from the reviewer's verdict is addressed below.

### C1 — passwordCallback call-site updates not listed explicitly
**Resolution: Agreed and addressed.** The `internal/server/auth.go` code-changes section now explicitly lists both `log.AuthOK` and `log.AuthFail` call sites in `passwordCallback` that must pass `method="password"` and `fingerprint=""`. The `recordingAuthLogger` stub update in `auth_test.go` is also now explicitly listed.

### C2 — `ok := userOK && keyOK` vs. bitwise AND
**Resolution: Agreed and addressed.** The concern is legitimate. `CheckUsername` returns `(bool, string)`, not `(int, string)`, so the combination is `bool && bool` not `int & int`. The plan now:
1. Explicitly states that `CheckUsername` returns `bool` and that the combination `ok := userOK && keyOK` is safe because both calls are pre-materialized into variables (no inlined call expression in the `&&`).
2. Added a clarifying comment in the `publickeyCallback` step 5 description explaining exactly why no branch is possible.
3. Updated the muddled "bitwise AND on int returns inside the helpers; here we accept the boolean view" comment throughout.

The `CheckUsername` doc comment was also rewritten (M5) to state it returns `(ok bool, reason string)`, reinforcing that the caller combines bools, not ints.

### C3 — MaxAuthTries = 3 library-version dependency
**Resolution: Agreed and addressed.** The proposed §4 spec text now includes an explicit catch-up-amendment notice, pins the behavioral guarantee to `TestIntegration_MaxAuthTriesCombinedCounter` passing before the spec value is committed, and names the library source location where the `none`-exemption comment lives.

### C4 — Unauthenticable check incorrectly includes `--pass` condition
**Resolution: Agreed and addressed.** The `--pass`/`MINISSHD_PASS` condition has been removed from:
- §2.2 step 2c spec text
- §2.4 error table
- `cmd/minisshd/main.go` code-changes section

The check is now simply: `methods == {publickey}` AND zero keys loaded → exit 2.

### C5 — `Config.Methods` nil/empty default and `TestNewServerConfig_OnlyPasswordAuthOffered`
**Resolution: Agreed and addressed.** A new sub-section under `config.go` specifies that nil/empty `Methods` defaults to `["password"]` in `newServerConfig`, with the exact Go code pattern. The `TestNewServerConfig_OnlyPasswordAuthOffered` test and `newTestServer` helper are explicitly listed as needing updates, along with a companion test for the publickey case.

### S1 — publickeyCallback library semantics not documented
**Resolution: Agreed and addressed.** A doc note has been added to the `publickeyCallback` description explicitly stating that `golang.org/x/crypto/ssh` only invokes the callback for real signature verifications (`has_signature=true`), not for pubkey queries.

### S2 — SIGHUP goroutine has no context for clean shutdown
**Resolution: Agreed and addressed.** The SIGHUP goroutine section now shows the exact `select { case <-sighupCh: ... case <-ctx.Done(): return }` loop pattern, explicitly noting it must exit when `ctx.Done()` fires to prevent racing against a partially-torn-down logger during the drain phase.

### S3 — No compile-time assertion for pubkeyLogger → *logging.Logger
**Resolution: Agreed and addressed.** Added `var _ pubkeyLogger = (*logging.Logger)(nil)` to the `internal/server/auth.go` compile-time assertions section, alongside the existing `_ rateLimiter`, `_ credentialChecker`, `_ authLogger`, and `_ publickeyChecker` assertions.

### S4 — "Result is forced to 0" not specified precisely
**Resolution: Agreed and addressed.** The `Keyset.Check` empty-keyset branch now shows the exact Go code pattern with `matched = 0` after the dummy compare, plus an explanatory comment about why it is required (to prevent a false positive on an all-zero presented key hash).

### S6 — Zero-keys-after-having-keys reload policy not in spec text
**Resolution: Agreed and addressed.** The spec amendment reload paragraph now explicitly states: "a reload that succeeds in parsing the file but yields zero usable keys is treated as a failure when the previous keyset had ≥1 key," with the rationale (prevents accidental empty-file rotation from locking all clients out). The `KeysetSource.Reload` code description was updated consistently.

### S7 — Same as C4
**Resolution: Addressed under C4 above.**

### M1 — MaxAuthTries = 3 catch-up amendment not acknowledged
**Resolution: Agreed and addressed.** The spec prose now includes `(**catch-up amendment**: the implementation was already set to 3 ahead of this spec revision, ...)`.

### M5 — CheckUsername doc comment confusing
**Resolution: Agreed and addressed.** The doc comment has been rewritten to: "CheckUsername returns (ok, reason) for the publickey path. Only the username comparison runs; the caller is responsible for combining this result with the keyset check. Reason is '' on match, ReasonBadUser otherwise."

### M6 — §12 amendment: other "key-based auth" references
**Resolution: Disagree that action is required.** A search of `SPEC.md` finds only one occurrence of "key-based auth" — the §12 non-goals bullet that this plan replaces. The §4 method description ("Only the SSH `password` authentication method is offered. `publickey`, …") is replaced wholesale by the §4 rewrite in §2.1. Line 466 (E2E test case 7, "Pubkey-only fails") correctly describes a test where the server runs in `--auth=password` mode and a publickey-only client fails — this remains valid after the change and does not need updating. No other section requires amendment.

### M7 — matched == 1 comment should say "non-zero"
**Resolution: Agreed and addressed.** The `Keyset.Check` description now uses `matched != 0` with a comment explaining why `!= 0` is preferred over `== 1` (OR-accumulation can produce non-1 non-zero values if the implementation changes).

### Accuracy note 1 — atomic.Pointer[Keyset] vs. atomic.Pointer[[]digest] inconsistency
**Resolution: Agreed and addressed.** The spec amendment reload paragraph now uses `atomic.Pointer[Keyset]` consistently. The code section already used `atomic.Pointer[Keyset]`.

### Accuracy note 2 — muddled "bitwise AND on int returns … boolean view" comment
**Resolution: Agreed and addressed.** The comment has been replaced throughout with a precise explanation: `CheckUsername` and `Keyset.Check` return `bool` values; both are pre-materialized into variables before `&&`; no branch is possible.

---

## Adversarial review responses (iter 2)

### Fix A — Incorrect doc comment on PublicKeyCallback invocation semantics
**Resolution: Agreed and fixed.** The iter-1 S1 addition ("the library invokes the callback only for real signature verifications, has_signature=true") was wrong. The library source (`server.go: serverAuthenticate`) shows `PublicKeyCallback` is called unconditionally on the first encounter of a (user, key) pair per connection, before the `isQuery` branch. The callback has no way to know whether it is serving a query or a real signature. The doc comment in the `publickeyCallback` description has been replaced with an accurate description of the library's cache-then-branch pattern, citing the exact source lines.

### Fix B — Rate-limiter design: queries feed the rate limiter
**Resolution: Agreed — Option (i) chosen.** The `lim.Acquire` call remains at the top of `publickeyCallback` and fires for every first-seen (user, key) pair, including probe-only keys. This is documented as a deliberate, tighter-than-OpenSSH posture. Two new unit tests (`TestPublickeyCallback_QueryAndSignBothAcquire`, `TestPublickeyCallback_CacheEvictionCausesDoubleAcquire`) are added to the test table to make this behavior explicit and regression-proof. Options (ii) and (iii) were considered and rejected: (ii) requires access to the library's internal `isQuery` flag, which is not exposed; (iii) per-callback state tracking would duplicate the library's own cache without offering stronger guarantees.

### Fix C — MaxAuthTries math: rejected-key queries burn authFailures slots
**Resolution: Agreed and fixed.** The library source (`server.go: serverAuthenticate`) shows `authFailures++` is reached for any auth failure that is not the initial `none` probe — including the `isQuery=true` path when `authErr = candidate.result` is non-nil. A client probing 3 rejected keys before signing consumes 3 `authFailures` slots. `MaxAuthTries` is raised from 3 to 6 in both the §4 spec amendment and the `config.go` code-changes section, accommodating up to 3 rejected-key probes plus 3 real credential attempts. The §4 explanation includes a "why 6" rationale. The `TestIntegration_MaxAuthTriesCombinedCounter` test description is updated accordingly. The existing `TestIntegration_ThreeWrongPasswordsCloseConnectionAfterThirdAttempt` test must also be updated since the password-only path is also affected by the MaxAuthTries increase (a password-only client now gets 6 attempts, not 3).

### Fix D — Cache-size-1 subtlety: probe→evict→sign causes double invocation
**Resolution: Agreed and acknowledged.** The cache holds at most 1 entry (`maxCachedPubKeys = 1`). If a client probes key A (rejected, cached), then key B (any result, evicts A), then signs with A — the cache misses and `PublicKeyCallback` fires again for A. This means `lim.Acquire` runs twice for key A. This is accepted as conservative behavior (more backoff, not less) and safe (the key-set check is idempotent). A new unit test documents this explicitly. No mitigation is applied.

### Fix E — Open question 6 stated wrong behavior; updated
**Resolution: Agreed and fixed.** The previous OQ6 said "the plan does NOT feed query-level failures into the rate limiter" — this was incorrect given the actual library behavior and the rate-limiter position in the callback. OQ6 has been rewritten to accurately describe what happens (queries feed the rate limiter) and to document the design decision (Option i: accept this, document it, justify it as a tighter posture than OpenSSH). The "This matches OpenSSH" claim has been removed.
