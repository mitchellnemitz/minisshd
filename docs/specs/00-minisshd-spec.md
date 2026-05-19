# minisshd — Spec

A minimal, single-user SSH server for macOS and Linux. Runs as the invoking user, authenticates clients with a username and password (a random 6-digit password is generated if none is supplied), and supports interactive shell, one-off command execution, and SFTP file transfer over the standard SSH protocol so the system `ssh` and `sftp` clients work unmodified.

---

## 1. Recommended stack

**Go** is the recommended and primary implementation language. Rationale:

- `golang.org/x/crypto/ssh` provides a production-grade SSH server library with full protocol support, password auth callbacks, channel/request handling, and SFTP subsystem hooks.
- `github.com/pkg/sftp` plugs straight into `x/crypto/ssh` for the file-transfer subsystem.
- `github.com/creack/pty` handles PTY allocation for interactive shells on macOS and Linux.
- Single static binary, no runtime dependencies.

Python (`asyncssh`) is a viable alternative if Go is unavailable, but the spec below uses Go-specific language throughout (`subtle.ConstantTimeCompare`, `crypto/rand`, `net.ParseIP`, `Setsid`, goroutines, `EADDRNOTAVAIL`, `go build -cover`, etc.). A non-Go implementation must provide the equivalent semantics: a constant-time string compare from a vetted library, a CSPRNG, IP literal parsing, POSIX `setsid`/process groups, the right errno mapping, and a coverage tool that produces line-coverage figures compatible with the §13.5 threshold.

---

## 2. Command-line interface

Binary name: `minisshd`

```
minisshd [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--port N` | `2222` | TCP port to listen on. |
| `--bind IP` | `0.0.0.0` | IP address to bind the listener to. Use `127.0.0.1` for loopback only, a specific LAN address to restrict to one interface, `::` for all IPv6 interfaces, etc. Both IPv4 and IPv6 literals are accepted. |
| `--pass XXXXXX` | random 6-digit | Password clients must present. Any non-empty string accepted as an SSH password is valid. Overrides `MINISSHD_PASS` if both are set. If neither is set, a random 6-digit numeric password is generated and printed at startup. |
| `--user NAME` | current OS user | Username clients must present. Overrides `MINISSHD_USER` if both are set. |
| `--shell PATH` | `$SHELL` | Shell binary for interactive sessions. Falls back to `/bin/zsh` if `$SHELL` is unset. |
| `--log-format FORMAT` | `logfmt` | Structured-log encoding. Valid values: `logfmt`, `json`. See §9. |
| `--host-key PATH` | `~/.minisshd/host_key` | Path to the persistent host key. Generated on first run if missing. |

### Environment variables

| Var | Purpose |
|---|---|
| `MINISSHD_PASS` | Password value. Used only if `--pass` is not provided. Preferred over `--pass` because command-line arguments are visible to any local user via `ps`; environment variables are less exposed (not visible in default `ps` output on macOS or Linux). |
| `MINISSHD_USER` | Expected username. Used only if `--user` is not provided. |
| `MINISSHD_LOG_FORMAT` | Log encoding. Used only if `--log-format` is not provided. Same valid values as the flag. |

### Startup validation

On startup the server must:

1. Validate `--port`: must be an integer in `[0, 65535]`. The value `0` is permitted and means "ask the kernel for an ephemeral port" — used by tests. Otherwise fail with exit code 2.
2. Resolve the user-supplied password: `--pass` if set, else `$MINISSHD_PASS`, else mark for generation in step 8. If a user-supplied value is the empty string, fail with exit code 2.
3. Resolve the expected username: `--user` if set, else `$MINISSHD_USER`, else the OS username of the process owner (`$USER`, falling back to `getpwuid(getuid())`). Must be non-empty; otherwise fail with exit code 2.
3a. Resolve `--log-format`: `--log-format` if set, else `$MINISSHD_LOG_FORMAT`, else `logfmt`. Reject any value other than `logfmt` or `json` with exit code 2 and a message naming the rejected value.
4. Validate `--shell`: resolve the path with `stat` (following symlinks) and verify the final target exists, is a regular file, and is executable by the current user. A broken symlink, a directory, or a non-executable target all exit with code 2 and a message naming the resolved path that failed.
5. Ensure `~/.minisshd/` exists with mode `0700`. If it exists with a wider mode, refuse to start with exit code 4 and instruct `chmod 700`.
6. Load or generate the host key (see §6).
7. Parse `--bind` as a textual IP literal (`net.ParseIP` in Go); fail with exit code 2 if invalid. Bind to `<bind>:<port>` — formatted as `bind:port` for IPv4 and `[bind]:port` for IPv6. On `EADDRINUSE` fail with exit code 3 and a clear message. On `EADDRNOTAVAIL` (the address isn't assigned to any local interface) fail with exit code 3 and a clear message naming the address.
8. **Only after the listener is successfully bound**, if no password was resolved in step 2, generate a fresh 6-digit numeric password using a cryptographically secure RNG (`crypto/rand` in Go) and print exactly one line to stdout: `Password: 482910`. This is the only path that writes the password to stdout. If a password was supplied via flag or env, no banner is printed.
9. Log a single structured `listening` event including the bind address, the **actually bound port** (which may differ from `--port` when `--port 0` was requested — read it from the listener's local address after bind), host key fingerprint, expected username, and PID.

The ordering matters for security: the password banner is printed only when the server is guaranteed to actually start. Any earlier failure exits before the banner runs.

---

## 3. Network exposure

By default the listener binds to `0.0.0.0`, so the server is reachable from the LAN over IPv4. Pass `--bind 127.0.0.1` to restrict it to IPv4 loopback, or a specific interface address to limit it further. For IPv6, use `--bind ::` to accept both IPv6 and IPv4-mapped clients (the implementation must explicitly set `IPV6_V6ONLY = 0` on the listening socket; the OS default varies and isn't safe to rely on), or `--bind ::1` for IPv6 loopback only. A single `--bind` value produces a single listening socket; if you need both pure-IPv4 and pure-IPv6 on the same port, run two instances. No firewall manipulation is performed; the user is responsible for any host firewall configuration (pf or Application Firewall on macOS, iptables/nftables/ufw on Linux).

The server must not be exposed to the public internet by design — this is called out in the README — but no code-level check enforces this.

---

## 4. Authentication

### Method

Only the SSH **`password`** authentication method is offered. `publickey`, `keyboard-interactive`, and all others are not advertised. The `none` method is part of the SSH negotiation flow — the server responds to a `none` attempt by listing `password` as the only allowed method, then rejects it.

The server must guarantee **3 real password attempts per connection** before disconnecting. Because `golang.org/x/crypto/ssh`'s `MaxAuthTries` counter increments on the mandatory `none` probe as well as on password failures, setting `MaxAuthTries = 3` would deliver only 2 password attempts. The spec therefore requires `MaxAuthTries = 4` (allowing one `none` + three passwords), with an integration test (§13.3) that proves a client offering 10 password attempts is disconnected on the third *password* failure, not earlier and not later. Implementers in other languages must implement the same guarantee: count password failures only.

### Credential check

To prevent timing attacks that distinguish wrong-user from wrong-password (or reveal the configured password length), the check must:

1. Compute SHA-256 over the presented username and over the presented password. The implementation pre-computes and caches SHA-256 of the resolved configured username and password after the password is finalized (per §2 step 2 if supplied via `--pass` or `MINISSHD_PASS`, or §2 step 8 if auto-generated) and before the listener accepts its first connection, so every auth callback compares against cached digests. SHA-256 over arbitrary-length input always produces 32 bytes, so equal-length comparison is guaranteed.
2. Compare each presented hash to the configured hash with `subtle.ConstantTimeCompare`. **Both comparisons must always run** — do not short-circuit on the first mismatch. Use `subtle.ConstantTimeSelect` or two boolean ANDs to combine the results without branching.
3. Decide the result:
   - both match → `(ok=true, reason="")`
   - user-hash mismatch, password-hash match → `(ok=false, reason="bad-user")`
   - user-hash match, password-hash mismatch → `(ok=false, reason="bad-password")`
   - both mismatch → `(ok=false, reason="bad-user")` (user wins for logging — keeps the reason field decisive when both are wrong)

The client sees a generic "Permission denied (password)" in all failure cases; only the logs distinguish the reasons (see §9).

**Residual side-channel:** SHA-256 itself is not constant-time over input length — a password that fills two blocks (≥ 56 bytes) takes measurably more CPU than one that fits in one block. The leak is at the block-count level (a handful of cycles per block), far smaller than a byte-by-byte string compare, and dwarfed by network jitter and the rate-limit backoff in §5. For the threat model this spec targets (single-user LAN server, 60 s backoff cap, 6-digit auto-generated default), the residual leak is acceptable. Spec implementers must not claim "fully constant-time auth"; the claim is "constant-time given equal-length inputs, with sub-cycle differences between length classes."

### Failure semantics

The 3-attempt-per-connection cap is described in §4 (Method). Cross-connection failures feed the rate limiter — see §5.

---

## 5. Rate limiting

Exponential backoff keyed by **client IP** (not by username, not by connection). Any failed auth attempt feeds the backoff — both wrong username (`reason=bad-user`) and wrong password (`reason=bad-password`).

**IP normalization:** before using the remote address as a map key, convert IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) to their bare IPv4 form. This prevents an attacker on a dual-stack listener from doubling their attempt budget by alternating between `127.0.0.1` and `::ffff:127.0.0.1`. In Go: `if v4 := ip.To4(); v4 != nil { ip = v4 }`. Pure IPv6 addresses (e.g. `2001:db8::1`) are kept as-is.

All access to the state map below must be thread-safe; multiple goroutines will read and update it concurrently when several connections from the same IP are in flight. The "compute delay → sleep → invoke password callback → record result" sequence must hold a per-IP lock for the entire duration; otherwise two simultaneous attempts from the same IP can both observe `fail_count=0` and bypass the first-attempt delay. The global map needs its own lock too, but contention is reduced if the per-IP locks are stored in the map values.

### State

The server maintains an in-memory map:

```
ip -> { fail_count: int, last_fail: timestamp }
```

### Algorithm

On every failed auth attempt from IP `X` (any `reason`):

1. Increment `fail_count[X]`.
2. Set `last_fail[X] = now`.

On every **incoming auth attempt** from IP `X`:

1. If `fail_count[X] == 0`, skip to step 3 (no delay).
2. Sleep `delay = min(60, 2 ^ (fail_count[X] - 1))` seconds. The sequence over rising `fail_count` is 1, 2, 4, 8, 16, 32, 60, 60, …. The TCP connection stays open during the sleep.
3. Invoke the password callback.

The "on every incoming auth attempt" rule includes every password attempt within a single connection, not just the first. So a connection that fails three times in a row sees sleeps of 0 s, 1 s, 2 s (for `fail_count` growing 0→1→2→3), adding ~3 s of intra-connection delay on top of the per-IP cross-connection backoff. Implementations must not optimize this away by hoisting the delay outside the callback.

### Reset

The entry for IP `X` is deleted (counter reset to zero) under either of two conditions:

- **Successful auth from `X`**: clears the backoff so a user who fat-fingered their password a few times isn't penalized after they get it right.
- **10 minutes idle**: if `now - last_fail[X] > 10 minutes`, the entry is deleted on the next access before processing.

### Memory bound

When an auth attempt arrives, the server checks that IP's entry; if `now - last_fail > 10 min`, the entry is deleted before processing (per §5 Reset). All timestamp arithmetic uses a monotonic clock (in Go: `time.Now()` returns a `Time` with monotonic component; `time.Since(t)` and `now.Sub(t)` use it automatically) so NTP adjustments don't accidentally expire entries or extend backoffs. A bulk sweep across the whole map is not required. Under a botnet hitting from many distinct IPs the map can grow unbounded — this is an accepted limitation for a single-user LAN server. Implementations may add an LRU cap (e.g. evict the 10 % oldest entries when size exceeds 10 000) but are not required to.

### Loopback policy

`127.0.0.1` and `::1` are **not** exempted from the backoff. The same delays apply — this protects against local malware. If a developer running on their own machine finds the backoff annoying, the answer is to authenticate correctly, not to weaken the loopback policy.

---

## 6. Host key

- **Type:** Ed25519.
- **Path:** `~/.minisshd/host_key` by default, overridable with `--host-key`. The public key is always written alongside as `<host_key>.pub` (mode `0644`) for the user's convenience.
- **Parent directory:** the parent of `--host-key` must exist and be writable by the current user at startup. If it does not exist, the binary refuses to start with exit code 4 and a message naming the missing directory. The binary does not auto-create non-default parent directories — the default `~/.minisshd/` is the one exception (§2 step 5 creates it).
- **Generation:** if the private key file is missing on startup, generate a new Ed25519 key, write the private key in OpenSSH private-key format with `chmod 0600`, and write the public key in OpenSSH `authorized_keys` format with `chmod 0644`.
- **`.pub` regeneration:** the public key is always re-derived from the private key at startup and written. Both when generating a new private key, and when the private key already exists but `<host_key>.pub` is missing or stale — the implementation derives the public key from the private key and writes it, overwriting any existing `.pub` file. This is safe because the public key is fully derivable; nothing important can be lost by overwriting.
- **Permissions check:** if the private key file exists with mode wider than `0600`, refuse to start and print a message instructing the user to `chmod 600`.
- **Corrupt key:** if the private key file exists with correct mode but cannot be parsed (truncated, garbled, wrong format), refuse to start with exit code 4 and print a message naming the unreadable path. The implementation does **not** silently regenerate, because a corrupt file could indicate a bug or attack and replacing it would change the host fingerprint and trigger known-hosts warnings on all clients.
- **Fingerprint:** the SHA256 fingerprint is logged at startup so the user can verify it on first client connection.

The host key is never regenerated automatically; deleting the file is the only way to roll it.

---

## 7. SSH features supported

The server must implement enough of the protocol to satisfy these client invocations:

| Client command | Channel type | Request | Required behaviour |
|---|---|---|---|
| `ssh host` | `session` | `pty-req` then `shell` | Interactive PTY-backed shell (see §8). |
| `ssh host CMD` | `session` | `exec` | Run `CMD` via `$SHELL -c CMD`, stream stdout/stderr, propagate `exit-status` or `exit-signal` per §8.2 step 5. |
| `sftp host` | `session` | `subsystem sftp` | Hand the channel to an SFTP server implementation rooted at `/`. |
| `scp` (modern) | `session` | `subsystem sftp` | Modern OpenSSH `scp` (9.0+, default on macOS Sonoma and recent Linux distros) uses SFTP. Works via the SFTP subsystem above. |
| `scp -O` (legacy) | `session` | `exec scp …` | Legacy `scp` invoked with `-O` runs a remote `scp` binary. Works via the `exec` path. |

The following must be **explicitly rejected** with a `ChannelOpenFailure` or request reject:

- `direct-tcpip` (local port forwarding)
- `forwarded-tcpip` / `tcpip-forward` (remote port forwarding)
- `direct-streamlocal@openssh.com`, `streamlocal-forward@openssh.com` (Unix-socket forwarding)
- `auth-agent-req@openssh.com` (agent forwarding)
- `x11-req` (X11 forwarding)
- Any subsystem name other than exactly `sftp` (case-sensitive, no leading/trailing whitespace). `SFTP`, `Sftp`, ` sftp`, `sftp-server` all rejected.

---

## 8. Session handling

### Request-type combinations

A session channel may receive `pty-req`, `env`, `shell`, `exec`, and `subsystem` requests in any order. The server's behavior:

| Sequence | Behavior |
|---|---|
| `pty-req` → `shell` | Interactive PTY shell, full rc-chain loaded. See §8.1. |
| `shell` (no prior `pty-req`) | Spawn the shell *without* a PTY using the hyphen-prefix `argv[0]` (login but not interactive). zsh loads `.zshenv`, `.zprofile`, `.zlogin` but **not** `.zshrc`. Channel ↔ stdio is piped instead of through a PTY. Treated like §8.1 but without PTY allocation. |
| `pty-req` → `exec CMD` | The PTY is allocated and `<shell> -c CMD` runs attached to it. `argv[0]` is still bare (no hyphen prefix), so the shell is interactive (PTY) but not a login shell. zsh loads `.zshenv` and `.zshrc` but not `.zprofile`. Behavior matches `ssh -t host CMD` in OpenSSH. |
| `exec CMD` (no prior `pty-req`) | Non-interactive, non-login. See §8.2. |
| `subsystem sftp` | See §8 SFTP. |
| `subsystem` (anything else) | Rejected per §7. |
| Two of `shell`/`exec`/`subsystem` on one channel | Only the first is honored; subsequent ones rejected with request-failure. |

### Interactive shell

1. On `pty-req`, allocate a PTY using `creack/pty`. Honor the requested `TERM`, rows, cols, and pixel dimensions. Handle subsequent `window-change` requests by resizing the PTY.
2. On `shell`, spawn the configured shell as a **login shell using the hyphen-prefix convention**: set the child's `argv[0]` to `-<basename>` (e.g. `-zsh` for `/bin/zsh`). If a PTY was allocated in step 1, attach the child's stdio to the PTY slave; otherwise wire stdin/stdout/stderr directly to the channel (see §8 Request-type combinations for the no-pty case). This is the same login convention OpenSSH uses. In Go: `cmd := exec.Command(shellPath); cmd.Args = []string{"-" + filepath.Base(shellPath)}`. Do not also pass `-l` — the hyphen prefix is sufficient and avoids redundant flags.
3. The child loads its shell rc files according to which conditions are met:
   - **PTY + login (the `pty-req → shell` case):** stdin/stderr are TTYs and `argv[0]` starts with `-`, so the shell is both interactive and a login shell. For zsh the full rc chain loads, in order: `/etc/zshenv` → `~/.zshenv` → `/etc/zprofile` → `~/.zprofile` → `/etc/zshrc` → `~/.zshrc` → `/etc/zlogin` → `~/.zlogin`.
   - **No PTY + login (the `shell` without `pty-req` case):** login but not interactive. zsh loads `.zshenv`, `.zprofile`, `.zlogin` but **not** `.zshrc`.

   In either case the implementation must not interfere with rc loading — no extra flags, no `-c`, no overriding of `ZDOTDIR`, `ENV`, or `BASH_ENV`.
4. The child process inherits a sanitized environment:
   - `HOME`, `USER`, `LOGNAME`, `SHELL` from the server process.
   - `PATH` from the server process.
   - `TERM` from the SSH `pty-req`.
   - `LANG`, `LC_*` from the server process if set.
   - The SSH client may send additional `env` requests; accept only `LANG` and `LC_*` (ignore the rest silently to avoid injection of `LD_*` etc.).
5. Pipe channel ↔ PTY bidirectionally. The session ends on whichever happens first:
   - **Child exits** (normal or signal): keep draining PTY output to the channel until the PTY master returns EOF (or `EIO` on platforms that surface it that way). Cap the drain at **2 seconds** as a backstop against a PTY that fails to close cleanly; anything past 2 s is dropped and a `drain-timeout` event (WARN, §9) is logged with the number of dropped bytes. Then send `exit-status`/`exit-signal` per step 6 and close the channel.
   - **Channel closes** (client disconnects, TCP drops, server sends EOF): send `SIGHUP` to the child's process group (see §8 Signal handling), wait up to 5 s for graceful exit, then `SIGKILL`. Do not send `exit-status` on the closed channel.
6. On child exit, send the appropriate channel request, then close: if the child exited normally, send `exit-status` with the real exit code (0–255). If the child was killed by a signal, send `exit-signal` with the POSIX signal name (e.g. `HUP`, `TERM`, `KILL`), the core-dump flag, and an empty error message — do not send `exit-status` in that case. SSH clients render `exit-signal` distinctly from a status-zero exit.

### Exec (one-off commands)

1. On `exec`, spawn `<shell> -c <command>` **without** the hyphen-prefix `argv[0]`. Whether a PTY is attached depends on whether a `pty-req` preceded the `exec` (per the §8 request-type combinations table):
   - **Bare exec (no `pty-req`):** the child is neither a login shell nor an interactive shell. **None of the shell's rc files load** — not `.zshrc` (interactive-only), not `.zprofile` or `.zlogin` (login-only). Only `.zshenv`/`/etc/zshenv` load for zsh. This matches OpenSSH's behavior. The practical consequence: commands installed only via `.zshrc` (e.g. Homebrew on `/opt/homebrew/bin` if it's not also in `.zshenv` or the system PATH) will not be found by `ssh host CMD`. Users who need the full environment can wrap explicitly: `ssh host 'zsh -lic "CMD"'`. The server does not paper over this.
   - **Exec with PTY (`ssh -t host CMD`):** stdin/stderr are TTYs so the shell is interactive but not a login shell. zsh loads `.zshenv` and `.zshrc` but not `.zprofile`/`.zlogin`.
2. Wire stdio:
   - Bare exec: `stdin` from the channel, `stdout` to the channel data stream, `stderr` to the channel `extended_data` stream (type 1).
   - Exec with PTY: stdio attached to the PTY slave; the channel data stream is piped to/from the PTY master. There is no separate `extended_data` stream when a PTY is in use (stderr is merged with stdout by the line discipline).
3. Same environment rules as interactive shell, with one conditional: `TERM` is included if and only if a PTY was allocated (per the request-type combinations table, exec-with-pty does get `TERM`; bare exec does not).
4. Channel/child lifecycle, mirroring §8.1 step 5:
   - **Child exits**: drain remaining output to the channel until upstream returns EOF — for the PTY case until the PTY master returns EOF; for the bare-exec case until both stdout/stderr pipes return EOF. Cap the drain at **2 seconds** as a backstop; anything past 2 s is dropped and a `drain-timeout` event (WARN, §9) is logged. Then send `exit-status`/`exit-signal` per step 5 and close the channel.
   - **Channel closes before child exit**: send `SIGHUP` to the child's process group (see §8 Signal handling), wait up to 5 s for graceful exit, then `SIGKILL`. Do not send `exit-status` on the closed channel.
5. On child exit, send `exit-status` or `exit-signal` per the same rules as the interactive shell (see §8 Interactive shell step 6).

### SFTP

Use `pkg/sftp` with default settings (server rooted at `/`, follows the invoking user's filesystem permissions). No chroot.

### Concurrency

Unlimited concurrent sessions. Each connection runs in its own goroutine; each channel within a connection runs in its own goroutine.

### Signal handling

Each spawned child is placed in its own process group (`setpgid(0, 0)` in the child, or `Setsid: true` on the Go `SysProcAttr`). All signal delivery from the server uses negative PIDs (`kill(-pgid, sig)`) so descendants of the shell — not just the shell itself — receive the signal. This matters because shells do not reliably propagate `SIGHUP` to their grandchildren.

On `SIGINT` or `SIGTERM` the server:

1. Stops accepting new connections.
2. Sends `SIGHUP` to the process group of each child shell.
3. Waits up to 5 seconds for connections to drain.
4. Sends `SIGKILL` to any process groups that didn't exit.
5. Exits with code 0.

### Client `signal` requests

SSH clients may send `signal` channel requests to deliver a signal to a server-side process (RFC 4254 §6.9). These requests carry `want_reply = false`, so the server **silently drops them** (no reply is sent or possible). Clients can still send signals to interactive shells via the PTY (e.g. Ctrl-C generates SIGINT via the line discipline). For exec sessions without a PTY, clients have no way to deliver signals other than closing the channel, which triggers the cleanup in §8.2 step 4.

---

## 9. Logging

Logs go to **stdout**, line-buffered. One event per line, terminated by a
single `\n`. The encoding is selectable at startup via `--log-format`
(`MINISSHD_LOG_FORMAT` env var); valid values are `logfmt` (default) and
`json`. An unknown value causes startup to fail with exit code 2 and a
message naming the rejected value.

**`logfmt` (default):** RFC 3339 timestamp, level, event name, then
space-separated `key=value` pairs. Values are quoted with double quotes when
they contain whitespace, `=`, `"`, or are empty; otherwise they appear bare.
Inside quoted values, `"` and `\` are backslash-escaped. IPv4 and IPv6
literals contain no special characters under this rule and appear unquoted
(e.g. `bind=0.0.0.0`, `bind=::`, `remote=[2001:db8::1]:51223`).

**`json`:** one JSON object per line, encoded per RFC 8259, terminated by a
single `\n` and no trailing whitespace. Field names match the logfmt keys
exactly. Field types:
- `ts` — RFC 3339 string with the same wire format as logfmt's leading
  timestamp (e.g. `"2026-05-17T14:22:01-07:00"`). Always present and always
  the first key in the JSON object (JSON ordering is stable by construction
  of the encoder; logfmt does not make a field-ordering guarantee).
- `level` — JSON string, one of `"INFO"`, `"WARN"`, `"ERROR"`. Always the
  second key in the JSON object.
- `event` — JSON string (e.g. `"listening"`, `"auth-fail"`). Always the
  third key in the JSON object.
- `bind`, `fingerprint`, `user`, `remote`, `reason`, `kind`, `what`, `sig`,
  `message` — JSON string. RFC 8259 escaping applies (`"` → `\"`,
  `\` → `\\`, control characters → `\uXXXX`).
- `port`, `pid`, `attempt`, `pgid`, `bytes_dropped` — JSON integer.
- `duration`, `next_delay` — JSON number, **seconds as a float** (e.g.
  `27.0`, `1.5`, `0.001`). This replaces the logfmt `time.Duration.String()`
  form because programmatic consumers benefit from a numeric type.
- All other event-defined fields preserve the type categories above.

Field ordering within a JSON object is stable across emissions: `ts`,
`level`, `event` first in that order, then the event-specific fields in
alphabetical order by key. JSON itself does not mandate ordering, but stable
ordering keeps line-diff-based tests legible and is cheap to produce.

In **both** formats, the password value must never appear in any structured
log event. The `logging` package enforces this with a runtime byte-level
substring replacement of the configured password with `[REDACTED]` applied
to the fully-encoded line immediately before it is written. For JSON the
substitution is safe under the following condition: the replacement string
`[REDACTED]` contains no JSON-special characters, and the password — when
embedded in a JSON string field — appears in its encoded form (with `"`,
`\`, and controls already escaped). Replacing that encoded form with
`[REDACTED]` yields a JSON string that is still well-formed, **provided the
password does not contain structural JSON delimiter characters (`,`, `:`,
`{`, `}`, `[`, `]`)**. Those characters appear verbatim inside JSON string
values and also appear in the surrounding structural JSON. A password equal
to, say, `","` would cause the scrub to replace delimiter characters,
producing a malformed object. Operators must not configure such passwords
when JSON output is selected. This is the same class of operator footgun
that affects logfmt with passwords containing `=`, space, or `"`. Duration
fields differ between formats: logfmt emits `time.Duration.String()` (e.g.
`27s`); JSON emits float seconds (e.g. `27.0`). Both representations carry
the same numeric value.

```
2026-05-17T14:22:01-07:00 INFO  listening bind=0.0.0.0 port=2222 fingerprint=SHA256:abc… user=alice pid=4711
2026-05-17T14:22:18-07:00 INFO  conn-open  remote=192.168.1.42:51223
2026-05-17T14:22:18-07:00 INFO  auth-ok    remote=192.168.1.42:51223 user=alice
2026-05-17T14:22:18-07:00 INFO  session    remote=192.168.1.42:51223 kind=shell
2026-05-17T14:22:45-07:00 INFO  shutdown-signal pgid=4733 sig=HUP reason=channel-close
2026-05-17T14:22:45-07:00 INFO  conn-close remote=192.168.1.42:51223 duration=27s
2026-05-17T14:23:02-07:00 WARN  auth-fail  remote=10.0.0.5:55001 user=bob reason=bad-user attempt=1 next_delay=1s
```

When `--log-format json` is in effect, the same events render as:

```
{"ts":"2026-05-17T14:22:01-07:00","level":"INFO","event":"listening","bind":"0.0.0.0","fingerprint":"SHA256:abc…","pid":4711,"port":2222,"user":"alice"}
{"ts":"2026-05-17T14:22:18-07:00","level":"INFO","event":"conn-open","remote":"192.168.1.42:51223"}
{"ts":"2026-05-17T14:22:18-07:00","level":"INFO","event":"auth-ok","remote":"192.168.1.42:51223","user":"alice"}
{"ts":"2026-05-17T14:23:02-07:00","level":"WARN","event":"auth-fail","attempt":1,"next_delay":1.0,"reason":"bad-user","remote":"10.0.0.5:55001","user":"bob"}
```

The `Password: XXXXXX` banner described in §2 step 8 is **not** a structured
log event. It is a one-shot human-readable line written directly to stdout
from `cmd/minisshd/main.go` and is unaffected by `--log-format`. The banner
appears verbatim in both formats' invocations.

### Required events

| Event | Level | Fields |
|---|---|---|
| `listening` | INFO | bind, port, fingerprint, user, pid |
| `conn-open` | INFO | remote |
| `conn-close` | INFO | remote, duration (Go `time.Duration.String()` form, e.g. `27s`, `1m3.5s`) |
| `auth-ok` | INFO | remote, user |
| `auth-fail` | WARN | remote, user, reason (`bad-user` / `bad-password`), attempt (per-IP cumulative `fail_count` after this failure), next_delay (sleep that the next attempt from this IP will incur) |
| `session` | INFO | remote, kind (`shell` / `exec` / `sftp`) |
| `reject` | WARN | remote, what (`x11`, `tcpip`, `agent`, `subsystem`, `streamlocal`, etc.) |
| `shutdown-signal` | INFO | pgid (process group ID receiving the signal), sig (POSIX signal name, e.g. `HUP` or `KILL`), reason (`shutdown` for server SIGINT/SIGTERM path, `channel-close` for client disconnect). Emitted every time the server sends a signal to a child process group. Lets tests verify signal delivery timing without racing the kernel. |
| `drain-timeout` | WARN | remote, kind (`shell` / `exec`), bytes_dropped. Emitted when post-exit output drain exceeds the 2 s cap (§8.1 step 5 / §8.2 step 4). Indicates the PTY or pipes didn't close cleanly after child exit. |
| `error` | ERROR | message, remote (if applicable) |

The password must **never** appear in any structured log event, including at startup or in errors. The single exception is the `Password: XXXXXX` banner line printed to stdout when the password is auto-generated (see §2 step 8); this is a one-shot user-facing notice, not a structured log entry.

If the user wants log persistence, the safe approach is to redirect *only* when the password was provided externally (so no banner is ever printed): `MINISSHD_PASS=hunter2 minisshd > minisshd.log 2>&1`. Redirecting an auto-generated invocation captures the password in the file — never do that for shared or persisted logs.

---

## 10. File layout

```
~/.minisshd/
├── host_key          # 0600  Ed25519 private key
└── host_key.pub      # 0644  public key (written alongside, for the user's reference)
```

The directory itself is `0700`. The binary creates the directory and key files if they are missing on startup. If the directory exists with a wider mode, or the private key file exists with a wider mode, startup fails per §2 step 5 / §6.

**Operator note (outside the runtime contract).** Example service-unit files for running `minisshd` under launchd (macOS) or `systemd --user` (Linux) live in `docs/examples/`. They are not loaded or referenced by the binary and are not part of the runtime contract; they are operator-facing templates only.

---

## 11. Error and edge cases

Exit code taxonomy: **0** clean shutdown, **1** unexpected internal error, **2** invalid configuration (CLI/env), **3** network bind failure, **4** filesystem/permission failure.

| Case | Behaviour |
|---|---|
| `--port` outside `[0, 65535]` | Exit 2, message to stderr naming the rejected value. |
| `--shell` path is missing, not a regular file, or not executable | Exit 2, message to stderr. |
| `~/.minisshd/` exists with mode wider than `0700` | Exit 4, instruct `chmod 700`. |
| Password provided but empty | Exit 2, message to stderr. |
| `--bind` value is not a valid IP literal | Exit 2, message to stderr naming the rejected value. |
| `--log-format` value other than `logfmt` or `json` | Exit 2, message to stderr naming the rejected value. |
| `--bind` address is not assigned to a local interface | Exit 3, message to stderr (`EADDRNOTAVAIL`). |
| Port already in use | Exit 3, message to stderr. |
| `~/.minisshd/host_key` is world-readable | Exit 4, instruct `chmod 600`. |
| `~/.minisshd/host_key` exists but is unparseable (corrupt) | Exit 4, message naming the unreadable path. Does not silently regenerate. |
| `--host-key` parent directory missing or not writable | Exit 4, message naming the missing/unwritable directory. |
| Client requests unsupported channel/subsystem | Reject the request, log `reject`, keep the connection open. |
| Client offers a non-password auth method | Server advertises only `password`; clients negotiate down. |
| PTY allocation fails | Reject the `pty-req`, keep the channel; client can still use `exec`. |
| Child shell fails to spawn | Send `exit-status` 127, log an `error`, close the channel. |

---

## 12. Explicit non-goals

- Public-internet exposure.
- Multiple users, key-based auth, certificates, or 2FA.
- Port forwarding (local, remote, dynamic), agent forwarding, X11.
- chroot / sandboxed SFTP.
- Audit logging of session content (keystrokes, transferred files).
- File-based logging, log rotation, log shipping. Logs go to stdout; redirect if you need a file. Structured JSON output **is** supported via `--log-format json` (§9) and is no longer a non-goal.
- Daemonization or auto-start at login *implemented in the binary*. `minisshd` is supervisor-naive — it does not fork, detach, write a PID file, manage its own restarts, or hook itself into a service manager. Run it in a terminal or under your own process supervisor.
- Operator escape hatch: copy/paste service-unit templates for launchd (macOS) and `systemd --user` (Linux) are provided in `docs/examples/`. The binary itself is unchanged. Operators using these templates must set `MINISSHD_PASS` (or one of the hardened credential mechanisms documented there) — running with an auto-generated password under a supervisor would capture each rotated password into the supervisor's log file, which §9 warns against.
- Privileged operations or running as another user.
- Windows support. macOS and Linux only.

---

## 13. Test suite

The implementation must ship with a comprehensive automated test suite organized into three layers: unit, integration, and end-to-end. Combined line coverage across the binary's packages must be **≥ 90.0%**, enforced by CI.

### 13.1 Organization

Suggested layout:

```
cmd/minisshd/             # main package
internal/
├── auth/                # password/username resolution + check
├── ratelimit/           # exponential backoff state machine
├── hostkey/             # load/generate/permission check
├── server/              # SSH server wiring, channel/request handling
├── session/             # PTY + exec + SFTP plumbing
└── logging/             # structured logger
test/
└── e2e/                 # //go:build e2e — runs against compiled binary
```

Unit tests live next to their packages as `*_test.go`. Integration tests sit in dedicated `*_integration_test.go` files that drive the server in-process with `golang.org/x/crypto/ssh` as the client. E2E tests are gated behind the `e2e` Go build tag so they don't run by default.

All tests run under `go test -race`.

### 13.2 Unit tests

Each component is tested in isolation. At minimum:

**`auth`**
- Password resolution precedence: `--pass` > `MINISSHD_PASS` > generated. Generated password is exactly 6 numeric digits drawn from `crypto/rand`.
- Password validation accepts any non-empty string (e.g. `"12345"`, `"hunter2"`, `"a very long passphrase with spaces"`, `"日本語"`); rejects only `""`.
- Username resolution precedence: `--user` > `MINISSHD_USER` > OS user. Empty resolved value is an error.
- Credential check uses SHA-256 + `subtle.ConstantTimeCompare`; both hash comparisons always run (no short-circuit). Verified by code inspection in review. A timing test (10 000 wrong-user and 10 000 wrong-password attempts) compares the two timing samples with a two-sided Mann-Whitney U test; the test asserts U-statistic p-value > 0.001 (i.e. no statistically detectable difference at α = 0.001). A simple mean-ratio check is **not** used because microsecond-scale operations on shared CI hardware have noise that defeats any tight threshold.
- Auth callback returns `(ok, reason)` for all four combinations of {good, bad} × {user, password}, with `reason ∈ {"", "bad-user", "bad-password"}`. When both inputs are bad, `reason == "bad-user"`.

**`cmd/minisshd` startup validation**
- `--port -1`, `--port 65536`, `--port abc` all exit 2 with a message naming the rejected value. `--port 0` succeeds and the `listening` event reports the actually-bound port.
- `--shell /nonexistent`, `--shell /etc/passwd` (not executable), `--shell /etc` (directory) all exit 2.
- `--bind not-an-ip`, `--bind 999.0.0.1` exit 2; `--bind 0.0.0.0`, `--bind ::`, `--bind ::1` succeed.
- `~/.minisshd/` pre-existing with mode `0755` exits 4 with a `chmod 700` message; mode `0700` is accepted and unchanged.
- Banner: with `--pass hunter2`, captured stdout does **not** contain a `Password:` line. Same with `MINISSHD_PASS=hunter2` in the environment (no `--pass`). With no `--pass` and no `MINISSHD_PASS`, captured stdout contains exactly one `^Password: \d{6}$` line, *after* the listener has bound.
- Banner-suppression on failure: with no `--pass` set and an intentionally bad `--bind 999.999.999.999`, the process exits non-zero and captured stdout is empty (the password is never generated, let alone printed).
- `--log-format xml` exits 2 with a message naming the rejected value. `--log-format ""` (explicit empty) also exits 2. `--log-format json` and `--log-format logfmt` succeed. `MINISSHD_LOG_FORMAT=json` with no `--log-format` flag selects JSON.

**`ratelimit`** (clock is injected for determinism)
- `delay(0) == 0`, `delay(1) == 1s`, `delay(2) == 2s`, `delay(7) == 60s`, `delay(20) == 60s` (capped).
- Recording a failure increments the counter and updates `last_fail`.
- After 10 min idle (advanced via the injected clock), the next call sees a fresh counter.
- Successful auth resets the counter: record 3 failures for IP X (fail_count=3), then record one success → fail_count=0; next attempt from X has no delay.
- Pruning removes stale entries from the map.
- Concurrent access from 100 goroutines is race-free under `-race`.

**`hostkey`**
- Generates an Ed25519 key when the file is missing; writes mode `0600`; writes the `.pub` sibling at `0644`.
- Loads an existing key without modification.
- Refuses to load a key whose mode is wider than `0600` (exit code 4 surface tested in `cmd/minisshd`).
- Refuses to load a corrupt/unparseable key (truncate the file to 5 random bytes, then try to load → returns an error; cmd/minisshd-level test verifies this surfaces as exit code 4).
- Round-trips: generate → load → marshal → load again → byte-identical.

**`server` / `session`**
- Env-var filter accepts `LANG`, `LC_ALL`, `LC_TIME`; rejects `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`, `HOME`, arbitrary keys.
- `direct-tcpip`, `forwarded-tcpip`, `direct-streamlocal@openssh.com`, and `streamlocal-forward@openssh.com` channel-opens are all rejected.
- Global requests `tcpip-forward` and `cancel-tcpip-forward` are rejected.
- Session requests `x11-req`, `auth-agent-req@openssh.com`, and `subsystem` for anything other than `sftp` are rejected.
- `window-change` request resizes the PTY (asserted against a mock ioctl).
- POSIX→SSH signal name mapping: SIGHUP→`HUP`, SIGINT→`INT`, SIGQUIT→`QUIT`, SIGILL→`ILL`, SIGABRT→`ABRT`, SIGFPE→`FPE`, SIGKILL→`KILL`, SIGSEGV→`SEGV`, SIGPIPE→`PIPE`, SIGALRM→`ALRM`, SIGTERM→`TERM`, SIGUSR1→`USR1`, SIGUSR2→`USR2`. Any signal outside this set is reported as `TERM` with `error_message="unmapped signal: <name>"`.

**`logging`**
- Every event type matches `^\S+ (INFO|WARN|ERROR) +\S+ .*$`.
- Password value never appears in any structured event, even when fed in via test fixtures (assert on full captured output).
- `auth-fail` carries the correct `reason` field per call site.
- Every existing logfmt envelope/quoting test has a JSON twin. The same event emitted via the JSON encoder is parsed back with `encoding/json` and asserted to carry the same field names and value types listed in §9.
- JSON output is one well-formed JSON object per line. `json.Unmarshal` succeeds for every emitted line under each event method.
- Password scrub for JSON: when the configured password contains a JSON metacharacter (test case: `"hello"world`), the encoded line is still well-formed JSON after the scrub, and the literal password byte sequence does not appear anywhere in the output.

### 13.3 Integration tests

In-process tests that spin up the server on `127.0.0.1:0` and drive it with `golang.org/x/crypto/ssh` as the client. No external processes.

Required scenarios:

- Correct user + password → shell channel returns expected output for a scripted command.
- Wrong user + correct password → auth fails; captured log contains `reason=bad-user`.
- Correct user + wrong password → auth fails; captured log contains `reason=bad-password`.
- Three wrong passwords in one connection → server closes the connection after the third password failure. Specifically, with a custom client config offering 10 password attempts, the server still terminates the connection after the third password failure (proving the 3-password-cap is enforced server-side, not by the client, despite `MaxAuthTries = 4` allowing room for the `none` probe per §4).
- Exec channel: `'echo hi; exit 7'` returns `"hi\n"` on stdout and exit-status 7.
- SFTP subsystem: `Stat`, write a 1 MB file, read it back, delete it; bytes match.
- Rate-limit state is shared across reconnects from one IP: fire 5 failed attempts (separate connections), then a 6th with the correct credentials. After the 5th failure `fail_count` is 5, so the delay before the 6th attempt's password callback is `2^(5-1) = 16 s`. Measure wall-clock time from the start of the 6th TCP connection to the `auth-ok` log entry. It must be within `[13 s, 21 s]` (16 s ±20% gives [12.8, 19.2]; add up to ~1 s for the handshake and ~1 s for general jitter on shared CI). The rate-limiter is given a real clock here, not an injected one.
- Successful-auth reset (end-to-end): after the test above, immediately open a 7th connection with correct credentials. Wall-clock time from connection start to `auth-ok` must be < 1 s (no backoff delay). This proves the success in attempt 6 reset the counter for that IP.
- 20 concurrent connections each running a short exec command all succeed.
- Server rejects `direct-tcpip` channel opens.
- Server rejects `x11-req` on a session channel.
- **Interactive shell loads `~/.zshrc`**: with `HOME=t.TempDir()` and `--shell /bin/zsh`, write `echo MINISSHD_RC_LOADED_$$` into `$HOME/.zshrc`, open a session channel, request a PTY, send `shell`, send `exit\n`, read all output → captured output must contain `MINISSHD_RC_LOADED_` followed by the child PID. Also write a sentinel into `$HOME/.zprofile` (`echo MINISSHD_PROFILE_LOADED`) and confirm both markers appear, in `.zprofile`-then-`.zshrc` order.
- **Exec does not load `~/.zshrc`**: same setup as above (sentinels in `.zshrc` and `.zprofile`), but instead of `shell` send `exec 'echo CMD_OUTPUT'`. Captured stdout must equal `"CMD_OUTPUT\n"` exactly — the `.zshrc` and `.zprofile` markers must **not** appear. A `.zshenv` sentinel written in the same test, by contrast, **must** appear (zsh sources `.zshenv` even for `-c`).
- **`shell` without prior `pty-req`** (matches the §8 combinations table): write a `.zprofile` sentinel and a `.zshrc` sentinel. Open a session channel, skip `pty-req`, send `shell`, then send `exit\n` on the channel data stream. Captured output must contain the `.zprofile` marker (login shell loaded it) and must NOT contain the `.zshrc` marker (not interactive).
- **IPv4-mapped IPv6 normalization (§5):** start the server with `--bind ::` (dual-stack). Make a single IPv4 connection from `127.0.0.1` and fail auth once. On a dual-stack listener that IPv4 connection arrives at the SSH layer with remote address `::ffff:127.0.0.1`. The rate-limiter must expose a way to inspect its current state (e.g. a `Snapshot()` method returning a `map[string]int` of `key → fail_count`; the same surface is useful for an eventual admin endpoint and so is not test-only). Assert: (a) the snapshot contains the key `127.0.0.1` (the normalized form) and not `::ffff:127.0.0.1` — proving normalization happened; (b) `fail_count == 1` under that key. Then make a second IPv4 connection from `127.0.0.1` and fail again; assert the count under `127.0.0.1` is now 2. For comparison, make a connection from `::1` (pure IPv6 loopback) and fail; assert it occupies a *separate* key `::1` with `fail_count == 1`.
- **`exec` with prior `pty-req`** (`ssh -t host CMD` shape): write a `.zshrc` sentinel. Open a session channel, send `pty-req`, then `exec 'echo DONE'`. Captured output must contain the `.zshrc` marker (PTY → interactive) and `DONE`. Verify the spawned process saw `TERM` in its environment (echo it via the exec command and assert).
- **End-to-end log capture in JSON mode.** Start the test server with `logFormat: logging.FormatJSON`, drive one good auth and one bad auth, capture stdout, split on `\n`, `json.Unmarshal` each line, assert the expected sequence of events (`conn-open`, `auth-ok`, `conn-close`, `auth-fail`) each appear at least once with the expected field structure.

### 13.4 End-to-end tests

Build-tag-gated tests that compile the binary and exercise it with the **system `ssh`, `sftp`, and `scp` clients** from `/usr/bin`. These are the only tests that exercise the real wire format from a real OpenSSH client.

**Harness requirements:**

1. A `TestMain` helper builds the binary once per `go test` run with `go build -cover -o $TMPDIR/minisshd-test ./cmd/minisshd` (Go 1.20+ coverage-instrumented binary) so coverage from the spawned process is captured.
2. Each test spawns the binary on a unique ephemeral port with a known `--user`, `--pass`, and a fresh `HOME` pointing at `t.TempDir()` to isolate `~/.minisshd/`.
3. The client side answers the password prompt by spawning `ssh`/`sftp`/`scp` under a PTY via `creack/pty`. **Every** invocation must pass these options to avoid host-key prompts and noisy output: `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o GlobalKnownHostsFile=/dev/null`. The exception is test 13 (host-key persistence), which must instead use `-o UserKnownHostsFile=<tmpfile> -o StrictHostKeyChecking=yes` on its second connect, having captured the fingerprint from the first connect. The harness then waits for the password prompt — read from the PTY until it sees `(?i)password:\s*$` at the end of the buffered output, or until a 10 s timeout (treat as failure). Only then write `<password>\n`. Writing earlier loses the password to the pre-prompt state. This avoids any dependency on `sshpass` or `expect`.
4. The harness waits for the `listening` log line on the server's stdout before driving the client.
5. `GOCOVERDIR` is set to a per-run directory; coverage data is merged into the overall report via `go tool covdata` after each test exits. **Coverage data is only flushed on graceful exit** — if the harness escalates to `SIGKILL` (e.g. server hangs past the 5 s drain in §8 Signal handling), that test's coverage is lost. Test authors should detect this and re-run rather than letting it silently lower the merged coverage.
6. After each test, send `SIGTERM`, wait up to 5 s for graceful exit; if the process is still alive, send `SIGKILL` and fail the test with a clear diagnostic.

**Required E2E test cases:**

All tests start the server with `--user testuser` unless a test explicitly varies it. The literal `testuser` below stands in for that configured username.

1. **Interactive shell** — drive `ssh -p PORT testuser@127.0.0.1` under a PTY, supply password, generate a random 16-char marker (e.g. `MARKER_<uuidv4-suffix>`), send `echo <marker>; exit`, assert the marker appears as a standalone line in the captured output. A random marker prevents collision with prompts or `~/.zshrc` output.
2. **Exec & exit code** — `ssh -p PORT testuser@127.0.0.1 'uname -a; exit 7'` → stdout contains `Darwin` (macOS) or `Linux`, exit code 7.
3. **SFTP round-trip** — `sftp -P PORT testuser@127.0.0.1` puts and gets a 1 MB random file at `<t.TempDir()>/sftp-payload` (the path is absolute and on the test's temp dir, writable by the test user since SFTP is rooted at `/`). Verify the round-tripped file matches the source via SHA-256.
4. **SCP** — generate a payload at `t.TempDir() + "/payload"`, run `scp -P PORT <payload> testuser@127.0.0.1:<t.TempDir()>/dest`, assert the copied file matches the source byte-for-byte. Per-test temp dirs avoid collisions when E2E tests run in parallel.
5. **Wrong username** — `ssh wronguser@…` with correct password → exits non-zero; server log contains `auth-fail reason=bad-user`.
6. **Wrong password** — three wrong passwords → ssh exits with `Permission denied`; server log contains three `reason=bad-password` entries.
7. **Pubkey-only fails** — `-o PreferredAuthentications=publickey -o PasswordAuthentication=no` → exits non-zero.
8. **Port forwarding rejected** — start `ssh -p PORT -N -L 18080:127.0.0.1:1 testuser@127.0.0.1` as a background process. Wait for the SSH session to establish by polling the local forwarded port `127.0.0.1:18080` with 100 ms `net.DialTimeout` attempts until one returns no error (the local listener only opens after ssh has authenticated and the channel-multiplexer is ready); fail the test if the poll doesn't succeed within 10 s. Once established, open a fresh `net.DialTimeout` connection to `127.0.0.1:18080` with a 2 s timeout; the connect must succeed at the local level but the connection must return EOF or close immediately (because the server rejects the `direct-tcpip` channel-open). The server log must contain `reject what=tcpip`. Terminate the background ssh process at the end of the test.
9. **Backoff observable** — open 5 separate TCP connections sequentially, each with exactly 1 wrong-password attempt before disconnecting. Total elapsed wall-clock time (from start of connection 1 to disconnect of connection 5) must be ≥ 1+2+4+8 = 15 s (allow ±20%). Each connection's auth happens after the per-IP lock acquires and the configured delay passes.
10. **Auto-generated password** — start binary with no `--pass` and no `MINISSHD_PASS`; parse the `Password: \d{6}` line from stdout; that password authenticates.
11. **Configured username variance** — restart the server with `--user alice` (overriding the default `testuser`): `ssh alice@127.0.0.1` works, `ssh testuser@127.0.0.1` fails with `reason=bad-user`. This proves `--user` actually changes the expected name (rather than being ignored or always falling back to the OS user).
12. **Graceful shutdown** — run an exec that echoes its own PID and then sleeps: `ssh -p PORT testuser@127.0.0.1 'echo PID=$$; exec sleep 60'`. The `exec` builtin replaces the shell with `sleep`, keeping the same PID, so the echoed `$$` is the PID of the sleeping child. Wait for the `PID=` line, parse it. Then send SIGTERM to the server. Assert: (a) within 1 s a `shutdown-signal sig=HUP reason=shutdown pgid=…` event appears in the server log; (b) the server process exits with code 0 within 5 s; (c) the captured child PID is no longer running (`syscall.Kill(pid, 0)` returns ESRCH).
13. **Host-key persistence** — first connect with `-o UserKnownHostsFile=<tmp> -o StrictHostKeyChecking=accept-new` and capture the fingerprint from `<tmp>` (or alternatively from `-o VisualHostKey=no` plus ssh output). Stop the server cleanly. Restart it with the same `HOME` (so the same `~/.minisshd/host_key`). Reconnect with the *same* `<tmp>` and `-o StrictHostKeyChecking=yes`; the connection must succeed without ssh complaining about a changed host key. Then change `HOME` to a fresh `t.TempDir()`, restart again (forcing a new host key), and reconnect with the same `<tmp>` — this attempt must fail with the SSH client's "REMOTE HOST IDENTIFICATION HAS CHANGED" error, confirming the test would have caught a regression that silently changed the host key.
14. **Host-key permission refusal** — first start the binary normally (with default `--host-key` pointing into the test's tmp HOME) so it generates the key with mode `0600`. Stop the binary cleanly. Then `chmod 0644 $HOME/.minisshd/host_key` and start the binary again — it must exit 4 with a stderr message instructing `chmod 600`.
15. **Bind to loopback** — start with `--bind 127.0.0.1`. (a) `ssh -p PORT testuser@127.0.0.1` succeeds. (b) Pick a non-loopback IPv4 address by enumerating interfaces (`net.InterfaceAddrs` in Go); skip the test if none is available (CI sometimes has only loopback). (c) `ssh -p PORT testuser@<non-loopback-ip>` must fail with a connection error (TCP refused or timeout — not a Permission denied), proving the bind restriction holds at the kernel level.
16. **Invalid bind address** — start with `--bind not-an-ip`, assert exit 2 with a clear stderr message naming the rejected value.

### 13.5 Coverage

- Combined coverage from unit + integration + E2E must be **≥ 90.0%** of statements across `cmd/` and `internal/`.
- `make coverage` (a) runs unit + integration with `-coverpkg=./cmd/...,./internal/...`, (b) builds the E2E binary with `go build -cover` and runs the E2E suite with `GOCOVERDIR=$TMPDIR/cover-e2e`, (c) merges the unit/integration `*.out` files and the E2E `covdata` directory using `go tool covdata textfmt`, (d) prints the per-package breakdown, and (e) exits non-zero if the merged threshold is missed.
- Excluded from the threshold: `internal/version` (constants only). No other exclusions permitted; if a code path is hard to cover, refactor for testability.
- The threshold value lives in the Makefile as a single variable so it can be raised over time.

### 13.6 Test invocation

The backoff integration test runs in real time and takes ~16 s, so it's tagged "slow" and skipped under `go test -short`. The fast target stays under 10 s by skipping it.

```
make test         # unit + integration -short, fast (target <10 s)
make test-slow    # unit + integration (full, includes the ~16 s backoff timing test)
make e2e          # compiles binary, runs E2E with real ssh client (~45 s including #9 backoff test)
make test-race    # unit + integration under -race
make coverage     # all layers + merged coverage report, fails if <90%
```

Slow tests guard themselves with `if testing.Short() { t.Skip(...) }` at the top so they are skipped automatically when `-short` is passed. `make coverage` runs the full suite (no `-short`) so the slow tests count toward coverage. `make e2e` skips with a clear message (not a failure) if `/usr/bin/ssh`, `/usr/bin/sftp`, or `/usr/bin/scp` is missing. CI must run `make test`, `make test-slow`, `make e2e`, `make test-race`, and `make coverage` on every PR (on both macOS and Linux runners); all must be green to merge.
