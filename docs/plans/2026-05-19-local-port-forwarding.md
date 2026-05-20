# Plan: Local port forwarding (`ssh -L`, `direct-tcpip`)

## Changelog (iter 3 → iter 4)

Applied in response to adversarial review round 3:

- **CRITICAL (§13.3 over-cap integration test rejection code):** Changed `ConnectionFailed` to `Prohibited` in the per-connection forward cap integration test bullet (§2.9 / §13.3). The over-cap case now consistently uses `Prohibited` in all locations: §7.1 step 2 prose, the §11 table, the `forward.go` code sketch (§4.3), and the integration test description.

## Changelog (iter 2 → iter 3)

Applied in response to adversarial review round 2:

- **CRITICAL (§7.1 step 2 rejection code):** Changed the over-cap rejection code in §2.2 (§7.1 step 2 prose) from `ConnectionFailed` to `Prohibited`, matching the §11 table in §2.7 and the `forward.go` code sketch in §4.3. All three locations now consistently say `Prohibited` for over-cap.
- **SIGNIFICANT (missing §13.2 amendment):** Added a §13.2 amendment to §2.9. The amendment removes `direct-tcpip` from the §13.2 unit-test rejection list (since §7.1 now accepts it) and notes that the renamed unit test covers only reverse/streamlocal rejections.

## Changelog (iter 1 → iter 2)

Applied in response to adversarial review round 1:

- **CRITICAL-5 (testServerOptions ForwardMax default):** Added `forwardMax int` and `disableForwarding bool` fields to `testServerOptions`; specified that `startTestServer` passes `ForwardMax: 32` by default, and `ForwardMax: 0` only when `disableForwarding: true` is set. Updated §7.5 accordingly.
- **SIGNIFICANT-8 (over-cap rejection reason code):** Changed the per-connection cap integration test to assert `Prohibited` specifically, not "ConnectionFailed or Prohibited". Updated the spec amendment (§2.7) to match — the §11 table now states `Prohibited` for over-cap.
- **SIGNIFICANT-9 (nextFreePort helper):** Removed the claim that `nextFreePort()` already exists in the e2e package; specified it must be implemented (`net.Listen("tcp","127.0.0.1:0")` then immediate close to harvest the port). Updated §7.6 accordingly.
- **SIGNIFICANT-10 (E2E cap test sequencing):** Rewrote the `TestE2E_LocalPortForwardingCap` description with the precise sequence: hold channel 1 open by keeping a local TCP connection active; open a second local TCP connection to trigger a second `direct-tcpip`; assert the second is dropped. Removed ambiguity about "when the second direct-tcpip fires".
- **MINOR-1 (redundant Dialer.Timeout):** Removed `Timeout: dialTimeout` from the `net.Dialer` literal; rely solely on the `context.WithTimeout` deadline.
- **MINOR-2 (forwardCounter variable name):** Added a note that the local variable in `handleConn` is named `fwdCap` (not `forwardCounter`, which is the type name), to avoid the type/variable name collision.
- **MINOR-3 (ssh.Unmarshal strictness):** Removed the hedge "or whatever ssh.Unmarshal returns" from `TestParseDirectTCPIP_MalformedTrailingGarbage`; the test must assert an error unconditionally.
- **MINOR-5 (step-10 ordering parenthetical):** Corrected the parenthetical in §2.8 step 10 — validation happens before the listener bind, matching §4.1.
- **MINOR-7 (--bind safe default wording):** Rewrote the §2.6 spec sentence to not call `--bind 127.0.0.1` the "safe default" (the actual binary default is `0.0.0.0`); now says "use `--bind 127.0.0.1` to restrict to loopback".
- **MINOR-8 (malformed-payload log fields):** Added a note in §6 that `forward-reject reason=malformed-payload` logs `dest_host=""` and `dest_port=0`; this is intentional (no valid dest parsed).
- **MINOR-10 (E2E #8 sync):** Replaced the `awaitPort` sync (which only works for `-L`) in the revised #8 test with a log-based sync: wait for `auth-ok` in the server log before asserting the rejection.

Date: 2026-05-19
Spec file: `SPEC.md`
Scope: implement server-side local port forwarding (`direct-tcpip`) end-to-end, leaving reverse forwarding (`tcpip-forward`/`forwarded-tcpip`), streamlocal, agent forwarding, and X11 untouched.

## 1. Summary

This plan adds support for the SSH `direct-tcpip` channel type, which is what the OpenSSH client opens for each `-L LOCAL:host:port` forward. The server will parse the RFC 4254 §7.2 channel-open payload, dial the requested TCP destination, accept the channel on success, and shuttle bytes bidirectionally between the SSH channel and the TCP socket until either side closes. Reverse (`forwarded-tcpip`/`tcpip-forward`/`cancel-tcpip-forward`), Unix-socket (`*-streamlocal*`), agent (`auth-agent-req`), and X11 (`x11-req`) forwarding all stay rejected — this change is a strict positive capability addition for `ssh -L` only.

The change touches spec §7 (move `direct-tcpip` from the reject list to a new accepted-features row) and §12 (drop "local" from the port-forwarding non-goal). It adds three new logging events (`forward-open`, `forward-close`, `forward-reject`) wired through `internal/logging`. It also adds a `--forward-max` flag (default 32) capping concurrent forwarded channels per SSH connection so a leaked password cannot be amplified into an unbounded outbound-connection fan-out. `--forward-allow` (destination policy) is intentionally deferred to a follow-up.

## 2. Spec amendments

All edits land in `SPEC.md`. Exact wording follows.

### 2.1 §7 — table addition and rejection-list trim

Current §7 lists five accepted invocations in a table, followed by the reject list. Make the following changes:

**a) Add a new row to the accepted-features table** (insert after the `scp -O` row, before "The following must be explicitly rejected"):

```
| `ssh -L LOCAL:host:port host` | `direct-tcpip` | (none — channel open carries the payload) | Parse the RFC 4254 §7.2 channel-open payload, dial `host:port` over TCP with a 10 s timeout, then pipe bytes channel↔TCP bidirectionally until either side closes. Subject to the per-connection cap of §7.1 below. See §7.1 for the channel-open payload format, lifecycle, and failure modes. |
```

**b) Replace the rejection bullet list**. Current text:

```
- `direct-tcpip` (local port forwarding)
- `forwarded-tcpip` / `tcpip-forward` (remote port forwarding)
- `direct-streamlocal@openssh.com`, `streamlocal-forward@openssh.com` (Unix-socket forwarding)
- `auth-agent-req@openssh.com` (agent forwarding)
- `x11-req` (X11 forwarding)
- Any subsystem name other than exactly `sftp` …
```

becomes:

```
- `forwarded-tcpip` / `tcpip-forward` / `cancel-tcpip-forward` (remote port forwarding)
- `direct-streamlocal@openssh.com`, `streamlocal-forward@openssh.com` (Unix-socket forwarding)
- `auth-agent-req@openssh.com` (agent forwarding)
- `x11-req` (X11 forwarding)
- Any subsystem name other than exactly `sftp` (case-sensitive, no leading/trailing whitespace). `SFTP`, `Sftp`, ` sftp`, `sftp-server` all rejected.
```

(`direct-tcpip` is removed; `cancel-tcpip-forward` is added explicitly so the bullet matches what the dispatcher already does.)

### 2.2 New §7.1 — `direct-tcpip` lifecycle

Insert a new subsection §7.1 directly after the rejection list, with the following exact text:

```
### 7.1 `direct-tcpip` (local port forwarding)

When the client sends a `direct-tcpip` channel-open the server:

1. Parses the channel-open `ExtraData` per RFC 4254 §7.2:
   - dest-host (string)
   - dest-port (uint32, must be in [1, 65535])
   - originator-host (string)
   - originator-port (uint32)

   A malformed payload (truncated, trailing garbage, dest-port == 0 or > 65535)
   is rejected with reason `ConnectionFailed` and the message
   `"malformed direct-tcpip payload"`. The server logs `forward-reject
   reason=malformed-payload` (see §9).

2. Checks the per-connection forwarded-channel cap. The default cap is 32;
   override with `--forward-max N` (`MINISSHD_FORWARD_MAX=N` if the flag
   is unset). `N == 0` disables forwarding entirely (channel-open rejected
   with `Prohibited` and reason `over-cap`); `N < 0` is rejected at startup
   with exit code 2. If the connection already holds `N` open forwarded
   channels, the new request is rejected with `Prohibited`, message
   `"too many concurrent forwards"`, and the server logs `forward-reject
   reason=over-cap`. Closed forwards free a slot.

3. Dials `dest-host:dest-port` via `net.Dialer{}.DialContext` with a 10 s
   timeout and the per-connection context. DNS resolution uses the host
   resolver; IP literals (both IPv4 and IPv6) are dialed directly. On
   dial failure (refused, timeout, no such host, route unreachable) the
   server rejects the channel with `ConnectionFailed`, message
   `"dial failed: <error>"`, and logs `forward-reject reason=dial-failed`.

4. On success: accept the channel, discard any per-channel requests (none
   are defined for `direct-tcpip`; reply false to anything that arrives
   with `want_reply = true`), and run two copy goroutines:
   - channel → TCP (use the TCP half-close on EOF via `CloseWrite()`)
   - TCP → channel (call `channel.CloseWrite()` on EOF)

   When both copies complete, close the channel and the TCP socket fully
   and log `forward-close` with the byte counts and the wall-clock
   duration.

The server does not honor any destination-policy restriction in this
release. The operator-trust model of §3 still applies: do not expose the
server to networks where the set of reachable destinations is part of
the threat model.

`direct-tcpip` channels do not carry `exit-status` or `exit-signal`. The
§8 exit-status semantics apply to session channels only.
```

### 2.3 §8 — single-line carve-out

Append one sentence to §8 (Session handling) header paragraph, immediately after the "request-type combinations table" introduction, before the table itself:

```
`direct-tcpip` channels (§7.1) are not session channels and are not
subject to anything in this section, including the exit-status/exit-signal
delivery in §8.1 step 6 / §8.2 step 5.
```

### 2.4 §9 — new logging events

Insert three rows into the §9 "Required events" table, in this order, immediately after the `drain-timeout` row (before `error`):

```
| `forward-open`   | INFO | remote, dest_host, dest_port, originator_host, originator_port |
| `forward-close`  | INFO | remote, dest_host, dest_port, bytes_in, bytes_out, duration |
| `forward-reject` | WARN | remote, dest_host, dest_port, reason (`malformed-payload` / `dial-failed` / `over-cap`) |
```

Notes that follow the table need no change — the password-scrub rule applies to these events as it does to every other event in §9.

Update the `reject` row's `what` enumeration in §9 to be explicit that
`tcpip` covers only the *reverse* (forwarded-tcpip / tcpip-forward /
cancel-tcpip-forward) cases; the local-forwarding events use the new
`forward-*` family above. Concretely, in the `reject` row replace the
example string `'tcpip'` enumeration with a footnote:

```
| `reject` | WARN | remote, what (`x11`, `tcpip`, `agent`, `subsystem`, `streamlocal`, …). `tcpip` covers only reverse forwarding (`tcpip-forward` / `cancel-tcpip-forward` / `forwarded-tcpip`); local forwarding is logged via the `forward-*` events. |
```

### 2.5 §12 — drop "local" from non-goals

Replace this bullet:

```
- Port forwarding (local, remote, dynamic), agent forwarding, X11.
```

with:

```
- Port forwarding (remote, dynamic), agent forwarding, X11. Local
  forwarding (`ssh -L`, `direct-tcpip`) is supported — see §7.1.
```

### 2.6 §3 — strengthen the operator-trust note

Append one sentence to the existing §3 paragraph that ends "the user is responsible for any host firewall configuration":

```
With local port forwarding now supported (§7.1), an authenticated client
can also reach any host:port the server process can reach on the
network. Treat the SSH server's network access as the operator's network
access — use `--bind 127.0.0.1` to restrict the listening interface to
loopback for single-host work, and cap concurrent forwards per connection
with `--forward-max`.
```

### 2.7 §11 — error and edge cases table

Insert two new rows into the §11 table (the one with "Case" / "Behaviour" columns), immediately after the "Client requests unsupported channel/subsystem" row:

```
| `direct-tcpip` payload is malformed | Reject the channel with `ConnectionFailed`, log `forward-reject reason=malformed-payload`, keep the connection open. |
| `direct-tcpip` dial fails (refused, timeout, DNS, unreachable) | Reject the channel with `ConnectionFailed`, log `forward-reject reason=dial-failed`, keep the connection open. |
| `direct-tcpip` exceeds `--forward-max` per connection | Reject the channel with `Prohibited`, log `forward-reject reason=over-cap`, keep the connection open. |
| `--forward-max` < 0 | Exit 2 with a message naming the rejected value. |
```

### 2.8 §2 — CLI/env table additions

Add a new row to the §2 flag table after `--host-key`:

```
| `--forward-max N` | `32` | Maximum concurrent `direct-tcpip` (local port forward) channels per SSH connection. `0` disables forwarding entirely. Negative values are an error. |
```

Add a new row to the §2 env-var table after `MINISSHD_USER`:

```
| `MINISSHD_FORWARD_MAX` | Forwarded-channel cap. Used only if `--forward-max` is not provided. Same range and semantics as the flag. |
```

Append a numbered startup-validation step §2 step 10 (renumbering nothing — the spec's existing 9 steps stay in order; this is a new step that runs alongside step 1):

```
10. Validate `--forward-max`: parse as a non-negative integer; reject
    negatives with exit code 2 and a message naming the rejected value.
    A missing value falls back to `MINISSHD_FORWARD_MAX`, then to the
    default `32`. The resolved value is cached on the server config and
    consulted in §7.1 step 2.
```

(This validation runs before the listener bind — same group as step 1 — so a misconfiguration cannot produce a password banner. The resolved value is only consulted at channel-open time, but the validation must be early so an operator typo fails fast.)

### 2.9 §13 — test additions

**§13.2 amendment (unit-test rejection list):**

Current §13.2 wording includes `direct-tcpip` among channel types that "must be rejected" in unit tests:

```
Unit tests must assert that the following are rejected by the channel
dispatcher: `direct-tcpip`, `forwarded-tcpip`, `direct-streamlocal@openssh.com`,
`streamlocal-forward@openssh.com`, `auth-agent-req@openssh.com`, `x11-req`, and
unknown channel types.
```

Because §7.1 now accepts `direct-tcpip`, this sentence is stale. Replace it with:

```
Unit tests must assert that the following are rejected by the channel
dispatcher: `forwarded-tcpip`, `direct-streamlocal@openssh.com`,
`streamlocal-forward@openssh.com`, `auth-agent-req@openssh.com`, `x11-req`, and
unknown channel types. (`direct-tcpip` is no longer rejected; the unit test
that previously asserted its rejection is renamed — see §7.2 of the plan —
and now covers `forwarded-tcpip` / `streamlocal` rejections only.)
```

Append to §13.3 (integration tests) a new bullet list:

```
- **Local port forwarding succeeds:** stand up a TCP echo server on
  `127.0.0.1:0` inside the test, open a `direct-tcpip` channel through
  the SSH connection with its address as dest, write a random payload
  through the channel, assert the echoed bytes come back. Confirm the
  server log contains `forward-open` and `forward-close` events with
  the correct `bytes_in`/`bytes_out`.
- **Local port forwarding dial failure:** open `direct-tcpip` to a port
  that is not listening (bind a listener, close it, reuse the port).
  Assert `OpenChannel` returns `*ssh.OpenChannelError` with reason
  `ConnectionFailed` and the server log contains
  `forward-reject reason=dial-failed`.
- **`direct-tcpip` malformed payload:** open `direct-tcpip` with a
  truncated payload (e.g. random 4 bytes) and assert the channel-open
  is rejected and the server log contains
  `forward-reject reason=malformed-payload`.
- **Per-connection forward cap:** start the server with
  `--forward-max 2`, open three TCP echo sinks, open two
  `direct-tcpip` channels (kept open), then open a third. The third
  must be rejected with `Prohibited`, and the server log must
  contain `forward-reject reason=over-cap`. Close one of the open
  forwards; a fourth open must then succeed (proving the cap counts
  live channels, not lifetime opens).
- **Forward closes on TCP EOF:** open a `direct-tcpip` to a TCP server
  that writes "hello" then closes; assert the SSH channel returns EOF
  with the same bytes and `forward-close` reports the right byte
  counts.
- **Reverse and streamlocal still rejected** (regression): keep the
  existing `tcpip-forward` / `cancel-tcpip-forward` / streamlocal
  rejection tests untouched; they remain the regression guard. (No
  new test code needed — list them in the plan's Tests section so a
  reviewer can confirm they were not deleted.)
```

Append to §13.4 (E2E tests) one new case (numbered #17, after the
existing #16 "Invalid bind address"):

```
17. **Local port forwarding (real ssh client)** — start an HTTP server
    inside the test on `127.0.0.1:0` (Go `net/http/httptest.NewServer`)
    that responds with a known body. Spawn
    `ssh -p PORT -N -L 127.0.0.1:0:127.0.0.1:HTTP_PORT testuser@127.0.0.1`
    under a PTY (poll for the local listener to be ready, same pattern
    as #8). Issue an HTTP GET against the local forwarded address;
    assert the response body matches. Assert the server log contains
    `forward-open` and `forward-close` events. Replace the previous
    "port forwarding rejected" test (§13.4 #8) with this success
    case — see Tests section of the plan for the precise replacement.
```

Replace E2E test #8 ("Port forwarding rejected") with:

```
8. **Reverse port forwarding rejected** — start
   `ssh -p PORT -N -R 18080:127.0.0.1:1 testuser@127.0.0.1` under a
   PTY. Wait briefly. Assert the server log contains
   `reject what=tcpip` (the `-R` flag triggers a `tcpip-forward`
   global request, which the server still rejects). Terminate the
   background ssh process. This preserves the original test's intent
   (forwarding-class rejection) and shifts the asserted behavior from
   local (now supported) to reverse (still rejected).
```

Update §13.5 coverage threshold? **No.** The threshold stays at 90.0. New code must come with tests that keep merged coverage above 90.0; if it slips, the new tests are insufficient.

## 3. CLI / env interface

The CLI surface gains one flag and one env var; no rename, no flag removal, no default change for any existing flag.

```
--forward-max N            default 32   (MINISSHD_FORWARD_MAX overrides default
                                          when flag is unset)
```

Behaviors:

- `--forward-max 32` (default): allow up to 32 concurrent `direct-tcpip` channels per SSH connection.
- `--forward-max 0`: disable forwarding entirely. Every `direct-tcpip` open is rejected with `Prohibited` and `forward-reject reason=over-cap`. (We use the same logging label rather than introducing a fourth reason like `disabled`; `0/0` reads as "over-cap" cleanly enough and keeps the field's vocabulary tight.)
- `--forward-max -1` (or any negative integer): exit 2 at startup with `--forward-max -1 out of range` to stderr.
- `--forward-max abc`: standard `flag` package failure, exit 2.
- `MINISSHD_FORWARD_MAX` is used only when `--forward-max` is unset. Same value-range rules apply; an invalid env value exits 2 at startup.
- Concurrency cap is **per SSH connection**, not global. A second SSH connection from the same client can open another 32 forwards. The server already has no global session cap (§8), so a global forward cap would be inconsistent. Operators who need a global cap can use OS-level resource controls.

`--forward-allow` is **not added in this PR**. Reasoning in Open Questions.

## 4. Code changes by file

The changes are deliberately narrow. No package layout changes; everything lives in `internal/server` plus the existing `internal/logging` and `cmd/minisshd`.

### 4.1 `cmd/minisshd/main.go`

- Add a new `fs.Int("forward-max", -1, "...")` flag. Use `-1` as the sentinel for "unset" (because `0` is a valid configured value).
- After flag parsing, run a new `resolveForwardMax(flagValue, flagSet, envValue, envSet)` helper that mirrors the precedence/empty-string semantics of `auth.ResolvePasswordStrict`:
  - explicit flag wins; if negative → exit 2 with a clear message.
  - else env var if set; parse with `strconv.Atoi`; if non-integer or negative → exit 2.
  - else default 32.
- Add the resolved value to `server.Config.ForwardMax` (see §4.4 below).
- The new validation happens *before* the listener bind (§2 step 1 group) so a misconfiguration cannot generate a password banner. This matches the §2 step-ordering invariant.

### 4.2 `internal/server/dispatch.go`

Update `routeChannel` to add a `direct-tcpip` arm that returns a new "needs special handling" path rather than the binary accepted/rejected we have today. Two options; recommendation = **B** (smaller blast radius):

- **A:** change the signature to return an enum `{accept-session, accept-forward, rejected}`.
- **B:** keep the boolean return for "accept the session", and route `direct-tcpip` from inside `handleConn` *before* calling `routeChannel`. The dispatcher gains a `routeNewChannel(ch newChannel) action` helper next to `routeChannel`, where `action` is one of `actionSession`, `actionForward`, `actionRejected`.

Pick **B**. Concrete edits to `dispatch.go`:

```go
type channelAction int

const (
    actionRejected channelAction = iota
    actionSession
    actionForward
)

// classifyChannel does the §7 routing: session goes through actionSession,
// direct-tcpip through actionForward. Everything else is rejected here
// with the same labels/log events as before. The "direct-tcpip" arm
// no longer touches log.Reject — forward open/reject events live in the
// new forward.go (§4.3).
func classifyChannel(ch newChannel, remote string, log rejectLogger) channelAction {
    switch ch.ChannelType() {
    case channelTypeSession:
        return actionSession
    case channelTypeDirectTCPIP:
        return actionForward
    case channelTypeForwardedTCPIP:
        log.Reject(remote, "tcpip")
        _ = ch.Reject(ssh.Prohibited, "port forwarding not supported")
        return actionRejected
    case channelTypeDirectStreamlocal, channelTypeStreamlocalForward:
        log.Reject(remote, "streamlocal")
        _ = ch.Reject(ssh.Prohibited, "unix-socket forwarding not supported")
        return actionRejected
    default:
        log.Reject(remote, ch.ChannelType())
        _ = ch.Reject(ssh.UnknownChannelType, "unknown channel type")
        return actionRejected
    }
}

// routeChannel is preserved as a thin wrapper that returns true iff
// classifyChannel returned actionSession. Keeps the existing test surface
// (TestRouteChannel_*) green without modification.
func routeChannel(ch newChannel, remote string, log rejectLogger) (accepted bool) {
    return classifyChannel(ch, remote, log) == actionSession
}
```

The existing `TestRouteChannel_RejectsTCPIP` test (which sweeps `direct-tcpip` and `forwarded-tcpip` together) **must be split**: the `forwarded-tcpip` case stays as-is in `routeChannel` semantics; the `direct-tcpip` case moves into a new `TestClassifyChannel_DirectTCPIPRoutedToForward` test that asserts `classifyChannel` returns `actionForward` and does NOT call `log.Reject`. Concrete diff is in §7 Tests.

### 4.3 `internal/server/forward.go` (new file)

New file with a single public entry point and small private helpers. Sketch:

```go
package server

import (
    "context"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "strconv"
    "sync"
    "sync/atomic"
    "time"

    "golang.org/x/crypto/ssh"
)

// directTCPIPPayload is the RFC 4254 §7.2 channel-open payload for
// "direct-tcpip". DestPort and OriginPort are uint32 on the wire even
// though the high half is meaningless for TCP — the parser enforces the
// [1, 65535] range.
type directTCPIPPayload struct {
    DestAddr   string
    DestPort   uint32
    OriginAddr string
    OriginPort uint32
}

// dialTimeout is the §7.1 step-3 cap on the dial.
const dialTimeout = 10 * time.Second

// forwardLogger captures the three new §9 events plus the existing
// rejectLogger surface that forward.go uses for type-aliased convenience.
type forwardLogger interface {
    ForwardOpen(remote, destHost string, destPort int, origHost string, origPort int)
    ForwardClose(remote, destHost string, destPort int, bytesIn, bytesOut int64, duration time.Duration)
    ForwardReject(remote, destHost string, destPort int, reason string)
}

// forwardCounter is the per-connection "currently open forwards" counter
// the cap consults. handleConn instantiates one per accepted SSH
// connection as `fwdCap` (not `forwardCounter` — that is the type name);
// channel goroutines call Acquire/Release.
type forwardCounter struct {
    cap      int       // <= 0 means forwarding disabled
    mu       sync.Mutex
    inflight int
}

func (c *forwardCounter) Acquire() bool {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.cap <= 0 || c.inflight >= c.cap {
        return false
    }
    c.inflight++
    return true
}
func (c *forwardCounter) Release() {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.inflight > 0 {
        c.inflight--
    }
}

// parseDirectTCPIP parses the RFC 4254 §7.2 payload. Returns
// (payload, ok). Strict: rejects trailing bytes, dest-port == 0,
// dest-port > 65535. originator-port is allowed to be 0 (some clients
// send 0 when the source socket is ephemeral).
func parseDirectTCPIP(data []byte) (directTCPIPPayload, error) {
    var p directTCPIPPayload
    if err := ssh.Unmarshal(data, &p); err != nil {
        return p, errors.New("malformed direct-tcpip payload: " + err.Error())
    }
    if p.DestPort == 0 || p.DestPort > 65535 {
        return p, errors.New("malformed direct-tcpip payload: dest-port out of range")
    }
    return p, nil
}

// dialDirect dials dest-host:dest-port with a 10 s timeout baked into
// the context (via the context.WithTimeout call in handleDirectTCPIP),
// honoring ctx so per-connection shutdown can cancel an outstanding dial.
// We do NOT set Dialer.Timeout — relying solely on the context deadline
// avoids the redundant double-timeout that would otherwise fire whichever
// is shorter.
func dialDirect(ctx context.Context, p directTCPIPPayload) (net.Conn, error) {
    addr := net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort)))
    d := net.Dialer{}
    return d.DialContext(ctx, "tcp", addr)
}

// handleDirectTCPIP is the entry point handleConn calls when
// classifyChannel returned actionForward. It owns the entire lifecycle
// of one direct-tcpip channel: payload parse, cap check, dial,
// channel.Accept(), bidi pipe, close.
func handleDirectTCPIP(
    ctx context.Context,
    newCh newChannelExt, // see §4.4 — wraps ssh.NewChannel with ExtraData()
    remote string,
    counter *forwardCounter,
    log forwardLogger,
) {
    payload, err := parseDirectTCPIP(newCh.ExtraData())
    if err != nil {
        log.ForwardReject(remote, "", 0, "malformed-payload")
        _ = newCh.Reject(ssh.ConnectionFailed, "malformed direct-tcpip payload")
        return
    }

    destHost := payload.DestAddr
    destPort := int(payload.DestPort)

    if !counter.Acquire() {
        log.ForwardReject(remote, destHost, destPort, "over-cap")
        _ = newCh.Reject(ssh.Prohibited, "too many concurrent forwards")
        return
    }
    // Release happens after Accept fails, after dial fails, or after
    // the pipe goroutine completes — never twice.

    dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
    defer cancel()
    tcp, err := dialDirect(dialCtx, payload)
    if err != nil {
        counter.Release()
        log.ForwardReject(remote, destHost, destPort, "dial-failed")
        _ = newCh.Reject(ssh.ConnectionFailed, "dial failed: "+err.Error())
        return
    }

    ch, reqs, err := newCh.Accept()
    if err != nil {
        counter.Release()
        _ = tcp.Close()
        // Accept failures are unusual; surface as a regular `error`
        // event via the existing logger (forward.go's logger interface
        // wraps that path too — see §4.4).
        return
    }
    go ssh.DiscardRequests(reqs)

    log.ForwardOpen(remote, destHost, destPort,
        payload.OriginAddr, int(payload.OriginPort))
    start := time.Now()

    var bytesIn, bytesOut atomic.Int64
    var wg sync.WaitGroup
    wg.Add(2)

    // channel -> TCP
    go func() {
        defer wg.Done()
        n, _ := io.Copy(tcp, ch)
        bytesOut.Store(n) // bytes flowing out of the SSH client into the destination
        if tw, ok := tcp.(interface{ CloseWrite() error }); ok {
            _ = tw.CloseWrite()
        } else {
            _ = tcp.Close()
        }
    }()

    // TCP -> channel
    go func() {
        defer wg.Done()
        n, _ := io.Copy(ch, tcp)
        bytesIn.Store(n) // bytes flowing from the destination back to the SSH client
        _ = ch.CloseWrite()
    }()

    wg.Wait()
    _ = ch.Close()
    _ = tcp.Close()
    counter.Release()
    log.ForwardClose(remote, destHost, destPort,
        bytesIn.Load(), bytesOut.Load(), time.Since(start))
}
```

Notes:

- `bytes_in` is "bytes that came in to the SSH client over this forward" — i.e. dest→channel.
- `bytes_out` is "bytes the SSH client sent out into the destination" — i.e. channel→dest.
- We use `atomic.Int64` rather than the WaitGroup's return values because `io.Copy` returns `(n, err)` and we want both readers visible from the main goroutine.
- `io.Copy` errors are intentionally ignored. Both common cases (EOF, "use of closed network connection") are not actionable; surfacing them as `error` events would be noise. If a copy error correlates with truncated bytes, the byte counts in `forward-close` are still accurate up to the failure point.
- Half-close is best-effort: `net.TCPConn` implements `CloseWrite`; `ssh.Channel` does too. If a `tcp` connection ever returns a non-`*net.TCPConn` (it won't, but we have to be conservative), fall back to a full `Close` on the TCP side.

### 4.4 `internal/server/config.go`

Add to `Config`:

```go
// ForwardMax is the per-connection cap on concurrent direct-tcpip
// channels. 0 disables local forwarding. Validation lives in
// cmd/minisshd (§2 step 10); the server treats whatever it is handed
// as truth.
ForwardMax int
```

Default-value handling lives in `cmd/minisshd`; `internal/server` does not invent its own default (keeps surface predictable).

Define the `newChannelExt` interface in `dispatch.go` (next to `newChannel`):

```go
// newChannelExt is the subset of *ssh.NewChannel that the forward
// handler needs: ChannelType, Reject (from newChannel), ExtraData, and
// Accept. Tests substitute a fake.
type newChannelExt interface {
    newChannel
    ExtraData() []byte
    Accept() (ssh.Channel, <-chan *ssh.Request, error)
}

// Compile-time assertion the real ssh.NewChannel satisfies the
// extended surface.
var _ newChannelExt = (ssh.NewChannel)(nil)
```

(The existing `newChannel` interface stays; `newChannelExt` extends it for the forward path.)

### 4.5 `internal/server/server.go`

Update `handleConn` to:

1. Build `fwdCap := &forwardCounter{cap: s.cfg.ForwardMax}` per SSH connection, scoped to the function so it is GC'd when the connection ends. (The local variable is named `fwdCap` to avoid shadowing the type name `forwardCounter`.)
2. Plumb a `forwardLogger` reference (from `s.cfg.Log` — it gains three new methods, see §4.6).
3. In the channel loop, replace the single `routeChannel` call with a `classifyChannel` switch:

```go
for newCh := range chans {
    switch classifyChannel(newCh, remote, s.cfg.Log) {
    case actionSession:
        channel, reqs, err := newCh.Accept()
        if err != nil {
            s.cfg.Log.Error("accept channel: "+err.Error(), remote)
            continue
        }
        sessionsWG.Add(1)
        go func() {
            defer sessionsWG.Done()
            s.session.Handle(connCtx, channel, reqs, remote)
        }()
    case actionForward:
        sessionsWG.Add(1) // reuse the same waitgroup for drain
        go func(nc ssh.NewChannel) {
            defer sessionsWG.Done()
            handleDirectTCPIP(connCtx, nc, remote, fwdCap, s.cfg.Log)
        }(newCh)
    case actionRejected:
        // already handled inside classifyChannel
    }
}
```

Using the same `sessionsWG` for forward goroutines ensures the existing drain logic in `Serve` waits for forwards too — important for `make e2e` coverage capture and for graceful shutdown.

### 4.6 `internal/logging/logging.go`

Add three new methods to `Logger`:

```go
func (l *Logger) ForwardOpen(remote, destHost string, destPort int, origHost string, origPort int) {
    l.emit(levelInfo, "forward-open", []field{
        {"remote", remote},
        {"dest_host", destHost},
        {"dest_port", itoa(destPort)},
        {"originator_host", origHost},
        {"originator_port", itoa(origPort)},
    })
}

func (l *Logger) ForwardClose(remote, destHost string, destPort int, bytesIn, bytesOut int64, duration time.Duration) {
    l.emit(levelInfo, "forward-close", []field{
        {"remote", remote},
        {"dest_host", destHost},
        {"dest_port", itoa(destPort)},
        {"bytes_in", strconv.FormatInt(bytesIn, 10)},
        {"bytes_out", strconv.FormatInt(bytesOut, 10)},
        {"duration", duration.String()},
    })
}

func (l *Logger) ForwardReject(remote, destHost string, destPort int, reason string) {
    l.emit(levelWarn, "forward-reject", []field{
        {"remote", remote},
        {"dest_host", destHost},
        {"dest_port", itoa(destPort)},
        {"reason", reason},
    })
}
```

The password-scrub already operates on the assembled line, so dest-host values that happen to equal the password byte-for-byte would get scrubbed — a minor (intentional) defense-in-depth side effect. The §9 prohibition on logging the password is preserved.

Add `strconv` to the imports.

## 5. Channel lifecycle — how a direct-tcpip channel is accepted, dialed, piped, and closed

Below is the step-by-step path one `direct-tcpip` open follows through the server, with the package and file owning each step in parentheses.

```
1.  Client (e.g. /usr/bin/ssh -L 8080:web.example.org:80) authenticates.
    [ssh handshake — internal/server/auth.go, unchanged]

2.  Client opens a session for `-L`: it does NOT open the channel until
    the local listener (127.0.0.1:8080) receives a connection. Once a
    client connects, ssh sends SSH_MSG_CHANNEL_OPEN with channel-type
    "direct-tcpip".

3.  The ssh transport hands the open to ssh.NewServerConn's `chans`
    channel. server.handleConn ranges over `chans`.
    [internal/server/server.go]

4.  handleConn calls classifyChannel(newCh, remote, log).
    classifyChannel returns actionForward.
    [internal/server/dispatch.go]

5.  handleConn spawns a goroutine: handleDirectTCPIP(connCtx, newCh,
    remote, forwardCounter, log). The goroutine is tracked via
    sessionsWG so Serve's drain waits for it.
    [internal/server/server.go → internal/server/forward.go]

6.  handleDirectTCPIP calls parseDirectTCPIP(newCh.ExtraData()).
    - On error → ForwardReject(reason="malformed-payload"),
      newCh.Reject(ConnectionFailed, "malformed direct-tcpip payload"),
      counter is NOT acquired, goroutine returns.
    [internal/server/forward.go]

7.  handleDirectTCPIP calls counter.Acquire().
    - false → ForwardReject(reason="over-cap"),
      newCh.Reject(Prohibited, "too many concurrent forwards"),
      goroutine returns.
    - true → continue. Counter holds 1 slot until Release.

8.  handleDirectTCPIP calls dialDirect(ctx, payload). The dial uses a
    10 s timeout via context.WithTimeout(ctx, 10s) so connCtx
    cancellation (server shutdown, client disconnect) preempts the
    dial.
    - error → counter.Release(); ForwardReject(reason="dial-failed");
      newCh.Reject(ConnectionFailed, "dial failed: <err>");
      goroutine returns.

9.  newCh.Accept() returns (channel, reqs, err).
    - err → counter.Release(); tcp.Close(); generic error log; return.
    - On success, ssh.DiscardRequests(reqs) drains any per-channel
      requests (there shouldn't be any, but RFC 4254 leaves room).

10. ForwardOpen event emitted, with all five fields.

11. Two goroutines start, both wired into a shared WaitGroup:
    - G1: io.Copy(tcp, ch).
      On return (channel EOF or error), call tcp.CloseWrite() so the
      destination sees the half-close. Bytes copied → bytesOut.
    - G2: io.Copy(ch, tcp).
      On return (TCP EOF or error), call ch.CloseWrite() so the SSH
      client sees the half-close. Bytes copied → bytesIn.

12. Both copies finish (any of: client closes the channel, destination
    closes the TCP socket, both ends EOF). The WaitGroup unblocks.

13. ch.Close() and tcp.Close() are called (full close after the
    half-closes; idempotent and cheap).

14. counter.Release() runs; another forward can now be opened.

15. ForwardClose event emitted with bytes_in, bytes_out, duration.

16. Goroutine returns; sessionsWG.Done() releases the slot in Serve's
    drain wait.
```

Shutdown paths:

- **Server SIGINT/SIGTERM (§8):** `connCtx` cancels → outstanding `dialCtx` cancels (dial returns context error → counted as `dial-failed`, but we are already shutting down and the client will see the connection drop). For *open* forwards mid-pipe, ctx cancellation does not by itself unblock `io.Copy`. We rely on the underlying ssh transport closing the channel (it does, because `serverConn.Close()` runs in `handleConn`'s defer), which makes both copies return EOF. The two copies finish; the forward goroutine emits `forward-close` and returns; `sessionsWG.Wait()` in `Serve` unblocks. If a forward is wedged past the 5 s drain cap, the bytes drop the same way a hung session does — no special handling needed beyond what `Serve` already does.

- **Client disconnect:** `serverConn` shuts down, `chans` closes, the ssh library closes any open channels. The two `io.Copy` goroutines see EOF and exit. Same as above.

- **TCP destination drops:** `io.Copy(ch, tcp)` returns EOF; `ch.CloseWrite()` runs. The reverse direction continues until the channel itself closes (or until the client gives up and closes the channel after getting the half-close). Symmetric.

- **Slow / hung destination:** no per-channel idle timeout in v1. TCP keepalive on the dialed socket follows OS defaults (about 2 hours on Linux). Documented in Open Questions for follow-up.

## 6. Logging

Three new events, all emitted from `internal/server/forward.go` via the `Logger` methods added in §4.6. All three pass through the existing password scrub in `Logger.emit`.

```
forward-open  remote=192.168.1.42:51223 dest_host=web.example.org dest_port=80 originator_host=127.0.0.1 originator_port=58123
forward-close remote=192.168.1.42:51223 dest_host=web.example.org dest_port=80 bytes_in=1452 bytes_out=89 duration=437ms
forward-reject remote=192.168.1.42:51223 dest_host=10.0.0.5 dest_port=5432 reason=dial-failed
```

Field rationale:

- `remote` matches the existing `conn-*` / `session` field for grep-ability across an SSH connection's lifetime.
- `dest_host` and `dest_port` are split (rather than a single `dest=host:port`) so an operator can filter logs by destination port (`grep "dest_port=5432"`) without regex pain. Existing `conn-open`/`conn-close` events combine into `remote=host:port` because that's already a single token from `RemoteAddr().String()`; the destination fields come from the parsed payload as separate values, so keep them separate.
- `originator_host` / `originator_port` are present in `forward-open` only because they are useful for forensics (which local client socket made the request) and absent from `forward-close` (would be redundant — both events share the same channel).
- `bytes_in` / `bytes_out` are emitted as raw decimal integers (no `B` suffix) so log analysers don't have to parse units.
- `reason` is a small closed set: `malformed-payload`, `dial-failed`, `over-cap`. If a fourth case shows up (e.g. policy violation when `--forward-allow` is added in v2), it joins this set with a new keyword.
- `forward-reject reason=malformed-payload` logs `dest_host=""` and `dest_port=0`. This is intentional: no valid destination was parsed, so there is nothing meaningful to log. The empty `dest_host` will be quoted per §9 quoting rules (`dest_host=""`); the zero `dest_port` appears as `dest_port=0`. Consumers of this event should treat these fields as "unavailable" for the malformed-payload case.

The existing `reject what=tcpip` log is no longer emitted for *local* forwarding — that path is replaced by `forward-reject`. It is still emitted for the *reverse* (`forwarded-tcpip` / `tcpip-forward` / `cancel-tcpip-forward`) cases. This is the §9 clarification the spec edit in §2.4 above pins down.

No new logging is required at startup; the resolved `--forward-max` value does not need its own event (the spec does not require flag values to be logged). If a follow-up wants visibility, extend the `listening` event in a separate PR with its own spec edit.

## 7. Tests

Tests are listed at three layers. Each new test gets a `Test*` function name so the reviewer can grep for it.

### 7.1 Unit tests (`internal/server/forward_test.go`, new)

- `TestParseDirectTCPIP_OK` — well-formed payload with `127.0.0.1`, port 80, `1.2.3.4`, port 12345 round-trips.
- `TestParseDirectTCPIP_OK_OriginPortZero` — origin port 0 is accepted (some clients send 0 for ephemeral sockets).
- `TestParseDirectTCPIP_MalformedTruncated` — 4 random bytes → error.
- `TestParseDirectTCPIP_MalformedTrailingGarbage` — well-formed payload with one extra trailing byte → error (unconditional; `ssh.Unmarshal` is strict and rejects trailing bytes, confirmed in `messages.go: Unmarshal`).
- `TestParseDirectTCPIP_DestPortZero` — dest-port 0 → error "dest-port out of range".
- `TestParseDirectTCPIP_DestPortTooLarge` — dest-port 70000 → error.
- `TestParseDirectTCPIP_EmptyDestHost` — empty dest host → currently allowed by the parser (an empty hostname dials to ""; OS returns ENOENT/Invalid argument, which surfaces as `dial-failed`). Document the choice. We don't reject in the parser because the spec says only the payload structure matters there.
- `TestForwardCounter_AcquireUntilCap` — cap=3, three acquires succeed, fourth fails, release, next acquire succeeds.
- `TestForwardCounter_CapZeroDisablesForwarding` — cap=0, every Acquire returns false.
- `TestForwardCounter_NegativeCapTreatedAsZero` — defensive; the validation rejects negatives at startup, but the data type allows them. Acquire returns false.
- `TestForwardCounter_RaceFreeUnderConcurrency` — 1000 goroutines acquire+release; `go test -race` must stay green; total inflight never exceeds cap.

### 7.2 Unit tests (`internal/server/dispatch_test.go`, modified)

- **Modify** `TestRouteChannel_RejectsTCPIP`: remove `"direct-tcpip"` from the sweep — only `"forwarded-tcpip"` remains under this name. The test docstring updates to mention that direct-tcpip now follows the forward path.
- **Add** `TestClassifyChannel_DirectTCPIPRoutedToForward` — assert `classifyChannel({chanType:"direct-tcpip"}, ...)` returns `actionForward` AND the channel is NOT rejected AND no `Reject` event is logged.
- **Add** `TestClassifyChannel_SessionRoutedToSession` — assert session returns `actionSession` (mirrors the existing `TestRouteChannel_SessionAccepted` but on the lower-level function).
- Keep all other dispatch tests unchanged: `TestRouteChannel_RejectsStreamlocal`, `TestRouteChannel_RejectsUnknownType`, `TestHandleGlobalRequest_*`, `TestSSHRequestAdapter_*`.

### 7.3 Unit tests (`internal/logging/logging_test.go`, modified)

- Add cases for each new event:
  - `TestLogger_ForwardOpenFormatting`
  - `TestLogger_ForwardCloseFormatting`
  - `TestLogger_ForwardRejectFormatting`
- Add `TestLogger_ForwardEventsScrubPassword` — feed the configured password as the dest-host value, assert it is replaced by `[REDACTED]` in the emitted line (verifies the existing scrub applies to the new methods because they all flow through `emit`).

### 7.4 Unit tests (`cmd/minisshd/main_test.go`, modified)

- `TestRun_ForwardMaxNegativeExits2` — `--forward-max -1` exits 2 with a stderr message naming the rejected value.
- `TestRun_ForwardMaxNonInteger_Env` — `MINISSHD_FORWARD_MAX=abc` exits 2 (when `--forward-max` is unset).
- `TestRun_ForwardMaxDefault32` — no flag, no env → resolved value 32 (verify via a small `resolveForwardMax` direct test).
- `TestRun_ForwardMaxFlagBeatsEnv` — `--forward-max 5` + `MINISSHD_FORWARD_MAX=99` → 5.
- `TestRun_ForwardMaxZeroAllowed` — `--forward-max 0` resolves to 0 (forwarding disabled; not an error).

### 7.5 Integration tests (`internal/server/forward_integration_test.go`, new)

These tests use `golang.org/x/crypto/ssh` as the in-process client and `net.Listen("tcp", "127.0.0.1:0")` for the echo server, following the existing `startTestServer` / `dialSSH` helpers in `testhelpers_integration_test.go`.

**Test-harness extension (`testhelpers_integration_test.go`):**

Add two fields to `testServerOptions`:

```go
forwardMax       int  // 0 means "use default 32"
disableForwarding bool // if true, pass ForwardMax: 0 (disables forwarding)
```

In `startTestServer`, resolve the effective cap before building `server.Config`:

```go
effectiveCap := 32 // production default
if opts.disableForwarding {
    effectiveCap = 0
} else if opts.forwardMax > 0 {
    effectiveCap = opts.forwardMax
}
// pass effectiveCap as server.Config.ForwardMax
```

This ensures existing tests that do not set either field get `ForwardMax: 32`, so no currently-passing test silently trips the cap. Only tests that set `disableForwarding: true` get `ForwardMax: 0`; tests that set `forwardMax: N` (N > 0) get that explicit cap.

- `TestIntegration_DirectTCPIP_EchoRoundTrip` — start an in-process TCP echo server, open `direct-tcpip` to it, write 64 random bytes, read 64 bytes back, close the channel. Assert the bytes match. Assert the server log contains `forward-open` then `forward-close` with `bytes_in=64` and `bytes_out=64`.

- `TestIntegration_DirectTCPIP_DialFailure` — pick an unused local port (bind, get the port, close), open `direct-tcpip` to it. Expect `*ssh.OpenChannelError` with `Reason == ssh.ConnectionFailed`. Assert log contains `forward-reject reason=dial-failed`.

- `TestIntegration_DirectTCPIP_MalformedPayload` — open with payload `[]byte{0,0,0,0}` (truncated). Expect `ConnectionFailed`. Assert log contains `forward-reject reason=malformed-payload`.

- `TestIntegration_DirectTCPIP_PerConnectionCap` — start the test server with `forwardMax: 2`. Open three echo servers. Open two `direct-tcpip` channels (keep them open by holding both ends of each TCP connection so the channel goroutines block in `io.Copy` and do not release the counter slot). The third `OpenChannel` must fail with `*ssh.OpenChannelError` where `Reason == ssh.Prohibited` (the spec specifies `Prohibited` for over-cap; test must assert this specific code, not "either"). Assert log contains `forward-reject reason=over-cap`. Close one of the open forwards by closing the local TCP side; a fourth open must succeed. Assert log contains a fresh `forward-open`.

- `TestIntegration_DirectTCPIP_TCPCloseTriggersChannelEOF` — echo server writes "hello" then closes the connection. Open `direct-tcpip`, read 5 bytes, then read again; expect EOF. Assert `forward-close` is emitted with `bytes_in=5`.

- `TestIntegration_DirectTCPIP_ChannelCloseTriggersTCPClose` — echo server records what it sees and a "did the client close?" flag. Open `direct-tcpip`, write 5 bytes, close the channel. Assert the echo server's connection saw EOF within 500 ms.

- `TestIntegration_DirectTCPIP_RejectedWhenForwardMaxZero` — start the test server with `disableForwarding: true` (which maps to `ForwardMax: 0`). Open `direct-tcpip`. Expect `*ssh.OpenChannelError` with `Reason == ssh.Prohibited`. Assert log contains `forward-reject reason=over-cap`.

- **Regression-keep:** the existing tests in `server_integration_test.go` and `coverage_integration_test.go` that assert *reverse* forwarding stays rejected stay unchanged:
  - `TestIntegration_RejectsDirectTCPIP` → **rename** to `TestIntegration_RejectsForwardedTCPIP` and change the channel type from `direct-tcpip` to `forwarded-tcpip`. The rejection it asserts is still correct (clients should never send `forwarded-tcpip` themselves; if one does, we still reject it). Same `what=tcpip` log assertion.
  - `TestIntegration_StreamlocalChannelRejected` — unchanged.
  - `TestIntegration_GlobalTCPIPForwardRejected` — unchanged.
  - `TestIntegration_GlobalCancelTCPIPForwardRejected` (or equivalent in coverage_integration_test.go) — unchanged.

  The original test name `TestIntegration_RejectsDirectTCPIP` is removed because the behavior it tested is now an explicit accepted feature.

### 7.6 E2E tests (`test/e2e/e2e_test.go`, modified)

- **Replace** `TestE2E_PortForwardingRejected` (was §13.4 #8):
  - Old name remains, body becomes the "reverse forwarding rejected" case — drives `ssh -N -R 18080:127.0.0.1:1 ...`. Uses a PTY / password-feeding (same helpers). Because `-R` opens no local listener, `awaitPort` cannot be used for sync. Instead: wait for `auth-ok` in the server log (via `srv.awaitLogContains(t, "auth-ok", 5*time.Second)`) to confirm the ssh session is authenticated before asserting that `reject what=tcpip` subsequently appears. The `-R` triggers a `tcpip-forward` global request immediately after auth; the 5 s auth-ok poll is sufficient. Assert `reject what=tcpip` in the server log.
- **Add** `TestE2E_LocalPortForwarding` (new §13.4 #17):
  - Start a `net/http/httptest.NewServer` inside the test serving `MARKER_<uuid>`. Pull its `:port`.
  - Spawn `/usr/bin/ssh -p PORT -N -L 127.0.0.1:0:127.0.0.1:HTTP_PORT testuser@127.0.0.1` under a PTY. The `:0` local-port trick: the OpenSSH client supports `-L bind_address:port:host:hostport` where `port=0` means "kernel-assigned ephemeral port", but it then exposes the chosen port only via `-O forward` or by logging. Since we can't easily extract that, fall back to picking a free local port ourselves (the `nextFreePort()` helper already used in #8 keeps the test stable).
  - The `nextFreePort()` helper does NOT exist yet and must be written as part of this PR. Implementation: `l, _ := net.Listen("tcp", "127.0.0.1:0"); port := l.Addr().(*net.TCPAddr).Port; l.Close(); return port`. Add it to `spawn_test.go` (alongside the other harness helpers). Note: there is a small TOCTOU race between closing the listener and `ssh -L` binding the port; this is unavoidable with OpenSSH's static port mode and is acceptable for a test helper.
  - `awaitPort("127.0.0.1:LOCAL", 10*time.Second)`.
  - `http.Get("http://127.0.0.1:LOCAL/")`; assert body contains the marker.
  - `srv.awaitLogContains(t, "forward-open", 3*time.Second)` and same for `forward-close`.
  - Terminate the background ssh.

- **Add** `TestE2E_LocalPortForwardingCap` — start the binary with `--forward-max 1`. The precise sequence is:
  1. Start an HTTP echo server inside the test on a free port.
  2. Pick a free local port `L1` via `nextFreePort()`. Spawn `ssh -N -L 127.0.0.1:L1:127.0.0.1:HTTP_PORT testuser@127.0.0.1`. Wait for `awaitPort("127.0.0.1:L1", ...)`.
  3. Open a TCP connection to `127.0.0.1:L1` and **hold it open** (do not close yet). This keeps the `direct-tcpip` channel goroutine alive and occupies the one allowed slot.
  4. Pick a second free local port `L2`. Spawn a second `ssh -N -L 127.0.0.1:L2:127.0.0.1:HTTP_PORT ...`. Wait for `awaitPort("127.0.0.1:L2", ...)` (the ssh client has authenticated and bound the local listener, but the server-side cap fires on `direct-tcpip` channel-open).
  5. Open a TCP connection to `127.0.0.1:L2`; the server must reject the `direct-tcpip` channel, so the connection returns EOF/RST immediately. Assert `forward-reject reason=over-cap` in the server log.
  6. Close the first TCP connection from step 3 (releasing the cap slot). A subsequent TCP connection to `127.0.0.1:L1` must now succeed with a valid HTTP response, proving the slot was released.

### 7.7 Coverage gate

Combined coverage threshold stays at 90.0% (§13.5). The new code is heavily testable (a payload parser, a counter, a state machine for cap/dial/pipe); meeting the threshold should not require any new exclusions. If a path is hard to cover, refactor for testability — do **not** carve a coverage exclusion. The Makefile variable is the only place to ever change the threshold, and this PR does not change it.

## 8. Backwards compatibility

This is a strict capability addition: any client that previously saw a `Prohibited` channel-open failure on `direct-tcpip` now sees the channel succeed (or, for dial failures, sees a `ConnectionFailed` rejection instead of `Prohibited` — different reason code, but still "channel-open did not succeed").

Known callers that change behavior:

- `ssh -L LOCAL:host:port` — used to fail with "channel-open failed" once the user actually connected to LOCAL. Now succeeds. **Intended.**
- `ssh -L … -o ExitOnForwardFailure=yes` — this flag inspects `tcpip-forward` / `forwarded-tcpip` (the reverse path) and does NOT trigger on `direct-tcpip`. So `-L` clients with `ExitOnForwardFailure=yes` were not affected before (because the local listener succeeds even if the eventual channel-open fails) and remain not affected. No behavior change for this flag.

No flags removed, no flags renamed, no log events removed. New events (`forward-*`) are additive.

Tests that currently assert `direct-tcpip` rejection are **modified**, not deleted — see §7.5 for the renames and §7.6 for the E2E replacement. The reverse/streamlocal/agent/X11 tests are untouched and serve as regression guards.

A user running pinned to a particular log line format would need to update if they were relying on `reject what=tcpip` to flag `-L` attempts; they would now look for `forward-open` instead. Mention this in the release notes / commit message body.

`go.mod` does not change — `golang.org/x/crypto/ssh` and the standard library already cover everything this needs. Run `go mod tidy` regardless after editing imports.

## 9. Definition of done

The following must all hold before merging:

1. Spec edits in §2.1–§2.9 of this plan are applied to `SPEC.md`. The plan's exact wording is copied verbatim into the spec.
2. `gofmt -l .` prints nothing.
3. `go vet ./...` passes.
4. `go mod tidy` leaves `go.mod` / `go.sum` unchanged (i.e. tidy was run after every import edit).
5. `make test` passes (unit + integration `-short`).
6. `make test-slow` passes.
7. `make test-race` passes.
8. `make e2e` passes (requires `/usr/bin/ssh`).
9. `make coverage` passes, with merged coverage ≥ 90.0%.
10. The renamed tests are present (`TestIntegration_RejectsForwardedTCPIP`, the E2E `TestE2E_PortForwardingRejected` body change) — verify by grep that no test still asserts `direct-tcpip` is rejected.
11. The CLI `--forward-max -1` exits 2 with a clear stderr message.
12. The password value still does not appear in any logged `forward-*` event when fed in as a dest-host fixture (the scrub test in §7.3 covers this).
13. A manual smoke test passes on macOS:
    - Run `./minisshd --bind 127.0.0.1 --port 2222 --pass testpass`.
    - `ssh -p 2222 -N -L 18080:example.com:80 $USER@127.0.0.1` (enter `testpass`).
    - `curl -v http://127.0.0.1:18080/` returns example.com's response.
    - The server log shows `forward-open` and (after the curl finishes) `forward-close`.
14. Manual smoke test on Linux: same as #13.
15. README is updated only if necessary. Currently the README does not list flag descriptions verbatim (it points at the spec); if it stays that way, no edit is needed. If the README has a table of features, add a row for `ssh -L`. (Verify by reading README.md during implementation.)
16. The commit message body cites §7.1 and lists the new log events.
17. A PR is opened and `copilot-pull-request-reviewer` is requested as a reviewer per global instructions.

## 11. Adversarial review responses (iter 1)

All issues from the iter-1 adversarial review are addressed. The issues that received plan edits are documented in the Changelog at the top. No issues were rejected. This section records the disposition of every numbered issue for traceability.

| Issue | Disposition |
|---|---|
| CRITICAL-5 | Plan edit: added `forwardMax int` / `disableForwarding bool` to `testServerOptions`; `startTestServer` defaults to `ForwardMax: 32`. §7.5 updated. |
| SIGNIFICANT-8 | Plan edit: changed over-cap integration test to assert `Reason == ssh.Prohibited` specifically. §2.7 §11 table also updated. |
| SIGNIFICANT-9 | Plan edit: `nextFreePort()` does not exist; plan now specifies it must be written, with the implementation (`net.Listen / l.Close()`). |
| SIGNIFICANT-10 | Plan edit: `TestE2E_LocalPortForwardingCap` rewritten with the precise 6-step sequence (hold-connection-1-open → trigger-channel-2 → assert-EOF → release-1 → assert-success). |
| MINOR-1 | Plan edit: removed `Timeout: dialTimeout` from `net.Dialer`; rely solely on context deadline. |
| MINOR-2 | Plan edit: local variable named `fwdCap` in `handleConn` and in the code sketch. |
| MINOR-3 | Plan edit: `TestParseDirectTCPIP_MalformedTrailingGarbage` must assert an error unconditionally; hedge removed. |
| MINOR-5 | Plan edit: step 10 parenthetical now correctly states validation happens before the listener bind. |
| MINOR-7 | Plan edit: §2.6 spec sentence now says "use `--bind 127.0.0.1` to restrict to loopback" rather than calling it the safe default. |
| MINOR-8 | Plan edit: §6 documents that `forward-reject reason=malformed-payload` emits empty/zero dest fields intentionally. |
| MINOR-10 | Plan edit: revised E2E #8 now uses `awaitLogContains(t, "auth-ok", ...)` for sync instead of `awaitPort` (which doesn't work for `-R`). |

---

## 10. Open questions / risks

### 10.1 Destination policy (`--forward-allow`) — deferred

The brief proposes an optional `--forward-allow PATTERNS` flag with CIDR + port wildcard support. **This plan defers it to v2** for these reasons:

- The §3 operator-trust model already places responsibility on the operator. The new §3 sentence in §2.6 of this plan makes that explicit for forwarding specifically.
- A correct allow-list implementation needs CIDR parsing, hostname-vs-IP semantics (do we resolve before matching?), wildcard syntax (`*:*`? `192.168.0.0/16:80,443`?), and tests for each. That doubles the size of this PR.
- The `--forward-max` cap addresses the most acute denial-of-service / amplification risk. Destination *restriction* is a defense-in-depth feature on top, not a replacement.

If/when added in v2:
- Format: comma-separated entries of `host[:port]` or `CIDR[:port]` with `*` as a wildcard for either component. Default = `*:*`.
- New `forward-reject reason=policy` log case.
- New §7.1 step between "cap check" and "dial" that consults the policy.
- New `--forward-deny` would compose by precedence (deny wins). Defer that too.

### 10.2 Per-channel idle timeout — deferred

No idle timeout in v1. Risks:

- A long-lived but idle forward (e.g. a SOCKS-over-SSH-style setup that holds a TCP socket open forever) consumes a `forward-max` slot until the client closes it.
- TCP keepalive defaults are very slow (~2 hours on Linux); a half-broken NAT path can leave a forward open until the keepalive trips.

Mitigation in v1: the per-connection cap prevents unbounded accumulation. Defer a `--forward-idle 5m` flag to v2.

### 10.3 DNS resolution at dial time

`net.Dialer.DialContext` uses the system resolver. If `dest-host` is a hostname that resolves to multiple addresses, `DialContext` will try each in order until one succeeds. We do not log the resolved address. Acceptable for v1; a future event field `dest_resolved` could be added without spec-revving the rest.

### 10.4 IPv6 destinations

The parsed `DestAddr` may be an IPv6 literal (`net.JoinHostPort` brackets correctly), an IPv4 literal, or a hostname. `net.Dialer.DialContext` handles all three. No special-case code needed. A test for an IPv6 destination is nice-to-have but not blocking; `127.0.0.1` and `::1` in tests cover the matrix.

### 10.5 Coverage of `handleDirectTCPIP` error branches

The function has many error branches (parse, cap, dial, accept). The integration tests in §7.5 exercise parse/cap/dial; the `Accept()` error path is unusual (the ssh library rarely fails Accept after a NewChannel has been delivered) and may be uncovered. Options:

- Acceptable if it stays below the threshold's noise level; total file is small.
- Refactor so the Accept error funnels through a tested helper, if needed.
- If coverage dips below 90.0%, add a unit test that calls `handleDirectTCPIP` with a fake `newChannelExt` whose `Accept()` returns an error. (Recommended pre-emptive coverage.)

### 10.6 What if the SSH library version bumps mid-PR?

The plan pins to current `golang.org/x/crypto/ssh` semantics for `ssh.NewChannel.ExtraData()` and `ssh.Channel.CloseWrite()`. Both are stable surface across recent versions. If a future bump renames or removes either, the seam is the `newChannelExt` interface — update the adapter and the compile-time assertion catches the drift.

### 10.7 Security note for §3

The plan adds a sentence to §3 (see §2.6 of this plan) but does not add a runtime check. This is consistent with §3's existing "operator responsibility" stance; do not introduce a runtime "is this a public address" heuristic without a separate spec change.

### 10.8 `--forward-allow`/policy in test fixtures

The integration test `testServerOptions` struct gains two new fields: `forwardMax int` and `disableForwarding bool`. `startTestServer` defaults to `ForwardMax: 32` (same as production) when neither field is set. Tests that want a specific cap set `forwardMax: N` (N > 0); tests that want forwarding completely off set `disableForwarding: true` (maps to `ForwardMax: 0`). A stray `forwardMax: 0` without `disableForwarding: true` is treated as "use the default 32" — this avoids the silent-disable footgun. Audit the testhelpers diff carefully when reviewing the PR.

### 10.9 Whether to emit `forward-open` *before* or *after* the per-channel-request discard goroutine

Plan emits `forward-open` immediately after `Accept()` and before the copy goroutines start. The DiscardRequests goroutine kicks off independently. This means `forward-open` and the copy goroutines have a sub-microsecond race that is not observable from the log perspective (they share the same `remote`/`dest_*` keys). No action needed; flagging in case a reviewer questions the ordering.

---

## 12. Adversarial review responses (iter 2)

| Issue | Severity | Disposition |
|---|---|---|
| §7.1 step 2 rejection code inconsistency | CRITICAL | **Agreed and fixed.** The §2.2 prose for step 2 said `ConnectionFailed` for the over-cap case while the §11 table (§2.7) and the `forward.go` code sketch (§4.3) both said `Prohibited`. Updated §2.2 to say `Prohibited`, matching all three locations. The message `"too many concurrent forwards"` is unchanged. |
| Missing §13.2 amendment | SIGNIFICANT | **Agreed and fixed.** Added a §13.2 amendment in §2.9 that removes `direct-tcpip` from the §13.2 unit-test rejection list. The amendment quotes the current §13.2 wording, proposes the updated wording in a fenced block, and notes that the renamed dispatch unit test (§7.2) now covers `forwarded-tcpip` and `streamlocal` rejections only — not `direct-tcpip`. |

---

## 13. Adversarial review responses (iter 3)

| Issue | Severity | Disposition |
|---|---|---|
| §13.3 integration test over-cap rejection code still `ConnectionFailed` | CRITICAL | **Agreed and fixed.** The per-connection forward cap integration test bullet (§2.9 / §13.3) said `ConnectionFailed` for the over-cap rejection. Changed to `Prohibited`, matching §7.1 step 2 prose, the §11 table, and the `forward.go` code sketch — all of which were already updated in iter 2. The `ConnectionFailed` references for `dial-failed` and `malformed-payload` are unaffected (those remain correct). |
