# Plan: Daemonization / auto-start examples (docs-only)

Date: 2026-05-19
Scope: docs/examples/, plus a small amendment to SPEC.md.
Out of scope: any change to .go files, the test suite, the coverage threshold, or the binary's behavior.

## Changelog (iter 3 → iter 4)

- **S1** — Fixed inconsistent placeholder in the newsyslog.d recipe: changed `/Users/REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log` to `REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log`, dropping the hardcoded `/Users/` prefix. The surrounding prose was updated to match: operators substitute `REPLACE_ME_WITH_HOME` with their full home directory path (e.g. `/Users/alice`), consistent with the established definition in "Before you install".

## Changelog (iter 2 → iter 3)

- **C1** — Replaced the broken `docker run alpine:edge` validation path with an honest assessment: Alpine does not ship systemd; no clean Docker-on-macOS validation path exists. Definition of done item 5 now specifies that `systemd-analyze --user verify` must be run on a real Linux host (or CI Linux runner) as a pre-merge requirement. The Docker one-liner is removed. PR description must state "verified on Linux host" or "verified on CI Linux runner".
- **C2** — Added concrete no-linger diagnostics to the Linux Linger section: how to check `loginctl show-user $USER | grep Linger` and how to interpret the result when the service silently stops after logout.
- **S1** — Updated newsyslog.d recipe: changed path from `/usr/local/etc/newsyslog.d/` to `/etc/newsyslog.d/` (the actual macOS system include directory); noted that this path is root-owned and requires `sudo`; replaced `YOURHOME` placeholder with `REPLACE_ME_WITH_HOME` for consistency.
- **S2** — Moved the Linger subsection to appear BEFORE the Install subsection in the Linux README outline, so operators encounter the linger decision before running `systemctl --user enable --now`.
- **S3 (SIGNIFICANT-3)** — Split the §12 replacement bullet in the Spec amendments section into two bullets: one that preserves the terse non-goal ("implemented in the binary") and a second that carries the forward pointer and credential requirement. Noted the reasoning in the Adversarial review responses section.
- **M1** — Updated plist `ProgramArguments` and README outline to use `REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY` as a single full-path token. Updated all placeholder count references accordingly (still six substitution points, but the binary-path placeholder is now a single token rather than a prefix).
- **M2** — Added a note in the macOS Install section that `launchctl load -w` / `unload -w` are deprecated since macOS Ventura; the modern equivalents `launchctl bootstrap gui/$(id -u) ...` / `launchctl bootout gui/$(id -u) ...` are listed as the preferred form on Ventura+.
- **M3** — Added a note in the Linux README outline (Hardening / `Environment=` section) that `Environment=` values are visible via `systemctl --user show minisshd`; the `chmod 600` framing does not prevent this.

## Changelog (iter 1 → iter 2)

- **C1** — Added a prominent "Auto-generated passwords are NOT suitable for supervised installs" callout to README outline and §12 amendment. Added a note that `REPLACE_ME_WITH_PASSWORD` is itself a valid literal password the binary will accept.
- **C2** — Promoted `loginctl enable-linger` to a primary install-time decision in the Linux section, with explicit "runs while logged in only" vs "headless host" framing rather than a side note.
- **C3** — Added respawn-loop diagnostics to macOS Logs section: how to detect via `launchctl list`, how to read stderr config errors from the same log file, and `launchctl print` for full state.
- **C4** — Updated §12 spec amendment to explicitly require `MINISSHD_PASS` when using the example units, with a sentence explaining the auto-password / log-capture risk.
- **S1** — Enumerated all six REPLACE_ME placeholders in README outline; added explicit "launchd does NOT expand `~` or `$HOME` — use an absolute path like `/Users/alice`" callout.
- **S2** — Reframed `chmod 600` as "hygiene, not isolation" in README outline.
- **S3** — Added a minimal `newsyslog.d` recipe to the macOS Logs section instead of deferring to "v2".
- **S4** — Dropped the `Documentation=` line from the systemd unit (or converted to placeholder); removed from unit contents and notes.
- **S5** — Tightened §10 amendment with an explicit "Operator note (outside the runtime contract)" lead.
- **S6** — Added a Docker one-liner validation path for `systemd-analyze --user verify` on macOS, in addition to the "tested on Linux" option.
- **S7** — Moved the `--bind 127.0.0.1` vs binary-default `0.0.0.0` divergence to a prominent callout in "Before you install".
- **Inaccuracy 1** — Corrected the `WorkingDirectory` rationale: `~/.minisshd/` resolution uses `os.UserHomeDir()`/`$HOME`, not CWD; the real reason to omit `WorkingDirectory` is irrelevance, not correctness.
- **Inaccuracy 2** — Removed `After=default.target` from the systemd unit (redundant with `WantedBy=default.target`).
- **M1** — Fixed duplicated "uninstall" in README outline deliverable list.
- **M2** — Replaced all three "v2" references with "a later docs-only follow-up".
- **M3** — Changed "are all no-ops" to "should be verified as no-ops" in Backwards compatibility and Definition of done.
- **M4** — Added a footnote about XML-style plist comments and `defaults` stripping.
- **M5** — Added `launchctl print gui/$(id -u)/com.<you>.minisshd` to macOS Logs/diagnostics.
- **M6** — Pinned the repo-root README pointer wording.

---

## Summary

Provide operators with copy/paste-ready service-unit examples so they can run
`minisshd` under their OS's native per-user supervisor (launchd on macOS,
systemd `--user` on Linux). This is a docs-only feature: the binary stays
supervisor-naive, so the §12 "Daemonization or auto-start at login" non-goal
is amended in spirit (binary remains naive) rather than removed.

Deliverables (and nothing else):

1. `docs/examples/com.example.minisshd.plist` — macOS LaunchAgent template.
2. `docs/examples/minisshd.service` — systemd `--user` unit template.
3. `docs/examples/README.md` — install/uninstall/logs/warnings.
4. Edits to `SPEC.md` (§10 file-layout note, §12
   non-goal rewording).
5. A short pointer from the repo-root `README.md` to `docs/examples/`.

No source code or test file is touched. `go vet`, `gofmt -l .`, the coverage
threshold, and `make` targets are unaffected by definition.

## Spec amendments

Two surgical edits to `SPEC.md`. The wording below is
the exact replacement text; the implementation pass must apply these verbatim.

### §12 — replace the existing "Daemonization or auto-start at login" bullet

Current:

> - Daemonization or auto-start at login. Run it in a terminal or under your own process supervisor.

Replacement (two bullets instead of one, to keep the non-goal terse and the
forward pointer separate so a scanning reader does not miss the qualifier):

> - Daemonization or auto-start at login *implemented in the binary*. `minisshd` is supervisor-naive — it does not fork, detach, write a PID file, manage its own restarts, or hook itself into a service manager. Run it in a terminal or under your own process supervisor.
> - Operator escape hatch: copy/paste service-unit templates for launchd (macOS) and `systemd --user` (Linux) are provided in `docs/examples/`. The binary itself is unchanged. Operators using these templates must set `MINISSHD_PASS` (or one of the hardened credential mechanisms documented there) — running with an auto-generated password under a supervisor would capture each rotated password into the supervisor's log file, which §9 warns against.

Rationale: splitting preserves a terse first bullet that a reader scanning §12
for "does the binary daemonize?" will absorb correctly, while the second bullet
carries the forward pointer and credential requirement. The phrase "implemented
in the binary" on the first bullet is the load-bearing clarification. The
explicit `MINISSHD_PASS` requirement on the second bullet resolves the potential
contradiction with §9's auto-generated-password redirect warning.

### §10 — add an operator note under the existing file-layout block

Insert immediately after the existing closing paragraph of §10 (the one that
ends "…startup fails per §2 step 5 / §6."):

> **Operator note (outside the runtime contract).** Example service-unit files for running `minisshd` under launchd (macOS) or `systemd --user` (Linux) live in `docs/examples/`. They are not loaded or referenced by the binary and are not part of the runtime contract; they are operator-facing templates only.

Rationale: §10 is "File layout", so a forward-reference here is where a
reader looking for "where do the example unit files live?" will end up. The
explicit "outside the runtime contract" signal makes clear the §10 invariants
are unchanged. The original wording lacked this signal and was flagged as
reading as if §10 had grown a new scope.

No other section of the spec is touched. In particular §2 (CLI/env/startup),
§3 (network exposure), §4 (auth), §5 (rate limit), §6 (host key), §8 (session),
§9 (logging), §11 (errors), and §13 (tests) are all unchanged because the
binary is unchanged.

## File layout — docs/examples/ tree, file names, what each file contains

```
docs/examples/
├── README.md                          # install/uninstall/logs/warnings
├── com.example.minisshd.plist         # macOS LaunchAgent template
└── minisshd.service                   # systemd --user unit template
```

File-by-file description:

- `docs/examples/README.md` — the operator-facing doc. Per-OS install
  commands, per-OS uninstall commands, log file locations, the plaintext
  password warning prominently, and the list of placeholders the operator
  must edit before installing.
- `docs/examples/com.example.minisshd.plist` — a literal `.plist` XML file
  that launchd parses. Uses `com.example.minisshd` as the placeholder reverse-DNS
  label (operators are instructed to rename, e.g. `com.alice.minisshd.plist`
  with a matching `<Label>`). Includes placeholders for the binary path, the
  password, the username, and the log paths. Validated with `plutil -lint`
  (see Definition of done).
- `docs/examples/minisshd.service` — a literal systemd unit file. Includes
  `[Unit]`, `[Service]`, `[Install]` sections, with placeholders for the
  binary path, the password, the username, and the bind address/port.
  Validated with `systemd-analyze --user verify` when on Linux.

All three files are checked in as-is; no Makefile target generates them and no
test consumes them.

## launchd plist — full proposed contents

Filename: `docs/examples/com.example.minisshd.plist`.

Conventions encoded in this template:

- `LaunchAgent` (runs as the logged-in user), **not** `LaunchDaemon` (which
  would be root). This matches spec §2 step 3 ("the OS username of the process
  owner") and §12 "Privileged operations or running as another user".
- `RunAtLoad=true` — start when launchd loads the agent at login.
- `KeepAlive` is a dict with `SuccessfulExit=false` — restart only if the
  process exited unsuccessfully. A clean `SIGTERM` (exit 0 per §8 Signal
  handling) does NOT trigger a relaunch, which matches operator expectation
  ("stop means stop").
- `StandardOutPath` / `StandardErrorPath` point at `~/Library/Logs/minisshd.log`
  so the §9 stdout log stream is captured to a predictable file. Because
  stdout is redirected to a file, `MINISSHD_PASS` **must** be set; an
  auto-generated password would be written into the log file on every restart,
  which §9 explicitly warns against.
- `EnvironmentVariables` carries `MINISSHD_PASS` and `MINISSHD_USER` so the
  password is set via env (preferred over `--pass` per spec §2 because env is
  not visible in default `ps` output). The plaintext-in-plist warning lives
  in the README.
- `ProgramArguments` invokes the binary with `--bind 127.0.0.1` by default.
  **Note:** the binary's default is `0.0.0.0` (listens on all interfaces).
  The template deliberately diverges to loopback because a supervisor-managed
  instance is more likely to be running unobserved. Operators who need LAN
  access must explicitly change this. (See also "Before you install" in the
  README.)
- `ProcessType=Background` — tells launchd this is a long-running background
  service for QoS/throttling purposes.

Full contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!--
        minisshd LaunchAgent (per-user, not a privileged daemon).

        Install to: ~/Library/LaunchAgents/com.<you>.minisshd.plist
        Rename the file and the <Label> below to match your reverse-DNS prefix.

        Before installing, edit every value marked REPLACE_ME below.

        NOTE: launchd does NOT expand ~ or $HOME in plist path strings.
        All REPLACE_ME_WITH_HOME values must be absolute paths (e.g. /Users/alice).

        NOTE: XML-style comments like this one are valid and pass plutil -lint,
        but are silently stripped by the `defaults` command. They survive
        launchd and direct XML editing, but disappear if you round-trip
        through the `defaults` tool.
    -->

    <key>Label</key>
    <string>com.example.minisshd</string>

    <key>ProgramArguments</key>
    <array>
        <string>REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY</string>
        <string>--bind</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>2222</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <!--
            MINISSHD_PASS and MINISSHD_USER are stored here in plaintext.
            See docs/examples/README.md for the security tradeoff and
            alternatives (Keychain, file with chmod 600, etc.).

            WARNING: Do NOT leave REPLACE_ME_WITH_PASSWORD as-is.
            The binary accepts ANY non-empty string as a password, including
            the literal text "REPLACE_ME_WITH_PASSWORD".
        -->
        <key>MINISSHD_PASS</key>
        <string>REPLACE_ME_WITH_PASSWORD</string>
        <key>MINISSHD_USER</key>
        <string>REPLACE_ME_WITH_USERNAME</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ProcessType</key>
    <string>Background</string>

    <key>StandardOutPath</key>
    <string>REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log</string>

    <key>StandardErrorPath</key>
    <string>REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log</string>
</dict>
</plist>
```

Notes for the implementing pass:

- The file must be valid XML and pass `plutil -lint`. The placeholders are
  inside `<string>` elements so they don't break XML parsing even before
  substitution.
- Do NOT include a `UserName` or `GroupName` key. Those are for `LaunchDaemon`;
  setting them on a `LaunchAgent` is either a no-op or an error depending on
  macOS version.
- Do NOT include `WorkingDirectory`. The binary resolves `~/.minisshd/` via
  `os.UserHomeDir()`/`$HOME`, which launchd sets correctly regardless of CWD.
  The key is irrelevant and omitting it avoids confusion.
- The `Disabled` key is intentionally absent. Operators set or clear it with
  `launchctl load -w` / `launchctl unload -w`.
- REPLACE_ME placeholder count: there are **six** values to substitute before
  installing — `REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY` (the full absolute
  path to the binary, e.g. `/usr/local/bin/minisshd` — a single token
  replacing the entire path string, not just a prefix),
  `REPLACE_ME_WITH_PASSWORD`, `REPLACE_ME_WITH_USERNAME`,
  `REPLACE_ME_WITH_HOME` (twice — StandardOutPath and StandardErrorPath),
  plus the `<Label>` value `com.example.minisshd` and the filename itself.
  The README enumerates each one explicitly.

## systemd `--user` unit — full proposed contents

Filename: `docs/examples/minisshd.service`.

Conventions encoded in this template:

- It is a **user unit** (installed under `~/.config/systemd/user/`, not
  `/etc/systemd/system/`). Matches §2 step 3 / §12 (no privilege).
- `Restart=on-failure`, `RestartSec=5` — restart only on non-zero exit,
  matching the launchd `SuccessfulExit=false` semantic.
- `Environment=` for `MINISSHD_PASS` and `MINISSHD_USER` (the env-pass-storage
  caveat is the same one the plist has; documented in the README).
- `StandardOutput=journal` and `StandardError=journal` so the §9 stdout
  stream lands in `journalctl --user -u minisshd`.
- `KillSignal=SIGTERM` and `TimeoutStopSec=10s` — gives the binary the full
  5 s drain window from §8 Signal handling plus headroom before systemd
  escalates to `SIGKILL`.
- `[Install] WantedBy=default.target` — `default.target` is the user-session
  default; this is what makes `systemctl --user enable` work.
- No `After=default.target` — this would be redundant with `WantedBy=default.target`
  and some versions of `systemd-analyze` warn about it.
- No `Documentation=` line — any URL here would be specific to a particular
  fork or deployment and would mislead operators copying the template.
- No `User=` line — user units already run as the invoking user; setting
  `User=` in a `--user` unit is an error.

Full contents:

```ini
# minisshd as a systemd --user unit.
#
# Install to: ~/.config/systemd/user/minisshd.service
# Enable:     systemctl --user daemon-reload
#             systemctl --user enable --now minisshd.service
#
# Before installing, edit every value marked REPLACE_ME below.

[Unit]
Description=minisshd userspace SSH server

[Service]
Type=simple
ExecStart=REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY --bind 127.0.0.1 --port 2222

# MINISSHD_PASS and MINISSHD_USER are stored here in plaintext.
# See docs/examples/README.md for the security tradeoff and alternatives
# (LoadCredential=, EnvironmentFile= with chmod 600, etc.).
#
# WARNING: Do NOT leave REPLACE_ME_WITH_PASSWORD as-is.
# The binary accepts ANY non-empty string as a password, including
# the literal text "REPLACE_ME_WITH_PASSWORD".
Environment=MINISSHD_PASS=REPLACE_ME_WITH_PASSWORD
Environment=MINISSHD_USER=REPLACE_ME_WITH_USERNAME

Restart=on-failure
RestartSec=5

# minisshd handles SIGTERM cleanly (drains within 5 s per spec §8).
# Give it a little more than that before systemd escalates to SIGKILL.
KillSignal=SIGTERM
TimeoutStopSec=10s

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

Notes for the implementing pass:

- Comment lines beginning with `#` are valid in systemd unit files; the
  REPLACE_ME markers inside `Environment=` lines must remain on a single line
  (systemd does not allow line continuations in `Environment=`).
- Do NOT include `WorkingDirectory=`. Same reasoning as launchd: `$HOME` is
  set by the systemd user manager and the binary resolves `~/.minisshd/` via
  `os.UserHomeDir()`/`$HOME` regardless of CWD.
- Do NOT use `EnvironmentFile=` in the default template; the plain `Environment=`
  lines keep the example self-contained and reviewable. The README mentions
  `EnvironmentFile=` as the recommended hardening step.
- **Note (M3):** `Environment=` values set in a unit file are visible via
  `systemctl --user show minisshd` — they appear in the `Environment=` field
  of the service introspection output. The `chmod 600` on the unit file prevents
  casual reads of the *file*, but does not prevent a process running as the same
  user from reading the environment via `systemctl show`. The README's Hardening
  section should note this explicitly so operators are not misled about the
  isolation `chmod 600` actually provides.

## docs/examples/README.md — outline of the install/uninstall instructions

The README is operator-facing prose. The implementation pass writes it
following this outline; section names below are the exact `##` headings.

```
# minisshd service-unit examples

Brief one-paragraph framing: these are templates, the binary is unchanged,
this is the supported "run under your own process supervisor" path that
§12 of the spec points at.

IMPORTANT: Auto-generated passwords (when MINISSHD_PASS is not set) are NOT
suitable for supervised installs. Under a supervisor that captures stdout to
a file, each restart generates a new password that gets written into the log.
Set MINISSHD_PASS before using these templates.

## Before you install

- "These templates contain placeholders. You MUST edit ALL of them before
  installing. The binary accepts any non-empty string as a password — it will
  not warn you if you forget to replace REPLACE_ME_WITH_PASSWORD."

- Explicit list of every REPLACE_ME_* marker and what to substitute:
  1. REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY — the full absolute path to the
     binary (e.g. /usr/local/bin/minisshd or /home/alice/.local/bin/minisshd).
     This is a single token that replaces the entire path string — substitute
     the complete path, not just a directory prefix.
  2. REPLACE_ME_WITH_PASSWORD — the password clients will use to authenticate
  3. REPLACE_ME_WITH_USERNAME — your OS login username
  4. REPLACE_ME_WITH_HOME (in StandardOutPath) — your home directory as an
     absolute path (e.g. /Users/alice on macOS). launchd does NOT expand ~
     or $HOME in plist path strings; you must use a literal absolute path.
  5. REPLACE_ME_WITH_HOME (in StandardErrorPath) — same as above
  6. com.example.minisshd (Label and filename) — rename to com.<you>.minisshd
     so the label matches the filename and does not collide with other installs

- IMPORTANT: The template defaults to --bind 127.0.0.1 (loopback only).
  The binary's own default when run without a flag is 0.0.0.0 (all interfaces).
  If you need LAN or remote access, change 127.0.0.1 to 0.0.0.0 or a specific
  interface address in the template before installing.

- The plaintext-password warning, called out as a fenced WARNING block
  near the top (not buried). Three sentences:
  1. The plist / service file contains your password in plaintext.
  2. The file is owned by your user and lives under ~/Library/LaunchAgents
     or ~/.config/systemd/user, both of which default to mode 0644 — readable
     by any process running as you. Set the file to mode 0600 after editing.
     This is file-system hygiene, not isolation: it does not protect against
     malware running as you, backup tools, or future OS permission changes.
  3. Alternatives (Keychain on macOS, systemd LoadCredential= on Linux,
     EnvironmentFile= with 0600) are listed below under "Hardening".

## macOS (launchd)

### Install
- `cp docs/examples/com.example.minisshd.plist ~/Library/LaunchAgents/com.<you>.minisshd.plist`
- Rename the `<Label>` inside the file to match the filename.
- Edit all six REPLACE_ME values (see "Before you install" above).
- `chmod 600 ~/Library/LaunchAgents/com.<you>.minisshd.plist`
- Load the agent. `launchctl load -w` (classic syntax) works on all macOS
  versions. **Note:** `load -w` / `unload -w` are deprecated since macOS
  Ventura (13). On Ventura and later the preferred syntax is:
  - Load: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist`
  - Unload: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist`
  Either form works, but new installs on Ventura+ should prefer `bootstrap`/`bootout`.
- Verify: `launchctl list | grep minisshd` shows the label and a PID.

### Uninstall
- `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist`
  (Or `launchctl unload -w ...` on pre-Ventura macOS.)
- `rm ~/Library/LaunchAgents/com.<you>.minisshd.plist`

### Logs
- `~/Library/Logs/minisshd.log` — the §9 stdout stream plus stderr (config
  errors, etc.).
- Tail with `tail -f ~/Library/Logs/minisshd.log`.
- launchd's own error stream is in `~/Library/Logs/com.<you>.minisshd*` if
  the agent fails to start at all (rare; usually a typo in the plist).
- For full loaded state including next respawn time:
  `launchctl print gui/$(id -u)/com.<you>.minisshd`
- Detecting a respawn loop: run `launchctl list | grep minisshd` twice a few
  seconds apart. If the PID changes each time, the agent is crash-looping.
  Check ~/Library/Logs/minisshd.log for the exit-2/3/4 error message — config
  errors (bad bind, permission failure, etc.) write to stderr which goes to
  the same log file. Fix the config issue, then `launchctl unload -w` and
  `launchctl load -w` to restart cleanly.

### Log rotation (macOS)
- The `StandardOutPath` log grows without bound. To cap its size with the
  system's built-in newsyslog, create a drop-in config at
  `/etc/newsyslog.d/minisshd.conf` (the macOS system include directory;
  creating a file there requires `sudo`):

  ```
  # logfile                                       mode  count  size  when  flags
  REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log  644   7     1000  *     J
  ```

  Replace `REPLACE_ME_WITH_HOME` with your home directory as an absolute path
  (e.g. `/Users/alice` on macOS), consistent with the definition in
  "Before you install" above.
  This retains 7 compressed rotations and rotates at 1000 KB.
  Run `sudo newsyslog -nvv` to verify the config is picked up before relying
  on it.

## Linux (systemd --user)

### Linger (running when not logged in) — decide BEFORE installing

By default a systemd `--user` instance is **destroyed when you log out**. This
means minisshd stops the moment your session ends.

**Workstation use:** This is usually fine. The server is reachable when you are
logged in and stops when you are not.

**Headless or server use:** Enable lingering so the user manager (and minisshd)
survive across logout/reboot. Decide this *before* running `enable --now` below:

- `loginctl enable-linger $USER` — keeps the user manager alive at all times.
- `loginctl disable-linger $USER` — reverts to "dies on logout" behavior.

**Diagnosing a silent stop after logout:** If minisshd appears to work while
logged in but becomes unreachable after you disconnect, the user manager
almost certainly exited when your session ended. To confirm:

```
loginctl show-user $USER | grep Linger
```

`Linger=no` means the user manager exits on logout and takes minisshd with it.
Run `loginctl enable-linger $USER` and then `systemctl --user start minisshd`
(or simply log back in and verify `systemctl --user status minisshd` shows
`active`). Connection refusal after logout with `Linger=no` is the most common
headless-host setup error for systemd `--user` services.

### Install
- `mkdir -p ~/.config/systemd/user`
- `cp docs/examples/minisshd.service ~/.config/systemd/user/minisshd.service`
- Edit the REPLACE_ME values (binary path, password, username).
- `chmod 600 ~/.config/systemd/user/minisshd.service`
- `systemctl --user daemon-reload`
- `systemctl --user enable --now minisshd.service`
- Verify: `systemctl --user status minisshd.service` shows `active (running)`.

### Uninstall
- `systemctl --user disable --now minisshd.service`
- `rm ~/.config/systemd/user/minisshd.service`
- `systemctl --user daemon-reload`

### Logs
- `journalctl --user -u minisshd.service -f` — live tail.
- `journalctl --user -u minisshd.service --since today` — historical.
- journald handles log rotation automatically.

## Hardening (both OSes)

- "The password is in the unit file. Decide whether that's acceptable for
  your threat model."
- Note: chmod 600 on the unit file is file-system hygiene, not isolation. It
  prevents casual reads by other local users but does not protect against
  malware running as you, backup tools, or future OS default changes.
- Note (Linux): `Environment=` values in a systemd unit are also visible via
  `systemctl --user show minisshd` (they appear in the `Environment=` field
  of the service introspection output). `chmod 600` on the unit file does NOT
  prevent a process running as the same user from reading the password through
  this interface. For stronger isolation, use `EnvironmentFile=` (a 0600 file)
  or `LoadCredential=` instead of inline `Environment=` lines.
- macOS: alternatives.
  - Store the password in the user keychain (`security add-generic-password
    -a $USER -s minisshd -w '<password>'`) and have a tiny wrapper script
    that retrieves it and execs `minisshd` with `MINISSHD_PASS` set. The
    plist invokes the wrapper instead of the binary. (Deferred to a later
    docs-only follow-up; not in this example.)
- Linux: alternatives.
  - `LoadCredential=` (systemd 250+) — store the password in a 0600 file
    and reference it from the unit; the secret is exposed to the service
    via `${CREDENTIALS_DIRECTORY}/minisshd-pass`, but minisshd reads only
    `MINISSHD_PASS`, so a wrapper would still be needed. (Deferred to a
    later docs-only follow-up.)
  - `EnvironmentFile=/path/to/file` with the file at mode 0600 owned by
    the user. This is the lightest hardening step and is recommended; the
    example unit can be edited to point at one.
- Both OSes: set the unit file itself to `chmod 600`. This is the baseline
  hardening posture documented in this README.

## What these examples deliberately do NOT do

- They do not run minisshd as root, and they do not change the user it runs
  as. minisshd is single-user by design (spec §12).
- They do not bind to 0.0.0.0 by default. The templates default to
  `--bind 127.0.0.1`. The binary's default when invoked without a flag is
  0.0.0.0. See "Before you install" for when to change this.
- They do not write a PID file. minisshd does not produce one; both
  launchd and systemd track the PID themselves.
```

## Backwards compatibility

- The binary is not modified. Anyone running an older `minisshd` build
  against these example files will get the same behavior they get today;
  the examples invoke only documented CLI flags and the documented
  `MINISSHD_PASS` / `MINISSHD_USER` env vars (§2).
- No new flag, no new env var, no new exit code, no new log event.
- The CLAUDE.md "logging always goes through `internal/logging` except the
  banner" invariant is unaffected — neither launchd nor systemd is in the
  log path; they merely capture the stdout the program is already writing.
- The `~/.minisshd/` filesystem invariant (§10) is unchanged. The service
  manager runs the binary as the operator's user with that operator's
  `$HOME`, so `~/.minisshd/host_key` resolves to the same location it does
  for an interactive run.
- Coverage threshold (§13.5) is untouched because no `.go` file is touched.
- `go vet`, `gofmt -l .`, `go mod tidy` should be verified as no-ops for
  this change set (no Go files are modified, but the implementing pass must
  confirm rather than assume).

## Definition of done

The implementing pass is done when ALL of the following hold:

1. `docs/examples/` exists and contains exactly three files:
   `README.md`, `com.example.minisshd.plist`, `minisshd.service`. No other
   files (no Makefile target, no install script, no fixture).
2. `SPEC.md` contains the two amendments described
   above (§10 note and §12 reworded bullet), and no other section is
   touched.
3. The repo-root `README.md` gains a pointer in an appropriate place
   (e.g. an "Auto-start at login" subsection near the end of the Usage
   section) with wording: "To run `minisshd` under launchd (macOS) or
   `systemd --user` (Linux), see the copy/paste templates in
   [`docs/examples/`](docs/examples/)." This is the only addition to the
   root README; "Build and test", "Usage", and "Supported platforms" are
   untouched.
4. `plutil -lint docs/examples/com.example.minisshd.plist` exits 0 on
   macOS. This is the validation gate for the plist; run it locally as
   part of the implementing pass. (No CI gate is added — keeping CI
   contract unchanged.)
5. `systemd-analyze --user verify docs/examples/minisshd.service` exits 0
   on a **real Linux host** (either a physical/virtual Linux machine or a CI
   Linux runner). There is no clean Docker-on-macOS path: Alpine does not ship
   full systemd (it uses OpenRC), and `systemd-analyze --user verify` requires
   a running systemd user bus even on Debian/Ubuntu-based containers. The
   implementing pass must either run this check on a Linux host directly, or
   confirm the check passes on a CI Linux runner before merging. The PR
   description must state "verified on Linux host" or "verified on CI Linux
   runner" — the honor system alone is not acceptable, but a Docker workaround
   is not a reliable substitute for a real Linux environment.
6. No `.go` file under `cmd/`, `internal/`, or `test/` is modified. `git
   diff --stat` shows changes only under `docs/` and the root `README.md`.
7. `go vet ./...` exits 0 (verified — no Go was touched, but run it to
   confirm). `gofmt -l .` prints nothing (verified). `go mod tidy` is
   confirmed a no-op (no imports added). These must actually be run, not
   assumed.
8. `make test` is not affected (unchanged source); the implementing pass
   does NOT add or alter a `make` target.

## Open questions / risks

1. **Plaintext password in the unit file is a real footgun.** Decision for
   this pass: document the warning prominently in the README and in both
   template files, ship the unit files as-is with the password inline via
   `Environment=` / `EnvironmentVariables`. Rationale: matches how operators
   write these files in practice; any other default (Keychain wrapper,
   `LoadCredential=`, EnvironmentFile with chmod 600) adds a second moving
   part the operator must understand. The README's "Hardening" section lists
   the alternatives and explicitly defers them to a later docs-only follow-up.
   **New risk (C1):** The literal `REPLACE_ME_WITH_PASSWORD` string is a
   valid password the binary will accept. Both template files and the README
   warn about this explicitly.

2. **Default `--bind`.** The example unit files use `--bind 127.0.0.1`,
   not the binary's default of `0.0.0.0`. This is a deliberate divergence
   for the supervisor case: a binary running interactively in a terminal
   is more likely to be a one-off the operator is watching; a binary
   running under launchd/systemd is more likely to be running unobserved.
   Loopback is the safer default for the latter. The README "Before you
   install" section calls this out prominently so operators are not
   surprised when they go to connect from another host on their LAN.

3. **Reverse-DNS plist label.** `com.example.minisshd` is a placeholder
   that must be edited. The README instructs the operator to rename both
   the filename and the `<Label>` element to match (e.g.
   `com.alice.minisshd`). Risk: an operator who installs without editing
   gets a label collision with literally everyone else who installed
   without editing, which manifests as a confusing launchctl error. The
   README's "Before you install" section lists the label rename as one of
   the six required edits.

4. **`KeepAlive` semantics on macOS.** The chosen `KeepAlive = { SuccessfulExit
   = false }` means: restart unless the previous exit was clean (exit 0).
   minisshd exits 0 on SIGTERM (spec §8 step 5) and on a normal `make stop`
   path, but exits non-zero on bind failures, fs-permission failures, etc.
   This is the right policy — a transient bind failure (e.g. another process
   on :2222) should retry, and a clean stop should stay stopped. The risk is
   a config error that produces a fast exit-2 loop; launchd has internal
   throttling (10 s between restarts of an agent that exits within 10 s of
   launch), so the loop is bounded. The README "Logs → Detecting a respawn
   loop" section explains how to diagnose and stop this.

5. **`systemd-analyze --user verify` may emit non-fatal warnings.** The
   implementing pass should review any warnings and accept them silently if
   they are stylistic, or amend the unit if they are substantive. We do not
   need a clean-warnings gate.

6. **Spec drift risk.** The §12 reword is delicate: it must keep the
   non-goal in spirit ("the binary doesn't daemonize") while pointing at
   the new examples. The exact replacement wording is given in the "Spec
   amendments" section above and should be applied verbatim, not
   paraphrased.

7. **Out-of-scope items deferred to a later docs-only follow-up, if ever:**
   - A Keychain-wrapper script for macOS (eliminates plaintext password
     in the plist).
   - A `LoadCredential=` recipe for Linux (eliminates plaintext password
     in the service file).
   - A `--bind 0.0.0.0` variant of the unit files (rejected here; the
     loopback-by-default stance is intentional).
   - A pre-flight smoke test that `loginctl enable-linger` actually
     produced the desired persistence (operator-side, out of scope).

## Adversarial review responses (iter 1)

All issues from the adversarial review verdict are addressed. Dispositions:

**Inaccuracy 1 (WorkingDirectory rationale):** Agreed. The plan incorrectly
stated "let it default to the user's home so `~/.minisshd/` resolves correctly".
The actual mechanism is `os.UserHomeDir()`/`$HOME`, not CWD. The notes now say
"the key is irrelevant and omitting it avoids confusion."

**Inaccuracy 2 (`After=default.target` redundancy):** Agreed. Removed from the
systemd unit and added a note explaining why.

**C1 (auto-gen password rotation):** Agreed. Added a top-level framing block to
the README outline, added a note inside the plist and unit template themselves,
and added explicit language to the §12 spec amendment requiring `MINISSHD_PASS`.
Also added a warning that the literal placeholder string `REPLACE_ME_WITH_PASSWORD`
is itself a valid password the binary will accept.

**C2 (linger as primary decision):** Agreed. Rewrote the Linux "Linger" section
to frame it as a primary install-time decision: "workstation use" vs "headless
or server use", with clear guidance that headless operators must decide before
using the service.

**C3 (respawn-loop diagnostics):** Agreed. Added a "Detecting a respawn loop"
paragraph to the macOS Logs section, explaining how to detect via `launchctl
list`, how stderr config errors land in the same log file, and how to recover.

**C4 (§12 vs §9 contradiction):** Agreed. Updated the §12 replacement wording
to include a sentence explicitly requiring `MINISSHD_PASS` when using the
example units, with the §9 rationale.

**S1 (placeholder count + absolute path):** Agreed. The plist notes now list all
six placeholders explicitly. Added an XML comment in the plist body and a "Before
you install" line explaining that launchd does not expand `~` or `$HOME`.

**S2 (`chmod 600` framing):** Agreed. Reframed in both the "Before you install"
and "Hardening" sections as "file-system hygiene, not isolation" with explicit
caveats about malware, backups, and OS changes.

**S3 (macOS log rotation):** Agreed. Replaced the deferral with a minimal
`newsyslog.d` recipe in the macOS Logs section.

**S4 (`Documentation=` URL):** Agreed. Removed the line entirely from the
systemd unit template. It was specific to a single fork and would mislead
operators copying from other repositories.

**S5 (§10 amendment scope):** Agreed. Added "Operator note (outside the runtime
contract)." as a lead-in to make the scope explicit.

**S6 (systemd validation on macOS):** Agreed. Added the Docker alpine:edge
one-liner to Definition of done item 5, and required the PR description to state
which validation path was used.

**S7 (bind divergence placement):** Agreed. Moved the `--bind` divergence
callout to the "Before you install" section as a prominent bullet, in addition
to keeping it in the plist conventions notes.

**M1 (duplicate "uninstall" in deliverable):** Agreed. Fixed in the Summary
deliverables list.

**M2 ("v2" references):** Agreed. Replaced all three occurrences with "a later
docs-only follow-up".

**M3 ("are all no-ops" overconfidence):** Agreed. Changed to "should be verified
as no-ops" and added "must actually be run, not assumed" in Definition of done.

**M4 (plist XML comments and `defaults`):** Agreed. Added a footnote as an XML
comment in the plist body itself.

**M5 (`launchctl print` command):** Agreed. Added to the macOS Logs section.

**M6 (repo-root README pointer wording):** Agreed. Pinned the exact wording in
Definition of done item 3.

## Adversarial review responses (iter 2)

All issues from the iter-2 adversarial review are addressed. Dispositions:

**CRITICAL-1 (Docker alpine:edge does not ship systemd):** Agreed. The Docker
one-liner was removed entirely from Definition of done item 5. The honest
position is that there is no clean Docker-on-macOS validation path: Alpine uses
OpenRC (not systemd); Debian/Ubuntu-based containers can install systemd
packages but `systemd-analyze --user verify` requires a running systemd user
bus, which a bare container does not provide. Definition of done item 5 now
requires the implementing pass to run `systemd-analyze --user verify` on a real
Linux host or CI Linux runner, and states this requirement explicitly. The PR
description must confirm which path was used.

**CRITICAL-2 (no-linger diagnostics gap):** Agreed. The Linger subsection (now
placed before Install, per SIGNIFICANT-2) was extended with a concrete
diagnostic block: run `loginctl show-user $USER | grep Linger`, interpret
`Linger=no` as the cause of silent connection refusal after logout, and follow
up with `loginctl enable-linger $USER` plus a `systemctl --user start minisshd`
to recover. This gives an operator with no prior systemd knowledge a clear
path from "it stopped working after I disconnected" to resolution.

**SIGNIFICANT-1 (newsyslog.d path, sudo, placeholder):** Agreed. Changed the
drop-in path from `/usr/local/etc/newsyslog.d/` (Homebrew convention) to
`/etc/newsyslog.d/` (the actual macOS system include directory). Added an
explicit note that creating a file there requires `sudo`. Replaced `YOURHOME`
with `REPLACE_ME_WITH_HOME` throughout the newsyslog recipe for consistency
with the rest of the document.

**SIGNIFICANT-2 (Linger placement):** Agreed. Moved the entire Linger subsection
to appear before the Install subsection in the Linux README outline. The new
section heading is "Linger (running when not logged in) — decide BEFORE
installing" to make the sequencing requirement explicit. Operators following the
README top-to-bottom will now encounter the linger decision before the
`systemctl --user enable --now` command.

**SIGNIFICANT-3 (§12 spec amendment too long):** Agreed. Split the single
replacement bullet into two: the first bullet keeps the terse non-goal
("implemented in the binary" + "supervisor-naive" + "run in a terminal or under
your own process supervisor") and the second bullet is the forward pointer and
credential requirement. A scanner reading §12 will get the correct answer from
the first bullet without needing to parse the qualification out of a long sentence.

**MINOR-1 (REPLACE_ME_WITH_ABSOLUTE_PATH_TO/minisshd ambiguity):** Agreed.
Changed the placeholder to `REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY` — a single
full-path token — in both the plist `<ProgramArguments>` array, the systemd
`ExecStart=` line, the README "Before you install" list, and the plist notes.
Updated the placeholder-count note to explain that this is a single token
replacing the entire path string (not just a prefix), with an example.

**MINOR-2 (launchctl load -w / unload -w deprecated on Ventura):** Agreed.
Added a note in the macOS Install section that `load -w` / `unload -w` are
deprecated since macOS Ventura (13). The preferred modern equivalents —
`launchctl bootstrap gui/$(id -u) <plist>` and
`launchctl bootout gui/$(id -u) <plist>` — are listed as the Ventura+ form.
The classic `load -w` remains documented because it still works and users on
pre-Ventura macOS should not be broken. The Uninstall section was updated to
lead with `bootout`.

**MINOR-3 (`systemctl --user show minisshd` visibility):** Agreed. Added a note
in two places: (1) in the systemd unit "Notes for the implementing pass" block,
explaining that `Environment=` values are visible via `systemctl --user show
minisshd` and that `chmod 600` on the unit file does not prevent this; (2) in
the README outline's Hardening section, directing operators to `EnvironmentFile=`
or `LoadCredential=` if stronger isolation is needed.

## Adversarial review responses (iter 3)

**SIGNIFICANT-1 (newsyslog.d broken path):** Agreed. The recipe previously used
`/Users/REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log` and instructed operators
to substitute only the username segment — inconsistent with the established
`REPLACE_ME_WITH_HOME` definition ("your home directory as an absolute path").
An operator following the documented definition would have produced the doubly
prefixed broken path `/Users//Users/alice/Library/Logs/minisshd.log`. Fixed by
dropping the hardcoded `/Users/` prefix and using
`REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log` throughout, with updated prose
directing operators to substitute the full absolute home path (e.g. `/Users/alice`).
This also makes the recipe work correctly for Linux home directory layouts
(e.g. `/home/alice`) where the `/Users/` prefix would be wrong regardless.
