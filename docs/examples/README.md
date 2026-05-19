# minisshd service-unit examples

These are copy/paste-ready templates for running `minisshd` under your OS's native per-user
process supervisor: launchd on macOS, `systemd --user` on Linux. The binary itself is
unchanged — it is supervisor-naive by design (spec §12). These templates represent the
"run under your own process supervisor" path that §12 points at.

> **IMPORTANT: Auto-generated passwords (when `MINISSHD_PASS` is not set) are NOT suitable
> for supervised installs.** Under a supervisor that captures stdout to a file, each restart
> generates a new password that gets written into the log. Set `MINISSHD_PASS` before using
> these templates.

## Before you install

These templates contain placeholders. You **MUST** edit ALL of them before installing. The
binary accepts any non-empty string as a password — it will not warn you if you forget to
replace `REPLACE_ME_WITH_PASSWORD`.

**Every placeholder you must substitute:**

1. `REPLACE_ME_WITH_ABSOLUTE_PATH_TO_BINARY` — the full absolute path to the binary
   (e.g. `/usr/local/bin/minisshd` or `/home/alice/.local/bin/minisshd`). This is a single
   token that replaces the entire path string — substitute the complete path, not just a
   directory prefix.
2. `REPLACE_ME_WITH_PASSWORD` — the password clients will use to authenticate.
3. `REPLACE_ME_WITH_USERNAME` — your OS login username.
4. `REPLACE_ME_WITH_HOME` (in `StandardOutPath`) — your home directory as an absolute path
   (e.g. `/Users/alice` on macOS). launchd does **NOT** expand `~` or `$HOME` in plist
   path strings; you must use a literal absolute path.
5. `REPLACE_ME_WITH_HOME` (in `StandardErrorPath`) — same as above.
6. `com.example.minisshd` (the `<Label>` value and the filename) — rename to
   `com.<you>.minisshd` so the label matches the filename and does not collide with other
   installs.

> **IMPORTANT: The template defaults to `--bind 127.0.0.1` (loopback only).** The binary's
> own default when run without a flag is `0.0.0.0` (all interfaces). If you need LAN or
> remote access, change `127.0.0.1` to `0.0.0.0` or a specific interface address in the
> template before installing.

> **WARNING: Your password is stored in plaintext in the unit file.**
>
> 1. The plist / service file contains your password in plaintext.
> 2. The file is owned by your user and lives under `~/Library/LaunchAgents` or
>    `~/.config/systemd/user`, both of which default to mode `0644` — readable by any process
>    running as you. Set the file to mode `0600` after editing. This is file-system hygiene,
>    not isolation: it does not protect against malware running as you, backup tools, or future
>    OS permission changes.
> 3. Alternatives (Keychain on macOS, systemd `LoadCredential=` on Linux, `EnvironmentFile=`
>    with `0600`) are listed below under "Hardening".

## macOS (launchd)

### Install

```sh
cp docs/examples/com.example.minisshd.plist ~/Library/LaunchAgents/com.<you>.minisshd.plist
```

- Rename the `<Label>` inside the file to match the filename.
- Edit all six `REPLACE_ME` values (see "Before you install" above).
- Set restrictive permissions:

```sh
chmod 600 ~/Library/LaunchAgents/com.<you>.minisshd.plist
```

- Load the agent. `launchctl load -w` (classic syntax) works on all macOS versions.
  **Note:** `load -w` / `unload -w` are deprecated since macOS Ventura (13). On Ventura and
  later the preferred syntax is:

  ```sh
  # Load (Ventura+):
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist

  # Unload (Ventura+):
  launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist
  ```

  Either form works on Ventura+, but new installs should prefer `bootstrap`/`bootout`.

- Verify: `launchctl list | grep minisshd` shows the label and a PID.

### Uninstall

```sh
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.<you>.minisshd.plist
# (Or: launchctl unload -w ... on pre-Ventura macOS)
rm ~/Library/LaunchAgents/com.<you>.minisshd.plist
```

### Logs

- `~/Library/Logs/minisshd.log` — the §9 stdout stream plus stderr (config errors, etc.).
- Tail with `tail -f ~/Library/Logs/minisshd.log`.
- launchd's own error stream is in `~/Library/Logs/com.<you>.minisshd*` if the agent fails
  to start at all (rare; usually a typo in the plist).
- For full loaded state including next respawn time:

  ```sh
  launchctl print gui/$(id -u)/com.<you>.minisshd
  ```

- **Detecting a respawn loop:** run `launchctl list | grep minisshd` twice a few seconds
  apart. If the PID changes each time, the agent is crash-looping. Check
  `~/Library/Logs/minisshd.log` for the exit-2/3/4 error message — config errors (bad bind,
  permission failure, etc.) write to stderr which goes to the same log file. Fix the config
  issue, then `launchctl unload -w` and `launchctl load -w` to restart cleanly.

### Log rotation (macOS)

The `StandardOutPath` log grows without bound. To cap its size with the system's built-in
newsyslog, create a drop-in config at `/etc/newsyslog.d/minisshd.conf` (the macOS system
include directory; creating a file there requires `sudo`):

```
# logfile                                       mode  count  size  when  flags
REPLACE_ME_WITH_HOME/Library/Logs/minisshd.log  644   7     1000  *     J
```

Replace `REPLACE_ME_WITH_HOME` with your home directory as an absolute path (e.g.
`/Users/alice` on macOS), consistent with the definition in "Before you install" above.
This retains 7 compressed rotations and rotates at 1000 KB. Run `sudo newsyslog -nvv` to
verify the config is picked up before relying on it.

## Linux (systemd --user)

### Linger (running when not logged in) — decide BEFORE installing

By default a systemd `--user` instance is **destroyed when you log out**. This means
minisshd stops the moment your session ends.

**Workstation use:** This is usually fine. The server is reachable when you are logged in
and stops when you are not.

**Headless or server use:** Enable lingering so the user manager (and minisshd) survive
across logout/reboot. Decide this *before* running `enable --now` below:

- `loginctl enable-linger $USER` — keeps the user manager alive at all times.
- `loginctl disable-linger $USER` — reverts to "dies on logout" behavior.

**Diagnosing a silent stop after logout:** If minisshd appears to work while logged in but
becomes unreachable after you disconnect, the user manager almost certainly exited when your
session ended. To confirm:

```sh
loginctl show-user $USER | grep Linger
```

`Linger=no` means the user manager exits on logout and takes minisshd with it. Run
`loginctl enable-linger $USER` and then `systemctl --user start minisshd` (or simply log
back in and verify `systemctl --user status minisshd` shows `active`). Connection refusal
after logout with `Linger=no` is the most common headless-host setup error for systemd
`--user` services.

### Install

```sh
mkdir -p ~/.config/systemd/user
cp docs/examples/minisshd.service ~/.config/systemd/user/minisshd.service
```

- Edit the `REPLACE_ME` values (binary path, password, username).

```sh
chmod 600 ~/.config/systemd/user/minisshd.service
systemctl --user daemon-reload
systemctl --user enable --now minisshd.service
```

- Verify: `systemctl --user status minisshd.service` shows `active (running)`.

### Uninstall

```sh
systemctl --user disable --now minisshd.service
rm ~/.config/systemd/user/minisshd.service
systemctl --user daemon-reload
```

### Logs

- `journalctl --user -u minisshd.service -f` — live tail.
- `journalctl --user -u minisshd.service --since today` — historical.
- journald handles log rotation automatically.

## Hardening (both OSes)

The password is in the unit file. Decide whether that's acceptable for your threat model.

**`chmod 600` on the unit file is file-system hygiene, not isolation.** It prevents casual
reads by other local users but does not protect against malware running as you, backup
tools, or future OS default changes.

**Linux note:** `Environment=` values in a systemd unit are also visible via
`systemctl --user show minisshd` (they appear in the `Environment=` field of the service
introspection output). `chmod 600` on the unit file does **NOT** prevent a process running
as the same user from reading the password through this interface. For stronger isolation,
use `EnvironmentFile=` (a `0600` file) or `LoadCredential=` instead of inline
`Environment=` lines.

**macOS alternatives:**

- Store the password in the user keychain (`security add-generic-password -a $USER -s minisshd -w '<password>'`)
  and have a tiny wrapper script that retrieves it and execs `minisshd` with `MINISSHD_PASS`
  set. The plist invokes the wrapper instead of the binary. (Deferred to a later docs-only
  follow-up; not in this example.)

**Linux alternatives:**

- `LoadCredential=` (systemd 250+) — store the password in a `0600` file and reference it
  from the unit; the secret is exposed to the service via
  `${CREDENTIALS_DIRECTORY}/minisshd-pass`, but minisshd reads only `MINISSHD_PASS`, so a
  wrapper would still be needed. (Deferred to a later docs-only follow-up.)
- `EnvironmentFile=/path/to/file` with the file at mode `0600` owned by the user. This is
  the lightest hardening step and is recommended; the example unit can be edited to point
  at one.

Both OSes: set the unit file itself to `chmod 600`. This is the baseline hardening posture
documented in this README.

## What these examples deliberately do NOT do

- They do not run minisshd as root, and they do not change the user it runs as. minisshd is
  single-user by design (spec §12).
- They do not bind to `0.0.0.0` by default. The templates default to `--bind 127.0.0.1`.
  The binary's default when invoked without a flag is `0.0.0.0`. See "Before you install"
  for when to change this.
- They do not write a PID file. minisshd does not produce one; both launchd and systemd
  track the PID themselves.
