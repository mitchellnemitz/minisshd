// Package main is the minisshd binary entry point. It implements the §2
// startup sequence — flag parsing, port/shell/bind validation, host key
// load, listener bind, password-banner emission (only after a successful
// bind), structured `listening` event, and SIGINT/SIGTERM-driven graceful
// shutdown — and wires the result to the internal/server accept loop.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/hostkey"
	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/mitchellnemitz/minisshd/internal/ratelimit"
	"github.com/mitchellnemitz/minisshd/internal/server"
	"github.com/mitchellnemitz/minisshd/internal/session"
)

// Exit codes per spec §11.
const (
	exitOK            = 0
	exitInternalError = 1
	exitBadConfig     = 2
	exitBindFailure   = 3
	exitFSFailure     = 4
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the binary's main flow against the given args and io
// streams, returning the process exit code. Tests drive it directly with
// a controllable context and captured stdout/stderr.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("minisshd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		port               = fs.Int("port", 2222, "TCP port to listen on")
		bind               = fs.String("bind", "0.0.0.0", "IP address to bind to")
		passFlag           = fs.String("pass", "", "Password clients must present (overrides MINISSHD_PASS)")
		userFlag           = fs.String("user", "", "Username clients must present (overrides MINISSHD_USER)")
		shellFlag          = fs.String("shell", "", "Shell binary for interactive sessions")
		hostKey            = fs.String("host-key", "", "Path to the persistent host key (default ~/.minisshd/host_key)")
		logFormatFlag      = fs.String("log-format", "", "Structured-log format: logfmt (default) or json")
		authFlag           = fs.String("auth", "", "Comma-separated SSH auth methods: password, publickey (overrides MINISSHD_AUTH)")
		authorizedKeysFlag = fs.String("authorized-keys", "", "Path to authorized-keys file (overrides MINISSHD_AUTHORIZED_KEYS)")
	)
	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already printed the usage to stderr.
		return exitBadConfig
	}

	// Distinguish "flag explicitly set" from "default" so an explicit
	// --pass="" can be rejected per spec §2 step 2. flag.Visit only
	// iterates flags that the user supplied.
	var passSet, userSet, hostKeySet, logFormatSet, authSet, authorizedKeysSet bool
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
		case "auth":
			authSet = true
		case "authorized-keys":
			authorizedKeysSet = true
		}
	})

	// §2 step 1 — port range.
	if *port < 0 || *port > 65535 {
		fmt.Fprintf(stderr, "minisshd: --port %d out of range [0, 65535]\n", *port)
		return exitBadConfig
	}

	// §2 step 2 — password.
	envPass, envPassSet := os.LookupEnv("MINISSHD_PASS")
	password, err := auth.ResolvePasswordStrict(*passFlag, passSet, envPass, envPassSet)
	if err != nil {
		fmt.Fprintf(stderr, "minisshd: %v\n", err)
		return exitBadConfig
	}

	// §2 step 2b — resolve auth methods.
	envAuth, envAuthSet := os.LookupEnv("MINISSHD_AUTH")
	methods, err := auth.ResolveMethods(*authFlag, authSet, envAuth, envAuthSet)
	if err != nil {
		fmt.Fprintf(stderr, "minisshd: %v\n", err)
		return exitBadConfig
	}

	// §2 step 3 — username.
	envUser := os.Getenv("MINISSHD_USER")
	osUser := ""
	if u, err := user.Current(); err == nil {
		osUser = u.Username
	} else if v := os.Getenv("USER"); v != "" {
		osUser = v
	}
	username, err := auth.ResolveUsername(*userFlag, envUser, osUser)
	if err != nil {
		fmt.Fprintf(stderr, "minisshd: %v\n", err)
		return exitBadConfig
	}
	_ = userSet // accepted-but-unused; presence is implied by username != ""

	// §2 step 3a — log format.
	envFmt, envFmtSet := os.LookupEnv("MINISSHD_LOG_FORMAT")
	logFormat, err := logging.ParseFormat(*logFormatFlag, logFormatSet, envFmt, envFmtSet)
	if err != nil {
		fmt.Fprintf(stderr, "minisshd: %v\n", err)
		return exitBadConfig
	}

	// §2 step 4 — shell.
	shellPath := *shellFlag
	if shellPath == "" {
		shellPath = os.Getenv("SHELL")
		if shellPath == "" {
			shellPath = "/bin/zsh"
		}
	}
	if err := validateShell(shellPath); err != nil {
		fmt.Fprintf(stderr, "minisshd: %v\n", err)
		return exitBadConfig
	}

	// §2 step 5 — ensure ~/.minisshd/ exists with mode 0700 (only on the
	// default --host-key path; per §6 the binary never auto-creates a
	// caller-supplied --host-key parent).
	if !hostKeySet {
		hd, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "minisshd: cannot resolve home directory: %v\n", err)
			return exitFSFailure
		}
		*hostKey = filepath.Join(hd, ".minisshd", "host_key")
		if err := ensureMinisshdDir(filepath.Dir(*hostKey)); err != nil {
			fmt.Fprintf(stderr, "minisshd: %v\n", err)
			return exitFSFailure
		}
	}

	// §2 step 5b — resolve the authorized-keys path now (validation only;
	// the actual Load happens after the real logger is built so all key-load
	// warning events flow through a logger that already has the password scrub
	// configured). This is the single-load design: no tmpLogger, no re-load.
	// Per §9 / CLAUDE.md: the password-scrub invariant must hold for every
	// emitted line, including pubkey-* events. A tmpLogger with an empty-string
	// scrub would emit those events without redaction.
	var keysPath string
	if methods.Contains(auth.MethodPublickey) {
		envKeys, envKeysSet := os.LookupEnv("MINISSHD_AUTHORIZED_KEYS")
		keysPath, err = auth.ResolveAuthorizedKeysPath(*authorizedKeysFlag, authorizedKeysSet, envKeys, envKeysSet)
		if err != nil {
			fmt.Fprintf(stderr, "minisshd: %v\n", err)
			return exitBadConfig
		}
	}

	// §2 step 6 — host key.
	signer, fingerprint, err := hostkey.LoadOrGenerate(*hostKey)
	if err != nil {
		switch {
		case errors.Is(err, hostkey.ErrKeyPermissionsTooOpen):
			fmt.Fprintf(stderr, "minisshd: host key %q has too-open permissions; run: chmod 600 %q\n", *hostKey, *hostKey)
		case errors.Is(err, hostkey.ErrKeyCorrupt):
			fmt.Fprintf(stderr, "minisshd: host key %q is corrupt; delete it to regenerate (this changes the host fingerprint)\n", *hostKey)
		case errors.Is(err, hostkey.ErrParentMissing):
			fmt.Fprintf(stderr, "minisshd: %v\n", err)
		default:
			fmt.Fprintf(stderr, "minisshd: %v\n", err)
		}
		return exitFSFailure
	}

	// §2 step 7 — parse --bind and bind the listener.
	bindIP := net.ParseIP(*bind)
	if bindIP == nil {
		fmt.Fprintf(stderr, "minisshd: --bind %q is not a valid IP literal\n", *bind)
		return exitBadConfig
	}
	addr := net.JoinHostPort(bindIP.String(), strconv.Itoa(*port))
	listener, err := listen(ctx, addr)
	if err != nil {
		switch {
		case errors.Is(err, syscall.EADDRINUSE):
			fmt.Fprintf(stderr, "minisshd: address %s already in use\n", addr)
		case errors.Is(err, syscall.EADDRNOTAVAIL):
			fmt.Fprintf(stderr, "minisshd: bind address %s is not assigned to any local interface\n", bindIP)
		default:
			fmt.Fprintf(stderr, "minisshd: bind %s: %v\n", addr, err)
		}
		return exitBindFailure
	}
	defer listener.Close()

	// §2 step 8 — generate password (if necessary) and emit the banner.
	// Only when --auth includes "password" and no password was supplied.
	// In publickey-only mode, no password is generated and no banner is printed.
	generatePasswordAtStartup := password == "" && methods.Contains(auth.MethodPassword)
	if generatePasswordAtStartup {
		password, err = auth.GeneratePassword()
		if err != nil {
			fmt.Fprintf(stderr, "minisshd: generate password: %v\n", err)
			return exitInternalError
		}
		fmt.Fprintf(stdout, "Password: %s\n", password)
	} else if !methods.Contains(auth.MethodPassword) && password == "" {
		// Publickey-only mode with no password supplied: use a random sentinel
		// so the password-callback path (even if somehow invoked) cannot succeed,
		// and the password scrub has a non-empty needle.
		sentinel := make([]byte, 32)
		if _, err := rand.Read(sentinel); err != nil {
			fmt.Fprintf(stderr, "minisshd: generate sentinel: %v\n", err)
			return exitInternalError
		}
		password = hex.EncodeToString(sentinel)
	}

	// Build the cached credential digests and the logger with the active
	// password-scrub guard. Both must be ready before the first connection
	// is accepted (§4).
	creds := auth.NewCredentials(username, password)
	logger := logging.New(stdout, password, logFormat)

	// §2 step 5b continued — single-load of the authorized-keys file, now
	// that the real logger (with password scrub) is available. This is the
	// only Load call; the tmpLogger/double-load pattern has been removed to
	// preserve the §9 scrub invariant for all pubkey-* events.
	var keysetSource *auth.KeysetSource
	if methods.Contains(auth.MethodPublickey) {
		keysetSource = auth.NewKeysetSource(keysPath, logger)
		if loadErr := keysetSource.Load(); loadErr != nil {
			fmt.Fprintf(stderr, "minisshd: authorized-keys %q: %v\n", keysPath, loadErr)
			return exitFSFailure
		}
		// §2 step 2c check — unauthenticable configuration (moved here so it
		// follows the single load; exit code 2 is correct per spec §11).
		if !methods.Contains(auth.MethodPassword) && keysetSource.Count() == 0 {
			fmt.Fprintf(stderr, "minisshd: --auth=publickey but no keys loaded; provide an authorized-keys file or add 'password' to --auth\n")
			return exitBadConfig
		}
	}

	// §2 step 9 — log the listening event with the actually-bound port.
	boundPort := listener.Addr().(*net.TCPAddr).Port
	pubkeyCount := 0
	if keysetSource != nil {
		pubkeyCount = keysetSource.Count()
	}
	logger.Listening(bindIP.String(), boundPort, fingerprint, username, os.Getpid(), methods.String(), pubkeyCount)

	// SIGHUP handler for authorized-keys reload (only when publickey is configured).
	if methods.Contains(auth.MethodPublickey) && keysetSource != nil {
		sighupCh := make(chan os.Signal, 1)
		signal.Notify(sighupCh, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-sighupCh:
					_ = keysetSource.Reload()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Construct the server and run its accept loop against ctx.
	srv := server.New(server.Config{
		Listener:       listener,
		HostKey:        signer,
		Credentials:    creds,
		Limiter:        ratelimit.New(ratelimit.RealClock{}),
		SessionService: &session.Service{Shell: shellPath, Log: logger},
		Log:            logger,
		Methods:        methods,
		KeysetSource:   keysetSource,
	})
	if err := srv.Serve(ctx); err != nil {
		logger.Error(err.Error(), "")
		return exitInternalError
	}
	return exitOK
}

// validateShell performs the §2 step 4 checks: resolve symlinks, then
// require the target to be a regular file that is executable by the
// current user. Any failure returns an error that names the resolved
// path so the operator can see what was actually checked.
func validateShell(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Distinguish "doesn't exist" from "broken symlink" only via the
		// message; both exit with code 2.
		return fmt.Errorf("--shell %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("--shell %q (resolved to %q): %w", path, resolved, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("--shell %q (resolved to %q) is not a regular file", path, resolved)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("--shell %q (resolved to %q) is not executable", path, resolved)
	}
	return nil
}

// ensureMinisshdDir implements §2 step 5: create the directory at mode
// 0700 if missing, or verify the existing directory is no wider than
// 0700 (otherwise §11 says exit 4 with a chmod 700 instruction).
func ensureMinisshdDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create %q: %w", path, err)
		}
		// MkdirAll may use the umask; ensure mode is exactly 0700.
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("chmod %q: %w", path, err)
		}
		return nil
	}
	if !info.IsDir() {
		return fmt.Errorf("%q exists but is not a directory", path)
	}
	if info.Mode().Perm()&^0o700 != 0 {
		return fmt.Errorf("directory %q has too-open permissions (mode %#o); run: chmod 700 %q",
			path, info.Mode().Perm(), path)
	}
	return nil
}

// listen binds a TCP listener at addr. For an IPv6 unspecified bind
// (`::`) we explicitly set IPV6_V6ONLY=0 so the socket accepts both
// IPv6 and IPv4-mapped clients (§3). The setsockopt is best-effort —
// it returns EINVAL on AF_INET sockets and we ignore that.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
			})
		},
	}
	return lc.Listen(ctx, "tcp", addr)
}
