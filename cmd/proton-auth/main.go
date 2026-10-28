// Command proton-auth is a thin CLI over the protonauth library. It performs
// Proton SRP authentication, solving a CAPTCHA in the browser when Proton
// demands one, and emits the resulting tokens as JSON for non-Go consumers.
//
// JSON contract: on success an object with accessToken, refreshToken, uid,
// userID, keyPassword, expiresAt and passwordMode is written to stdout, or to
// the file given by -o. On failure an object with error (human-readable) and
// errorCode (one of the protonauth ErrCode values, or 1000 when interactive
// credentials could not be read) is written to stdout; a -o file is never
// touched by a failure, so a result saved there by an earlier run survives a
// failed re-login. The process exits 1 on any failure.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	protonauth "github.com/Arsylk/proton-auth"
	"github.com/Arsylk/proton-auth/internal/captcha"
	"github.com/Arsylk/proton-auth/internal/proxy"
	"golang.org/x/term"
)

// version is set by the release build (-ldflags "-X main.version=..."). A
// plain go build or go install reports the module version from build info.
var version = "dev"

// errCodeCredentials is the CLI-only error code for failing to read the
// credentials. The library's codes start at 1001.
const errCodeCredentials = 1000

// authResult is the JSON output. Field names are the stable contract relied on
// by downstream consumers; do not rename them.
type authResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	UID          string `json:"uid"`
	UserID       string `json:"userID"`
	KeyPassword  string `json:"keyPassword"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	PasswordMode int    `json:"passwordMode,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorCode    int    `json:"errorCode,omitempty"`
}

func main() {
	os.Exit(run())
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "Usage: proton-auth [flags]\n\n")
	fmt.Fprintf(w, "Authenticates against Proton (SRP, 2FA, browser-assisted CAPTCHA) and prints\n")
	fmt.Fprintf(w, "the session tokens as JSON on stdout. With no credentials given it prompts on\n")
	fmt.Fprintf(w, "stderr for the username, the password and, if the account needs them, the 2FA\n")
	fmt.Fprintf(w, "code and the mailbox password. Once both the username and the password are\n")
	fmt.Fprintf(w, "supplied (flags or PROTON_AUTH_* environment variables; flags win) nothing is\n")
	fmt.Fprintf(w, "prompted for, and a missing 2FA code or mailbox password is an error.\n\n")
	fmt.Fprintf(w, "Flags:\n")
	flag.PrintDefaults()
}

func run() int {
	outputPath := flag.String("o", "",
		"write the JSON result to this file (mode 0600) instead of stdout; a failure leaves the file untouched")
	username := flag.String("username", "", "Proton username or email (env PROTON_AUTH_USERNAME); prompted for if empty")
	password := flag.String("password", "",
		"Proton password (env PROTON_AUTH_PASSWORD); prompted for if empty. "+
			"Visible to other local users in the process list: prefer the env variable or -password-stdin")
	passwordStdin := flag.Bool("password-stdin", false,
		"read the password from the first line of stdin; requires -username or PROTON_AUTH_USERNAME and disables prompting")
	totpCode := flag.String("totp", "", "current TOTP code for 2FA (env PROTON_AUTH_TOTP)")
	totpSecret := flag.String("totp-secret", "", "base32 TOTP secret to generate 2FA codes from (env PROTON_AUTH_TOTP_SECRET)")
	mailboxPassword := flag.String("mailbox-password", "",
		"second (mailbox) password for a two-password-mode account (env PROTON_AUTH_MAILBOX_PASSWORD)")
	appVersion := flag.String("app-version", protonauth.DefaultAppVersion, "X-Pm-Appversion header value")
	userAgent := flag.String("user-agent", protonauth.DefaultUserAgent, "User-Agent header value")
	hostURL := flag.String("host-url", "", "Proton API base URL; leave empty for production (for tests against a fake server)")
	proxyURL := flag.String("proxy", "",
		"route the login and the CAPTCHA solve through this proxy (http://user:pass@host:port or socks5://host:port) "+
			"so they share one IP")
	captchaAutoOpen := flag.Bool("captcha-auto-open", true, "open the browser automatically when a CAPTCHA is required")
	captchaTimeout := flag.Duration("captcha-timeout", protonauth.DefaultCaptchaTimeout, "how long to wait for a CAPTCHA to be solved")
	requestTimeout := flag.Duration("request-timeout", protonauth.DefaultRequestTimeout,
		"how long each request to Proton may wait for its response headers before it counts as unreachable")
	captchaTest := flag.Bool("captcha-test", false,
		"open Proton's CAPTCHA widget without logging in, to check the local server and browser wiring, then exit")
	fallbackExpiryHours := flag.Int("expiry-fallback-hours", 12,
		"expiresAt margin in hours from now, used only when Proton does not report a token lifetime")
	skipKeyPassword := flag.Bool("skip-key-password", false,
		"stop after authentication and 2FA without deriving the key password (keyPassword is empty); "+
			"how Proton's VPN clients log in, needed with a VPN client -app-version")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("proton-auth " + buildVersion())
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal cancels ctx, which every prompt and wait below
	// observes. Releasing the handler then lets a second signal end the
	// process the usual way should the cleanup itself hang.
	go func() {
		<-ctx.Done()
		stop()
	}()

	if *captchaTest {
		return runCaptchaTest(ctx, os.Stderr, protonauth.CaptchaOptions{
			AutoOpen:       *captchaAutoOpen,
			ProxyURL:       *proxyURL,
			Timeout:        *captchaTimeout,
			RequestTimeout: *requestTimeout,
		})
	}

	emit := func(r authResult) int {
		if r.Error != "" {
			// A failure never touches the -o file: a result saved there by an
			// earlier run must not be replaced by an error object. The error
			// goes to stdout as JSON and, when the result was headed for a
			// file, to stderr as text as well so that it is seen.
			if err := writeResult(os.Stdout, "", r); err != nil {
				fmt.Fprintf(os.Stderr, "proton-auth: %v\n", err)
			}
			if *outputPath != "" {
				fmt.Fprintf(os.Stderr, "proton-auth: %s (%s left untouched)\n", r.Error, *outputPath)
			}
			return 1
		}
		if err := writeResult(os.Stdout, *outputPath, r); err != nil {
			fmt.Fprintf(os.Stderr, "proton-auth: %v\n", err)
			return 1
		}
		if *outputPath != "" {
			fmt.Fprintf(os.Stderr, "Auth tokens written to %s\n", *outputPath)
		}
		return 0
	}

	fd := int(os.Stdin.Fd())
	p := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stderr, fd: fd, terminal: term.IsTerminal(fd)}
	user, pass, interactive, err := resolveCredentials(ctx, p,
		firstNonEmpty(*username, os.Getenv("PROTON_AUTH_USERNAME")),
		firstNonEmptyExact(*password, os.Getenv("PROTON_AUTH_PASSWORD")),
		*passwordStdin)
	if err != nil {
		return emit(authResult{Error: err.Error(), ErrorCode: errCodeCredentials})
	}

	creds := protonauth.Credentials{
		Username:        user,
		Password:        pass,
		TOTPCode:        firstNonEmpty(*totpCode, os.Getenv("PROTON_AUTH_TOTP")),
		TOTPSecret:      firstNonEmpty(*totpSecret, os.Getenv("PROTON_AUTH_TOTP_SECRET")),
		MailboxPassword: firstNonEmptyExact(*mailboxPassword, os.Getenv("PROTON_AUTH_MAILBOX_PASSWORD")),
	}
	// In interactive mode, let the library ask us for a 2FA code and (for
	// two-password accounts) the mailbox password when it needs them. In
	// non-interactive mode leave these nil so Login fails with guidance.
	if interactive {
		creds.TOTPProvider = func(ctx context.Context) (string, error) {
			code, err := p.line(ctx, "2FA TOTP code: ")
			if err != nil {
				return "", fmt.Errorf("failed to read TOTP code: %w", err)
			}
			return strings.TrimSpace(code), nil
		}
		creds.MailboxPasswordProvider = func(ctx context.Context) (string, error) {
			mbox, err := p.secret(ctx, "Mailbox password (second password): ")
			if err != nil {
				return "", fmt.Errorf("failed to read mailbox password: %w", err)
			}
			return mbox, nil
		}
	}

	opts := protonauth.Options{
		AppVersion:      *appVersion,
		UserAgent:       *userAgent,
		HostURL:         *hostURL,
		ProxyURL:        *proxyURL,
		CaptchaAutoOpen: *captchaAutoOpen,
		CaptchaTimeout:  *captchaTimeout,
		RequestTimeout:  *requestTimeout,
		SkipKeyPassword: *skipKeyPassword,
		Output:          os.Stderr, // CAPTCHA instructions go to stderr; stdout is the JSON
	}

	result, err := protonauth.Login(ctx, opts, creds)
	if err != nil {
		return emit(errorResult(err))
	}

	return emit(authResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UID:          result.UID,
		UserID:       result.UserID,
		KeyPassword:  result.KeyPassword,
		ExpiresAt:    expiresAt(result.ExpiresIn, *fallbackExpiryHours),
		PasswordMode: int(result.PasswordMode),
	})
}

// buildVersion reports the release version, or the module version recorded by
// go install, or "dev".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

// expiresAt turns Proton's token lifetime into an absolute RFC3339 timestamp.
// Proton's real ExpiresIn (seconds) is used when present; otherwise it falls
// back to a conservative client-side margin. This margin is a CLI policy, not a
// library one: the protonauth library reports only Proton's raw value.
func expiresAt(expiresInSeconds, fallbackHours int) string {
	d := time.Duration(expiresInSeconds) * time.Second
	if expiresInSeconds <= 0 {
		d = time.Duration(fallbackHours) * time.Hour
	}
	return time.Now().Add(d).UTC().Format(time.RFC3339)
}

// prompter reads interactive input. Secrets are read without echo when stdin
// is a terminal; otherwise (a pipe or a file) they are read as a plain line so
// scripted use still works. Every read gives up when its ctx ends, so Ctrl-C
// works at a prompt and not only during the CAPTCHA wait.
type prompter struct {
	in       *bufio.Reader
	out      io.Writer
	fd       int
	terminal bool
	// abandoned is set once a read was given up on because its ctx ended.
	// That read is still blocked on stdin, so no further read may start: two
	// readers on one stream would race for the input.
	abandoned bool
}

// errPromptAbandoned is returned by every read after one was cancelled.
var errPromptAbandoned = errors.New("input abandoned after cancellation")

// line prints prompt and reads one line, without its line ending, or returns
// ctx.Err() if ctx ends first.
func (p *prompter) line(ctx context.Context, prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	return p.await(ctx, func() (string, error) { return readLine(p.in) }, nil)
}

// secret prints prompt and reads one line without echo when possible. The
// value is byte-exact: passwords may begin or end with whitespace. If ctx ends
// first the terminal's echo is restored and ctx.Err() returned.
func (p *prompter) secret(ctx context.Context, prompt string) (string, error) {
	if !p.terminal {
		return p.line(ctx, prompt)
	}
	fmt.Fprint(p.out, prompt)
	state, err := term.GetState(p.fd)
	if err != nil {
		return "", err
	}
	s, err := p.await(ctx, func() (string, error) {
		b, err := term.ReadPassword(p.fd)
		return string(b), err
	}, func() { _ = term.Restore(p.fd, state) })
	fmt.Fprintln(p.out)
	return s, err
}

// await runs read on its own goroutine and returns its result, unless ctx ends
// first: then abort runs (if given) and ctx.Err() is returned. The abandoned
// read stays blocked on stdin, which is fine for a process about to exit, and
// the prompter refuses every later read so nothing competes with it.
func (p *prompter) await(ctx context.Context, read func() (string, error), abort func()) (string, error) {
	if p.abandoned {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errPromptAbandoned
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := read()
		ch <- result{s, err}
	}()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-ctx.Done():
		p.abandoned = true
		if abort != nil {
			abort()
		}
		return "", ctx.Err()
	}
}

// readLine returns the next line without its line ending. A final line with
// no trailing newline is still returned; only an exhausted stream is an error.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// resolveCredentials returns the username and password to use, prompting for
// whatever was not supplied, or, with passwordStdin, reading the password from
// the first line of stdin without prompting. interactive reports whether a
// prompt ran, which decides whether a missing 2FA code or mailbox password is
// prompted for or treated as fatal.
func resolveCredentials(ctx context.Context, p *prompter, suppliedUser, suppliedPass string, passwordStdin bool) (user, pass string, interactive bool, err error) {
	user, pass = suppliedUser, suppliedPass

	if passwordStdin {
		if user == "" {
			return "", "", false, errors.New("-password-stdin requires -username or PROTON_AUTH_USERNAME")
		}
		pass, err = p.await(ctx, func() (string, error) { return readLine(p.in) }, nil)
		if err != nil {
			return "", "", false, fmt.Errorf("failed to read password from stdin: %w", err)
		}
		if pass == "" {
			return "", "", false, errors.New("empty password on stdin")
		}
		return user, pass, false, nil
	}

	if user != "" && pass != "" {
		return user, pass, false, nil
	}
	if user == "" {
		line, err := p.line(ctx, "Proton username (email): ")
		if err != nil {
			return "", "", true, fmt.Errorf("failed to read username: %w", err)
		}
		user = strings.TrimSpace(line)
		if user == "" {
			return "", "", true, errors.New("empty username")
		}
	}
	if pass == "" {
		pass, err = p.secret(ctx, "Password: ")
		if err != nil {
			return "", "", true, fmt.Errorf("failed to read password: %w", err)
		}
		if pass == "" {
			return "", "", true, errors.New("empty password")
		}
	}
	return user, pass, true, nil
}

// runCaptchaTest opens Proton's self-initialising CAPTCHA app without logging
// in, so the local server, browser launch and postMessage wiring can be checked
// on demand. The token it yields cannot authenticate a login.
func runCaptchaTest(ctx context.Context, out io.Writer, opts protonauth.CaptchaOptions) int {
	requestTimeout := opts.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = protonauth.DefaultRequestTimeout
	}
	transport, err := proxy.Transport(opts.ProxyURL, requestTimeout)
	if err != nil {
		fmt.Fprintf(out, "proton-auth: %v\n", err)
		return 1
	}
	defer transport.CloseIdleConnections()
	token, err := captcha.Solve(ctx, captcha.OnDemandTarget(), captcha.Options{
		Transport: transport,
		AutoOpen:  opts.AutoOpen,
		Timeout:   opts.Timeout,
		Output:    out,
	})
	if err != nil {
		fmt.Fprintf(out, "captcha test ended: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Received captcha token: %s\n", token)
	return 0
}

// errorResult maps a protonauth error onto the JSON contract, preserving the
// typed error code when present.
func errorResult(err error) authResult {
	if authErr, ok := errors.AsType[*protonauth.AuthError](err); ok {
		return authResult{Error: authErr.Message, ErrorCode: int(authErr.Code)}
	}
	return authResult{Error: err.Error(), ErrorCode: int(protonauth.ErrCodeLogin)}
}

// writeResult writes the JSON result to stdout, or to path with mode 0600
// when it is set. A failure to write is returned so the caller can exit
// non-zero rather than silently losing the tokens.
func writeResult(stdout io.Writer, path string, result authResult) error {
	out, err := json.MarshalIndent(result, "", "  ") //nolint:gosec // G117: emitting the session tokens is this command's purpose.
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if path == "" {
		_, err := stdout.Write(out)
		return err
	}
	if err := writeSecretFile(path, out); err != nil {
		return fmt.Errorf("writing result to %s: %w", path, err)
	}
	return nil
}

// writeSecretFile replaces path's contents with data and leaves the file with
// mode 0600. The mode given to OpenFile applies only when the file is created,
// so a pre-existing, more permissive file is tightened explicitly; on Windows
// the chmod is a no-op beyond the read-only bit.
func writeSecretFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: path is the user's own -o argument.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// firstNonEmpty returns the first value that is non-blank, trimmed. It is for
// non-secret inputs such as usernames and TOTP codes.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// firstNonEmptyExact keeps credential bytes intact. Passwords may legitimately
// begin or end with whitespace, so they must not use firstNonEmpty's trimming.
func firstNonEmptyExact(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
