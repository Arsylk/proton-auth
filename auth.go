package protonauth

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Arsylk/proton-auth/internal/proxy"
	proton "github.com/henrybear327/go-proton-api"
)

// Default header values. go-proton-api does not set these to Proton web-client
// values, and the right pair reduces how often Proton demands a CAPTCHA.
//
// DefaultAppVersion identifies the client to Proton as rclone's Proton Drive
// backend, a client Proton accepts for this login flow. Set Options.AppVersion
// to identify as something else.
const (
	DefaultAppVersion = "macos-drive@1.0.0-alpha.1+rclone"
	DefaultUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/120.0.0.0 Safari/537.36"
)

// revokeTimeout bounds the best-effort revocation of the session a failed
// login would otherwise leave behind on Proton's side.
const revokeTimeout = 5 * time.Second

// Options configures a Login attempt. The zero value is usable: it talks to
// Proton's production API, uses no proxy, does not open a browser for a
// CAPTCHA, waits DefaultCaptchaTimeout for one to be solved, and writes nothing.
type Options struct {
	// AppVersion sets the X-Pm-Appversion header. Empty means DefaultAppVersion.
	AppVersion string
	// UserAgent sets the User-Agent header. Empty means DefaultUserAgent.
	UserAgent string
	// HostURL overrides the Proton API base URL. Empty means go-proton-api's
	// default, https://mail.proton.me/api. It exists for tests against a local
	// fake server; the CAPTCHA widget is always proxied from Proton's
	// production host regardless of HostURL.
	HostURL string
	// ProxyURL, when set (for example http://user:pass@host:port or
	// socks5://host:port), routes both the login and the proxied CAPTCHA solve
	// so they exit from one IP. Proton binds a verification token to the IP
	// that solved the challenge. A malformed value fails Login with
	// ErrCodeInvalidInput; the value itself is never echoed in the error.
	ProxyURL string
	// CaptchaAutoOpen opens the solver page in the default browser when a
	// CAPTCHA is required. The URL is always reported through OnCaptchaPrompt
	// and Output as well, for headless use.
	CaptchaAutoOpen bool
	// CaptchaTimeout bounds how long Login waits for a CAPTCHA to be solved.
	// Zero means DefaultCaptchaTimeout. The ctx passed to Login also applies.
	CaptchaTimeout time.Duration
	// RequestTimeout bounds how long each request to Proton may wait for its
	// response headers: connecting, the TLS handshake and server think time
	// count, the transfer of the body does not. Zero means
	// DefaultRequestTimeout. It is what turns an unreachable or stalled API
	// into ErrCodeConnection instead of a hang when ctx has no deadline.
	// go-proton-api retries a failed request a few times with backoff, so an
	// unreachable host is reported after several multiples of this value.
	RequestTimeout time.Duration
	// OnCaptchaPrompt, if non-nil, is called once the local solver page is
	// listening, with the URL a user must open. It is the structured
	// counterpart of Output for callers that render the prompt themselves (a
	// GUI, a bot, a daemon). It is called synchronously from Login, so it
	// should return promptly; the page stays up until the CAPTCHA is solved
	// or times out.
	OnCaptchaPrompt func(CaptchaPrompt)
	// Output, if non-nil, receives human-readable CAPTCHA instruction lines
	// (the URL to open, a port-forward hint, progress). os.Stderr is the usual
	// choice for a CLI. Nil is silent.
	Output io.Writer
}

func (o Options) appVersion() string { return cmp.Or(o.AppVersion, DefaultAppVersion) }

func (o Options) userAgent() string { return cmp.Or(o.UserAgent, DefaultUserAgent) }

func (o Options) requestTimeout() time.Duration { return requestTimeoutOrDefault(o.RequestTimeout) }

// captchaOptions derives the CAPTCHA solver settings for a login as account.
func (o Options) captchaOptions(account string) CaptchaOptions {
	return CaptchaOptions{
		Account:        account,
		AutoOpen:       o.CaptchaAutoOpen,
		ProxyURL:       o.ProxyURL,
		Timeout:        o.CaptchaTimeout,
		RequestTimeout: o.RequestTimeout,
		OnPrompt:       o.OnCaptchaPrompt,
		Output:         o.Output,
	}
}

// Credentials carry the login inputs. Username and Password are required.
//
// For an account with 2FA enabled, supply one of TOTPCode, TOTPSecret or
// TOTPProvider; they are consulted in that order. If none yields a code, Login
// returns an AuthError with ErrCode2FARequired.
//
// The provider callbacks receive the ctx passed to Login. A provider that
// prompts a user should give up and return ctx.Err() when that ctx ends; Login
// then fails with ErrCodeCancelled rather than blaming the missing value.
type Credentials struct {
	// Username is the Proton username or email address.
	Username string
	// Password is the login password, byte-exact (it may contain whitespace).
	Password string
	// TOTPCode is a current 6-digit 2FA code.
	TOTPCode string
	// TOTPSecret is the base32 2FA secret; the current code is generated from
	// it (RFC 6238: SHA-1, 6 digits, 30-second step). Spaces, case and padding
	// are tolerated.
	TOTPSecret string
	// TOTPProvider is called, at most once, to obtain a 2FA code when neither
	// TOTPCode nor TOTPSecret is set. It lets a CLI prompt the user without
	// pulling stdin handling into the library. May be nil.
	TOTPProvider func(ctx context.Context) (string, error)
	// MailboxPassword is the second password that unlocks the keys on a
	// two-password-mode account (PasswordModeTwo). It is ignored on
	// one-password accounts, where Password unlocks the keys.
	MailboxPassword string
	// MailboxPasswordProvider is called, at most once, to obtain the mailbox
	// password when the account is in two-password mode and MailboxPassword is
	// empty. May be nil; such an account then fails with
	// ErrCodeMailboxPasswordRequired.
	MailboxPasswordProvider func(ctx context.Context) (string, error)
}

// PasswordMode is Proton's PASSWORD_MODE account setting.
type PasswordMode int

const (
	// PasswordModeUnknown is the zero value: no mode has been reported. Login
	// never returns it; Proton always states one of the two modes below.
	PasswordModeUnknown PasswordMode = 0
	// PasswordModeOne means the login password also unlocks the keys.
	PasswordModeOne PasswordMode = 1
	// PasswordModeTwo means a separate mailbox password unlocks the keys.
	PasswordModeTwo PasswordMode = 2
)

// String returns "one-password", "two-password", "unknown password mode", or
// the raw number.
func (m PasswordMode) String() string {
	switch m {
	case PasswordModeUnknown:
		return "unknown password mode"
	case PasswordModeOne:
		return "one-password"
	case PasswordModeTwo:
		return "two-password"
	}
	return fmt.Sprintf("password mode %d", int(m))
}

// Result holds the tokens and derived secrets from a successful login. Every
// field is sensitive. The fields are plain strings so callers need not import
// this module's go-proton-api fork.
type Result struct {
	// AccessToken and RefreshToken are the session's bearer tokens. UID is the
	// session identifier sent as X-Pm-Uid alongside them.
	AccessToken  string
	RefreshToken string
	UID          string
	// UserID is Proton's identifier for the account.
	UserID string
	// KeyPassword is the derived passphrase that unlocks the user's primary
	// key.
	KeyPassword string
	// ExpiresIn is the access-token lifetime in seconds, exactly as Proton
	// returned it. It is 0 if Proton omitted it or it could not be read. No
	// safety margin is applied and it is not turned into a timestamp; that
	// policy belongs to the caller.
	ExpiresIn int
	// PasswordMode reports whether KeyPassword was derived from the login
	// password (PasswordModeOne) or from the mailbox password (PasswordModeTwo).
	PasswordMode PasswordMode
}

// Login performs SRP authentication, solving a CAPTCHA in the browser if Proton
// demands human verification, then completes 2FA if the account has it, and
// derives the primary key password.
//
// Every error it returns is a *AuthError carrying a stable ErrCode. The
// underlying cause, when there is one, is reachable with errors.As and
// errors.Is through Unwrap.
//
// If Proton has issued a session but the login still fails (a rejected 2FA
// code, a wrong mailbox password, a failed user or salt fetch, a cancellation),
// Login revokes that session, best effort and within a few seconds, before
// returning: the caller never sees its tokens, so nothing else could.
func Login(ctx context.Context, opts Options, creds Credentials) (*Result, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, &AuthError{Code: ErrCodeInvalidInput, Message: "username and password are required"}
	}

	s, err := srpLogin(ctx, opts, creds.Username, creds.Password)
	if err != nil {
		return nil, err
	}

	res, err := s.finish(ctx, creds)
	if err != nil {
		s.revoke(ctx)
	}
	s.close()
	return res, err
}

// finish turns an SRP session into a Result: it completes 2FA if the account
// has it, fetches the user and the key salts, derives the key password and
// checks it against the primary key. Every error is a *AuthError.
func (s *session) finish(ctx context.Context, creds Credentials) (*Result, error) {
	// TwoFA.Enabled is a bitmask of the account's second factors. Only TOTP is
	// supported; Proton requires TOTP before a security key can be added, so
	// the second case is defensive.
	switch {
	case s.auth.TwoFA.Enabled&proton.HasTOTP != 0:
		if err := complete2FA(ctx, s.client, creds); err != nil {
			return nil, err
		}
	case s.auth.TwoFA.Enabled != 0:
		return nil, &AuthError{Code: ErrCode2FARequired, Message: fmt.Sprintf(
			"the account's second factor (2FA status %d) is not TOTP; only TOTP codes are supported", s.auth.TwoFA.Enabled)}
	}

	user, err := s.client.GetUser(ctx)
	if err != nil {
		return nil, requestError(ctx, err, ErrCodeGetUser, "failed to get user: ")
	}
	primary, ok := primaryKey(user.Keys)
	if !ok {
		return nil, &AuthError{Code: ErrCodeKeyPassword, Message: "account has no primary key"}
	}

	// Salts are only available in a time-limited window right after auth.
	salts, err := s.client.GetSalts(ctx)
	if err != nil {
		return nil, requestError(ctx, err, ErrCodeKeyPassword, "failed to get salts: ")
	}

	// The key (mailbox) password unlocks the user's keys. On a two-password
	// account it is a separate secret from the login password; on a one-password
	// account the login password is reused. This mirrors Proton's web client,
	// where keys unlock with the second password iff PasswordMode is
	// TWO_PASSWORD (packages/shared/lib/authentication/twoFactor.ts).
	mode := PasswordMode(s.auth.PasswordMode)
	keySource, err := keyPasswordSource(ctx, mode, creds)
	if err != nil {
		return nil, err
	}

	keyPassword, err := salts.SaltForKey([]byte(keySource), primary.ID)
	if err != nil {
		return nil, &AuthError{Code: ErrCodeKeyPassword, Message: "failed to derive key password: " + err.Error(), Err: err}
	}

	// Proton accepts the login before the mailbox password is ever checked,
	// so a wrong one would otherwise yield a key password that only fails
	// later, in whatever consumes the Result. Verify it the way Proton's
	// clients do: by unlocking the primary key.
	if err := verifyKeyPassword(primary, keyPassword); err != nil {
		which := "login password"
		if mode == PasswordModeTwo {
			which = "mailbox password"
		}
		return nil, &AuthError{
			Code:    ErrCodeKeyPassword,
			Message: "the " + which + " does not unlock the account's primary key",
			Err:     err,
		}
	}

	return &Result{
		AccessToken:  s.auth.AccessToken,
		RefreshToken: s.auth.RefreshToken,
		UID:          s.auth.UID,
		UserID:       s.auth.UserID,
		KeyPassword:  string(keyPassword),
		ExpiresIn:    s.expiresIn,
		PasswordMode: mode,
	}, nil
}

// primaryKey returns the user's primary key. go-proton-api's Keys.Primary
// panics when there is none, so this is checked explicitly.
func primaryKey(keys proton.Keys) (proton.Key, bool) {
	for _, key := range keys {
		if key.Primary {
			return key, true
		}
	}
	return proton.Key{}, false
}

// verifyKeyPassword unlocks key with keyPassword and discards the result; it
// returns the unlock error if the password is wrong.
func verifyKeyPassword(key proton.Key, keyPassword []byte) error {
	unlocked, err := key.Unlock(keyPassword, nil)
	if err != nil {
		return err
	}
	unlocked.ClearPrivateParams()
	return nil
}

// keyPasswordSource returns the password that unlocks the user's keys: the
// login password in one-password mode, or the separate mailbox password in
// two-password mode (resolved from MailboxPassword, else MailboxPasswordProvider).
func keyPasswordSource(ctx context.Context, mode PasswordMode, creds Credentials) (string, error) {
	if mode != PasswordModeTwo {
		return creds.Password, nil
	}
	if creds.MailboxPassword != "" {
		return creds.MailboxPassword, nil
	}
	if creds.MailboxPasswordProvider != nil {
		mbox, err := creds.MailboxPasswordProvider(ctx)
		if err != nil {
			if cancelled(ctx, err) {
				return "", cancelledError(ctx, err)
			}
			return "", &AuthError{
				Code:    ErrCodeMailboxPasswordRequired,
				Message: "failed to obtain mailbox password: " + err.Error(),
				Err:     err,
			}
		}
		if mbox != "" {
			return mbox, nil
		}
	}
	return "", &AuthError{
		Code:    ErrCodeMailboxPasswordRequired,
		Message: "two-password account: a separate mailbox password is required",
	}
}

// complete2FA resolves the 2FA code from the credentials and submits it.
func complete2FA(ctx context.Context, client *proton.Client, creds Credentials) error {
	code, err := resolve2FACode(ctx, creds, time.Now())
	if err != nil {
		return err
	}
	if err := client.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: code}); err != nil {
		return requestError(ctx, err, ErrCode2FAFailed, "2FA failed: ")
	}
	return nil
}

// resolve2FACode picks the 2FA code from the credentials: the static code, else
// one generated from the secret, else one obtained from the provider.
func resolve2FACode(ctx context.Context, creds Credentials, now time.Time) (string, error) {
	switch {
	case creds.TOTPCode != "":
		return creds.TOTPCode, nil
	case creds.TOTPSecret != "":
		code, err := generateTOTP(creds.TOTPSecret, now)
		if err != nil {
			return "", &AuthError{Code: ErrCode2FARequired, Message: "invalid TOTP secret: " + err.Error(), Err: err}
		}
		return code, nil
	case creds.TOTPProvider != nil:
		code, err := creds.TOTPProvider(ctx)
		if err != nil {
			if cancelled(ctx, err) {
				return "", cancelledError(ctx, err)
			}
			return "", &AuthError{Code: ErrCode2FARequired, Message: "failed to obtain 2FA code: " + err.Error(), Err: err}
		}
		if code == "" {
			return "", &AuthError{Code: ErrCode2FARequired, Message: "2FA required: the provider returned an empty code"}
		}
		return code, nil
	}
	return "", &AuthError{
		Code:    ErrCode2FARequired,
		Message: "2FA required: supply a TOTP code, a base32 secret, or a provider",
	}
}

// session is a successful SRP login: the manager and client that own the
// connection, the auth response, and the token lifetime read off the wire.
type session struct {
	manager   *proton.Manager
	client    *proton.Client
	auth      proton.Auth
	expiresIn int
}

// close releases the client and the connections this login owns.
// Manager.Close is http.Client.CloseIdleConnections, which the wrapper
// transports forward down to the transport built for this login.
func (s *session) close() {
	s.client.Close()
	s.manager.Close()
}

// revoke ends the session on Proton's side, best effort. It runs under its own
// short deadline, detached from ctx, so that a cancelled login still cleans up.
func (s *session) revoke(ctx context.Context) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	_ = s.client.AuthDelete(rctx)
}

// srpLogin runs the SRP exchange. On a human-verification error offering a
// CAPTCHA, it solves it in the browser and retries once with the verification
// token attached. The login and the solve share one transport, routed through
// ProxyURL when set, so the retry comes from the IP the token was issued to.
// Every error is a *AuthError.
func srpLogin(ctx context.Context, opts Options, username, password string) (*session, error) {
	transport, err := proxy.Transport(opts.ProxyURL, opts.requestTimeout())
	if err != nil {
		return nil, &AuthError{Code: ErrCodeInvalidInput, Message: err.Error(), Err: err}
	}
	// fail releases the connections an unsuccessful attempt leaves idle. Every
	// err handed to it is already a *AuthError.
	fail := func(err error) (*session, error) {
		transport.CloseIdleConnections()
		return nil, err
	}

	// expiresIn is populated from the successful /auth/v4 response, whichever
	// attempt wins; every manager built here tees that response through the
	// capture.
	var expiresIn int
	login := func(rt http.RoundTripper) (*session, error) {
		managerOpts := []proton.Option{
			proton.WithAppVersion(opts.appVersion()),
			proton.WithUserAgent(opts.userAgent()),
			proton.WithTransport(newExpiryCapture(rt, &expiresIn)),
			// go-proton-api's resty client logs every failed request to
			// stderr by default; the failure is returned as an error instead.
			proton.WithLogger(quietLogger{}),
		}
		if opts.HostURL != "" {
			managerOpts = append(managerOpts, proton.WithHostURL(opts.HostURL))
		}
		manager := proton.New(managerOpts...)
		client, auth, err := manager.NewClientWithLogin(ctx, username, []byte(password))
		if err != nil {
			manager.Close()
			return nil, err
		}
		return &session{manager: manager, client: client, auth: auth, expiresIn: expiresIn}, nil
	}

	s, err := login(transport)
	if err == nil {
		return s, nil
	}

	hv, ok := asHumanVerification(err)
	if !ok {
		return fail(loginError(ctx, err))
	}
	if !hv.supportsCaptcha() {
		return fail(&AuthError{Code: ErrCodeCaptcha, Message: captchaUnavailableMessage(hv.Methods), Err: err})
	}

	token, err := solveCaptcha(ctx, hv.Token, opts.captchaOptions(username), transport)
	if err != nil {
		return fail(err)
	}

	s, err = login(newHVTransport(transport, token, hvTokenTypeCaptcha))
	if err != nil {
		if isHumanVerification(err) {
			return fail(&AuthError{
				Code: ErrCodeCaptcha,
				Message: "Proton did not accept the solved CAPTCHA token; it must be solved and the login " +
					"retried from the same IP (route both through one proxy with ProxyURL if they differ)",
				Err: err,
			})
		}
		return fail(loginError(ctx, err))
	}
	return s, nil
}

// loginError classifies a failed SRP exchange: a cancelled context or a
// connection failure, else Proton's verdict with guidance.
func loginError(ctx context.Context, err error) *AuthError {
	if t := transportError(ctx, err); t != nil {
		return t
	}
	return &AuthError{Code: ErrCodeLogin, Message: friendlyAuthError(err), Err: err}
}

// quietLogger satisfies resty.Logger without writing anything. A library
// should not log to the process's stderr; every failure reaches the caller
// through the returned error.
type quietLogger struct{}

func (quietLogger) Errorf(string, ...any) {}
func (quietLogger) Warnf(string, ...any)  {}
func (quietLogger) Debugf(string, ...any) {}
