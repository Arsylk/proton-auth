// Package protonauth performs Proton SRP authentication, transparently solving
// the CAPTCHA (human-verification Code=9001) challenge that blocks many
// headless/community Proton clients.
//
// It wraps ProtonMail's go-proton-api (via the henrybear327 fork) and adds:
//   - SRP login with optional 2FA (static TOTP code, auto-generated from a
//     base32 secret, or supplied on demand through a callback),
//   - browser-assisted CAPTCHA solving: Proton's widget is reverse-proxied on a
//     throwaway local server so it frames same-origin, the solved token is
//     captured, and the login is retried with the verification header attached,
//   - optional routing of every Proton-facing request through one proxy so the
//     login and the CAPTCHA solve share the IP the token was issued to.
//
// The library returns plain string tokens, so a caller does not have to share
// this module's go-proton-api fork. Callers on a different fork (e.g. rclone's)
// can instead call SolveCaptcha to obtain a verification token and inject it
// into their own login. The bundled cmd/proton-auth exposes all of this as a
// binary with a stable JSON contract for non-Go consumers.
package protonauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/henrybear327/go-proton-api"
)

// writeLine writes one instruction line to w (nothing if w is nil). These are
// the CAPTCHA messages a user must act on, chiefly the URL to open and the
// headless port-forward hint, so they are plain output, not structured logs.
func writeLine(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// Options configures a Login attempt. The zero value is usable: it uses
// go-proton-api's default host (mail.proton.me/api), no proxy, does not
// auto-open a browser for CAPTCHA, and writes nothing.
type Options struct {
	// AppVersion sets the X-PM-AppVersion header. Leave empty for DefaultAppVersion.
	AppVersion string
	// UserAgent sets the User-Agent header. Leave empty for DefaultUserAgent.
	UserAgent string
	// ProxyURL, when set (http://user:pass@host:port), routes both the login
	// and the proxied CAPTCHA solve so they exit from one IP. The default host
	// is assumed; do not combine ProxyURL with a non-default Proton host.
	ProxyURL string
	// CaptchaAutoOpen opens the solver page in the default browser when a
	// CAPTCHA is required. The URL is always written to Output for headless use.
	CaptchaAutoOpen bool
	// Output, if non-nil, receives CAPTCHA progress/instruction lines
	// (e.g. os.Stderr). Nil is silent.
	Output io.Writer
}

// Credentials carry the login inputs. Username and Password are required.
// For 2FA, supply exactly one of TOTPCode, TOTPSecret, or TOTPProvider; if none
// is set and the account has 2FA enabled, Login returns an AuthError with code
// ErrCode2FARequired.
type Credentials struct {
	Username string
	Password string
	// TOTPCode is a current 6-digit 2FA code.
	TOTPCode string
	// TOTPSecret is a base32 2FA secret used to generate the code automatically.
	TOTPSecret string
	// TOTPProvider is called to obtain a 2FA code when neither TOTPCode nor
	// TOTPSecret is set. It lets a CLI prompt the user interactively without
	// pulling stdin handling into the library. May be nil.
	TOTPProvider func() (string, error)
	// MailboxPassword is the second password that unlocks the keys on a
	// two-password-mode account (Proton's PASSWORD_MODE TWO_PASSWORD). It is
	// ignored on one-password accounts, where Password unlocks the keys.
	MailboxPassword string
	// MailboxPasswordProvider is called to obtain the mailbox password when the
	// account is two-password mode and MailboxPassword is empty. May be nil;
	// if so, such an account fails with ErrCodeMailboxPasswordRequired.
	MailboxPasswordProvider func() (string, error)
}

// Result holds the tokens and derived secrets from a successful login. The
// token fields are plain strings so callers need not import this module's
// proton fork.
type Result struct {
	AccessToken  string
	RefreshToken string
	UID          string
	UserID       string
	KeyPassword  string
	// ExpiresIn is the access-token lifetime in seconds, exactly as Proton
	// returned it (its AuthResponse.ExpiresIn). It is 0 if Proton omitted it or
	// it could not be read. The library does not turn this into a timestamp or
	// apply a safety margin; that policy is left to the caller.
	ExpiresIn int
	// PasswordMode is Proton's PASSWORD_MODE: 1 (single) or 2 (two-password).
	// KeyPassword was derived from the login password when 1, from the mailbox
	// password when 2.
	PasswordMode int
}

// Default header values. go-proton-api does not set these to Proton web-client
// values, and the right pair reduces how often Proton demands a CAPTCHA.
const (
	DefaultAppVersion = "macos-drive@1.0.0-alpha.1+rclone"
	DefaultUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

func (o Options) appVersion() string {
	if o.AppVersion != "" {
		return o.AppVersion
	}
	return DefaultAppVersion
}

func (o Options) userAgent() string {
	if o.UserAgent != "" {
		return o.UserAgent
	}
	return DefaultUserAgent
}

// Login performs SRP authentication, solving a CAPTCHA in the browser if Proton
// demands human verification, then completes 2FA (if enabled), and derives the
// primary key password. Credentials.Username and Credentials.Password must be set.
func Login(ctx context.Context, opts Options, creds Credentials) (*Result, error) {
	if creds.Username == "" || creds.Password == "" {
		return nil, &AuthError{Code: ErrCodeLogin, Message: "username and password are required"}
	}

	manager, client, auth, expiresIn, err := srpLogin(ctx, opts, creds.Username, creds.Password)
	if err != nil {
		return nil, &AuthError{Code: ErrCodeLogin, Message: friendlyAuthError(err)}
	}
	defer manager.Close()
	defer client.Close()

	if auth.TwoFA.Enabled != 0 {
		if err := complete2FA(ctx, client, creds); err != nil {
			return nil, err
		}
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		return nil, &AuthError{Code: ErrCodeGetUser, Message: fmt.Sprintf("failed to get user: %v", err)}
	}

	// Salts are only available in a time-limited window right after auth.
	salts, err := client.GetSalts(ctx)
	if err != nil {
		return nil, &AuthError{Code: ErrCodeKeyPassword, Message: fmt.Sprintf("failed to get salts: %v", err)}
	}

	// The key (mailbox) password unlocks the user's keys. On a two-password
	// account it is a separate secret from the login password; on a one-password
	// account the login password is reused. This mirrors Proton's web client,
	// where keys unlock with the second password iff PasswordMode is
	// TWO_PASSWORD (packages/shared/lib/authentication/twoFactor.ts).
	keySource, err := keyPasswordSource(auth.PasswordMode, creds)
	if err != nil {
		return nil, err
	}

	keyPassword, err := salts.SaltForKey([]byte(keySource), user.Keys.Primary().ID)
	if err != nil {
		return nil, &AuthError{Code: ErrCodeKeyPassword, Message: fmt.Sprintf("failed to derive key password: %v", err)}
	}

	return &Result{
		AccessToken:  auth.AccessToken,
		RefreshToken: auth.RefreshToken,
		UID:          auth.UID,
		UserID:       auth.UserID,
		KeyPassword:  string(keyPassword),
		ExpiresIn:    expiresIn,
		PasswordMode: int(auth.PasswordMode),
	}, nil
}

// keyPasswordSource returns the password that unlocks the user's keys: the
// login password in one-password mode, or the separate mailbox password in
// two-password mode (resolved from MailboxPassword, else MailboxPasswordProvider).
func keyPasswordSource(mode proton.PasswordMode, creds Credentials) (string, error) {
	if mode != proton.TwoPasswordMode {
		return creds.Password, nil
	}
	if creds.MailboxPassword != "" {
		return creds.MailboxPassword, nil
	}
	if creds.MailboxPasswordProvider != nil {
		mbox, err := creds.MailboxPasswordProvider()
		if err != nil {
			return "", &AuthError{Code: ErrCodeMailboxPasswordRequired, Message: fmt.Sprintf("failed to obtain mailbox password: %v", err)}
		}
		if mbox != "" {
			return mbox, nil
		}
	}
	return "", &AuthError{Code: ErrCodeMailboxPasswordRequired, Message: "two-password account: a separate mailbox password is required"}
}

// complete2FA resolves the 2FA code from the credentials (static, generated, or
// via the provider callback) and submits it.
func complete2FA(ctx context.Context, client *proton.Client, creds Credentials) error {
	totp := creds.TOTPCode
	if totp == "" && creds.TOTPSecret != "" {
		totp = generateTOTP(creds.TOTPSecret, time.Now())
	}
	if totp == "" && creds.TOTPProvider != nil {
		code, err := creds.TOTPProvider()
		if err != nil {
			return &AuthError{Code: ErrCode2FARequired, Message: fmt.Sprintf("failed to obtain 2FA code: %v", err)}
		}
		totp = code
	}
	if totp == "" {
		return &AuthError{Code: ErrCode2FARequired, Message: "2FA required: supply a TOTP code or base32 secret"}
	}
	if err := client.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: totp}); err != nil {
		return &AuthError{Code: ErrCode2FAFailed, Message: fmt.Sprintf("2FA failed: %v", err)}
	}
	return nil
}

// srpLogin runs the SRP exchange. On a human-verification error offering a
// CAPTCHA, it solves it in the browser and retries once with the verification
// token attached. A non-empty ProxyURL routes every request through the proxy,
// so the retry comes from the IP the token was issued to.
func srpLogin(ctx context.Context, opts Options, username, password string) (*proton.Manager, *proton.Client, proton.Auth, int, error) {
	baseTransport, err := proxyTransport(opts.ProxyURL)
	if err != nil {
		return nil, nil, proton.Auth{}, 0, err
	}

	// expiresIn is populated from the successful /auth/v4 response, whichever
	// attempt wins. Both transports below tee that response through the capture.
	var expiresIn int

	newManager := func(rt http.RoundTripper) *proton.Manager {
		managerOpts := []proton.Option{
			proton.WithAppVersion(opts.appVersion()),
			proton.WithUserAgent(opts.userAgent()),
			proton.WithTransport(newExpiryCapture(rt, &expiresIn)),
		}
		return proton.New(managerOpts...)
	}

	// A nil round-tripper means "go-proton-api's default transport"; the capture
	// wraps that default so expiry is read even without a proxy.
	manager := newManager(baseTransportOrDefault(baseTransport, opts.ProxyURL))

	client, auth, err := manager.NewClientWithLogin(ctx, username, []byte(password))
	if err == nil {
		return manager, client, auth, expiresIn, nil
	}
	manager.Close()

	hv, ok := asHumanVerification(err)
	if !ok {
		return nil, nil, proton.Auth{}, 0, err
	}
	if !hv.supportsCaptcha() {
		return nil, nil, proton.Auth{}, 0, fmt.Errorf(
			"human verification required, but CAPTCHA is not offered (available methods: %v): %w",
			hv.Methods, err,
		)
	}

	captchaToken, err := solveCaptcha(ctx, legacyTarget(hv.Token), username, opts.CaptchaAutoOpen, opts.ProxyURL, opts.Output)
	if err != nil {
		return nil, nil, proton.Auth{}, 0, err
	}

	manager = newManager(newHVTransport(baseTransport, captchaToken, "captcha"))
	client, auth, err = manager.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		manager.Close()
		return nil, nil, proton.Auth{}, 0, err
	}
	return manager, client, auth, expiresIn, nil
}

// baseTransportOrDefault returns the proxy transport when a proxy is configured,
// or http.DefaultTransport otherwise, so the first login attempt still routes
// through go-proton-api's default behaviour while remaining wrappable.
func baseTransportOrDefault(proxyTransport http.RoundTripper, proxyURL string) http.RoundTripper {
	if proxyURL == "" {
		return http.DefaultTransport
	}
	return proxyTransport
}
