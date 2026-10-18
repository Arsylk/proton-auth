package protonauth

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/Arsylk/proton-auth/internal/captcha"
	"github.com/Arsylk/proton-auth/internal/proxy"
)

// DefaultCaptchaTimeout is how long a CAPTCHA solve waits for the user when no
// timeout is configured.
const DefaultCaptchaTimeout = 10 * time.Minute

// DefaultRequestTimeout is how long a single request to Proton may wait for
// its response headers when Options.RequestTimeout is zero.
const DefaultRequestTimeout = 30 * time.Second

// requestTimeoutOrDefault resolves a zero or negative request timeout to
// DefaultRequestTimeout.
func requestTimeoutOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultRequestTimeout
	}
	return d
}

// CaptchaPrompt describes a running local CAPTCHA solver page. It is passed to
// Options.OnCaptchaPrompt and CaptchaOptions.OnPrompt.
type CaptchaPrompt struct {
	// URL is the page to open in a browser: http://127.0.0.1:<port>/.
	URL string
	// Port is the local port the page listens on, for forwarding from a
	// headless host: ssh -L <port>:127.0.0.1:<port> <host>.
	Port int
	// Account is the label shown on the page, if one was given.
	Account string
}

// CaptchaOptions configures SolveCaptcha. The zero value is usable: no label,
// no browser auto-open, no proxy, DefaultCaptchaTimeout, and no output.
type CaptchaOptions struct {
	// Account is shown on the solver page so that sequential CAPTCHAs for
	// different accounts are distinguishable. Optional.
	Account string
	// AutoOpen opens the page in the default browser. The URL is always
	// reported through OnPrompt and Output as well, for headless use.
	AutoOpen bool
	// ProxyURL routes the proxied widget through this proxy. Use the same
	// proxy as the login that will consume the token: Proton binds the token
	// to the IP that solved the challenge.
	ProxyURL string
	// Timeout bounds the wait for a solved token. Zero means
	// DefaultCaptchaTimeout. The ctx passed to SolveCaptcha also applies.
	Timeout time.Duration
	// RequestTimeout bounds how long each proxied widget request may wait for
	// Proton's response headers. Zero means DefaultRequestTimeout.
	RequestTimeout time.Duration
	// OnPrompt, if non-nil, is called once the page is listening, with the URL
	// a user must open. It is called synchronously, so it should return
	// promptly; the page stays up until the CAPTCHA is solved or times out.
	OnPrompt func(CaptchaPrompt)
	// Output, if non-nil, receives human-readable instruction lines (the URL,
	// a port-forward hint, progress). Nil is silent.
	Output io.Writer
}

// SolveCaptcha serves Proton's CAPTCHA widget, bound to the
// HumanVerificationToken from a Code=9001 response, on a throwaway 127.0.0.1
// server, optionally opens it in the user's browser, and returns the solved
// verification token once the user completes the challenge.
//
// Login calls this internally. It is exported for consumers that drive their
// own login against a different go-proton-api fork: retry the login from the
// same IP with the header X-Pm-Human-Verification-Token set to the returned
// token and X-Pm-Human-Verification-Token-Type set to "captcha".
//
// Every error is a *AuthError, as with Login: ErrCodeInvalidInput for an
// empty token or a malformed ProxyURL, ErrCodeCancelled when ctx ends first,
// and ErrCodeCaptcha when the timeout elapses or the local page cannot be
// served. AuthError.Err carries the cause, so errors.Is sees
// context.DeadlineExceeded after a timeout.
func SolveCaptcha(ctx context.Context, hvToken string, opts CaptchaOptions) (string, error) {
	if hvToken == "" {
		return "", &AuthError{Code: ErrCodeInvalidInput, Message: "HumanVerificationToken is empty"}
	}
	transport, err := proxy.Transport(opts.ProxyURL, requestTimeoutOrDefault(opts.RequestTimeout))
	if err != nil {
		return "", &AuthError{Code: ErrCodeInvalidInput, Message: err.Error(), Err: err}
	}
	defer transport.CloseIdleConnections()
	return solveCaptcha(ctx, hvToken, opts, transport)
}

// solveCaptcha runs the solver over an existing transport, so that a login
// and its CAPTCHA share one connection pool and one proxy. Every error is a
// *AuthError.
func solveCaptcha(
	ctx context.Context,
	hvToken string,
	opts CaptchaOptions,
	transport http.RoundTripper,
) (string, error) {
	token, err := captcha.Solve(ctx, captcha.LegacyTarget(hvToken), opts.internal(transport))
	if err != nil {
		if ctx.Err() != nil {
			return "", cancelledError(ctx, err)
		}
		return "", &AuthError{Code: ErrCodeCaptcha, Message: "CAPTCHA not solved: " + err.Error(), Err: err}
	}
	return token, nil
}

// internal translates the public options into the internal solver's, routing
// the widget proxy through transport. A zero Timeout is left for the solver
// to resolve to its default.
func (o CaptchaOptions) internal(transport http.RoundTripper) captcha.Options {
	co := captcha.Options{
		Account:   o.Account,
		Transport: transport,
		AutoOpen:  o.AutoOpen,
		Timeout:   o.Timeout,
		Output:    o.Output,
	}
	if o.OnPrompt != nil {
		co.OnPrompt = func(p captcha.Prompt) { o.OnPrompt(CaptchaPrompt(p)) }
	}
	return co
}
