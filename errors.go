package protonauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	proton "github.com/henrybear327/go-proton-api"
)

// ErrCode classifies a failed Login. The numeric values are stable, are the
// errorCode of the CLI's JSON contract, and may be branched on. Code 1000 is
// reserved for the CLI (failure to read interactive credentials) and 1005 is
// unused; neither is produced by this package.
type ErrCode int

const (
	// ErrCodeLogin means Proton rejected the SRP login: wrong credentials, an
	// abuse lock on the account, or a protocol failure such as an invalid
	// server proof. Retrying with the same inputs will not help.
	ErrCodeLogin ErrCode = 1001
	// ErrCode2FARequired means the account has a second factor but no usable
	// TOTP code, secret or provider was supplied, the supplied secret is
	// malformed, or the account's second factor is not TOTP at all (a security
	// key alone), which this package does not support.
	ErrCode2FARequired ErrCode = 1002
	// ErrCode2FAFailed means Proton rejected the 2FA code.
	ErrCode2FAFailed ErrCode = 1003
	// ErrCodeMailboxPasswordRequired means the account is in two-password mode
	// but no mailbox password was supplied.
	ErrCodeMailboxPasswordRequired ErrCode = 1004
	// ErrCodeGetUser means authentication succeeded but fetching the user failed.
	ErrCodeGetUser ErrCode = 1006
	// ErrCodeKeyPassword means the key password could not be produced: the
	// account has no primary key, fetching the key salts or deriving the key
	// password failed, or the derived password does not unlock the primary key
	// (a wrong mailbox password on a two-password account).
	ErrCodeKeyPassword ErrCode = 1007
	// ErrCodeInvalidInput means Login was called with unusable input: no
	// username or password, or a malformed Options.ProxyURL. Nothing was sent
	// to Proton; fix the call.
	ErrCodeInvalidInput ErrCode = 1008
	// ErrCodeCaptcha means Proton demanded human verification and it was not
	// completed: no CAPTCHA was among the offered methods, the local solver
	// page could not be started, CaptchaTimeout elapsed before the user solved
	// it, or Proton did not accept the solved token. Retry when a user can
	// solve one.
	ErrCodeCaptcha ErrCode = 1009
	// ErrCodeConnection means Proton could not be reached or the connection
	// failed mid-request: DNS, connect, TLS or proxy errors. The credentials
	// were not judged; retrying later may help.
	ErrCodeConnection ErrCode = 1010
	// ErrCodeCancelled means the ctx passed to Login ended (was cancelled or
	// its deadline passed) before the login completed, including while waiting
	// for a CAPTCHA or inside a provider callback. AuthError.Err wraps the
	// context error.
	ErrCodeCancelled ErrCode = 1011
)

// String returns a short, stable label for the code, for logs.
func (c ErrCode) String() string {
	switch c {
	case ErrCodeLogin:
		return "login failed"
	case ErrCode2FARequired:
		return "2FA required"
	case ErrCode2FAFailed:
		return "2FA failed"
	case ErrCodeMailboxPasswordRequired:
		return "mailbox password required"
	case ErrCodeGetUser:
		return "get user failed"
	case ErrCodeKeyPassword:
		return "key password derivation failed"
	case ErrCodeInvalidInput:
		return "invalid input"
	case ErrCodeCaptcha:
		return "CAPTCHA not solved"
	case ErrCodeConnection:
		return "connection failed"
	case ErrCodeCancelled:
		return "cancelled"
	}
	return fmt.Sprintf("error %d", int(c))
}

// AuthError is the error type returned by Login.
type AuthError struct {
	// Code is the stable classification of the failure.
	Code ErrCode
	// Message is human-friendly and safe to show to the user. It already
	// strips go-proton-api's "<status> <method> <url>:" prefix and adds
	// guidance for well-known failures such as an account lock.
	Message string
	// Err is the underlying cause when there is one: typically a
	// *proton.APIError from go-proton-api, a *url.Error for a connection
	// failure, or a context error when the login was cancelled or a CAPTCHA
	// solve timed out. It is reachable with errors.As and errors.Is because
	// AuthError implements Unwrap. May be nil.
	Err error
}

func (e *AuthError) Error() string { return e.Message }

// Unwrap returns the underlying cause, so errors.Is and errors.As see through
// an AuthError.
func (e *AuthError) Unwrap() error { return e.Err }

// accountLockedCode is Proton's "unusual activity, access temporarily limited"
// abuse response. It is account/IP-level and time-based, not something the
// client can retry around.
const accountLockedCode proton.Code = 2028

// captchaUnavailableMessage describes a human-verification demand that offers
// no CAPTCHA, which this package cannot satisfy.
func captchaUnavailableMessage(methods []string) string {
	list := "none"
	if len(methods) > 0 {
		list = strings.Join(methods, ", ")
	}
	return "Proton requires human verification, but a CAPTCHA is not offered (available methods: " + list + ")"
}

// apiMessage strips go-proton-api's "<status> <method> <url>:" prefix down to
// the API's own message, or returns err.Error() for non-API errors.
func apiMessage(err error) string {
	apiErr, ok := errors.AsType[*proton.APIError](err)
	if !ok {
		return err.Error()
	}
	if apiErr.Message != "" {
		return apiErr.Message
	}
	return fmt.Sprintf("Proton returned an error (Code=%d, Status=%d)", apiErr.Code, apiErr.Status)
}

// friendlyAuthError is apiMessage plus guidance for well-known login
// failures: the account lock and a wrong password.
func friendlyAuthError(err error) string {
	apiErr, ok := errors.AsType[*proton.APIError](err)
	if !ok {
		return err.Error()
	}
	switch apiErr.Code {
	case accountLockedCode:
		return apiMessage(err) + "\nThis is an account-level limit from Proton, not a client error. " +
			"Wait a while and retry, ideally after signing in to this account in a normal browser " +
			"from the same network. If it persists, appeal at https://proton.me/support/appeal-abuse"
	case proton.PasswordWrong:
		// Proton's own text is more specific ("This email address does not
		// exist" versus "Incorrect login credentials"); add the hint only
		// when it says nothing.
		if apiErr.Message == "" {
			return "Incorrect password (or username)."
		}
		return apiErr.Message + " Check the username and password."
	default:
		return apiMessage(err)
	}
}

// cancelled reports whether the login was cut short: ctx has ended, or err is
// a context error (from a provider that ran under its own deadline).
func cancelled(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// cancelledError is the AuthError for a login cut short by ctx (or, failing
// that, by the context error err).
func cancelledError(ctx context.Context, err error) *AuthError {
	cause := ctx.Err()
	if cause == nil {
		cause = err
	}
	return &AuthError{Code: ErrCodeCancelled, Message: "login cancelled: " + cause.Error(), Err: err}
}

// requestError classifies a failed request to Proton: code with Proton's own
// message when Proton answered, ErrCodeCancelled when ctx ended first, and
// ErrCodeConnection when the request got no answer at all.
func requestError(ctx context.Context, err error, code ErrCode, prefix string) *AuthError {
	if t := transportError(ctx, err); t != nil {
		return t
	}
	return &AuthError{Code: code, Message: prefix + apiMessage(err), Err: err}
}

// transportError returns the AuthError for an error that is not an answer from
// Proton (a cancelled context, or a connection failure), or nil when err is a
// *proton.APIError or something else entirely.
func transportError(ctx context.Context, err error) *AuthError {
	if _, ok := errors.AsType[*proton.APIError](err); ok {
		return nil
	}
	if ctx.Err() != nil {
		return cancelledError(ctx, err)
	}
	var netErr net.Error
	var urlErr *url.Error
	if errors.As(err, &netErr) || errors.As(err, &urlErr) {
		return &AuthError{Code: ErrCodeConnection, Message: "could not reach Proton: " + err.Error(), Err: err}
	}
	return nil
}
