package protonauth

import (
	"errors"
	"fmt"

	"github.com/henrybear327/go-proton-api"
)

// Error codes reported on an AuthError and in the CLI JSON contract. They are
// stable: consumers may branch on them. 1000 is reserved for the CLI (failure
// to read interactive credentials) and never produced by the library.
const (
	ErrCodeLogin                   = 1001 // SRP login failed (bad credentials, CAPTCHA give-up, network)
	ErrCode2FARequired             = 1002 // account has 2FA but no code/secret/provider was supplied
	ErrCode2FAFailed               = 1003 // the supplied 2FA code was rejected
	ErrCodeMailboxPasswordRequired = 1004 // two-password account, but no mailbox password was supplied
	ErrCodeGetUser                 = 1006 // authenticated but fetching the user failed
	ErrCodeKeyPassword             = 1007 // fetching salts or deriving the key password failed
)

// AuthError is the typed error returned by Login. Message is already
// human-friendly (see friendlyAuthError); Code is one of the ErrCode constants.
type AuthError struct {
	Code    int
	Message string
}

func (e *AuthError) Error() string { return e.Message }

// accountLockedCode is Proton's "unusual activity, access temporarily limited"
// abuse response. It is account/IP-level and time-based, not something the
// client can retry around.
const accountLockedCode proton.Code = 2028

// friendlyAuthError unwraps go-proton-api's "<status> <method> <url>:" error
// prefix down to the API message, then appends guidance for a couple of
// well-known codes (account lock, wrong password).
func friendlyAuthError(err error) string {
	var apiErr *proton.APIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}

	msg := apiErr.Message
	if msg == "" {
		msg = fmt.Sprintf("Proton returned an error (Code=%d, Status=%d)", apiErr.Code, apiErr.Status)
	}

	switch apiErr.Code {
	case accountLockedCode:
		return msg + "\nThis is an account-level limit from Proton, not a client error. " +
			"Wait a while and retry, ideally after signing in to this account in a normal browser from the same network. " +
			"If it persists, appeal at https://proton.me/support/appeal-abuse"
	case proton.PasswordWrong:
		return "Incorrect password (or username)."
	}
	return msg
}
