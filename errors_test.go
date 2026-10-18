package protonauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	proton "github.com/henrybear327/go-proton-api"
)

func TestFriendlyAuthError(t *testing.T) {
	locked := fmt.Errorf("422 POST /auth/v4: %w", &proton.APIError{
		Status: 422, Code: accountLockedCode,
		Message: "Our systems detected unusual activity targeting your account.",
	})
	got := friendlyAuthError(locked)
	if !strings.HasPrefix(got, "Our systems detected unusual activity") {
		t.Errorf("locked message not surfaced: %q", got)
	}
	if !strings.Contains(got, "appeal-abuse") {
		t.Errorf("locked message missing guidance: %q", got)
	}
	if strings.Contains(got, "422 POST") {
		t.Errorf("verbose transport prefix not stripped: %q", got)
	}

	wrong := fmt.Errorf("wrap: %w", &proton.APIError{Code: proton.PasswordWrong, Message: "Incorrect login credentials"})
	if got := friendlyAuthError(wrong); !strings.HasPrefix(got, "Incorrect login credentials") || !strings.Contains(got, "username and password") {
		t.Errorf("password message = %q", got)
	}
	blank := &proton.APIError{Code: proton.PasswordWrong}
	if got := friendlyAuthError(blank); got != "Incorrect password (or username)." {
		t.Errorf("blank password message = %q", got)
	}

	plain := fmt.Errorf("network is down")
	if got := friendlyAuthError(plain); got != "network is down" {
		t.Errorf("plain error = %q", got)
	}

	noMessage := &proton.APIError{Code: 12345, Status: 500}
	if got := friendlyAuthError(noMessage); !strings.Contains(got, "Code=12345") {
		t.Errorf("message-less APIError = %q", got)
	}
}

func TestCaptchaUnavailableMessage(t *testing.T) {
	if got := captchaUnavailableMessage(nil); !strings.Contains(got, "available methods: none") {
		t.Errorf("no methods = %q", got)
	}
	if got := captchaUnavailableMessage([]string{"email", "sms"}); !strings.Contains(got, "email, sms") {
		t.Errorf("methods = %q", got)
	}
}

// transportError must separate "Proton answered" (left to the caller's code),
// "ctx ended" and "no answer at all", in that order of precedence.
func TestTransportErrorClassification(t *testing.T) {
	ctx := t.Context()
	answered := fmt.Errorf("422 POST /auth/v4: %w", &proton.APIError{Code: proton.PasswordWrong})
	if got := transportError(ctx, answered); got != nil {
		t.Errorf("an API answer classified as %v", got.Code)
	}
	if got := transportError(ctx, errors.New("invalid server proof")); got != nil {
		t.Errorf("a protocol error classified as %v", got.Code)
	}

	refused := &url.Error{Op: "Post", URL: "https://mail.proton.me/api/auth/v4/info", Err: errors.New("dial tcp: connection refused")}
	got := transportError(ctx, refused)
	if got == nil || got.Code != ErrCodeConnection {
		t.Fatalf("connection failure classified as %v", got)
	}
	if !strings.Contains(got.Message, "could not reach Proton") || !errors.Is(got, refused) {
		t.Errorf("connection error = %q (unwraps: %v)", got.Message, errors.Is(got, refused))
	}

	ended, cancel := context.WithCancel(ctx)
	cancel()
	got = transportError(ended, &url.Error{Op: "Post", Err: context.Canceled})
	if got == nil || got.Code != ErrCodeCancelled || !errors.Is(got, context.Canceled) {
		t.Errorf("cancelled login classified as %v", got)
	}
	// Proton's answer still wins over a context that ended just after it.
	if got := transportError(ended, answered); got != nil {
		t.Errorf("an API answer under an ended ctx classified as %v", got.Code)
	}

	if got := requestError(ctx, answered, ErrCode2FAFailed, "2FA failed: "); got.Code != ErrCode2FAFailed || !strings.HasPrefix(got.Message, "2FA failed: ") {
		t.Errorf("requestError = %+v", got)
	}
	if got := requestError(ended, refused, ErrCode2FAFailed, "2FA failed: "); got.Code != ErrCodeCancelled {
		t.Errorf("requestError under an ended ctx = %v", got.Code)
	}
}

func TestAuthErrorUnwrap(t *testing.T) {
	cause := &proton.APIError{Code: proton.PasswordWrong, Message: "nope"}
	var err error = &AuthError{Code: ErrCode2FAFailed, Message: "2FA failed: nope", Err: cause}

	if err.Error() != "2FA failed: nope" {
		t.Errorf("Error() = %q", err.Error())
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Code != ErrCode2FAFailed {
		t.Fatalf("errors.As to *AuthError failed: %v", err)
	}
	var apiErr *proton.APIError
	if !errors.As(err, &apiErr) || apiErr != cause {
		t.Errorf("errors.As to the cause failed: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is to the cause failed")
	}

	bare := &AuthError{Code: ErrCodeLogin, Message: "x"}
	if bare.Unwrap() != nil {
		t.Error("Unwrap of a cause-less AuthError must be nil")
	}
}

func TestErrCodeString(t *testing.T) {
	cases := map[ErrCode]string{
		ErrCodeLogin:                   "login failed",
		ErrCode2FARequired:             "2FA required",
		ErrCode2FAFailed:               "2FA failed",
		ErrCodeMailboxPasswordRequired: "mailbox password required",
		ErrCodeGetUser:                 "get user failed",
		ErrCodeKeyPassword:             "key password derivation failed",
		ErrCodeInvalidInput:            "invalid input",
		ErrCodeCaptcha:                 "CAPTCHA not solved",
		ErrCodeConnection:              "connection failed",
		ErrCodeCancelled:               "cancelled",
		ErrCode(1005):                  "error 1005",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("ErrCode(%d).String() = %q, want %q", int(code), got, want)
		}
	}
}

// The numeric values are a published contract; a renumbering must not slip
// through as a refactor.
func TestErrCodeValuesAreStable(t *testing.T) {
	want := map[ErrCode]int{
		ErrCodeLogin: 1001, ErrCode2FARequired: 1002, ErrCode2FAFailed: 1003,
		ErrCodeMailboxPasswordRequired: 1004, ErrCodeGetUser: 1006, ErrCodeKeyPassword: 1007,
		ErrCodeInvalidInput: 1008, ErrCodeCaptcha: 1009, ErrCodeConnection: 1010, ErrCodeCancelled: 1011,
	}
	for code, value := range want {
		if int(code) != value {
			t.Errorf("%s = %d, want %d", code, int(code), value)
		}
	}
}
