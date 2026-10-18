package protonauth

import (
	"errors"
	"testing"

	"github.com/henrybear327/go-proton-api"
)

func TestKeyPasswordSourceOnePasswordUsesLoginPassword(t *testing.T) {
	got, err := keyPasswordSource(proton.OnePasswordMode, Credentials{Password: "login-pw", MailboxPassword: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "login-pw" {
		t.Fatalf("one-password mode must use login password, got %q", got)
	}
}

func TestKeyPasswordSourceTwoPasswordUsesMailboxPassword(t *testing.T) {
	got, err := keyPasswordSource(proton.TwoPasswordMode, Credentials{Password: "login-pw", MailboxPassword: "mbox-pw"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "mbox-pw" {
		t.Fatalf("two-password mode must use mailbox password, got %q", got)
	}
}

func TestKeyPasswordSourceTwoPasswordFallsBackToProvider(t *testing.T) {
	got, err := keyPasswordSource(proton.TwoPasswordMode, Credentials{
		Password:                "login-pw",
		MailboxPasswordProvider: func() (string, error) { return "from-prompt", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-prompt" {
		t.Fatalf("provider value expected, got %q", got)
	}
}

func TestKeyPasswordSourceTwoPasswordMissingErrors(t *testing.T) {
	_, err := keyPasswordSource(proton.TwoPasswordMode, Credentials{Password: "login-pw"})
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Code != ErrCodeMailboxPasswordRequired {
		t.Fatalf("want ErrCodeMailboxPasswordRequired, got %v", err)
	}
}
