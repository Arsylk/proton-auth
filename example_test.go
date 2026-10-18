package protonauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	protonauth "github.com/Arsylk/proton-auth"
)

// Log in with a username, password and (if the account has 2FA) a TOTP secret.
// A CAPTCHA, if Proton demands one, is opened in the browser and its
// instructions are written to stderr.
func ExampleLogin() {
	res, err := protonauth.Login(context.Background(), protonauth.Options{
		CaptchaAutoOpen: true,
		Output:          os.Stderr,
	}, protonauth.Credentials{
		Username:   os.Getenv("PROTON_USERNAME"),
		Password:   os.Getenv("PROTON_PASSWORD"),
		TOTPSecret: os.Getenv("PROTON_TOTP_SECRET"), // optional
	})
	if err != nil {
		log.Fatal(err)
	}

	// Every field of res is a secret; store them accordingly.
	fmt.Println(res.UID, res.AccessToken, res.RefreshToken, res.KeyPassword)
	fmt.Println("expires in", res.ExpiresIn, "seconds")
}

// Branch on the stable error code, and reach the underlying go-proton-api
// error through errors.As when more detail is needed.
func ExampleAuthError() {
	_, err := protonauth.Login(context.Background(), protonauth.Options{}, protonauth.Credentials{
		Username: "someone@proton.me",
		Password: "wrong",
	})

	if authErr, ok := errors.AsType[*protonauth.AuthError](err); ok {
		switch authErr.Code {
		case protonauth.ErrCode2FARequired:
			fmt.Println("ask the user for a 2FA code and retry")
		case protonauth.ErrCodeMailboxPasswordRequired:
			fmt.Println("ask the user for the mailbox password and retry")
		case protonauth.ErrCodeCaptcha, protonauth.ErrCodeConnection:
			fmt.Println("nothing wrong with the credentials; retry later:", authErr.Message)
		case protonauth.ErrCodeLogin:
			fmt.Println("Proton rejected the credentials:", authErr.Message)
		default:
			fmt.Println(authErr.Code, "-", authErr.Message)
		}
	}
}

// Supply the 2FA code and the mailbox password on demand. The providers
// receive Login's ctx; returning its error when it ends makes Login fail with
// ErrCodeCancelled instead of blaming a missing value.
func ExampleCredentials_providers() {
	creds := protonauth.Credentials{
		Username: os.Getenv("PROTON_USERNAME"),
		Password: os.Getenv("PROTON_PASSWORD"),
		TOTPProvider: func(ctx context.Context) (string, error) {
			return askUser(ctx, "2FA code")
		},
		MailboxPasswordProvider: func(ctx context.Context) (string, error) {
			return askUser(ctx, "mailbox password")
		},
	}
	if _, err := protonauth.Login(context.Background(), protonauth.Options{}, creds); err != nil {
		log.Fatal(err)
	}
}

// askUser stands in for a prompt that gives up when ctx ends.
func askUser(ctx context.Context, what string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
		return os.Getenv("PROTON_" + what), nil
	}
}

// Render the CAPTCHA prompt yourself (a GUI, a chat bot, a daemon) instead of
// relying on the text written to Output. The page stays up until the CAPTCHA
// is solved or Options.CaptchaTimeout elapses.
func ExampleLogin_onCaptchaPrompt() {
	opts := protonauth.Options{
		OnCaptchaPrompt: func(p protonauth.CaptchaPrompt) {
			fmt.Printf("open %s to solve the CAPTCHA for %s (port %d)\n", p.URL, p.Account, p.Port)
		},
	}
	_, err := protonauth.Login(context.Background(), opts, protonauth.Credentials{
		Username: os.Getenv("PROTON_USERNAME"),
		Password: os.Getenv("PROTON_PASSWORD"),
	})
	if err != nil {
		log.Fatal(err)
	}
}

// Consumers that drive their own login against a different go-proton-api fork
// only need the CAPTCHA solver: take the HumanVerificationToken from the
// Code=9001 response, obtain a verification token, and retry the login with
// the two X-Pm-Human-Verification-Token headers set.
func ExampleSolveCaptcha() {
	hvToken := "HumanVerificationToken from the Code=9001 error details"

	token, err := protonauth.SolveCaptcha(context.Background(), hvToken, protonauth.CaptchaOptions{
		Account:  "someone@proton.me",
		AutoOpen: true,
		Output:   os.Stderr,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Retry your login from the same IP with:
	//   X-Pm-Human-Verification-Token:      token
	//   X-Pm-Human-Verification-Token-Type: captcha
	fmt.Println(token)
}
