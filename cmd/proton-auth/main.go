// Command proton-auth is a thin CLI over the protonauth library. It performs
// Proton SRP authentication (solving a CAPTCHA in the browser when required)
// and emits the resulting tokens as JSON, for consumption by non-Go clients.
//
// JSON contract (stdout, or the file given by -o): on success the object has
// accessToken, refreshToken, uid, userID, keyPassword and expiresAt. On failure
// it has error (human-readable) and errorCode (see the protonauth ErrCode*
// constants). The process exits non-zero on failure.
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
	"strings"
	"syscall"
	"time"

	protonauth "github.com/Arsylk/proton-auth"
	"golang.org/x/term"
)

// AuthResult is the JSON output structure. Field names are the stable contract
// relied on by downstream (TypeScript) consumers; do not rename them.
type AuthResult struct {
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
	outputPath := flag.String("o", "", "Output file path (if not specified, outputs to stdout)")
	username := flag.String("username", "", "Proton username (email); non-interactive when set (env PROTON_AUTH_USERNAME)")
	password := flag.String("password", "", "Proton password; non-interactive when set (env PROTON_AUTH_PASSWORD)")
	totpCode := flag.String("totp", "", "Current TOTP code for 2FA (env PROTON_AUTH_TOTP)")
	totpSecret := flag.String("totp-secret", "", "Base32 TOTP secret to auto-generate 2FA codes (env PROTON_AUTH_TOTP_SECRET)")
	mailboxPassword := flag.String("mailbox-password", "", "Second (mailbox) password for two-password-mode accounts (env PROTON_AUTH_MAILBOX_PASSWORD)")
	appVersion := flag.String("app-version", protonauth.DefaultAppVersion, "X-PM-AppVersion header value")
	userAgent := flag.String("user-agent", protonauth.DefaultUserAgent, "User-Agent header value")
	captchaAutoOpen := flag.Bool("captcha-auto-open", true, "Open the browser automatically when a CAPTCHA is required")
	captchaTest := flag.Bool("captcha-test", false, "Open Proton's CAPTCHA in a browser without logging in (smoke test), then exit")
	proxyURL := flag.String("proxy", "", "Route Proton requests (login and CAPTCHA solve) through this proxy, e.g. http://user:pass@host:port, so they share one IP")
	fallbackExpiryHours := flag.Int("expiry-fallback-hours", 12, "expiresAt margin (hours from now) used only when Proton does not report a token lifetime")
	flag.Parse()

	if *captchaTest {
		os.Exit(runCaptchaTest(os.Stderr))
	}

	// Credential inputs: flags take precedence over environment. Passwords are
	// kept byte-exact (they may begin or end with whitespace).
	suppliedUser := firstNonEmpty(*username, os.Getenv("PROTON_AUTH_USERNAME"))
	suppliedPass := firstNonEmptyExact(*password, os.Getenv("PROTON_AUTH_PASSWORD"))

	reader := bufio.NewReader(os.Stdin)
	user, pass, interactive, err := resolveCredentials(reader, suppliedUser, suppliedPass)
	if err != nil {
		writeResult(*outputPath, AuthResult{Error: err.Error(), ErrorCode: 1000})
		os.Exit(1)
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
		creds.TOTPProvider = func() (string, error) {
			fmt.Fprint(os.Stderr, "2FA TOTP code: ")
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("failed to read TOTP")
			}
			return strings.TrimSpace(line), nil
		}
		creds.MailboxPasswordProvider = func() (string, error) {
			fmt.Fprint(os.Stderr, "Mailbox password (second password): ")
			mboxBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", fmt.Errorf("failed to read mailbox password")
			}
			return string(mboxBytes), nil
		}
	}

	opts := protonauth.Options{
		AppVersion:      *appVersion,
		UserAgent:       *userAgent,
		ProxyURL:        *proxyURL,
		CaptchaAutoOpen: *captchaAutoOpen,
		Output:          os.Stderr, // library CAPTCHA instructions go to stderr
	}

	result, err := protonauth.Login(context.Background(), opts, creds)
	if err != nil {
		writeResult(*outputPath, errorResult(err))
		os.Exit(1)
	}

	writeResult(*outputPath, AuthResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		UID:          result.UID,
		UserID:       result.UserID,
		KeyPassword:  result.KeyPassword,
		ExpiresAt:    expiresAt(result.ExpiresIn, *fallbackExpiryHours),
		PasswordMode: result.PasswordMode,
	})
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

// resolveCredentials returns the username/password to use, prompting on stdin
// for whatever was not supplied. interactive reports whether either prompt ran,
// which decides whether a missing 2FA code is prompted for or treated as fatal.
func resolveCredentials(reader *bufio.Reader, suppliedUser, suppliedPass string) (user, pass string, interactive bool, err error) {
	user, pass = suppliedUser, suppliedPass
	if user != "" && pass != "" {
		return user, pass, false, nil
	}

	if user == "" {
		fmt.Fprint(os.Stderr, "Proton username (email): ")
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return "", "", true, fmt.Errorf("failed to read username")
		}
		user = strings.TrimSpace(line)
	}
	if pass == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		passwordBytes, readErr := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if readErr != nil {
			return "", "", true, fmt.Errorf("failed to read password")
		}
		pass = string(passwordBytes)
	}
	return user, pass, true, nil
}

// runCaptchaTest drives the library's CAPTCHA smoke test and reports an exit code.
func runCaptchaTest(out io.Writer) int {
	token, err := protonauth.RunCaptchaTest(context.Background(), out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "captcha test ended: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Received captcha token: %s\n", token)
	return 0
}

// errorResult maps a protonauth error onto the JSON contract, preserving the
// typed error code when present.
func errorResult(err error) AuthResult {
	var authErr *protonauth.AuthError
	if errors.As(err, &authErr) {
		return AuthResult{Error: authErr.Message, ErrorCode: authErr.Code}
	}
	return AuthResult{Error: err.Error(), ErrorCode: protonauth.ErrCodeLogin}
}

func writeResult(outputPath string, result AuthResult) {
	output, _ := json.MarshalIndent(result, "", "  ")
	if outputPath != "" {
		if err := os.WriteFile(outputPath, output, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Auth tokens written to %s\n", outputPath)
		return
	}
	fmt.Println(string(output))
}

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
