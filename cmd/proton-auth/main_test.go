package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	protonauth "github.com/Arsylk/proton-auth"
	"github.com/henrybear327/go-proton-api/server"
)

// TestMain lets the test binary double as the CLI: when re-executed with
// PROTON_AUTH_TEST_RUN_MAIN=1 it runs main's run() instead of the tests, so
// the end-to-end tests below exercise flag parsing, stdin handling, the JSON
// contract and exit codes exactly as a user would see them.
func TestMain(m *testing.M) {
	if os.Getenv("PROTON_AUTH_TEST_RUN_MAIN") == "1" {
		os.Exit(run())
	}
	os.Exit(m.Run())
}

const (
	fakeUser     = "alice"
	fakePassword = "hunter2"
)

var fake struct {
	once sync.Once
	dev  *server.Server
	err  error
}

// fakeHostURL returns a go-proton-api development server with one user,
// created once per test binary because key generation is slow.
func fakeHostURL(t *testing.T) string {
	t.Helper()
	fake.once.Do(func() {
		fake.dev = server.New(server.WithTLS(false))
		_, _, fake.err = fake.dev.CreateUser(fakeUser, []byte(fakePassword))
	})
	if fake.err != nil {
		t.Fatalf("fake proton: %v", fake.err)
	}
	return fake.dev.GetHostURL()
}

// runCLI runs the CLI with args and stdin, with every PROTON_AUTH_* variable
// cleared unless given in env, and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, stdin string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(),
		"PROTON_AUTH_TEST_RUN_MAIN=1",
		"PROTON_AUTH_USERNAME=", "PROTON_AUTH_PASSWORD=", "PROTON_AUTH_TOTP=",
		"PROTON_AUTH_TOTP_SECRET=", "PROTON_AUTH_MAILBOX_PASSWORD=",
	)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running CLI: %v", err)
	}
	return out.String(), errOut.String(), code
}

func parseResult(t *testing.T, stdout string) authResult {
	t.Helper()
	var r authResult
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("stdout is not the JSON contract: %v\n%s", err, stdout)
	}
	return r
}

func TestCLIVersion(t *testing.T) {
	stdout, _, code := runCLI(t, "", nil, "-version")
	if code != 0 || !strings.HasPrefix(stdout, "proton-auth ") {
		t.Errorf("-version: code=%d stdout=%q", code, stdout)
	}
}

func TestCLIPasswordStdinRequiresUsername(t *testing.T) {
	stdout, _, code := runCLI(t, "hunter2\n", nil, "-password-stdin")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	r := parseResult(t, stdout)
	if r.ErrorCode != errCodeCredentials || r.Error == "" {
		t.Errorf("result = %+v, want errorCode %d", r, errCodeCredentials)
	}
}

func TestCLIEndToEnd(t *testing.T) {
	host := fakeHostURL(t)

	t.Run("password on stdin", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, fakePassword+"\n", nil,
			"-host-url", host, "-username", fakeUser, "-password-stdin", "-captcha-auto-open=false")
		if code != 0 {
			t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		r := parseResult(t, stdout)
		if r.AccessToken == "" || r.RefreshToken == "" || r.UID == "" || r.UserID == "" || r.KeyPassword == "" {
			t.Errorf("tokens missing: %+v", r)
		}
		if r.PasswordMode != 1 || r.Error != "" || r.ErrorCode != 0 {
			t.Errorf("unexpected fields: %+v", r)
		}
		if _, err := time.Parse(time.RFC3339, r.ExpiresAt); err != nil {
			t.Errorf("expiresAt = %q: %v", r.ExpiresAt, err)
		}
		if strings.Contains(stderr, "Password:") {
			t.Errorf("-password-stdin must not prompt; stderr: %s", stderr)
		}
	})

	t.Run("credentials from the environment", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "", []string{"PROTON_AUTH_USERNAME=" + fakeUser, "PROTON_AUTH_PASSWORD=" + fakePassword},
			"-host-url", host, "-captcha-auto-open=false")
		if code != 0 {
			t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		if r := parseResult(t, stdout); r.AccessToken == "" {
			t.Errorf("no access token: %+v", r)
		}
	})

	t.Run("prompts on a pipe", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, fakeUser+"\n"+fakePassword+"\n", nil, "-host-url", host, "-captcha-auto-open=false")
		if code != 0 {
			t.Fatalf("exit code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		if !strings.Contains(stderr, "Proton username") || !strings.Contains(stderr, "Password:") {
			t.Errorf("prompts missing from stderr: %s", stderr)
		}
		if r := parseResult(t, stdout); r.AccessToken == "" {
			t.Errorf("no access token: %+v", r)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		stdout, _, code := runCLI(t, "", []string{"PROTON_AUTH_USERNAME=" + fakeUser, "PROTON_AUTH_PASSWORD=nope"},
			"-host-url", host, "-captcha-auto-open=false")
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		r := parseResult(t, stdout)
		if r.ErrorCode != int(protonauth.ErrCodeLogin) || r.Error == "" || r.AccessToken != "" {
			t.Errorf("result = %+v", r)
		}
	})

	t.Run("output file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tokens.json")
		stdout, stderr, code := runCLI(t, "", []string{"PROTON_AUTH_USERNAME=" + fakeUser, "PROTON_AUTH_PASSWORD=" + fakePassword},
			"-host-url", host, "-captcha-auto-open=false", "-o", path)
		if code != 0 {
			t.Fatalf("exit code = %d\nstderr: %s", code, stderr)
		}
		if stdout != "" {
			t.Errorf("stdout must be empty with -o: %q", stdout)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if r := parseResult(t, string(data)); r.AccessToken == "" {
			t.Errorf("file lacks tokens: %s", data)
		}
	})

	// A failed re-login must not replace the tokens an earlier run saved
	// with an error object; the error goes to stdout and stderr instead.
	t.Run("failure leaves the output file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tokens.json")
		const previous = `{"accessToken": "still-valid"}` + "\n"
		if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := runCLI(t, "", []string{"PROTON_AUTH_USERNAME=" + fakeUser, "PROTON_AUTH_PASSWORD=nope"},
			"-host-url", host, "-captcha-auto-open=false", "-o", path)
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != previous {
			t.Errorf("the failure overwrote the output file:\n%s", data)
		}
		if r := parseResult(t, stdout); r.ErrorCode != int(protonauth.ErrCodeLogin) || r.Error == "" {
			t.Errorf("stdout should carry the error JSON: %+v", r)
		}
		if !strings.Contains(stderr, "left untouched") {
			t.Errorf("stderr should say the file was left alone:\n%s", stderr)
		}
	})

	t.Run("unwritable output file exits non-zero", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "tokens.json")
		_, stderr, code := runCLI(t, "", []string{"PROTON_AUTH_USERNAME=" + fakeUser, "PROTON_AUTH_PASSWORD=" + fakePassword},
			"-host-url", host, "-captcha-auto-open=false", "-o", path)
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr, "writing result") {
			t.Errorf("stderr should explain the write failure: %s", stderr)
		}
	})
}

func newTestPrompter(stdin string) (*prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &prompter{in: bufio.NewReader(strings.NewReader(stdin)), out: &out, terminal: false}, &out
}

func TestFirstNonEmptyTrimsNonSecretInput(t *testing.T) {
	if got := firstNonEmpty("  ", "  user@example.test  "); got != "user@example.test" {
		t.Fatalf("firstNonEmpty() = %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("firstNonEmpty() = %q", got)
	}
}

func TestFirstNonEmptyExactPreservesPasswordWhitespace(t *testing.T) {
	if got := firstNonEmptyExact("", "  password with spaces  "); got != "  password with spaces  " {
		t.Fatalf("firstNonEmptyExact() = %q", got)
	}
}

func TestExpiresAtUsesProtonValue(t *testing.T) {
	got := expiresAt(3600, 12) // 1h from Proton, ignore fallback
	ts, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("not RFC3339: %q (%v)", got, err)
	}
	delta := time.Until(ts)
	if delta < 59*time.Minute || delta > 61*time.Minute {
		t.Fatalf("expiry ~1h expected, got %v", delta)
	}
}

func TestExpiresAtFallsBackWhenUnknown(t *testing.T) {
	got := expiresAt(0, 12) // no Proton value -> 12h fallback
	ts, _ := time.Parse(time.RFC3339, got)
	delta := time.Until(ts)
	if delta < 11*time.Hour+59*time.Minute || delta > 12*time.Hour+1*time.Minute {
		t.Fatalf("fallback ~12h expected, got %v", delta)
	}
}

func TestResolveCredentialsNonInteractive(t *testing.T) {
	p, out := newTestPrompter("should not be read\n")
	user, pass, interactive, err := resolveCredentials(t.Context(), p, "alice", " s3cret ", false)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != " s3cret " || interactive {
		t.Errorf("got %q, %q, interactive=%v", user, pass, interactive)
	}
	if out.Len() != 0 {
		t.Errorf("prompted although both values were supplied: %q", out.String())
	}
}

func TestResolveCredentialsPromptsFromPipe(t *testing.T) {
	p, out := newTestPrompter("  alice@example.test \r\nhunter2 \n")
	user, pass, interactive, err := resolveCredentials(t.Context(), p, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice@example.test" {
		t.Errorf("username = %q (should be trimmed)", user)
	}
	if pass != "hunter2 " {
		t.Errorf("password = %q (trailing whitespace must be kept, newline dropped)", pass)
	}
	if !interactive {
		t.Error("prompting must report interactive mode")
	}
	for _, want := range []string{"Proton username", "Password:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt output missing %q: %q", want, out.String())
		}
	}
}

func TestResolveCredentialsPromptsOnlyForMissingValue(t *testing.T) {
	p, out := newTestPrompter("hunter2\n")
	user, pass, interactive, err := resolveCredentials(t.Context(), p, "alice", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != "hunter2" || !interactive {
		t.Errorf("got %q, %q, interactive=%v", user, pass, interactive)
	}
	if strings.Contains(out.String(), "username") {
		t.Errorf("username was prompted for although supplied: %q", out.String())
	}
}

func TestResolveCredentialsLastLineWithoutNewline(t *testing.T) {
	p, _ := newTestPrompter("hunter2")
	_, pass, _, err := resolveCredentials(t.Context(), p, "alice", "", false)
	if err != nil || pass != "hunter2" {
		t.Fatalf("got %q, %v", pass, err)
	}
}

func TestResolveCredentialsEmptyStdin(t *testing.T) {
	ctx := t.Context()
	p, _ := newTestPrompter("")
	if _, _, _, err := resolveCredentials(ctx, p, "", "", false); err == nil {
		t.Error("expected an error when stdin is exhausted")
	}
	p, _ = newTestPrompter("\n")
	if _, _, _, err := resolveCredentials(ctx, p, "", "", false); err == nil {
		t.Error("expected an error for an empty username")
	}
	p, _ = newTestPrompter("\n")
	if _, _, _, err := resolveCredentials(ctx, p, "alice", "", false); err == nil {
		t.Error("expected an error for an empty password")
	}
}

func TestResolveCredentialsPasswordStdin(t *testing.T) {
	ctx := t.Context()
	p, out := newTestPrompter("s3cret \nignored\n")
	user, pass, interactive, err := resolveCredentials(ctx, p, "alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != "s3cret " || interactive {
		t.Errorf("got %q, %q, interactive=%v", user, pass, interactive)
	}
	if out.Len() != 0 {
		t.Errorf("-password-stdin must not prompt: %q", out.String())
	}

	p, _ = newTestPrompter("s3cret\n")
	if _, _, _, err := resolveCredentials(ctx, p, "", "", true); err == nil {
		t.Error("-password-stdin without a username must fail")
	}
	p, _ = newTestPrompter("\n")
	if _, _, _, err := resolveCredentials(ctx, p, "alice", "", true); err == nil {
		t.Error("-password-stdin with an empty line must fail")
	}
}

// A prompt blocked on stdin must give up when ctx ends (Ctrl-C), instead of
// holding the process until the user presses Enter.
func TestPromptAbortsWhenContextEnds(t *testing.T) {
	pr, pw := io.Pipe() // nothing is ever written: a user who never types
	defer pw.Close()
	var out bytes.Buffer
	p := &prompter{in: bufio.NewReader(pr), out: &out, terminal: false}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.secret(ctx, "Password: ")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the prompt did not return promptly after ctx ended")
	}
	if !strings.Contains(out.String(), "Password:") {
		t.Errorf("prompt not shown: %q", out.String())
	}

	_, _, _, err = resolveCredentials(ctx, p, "alice", "", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("resolveCredentials under an ended ctx = %v, want the context error", err)
	}
}

func TestErrorResult(t *testing.T) {
	typed := &protonauth.AuthError{Code: protonauth.ErrCode2FARequired, Message: "need 2fa"}
	if got := errorResult(typed); got.Error != "need 2fa" || got.ErrorCode != 1002 {
		t.Errorf("typed error mapped to %+v", got)
	}
	if got := errorResult(errors.New("boom")); got.Error != "boom" || got.ErrorCode != 1001 {
		t.Errorf("plain error mapped to %+v", got)
	}
}

func TestWriteResultStdout(t *testing.T) {
	var out bytes.Buffer
	err := writeResult(&out, "", authResult{AccessToken: "a", RefreshToken: "r", UID: "u", UserID: "id", KeyPassword: "k", ExpiresAt: "t", PasswordMode: 1})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	for _, key := range []string{"accessToken", "refreshToken", "uid", "userID", "keyPassword", "expiresAt", "passwordMode"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON contract missing %q: %s", key, out.String())
		}
	}
	if _, ok := m["error"]; ok {
		t.Error("error must be omitted on success")
	}
	if !strings.HasSuffix(out.String(), "\n") {
		t.Error("output should end with a newline")
	}
}

func TestWriteResultErrorShape(t *testing.T) {
	var out bytes.Buffer
	if err := writeResult(&out, "", authResult{Error: "nope", ErrorCode: 1001}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "nope" || m["errorCode"] != float64(1001) {
		t.Errorf("error JSON = %v", m)
	}
	if _, ok := m["accessToken"]; !ok {
		t.Error("accessToken key is part of the contract even when empty")
	}
}

func TestWriteResultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	var out bytes.Buffer
	if err := writeResult(&out, path, authResult{AccessToken: "a"}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty when writing to a file: %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"accessToken": "a"`) {
		t.Errorf("file content = %s", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file mode = %o, want 0600", perm)
		}
	}
}

func TestWriteResultFileFailureIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "tokens.json")
	err := writeResult(&bytes.Buffer{}, path, authResult{AccessToken: "a"})
	if err == nil {
		t.Fatal("an unwritable output path must be an error, not a silent success")
	}
}

func TestBuildVersion(t *testing.T) {
	if v := buildVersion(); v == "" {
		t.Error("buildVersion() must not be empty")
	}
	original := version
	version = "v9.9.9"
	t.Cleanup(func() { version = original })
	if v := buildVersion(); v != "v9.9.9" {
		t.Errorf("ldflags version not honoured: %q", v)
	}
}

// -captcha-test with the browser disabled must print the local URL, wait for
// the configured timeout, and exit 1 when nobody solves the widget. No request
// leaves the machine unless the page is opened.
func TestCLICaptchaTestHeadless(t *testing.T) {
	stdout, stderr, code := runCLI(t, "", nil, "-captcha-test", "-captcha-auto-open=false", "-captcha-timeout", "100ms")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr:\n%s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("captcha test wrote to stdout: %q", stdout)
	}
	for _, want := range []string{"http://127.0.0.1:", "captcha test ended: timed out waiting for the CAPTCHA after 100ms"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestRunCaptchaTestRejectsBadProxy(t *testing.T) {
	var out bytes.Buffer
	code := runCaptchaTest(t.Context(), &out, protonauth.CaptchaOptions{ProxyURL: "http://bob:Sup3r Secret@proxy.example:1"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "invalid proxy URL") || strings.Contains(out.String(), "Sup3r") {
		t.Errorf("output = %q, want an invalid proxy message without the password", out.String())
	}
}

func TestRunCaptchaTestStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	code := runCaptchaTest(ctx, &out, protonauth.CaptchaOptions{})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "captcha test ended: context canceled") {
		t.Errorf("output = %q, want the cancellation reported", out.String())
	}
}

// The 0600 promise must hold for a file that already exists with a looser
// mode, since OpenFile's mode applies only on creation.
func TestWriteResultFileTightensExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeResult(nil, path, authResult{AccessToken: "a"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"accessToken": "a"`) || strings.Contains(string(data), "old") {
		t.Errorf("file not replaced: %q", data)
	}
}
