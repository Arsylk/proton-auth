package protonauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	proton "github.com/henrybear327/go-proton-api"
	"github.com/henrybear327/go-proton-api/server"
)

const (
	fakeUser     = "alice"
	fakePassword = "hunter2"
	fakeTOTP     = "123456"
	fakeHVToken  = "hv-token-123"
	// RFC 6238 test secret.
	fakeTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// fakeProton fronts go-proton-api's development server with an interception
// layer adding what that server lacks: human-verification (Code=9001)
// challenges, 2FA, PasswordMode/ExpiresIn on the auth response, and a few
// induced failures.
type fakeProton struct {
	t      *testing.T
	front  *httptest.Server
	userID string

	mu sync.Mutex
	// Knobs, set before Login.
	captchaMethods []string           // non-nil: a login without a HV token gets a 9001 offering these methods
	rejectHVToken  bool               // answer 9001 even when the login carries a token
	twoFA          proton.TwoFAStatus // the account's second factors; /auth/v4/2fa accepts codes for which accept2FA is true
	accept2FA      func(string) bool  // nil accepts nothing
	passwordMode   int                // 0 keeps the dev server's value (1)
	expiresIn      int                // 0 omits ExpiresIn
	failGetUser    bool               // answer GET /core/v4/users with a 500

	// Observations.
	hvTokens    []string // X-Pm-Human-Verification-Token on each POST /auth/v4
	hvTypes     []string
	twoFACodes  []string
	appVersions []string
	userAgents  []string
	authDeletes int // DELETE /auth/v4 calls, i.e. sessions revoked
}

// shared is the one go-proton-api development server for the whole test
// binary: creating a user generates keys, which is too slow to repeat per
// test. Each test still gets its own fronting server with its own knobs.
var shared struct {
	dev    *server.Server
	userID string
}

func TestMain(m *testing.M) {
	shared.dev = server.New(server.WithTLS(false))
	userID, _, err := shared.dev.CreateUser(fakeUser, []byte(fakePassword))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake proton: create user:", err)
		os.Exit(1)
	}
	shared.userID = userID
	code := m.Run()
	shared.dev.Close()
	os.Exit(code)
}

func newFakeProton(t *testing.T) *fakeProton {
	t.Helper()
	f := &fakeProton{t: t, userID: shared.userID}

	target, err := url.Parse(shared.dev.GetHostURL())
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		ModifyResponse: f.modifyAuthResponse,
	}
	f.front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.appVersions = append(f.appVersions, r.Header.Get("X-Pm-Appversion"))
		f.userAgents = append(f.userAgents, r.Header.Get("User-Agent"))
		f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4":
			if f.interceptLogin(w, r) {
				return
			}
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4/2fa":
			f.handle2FA(w, r)
			return
		case r.Method == http.MethodDelete && r.URL.Path == "/auth/v4":
			f.mu.Lock()
			f.authDeletes++
			f.mu.Unlock()
		case r.Method == http.MethodGet && r.URL.Path == "/core/v4/users":
			f.mu.Lock()
			fail := f.failGetUser
			f.mu.Unlock()
			if fail {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"Code": 5000, "Error": "user service unavailable"})
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(f.front.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// interceptLogin records the verification headers and answers with a 9001
// when a CAPTCHA is demanded and the request carries no (accepted) token.
func (f *fakeProton) interceptLogin(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("X-Pm-Human-Verification-Token")
	f.mu.Lock()
	f.hvTokens = append(f.hvTokens, token)
	f.hvTypes = append(f.hvTypes, r.Header.Get("X-Pm-Human-Verification-Token-Type"))
	methods, reject := f.captchaMethods, f.rejectHVToken
	f.mu.Unlock()
	if methods == nil || (token != "" && !reject) {
		return false
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"Code":  proton.HumanVerificationRequired,
		"Error": "Human verification required",
		"Details": map[string]any{
			"HumanVerificationToken":   fakeHVToken,
			"HumanVerificationMethods": methods,
		},
	})
	return true
}

func (f *fakeProton) handle2FA(w http.ResponseWriter, r *http.Request) {
	var req struct{ TwoFactorCode string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.twoFACodes = append(f.twoFACodes, req.TwoFactorCode)
	accept := f.accept2FA
	f.mu.Unlock()
	if accept != nil && accept(req.TwoFactorCode) {
		writeJSON(w, http.StatusOK, map[string]any{"Code": proton.SuccessCode})
		return
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
		"Code":  proton.PasswordWrong,
		"Error": "Incorrect login credentials. Please try again",
	})
}

// modifyAuthResponse decorates a successful /auth/v4 response with the
// fields the dev server never sets.
func (f *fakeProton) modifyAuthResponse(res *http.Response) error {
	if res.Request.Method != http.MethodPost || res.Request.URL.Path != "/auth/v4" || res.StatusCode != http.StatusOK {
		return nil
	}
	f.mu.Lock()
	twoFA, mode, exp := f.twoFA, f.passwordMode, f.expiresIn
	f.mu.Unlock()
	if twoFA == 0 && mode == 0 && exp == 0 {
		return nil
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}
	if twoFA != 0 {
		m["2FA"] = map[string]any{"Enabled": int(twoFA)}
	}
	if mode != 0 {
		m["PasswordMode"] = mode
	}
	if exp != 0 {
		m["ExpiresIn"] = exp
	}
	out, err := json.Marshal(m)
	if err != nil {
		return err
	}
	res.Body = io.NopCloser(bytes.NewReader(out))
	res.ContentLength = int64(len(out))
	res.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

func (f *fakeProton) options() Options {
	return Options{HostURL: f.front.URL, CaptchaTimeout: 5 * time.Second}
}

// revoked returns how many sessions were revoked (DELETE /auth/v4) so far.
func (f *fakeProton) revoked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authDeletes
}

// assertRevoked fails unless exactly want sessions were revoked.
func (f *fakeProton) assertRevoked(t *testing.T, want int) {
	t.Helper()
	if got := f.revoked(); got != want {
		t.Errorf("sessions revoked (DELETE /auth/v4) = %d, want %d", got, want)
	}
}

func fakeCreds() Credentials {
	return Credentials{Username: fakeUser, Password: fakePassword}
}

// solveOnPrompt acts as the browser: it delivers token to the solver page.
func solveOnPrompt(t *testing.T, token string) func(CaptchaPrompt) {
	return func(p CaptchaPrompt) {
		res, err := http.Post(p.URL+"submit", "text/plain", strings.NewReader(token))
		if err != nil {
			t.Error(err)
			return
		}
		res.Body.Close()
	}
}

// assertAuthError fails unless err is an *AuthError with the given code.
func assertAuthError(t *testing.T, err error, code ErrCode) *AuthError {
	t.Helper()
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v (%T), want *AuthError with code %d", err, err, int(code))
	}
	if authErr.Code != code {
		t.Fatalf("code = %d (%s), want %d (%s); message: %s", int(authErr.Code), authErr.Code, int(code), code, authErr.Message)
	}
	if authErr.Message == "" {
		t.Fatal("AuthError has an empty message")
	}
	return authErr
}

func TestLoginSucceeds(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.expiresIn = 86400

	res, err := Login(t.Context(), f.options(), fakeCreds())
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" || res.UID == "" {
		t.Errorf("tokens missing: %+v", res)
	}
	if res.UserID != f.userID {
		t.Errorf("UserID = %q, want %q", res.UserID, f.userID)
	}
	if res.KeyPassword == "" {
		t.Error("KeyPassword is empty")
	}
	if res.ExpiresIn != 86400 {
		t.Errorf("ExpiresIn = %d, want 86400", res.ExpiresIn)
	}
	if res.PasswordMode != PasswordModeOne {
		t.Errorf("PasswordMode = %v, want one-password", res.PasswordMode)
	}
	f.assertRevoked(t, 0)

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.appVersions) == 0 || f.appVersions[0] != DefaultAppVersion {
		t.Errorf("X-Pm-Appversion = %q, want %q", f.appVersions, DefaultAppVersion)
	}
	if f.userAgents[0] != DefaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", f.userAgents[0], DefaultUserAgent)
	}
	if len(f.twoFACodes) != 0 {
		t.Errorf("2FA was attempted on an account without it: %v", f.twoFACodes)
	}
}

func TestLoginKeyPasswordIsDeterministic(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	first, err := Login(t.Context(), f.options(), fakeCreds())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Login(t.Context(), f.options(), fakeCreds())
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyPassword != second.KeyPassword {
		t.Errorf("KeyPassword differs between logins: %q vs %q", first.KeyPassword, second.KeyPassword)
	}
	if first.ExpiresIn != 0 {
		t.Errorf("ExpiresIn = %d, want 0 when Proton omits it", first.ExpiresIn)
	}
}

func TestLoginHonoursHeaderOverrides(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	opts := f.options()
	opts.AppVersion = "test-app@1.0.0"
	opts.UserAgent = "test-agent/1.0"
	if _, err := Login(t.Context(), opts, fakeCreds()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.appVersions[0] != "test-app@1.0.0" || f.userAgents[0] != "test-agent/1.0" {
		t.Errorf("headers = %q / %q", f.appVersions[0], f.userAgents[0])
	}
}

func TestLoginRejectsEmptyCredentials(t *testing.T) {
	t.Parallel()
	for _, creds := range []Credentials{{}, {Username: fakeUser}, {Password: fakePassword}} {
		_, err := Login(t.Context(), Options{}, creds)
		assertAuthError(t, err, ErrCodeInvalidInput)
	}
}

// A malformed proxy URL is a caller error, and its message must not echo the
// URL: it may carry a password, which is often what makes it malformed.
func TestLoginRejectsInvalidProxy(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	opts := f.options()
	opts.ProxyURL = "http://alice:Sup3r Secret@proxy.example:8080"
	_, err := Login(t.Context(), opts, fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeInvalidInput)
	if !strings.Contains(authErr.Message, "invalid proxy URL") {
		t.Errorf("message = %q", authErr.Message)
	}
	if strings.Contains(authErr.Message, "Sup3r") || strings.Contains(err.Error(), "Sup3r") {
		t.Errorf("the proxy password leaked into the error: %q", authErr.Message)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.appVersions) != 0 {
		t.Error("a request reached Proton despite the invalid proxy URL")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	_, err := Login(t.Context(), f.options(), Credentials{Username: fakeUser, Password: "nope"})
	authErr := assertAuthError(t, err, ErrCodeLogin)
	// The development server answers a wrong password with a bad SRP server
	// proof rather than Proton's PasswordWrong; either way the cause is kept
	// and it is a verdict on the credentials, not a transport problem.
	if authErr.Err == nil {
		t.Error("AuthError.Err should carry the underlying error")
	}
	f.assertRevoked(t, 0) // nothing was issued, nothing to revoke
}

// Proton unreachable (here: a port nobody listens on) is neither a verdict on
// the credentials nor a CAPTCHA problem.
func TestLoginConnectionFailure(t *testing.T) {
	t.Parallel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	_, err = Login(t.Context(), Options{HostURL: "http://" + addr}, fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeConnection)
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Errorf("underlying *url.Error not reachable through Unwrap: %v", authErr.Err)
	}
	if !strings.Contains(authErr.Message, "could not reach Proton") {
		t.Errorf("message = %q", authErr.Message)
	}
}

func TestLoginCancelledBeforeStart(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Login(ctx, f.options(), fakeCreds())
	assertAuthError(t, err, ErrCodeCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err should wrap context.Canceled: %v", err)
	}
}

func TestLoginSolvesCaptcha(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha", "email"}

	var out bytes.Buffer
	var prompt CaptchaPrompt
	opts := f.options()
	opts.Output = &out
	opts.OnCaptchaPrompt = func(p CaptchaPrompt) {
		prompt = p
		solveOnPrompt(t, "solved-token")(p)
	}

	res, err := Login(t.Context(), opts, fakeCreds())
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" {
		t.Error("no access token after the CAPTCHA retry")
	}

	f.mu.Lock()
	hvTokens, hvTypes := f.hvTokens, f.hvTypes
	f.mu.Unlock()
	if len(hvTokens) != 2 || hvTokens[0] != "" || hvTokens[1] != "solved-token" {
		t.Errorf("verification tokens on /auth/v4 = %q, want [\"\" \"solved-token\"]", hvTokens)
	}
	if len(hvTypes) == 2 && hvTypes[1] != "captcha" {
		t.Errorf("token type on retry = %q, want captcha", hvTypes[1])
	}

	if prompt.Account != fakeUser || prompt.Port <= 0 || !strings.HasPrefix(prompt.URL, "http://127.0.0.1:") {
		t.Errorf("prompt = %+v", prompt)
	}
	text := out.String()
	for _, want := range []string{prompt.URL, "as " + fakeUser, "CAPTCHA solved."} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
}

func TestLoginCaptchaPageEmbedsToken(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}

	opts := f.options()
	opts.OnCaptchaPrompt = func(p CaptchaPrompt) {
		res, err := http.Get(p.URL)
		if err != nil {
			t.Error(err)
			return
		}
		page, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !strings.Contains(string(page), "Token="+fakeHVToken) {
			t.Errorf("solver page does not reference the HumanVerificationToken:\n%s", page)
		}
		solveOnPrompt(t, "ok")(p)
	}
	if _, err := Login(t.Context(), opts, fakeCreds()); err != nil {
		t.Fatal(err)
	}
}

// The CAPTCHA is solved first and then the retried login reports 2FA: both
// steps must run, in that order, on the one session.
func TestLoginCaptchaThen2FA(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}
	f.twoFA = proton.HasTOTP
	f.accept2FA = func(code string) bool { return code == fakeTOTP }

	opts := f.options()
	opts.OnCaptchaPrompt = solveOnPrompt(t, "solved-token")
	creds := fakeCreds()
	creds.TOTPCode = fakeTOTP
	if _, err := Login(t.Context(), opts, creds); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hvTokens) != 2 || f.hvTokens[1] != "solved-token" {
		t.Errorf("verification tokens on /auth/v4 = %q", f.hvTokens)
	}
	if len(f.twoFACodes) != 1 || f.twoFACodes[0] != fakeTOTP {
		t.Errorf("2FA codes submitted = %v, want [%s]", f.twoFACodes, fakeTOTP)
	}
}

func TestLoginCaptchaNotOffered(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"email"}

	_, err := Login(t.Context(), f.options(), fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeCaptcha)
	if !strings.Contains(authErr.Message, "CAPTCHA is not offered") || !strings.Contains(authErr.Message, "email") {
		t.Errorf("message = %q", authErr.Message)
	}
	var apiErr *proton.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proton.HumanVerificationRequired {
		t.Errorf("underlying APIError not reachable through Unwrap: %v", err)
	}
}

func TestLoginCaptchaTimeout(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}
	opts := f.options()
	opts.CaptchaTimeout = 50 * time.Millisecond

	_, err := Login(t.Context(), opts, fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeCaptcha)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err should wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(authErr.Message, "timed out") {
		t.Errorf("message = %q", authErr.Message)
	}
}

func TestLoginCaptchaCancelled(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	opts := f.options()
	opts.CaptchaTimeout = time.Minute
	opts.OnCaptchaPrompt = func(CaptchaPrompt) { cancel() }

	_, err := Login(ctx, opts, fakeCreds())
	assertAuthError(t, err, ErrCodeCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err should wrap context.Canceled: %v", err)
	}
}

// Proton answering the retry with another 9001 means the token was not
// accepted (typically: solved from a different IP). That is a CAPTCHA
// failure, not a credentials verdict.
func TestLoginCaptchaTokenRejected(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}
	f.rejectHVToken = true
	opts := f.options()
	opts.OnCaptchaPrompt = solveOnPrompt(t, "solved-token")

	_, err := Login(t.Context(), opts, fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeCaptcha)
	if !strings.Contains(authErr.Message, "did not accept") {
		t.Errorf("message = %q", authErr.Message)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hvTokens) != 2 || f.hvTokens[1] != "solved-token" {
		t.Errorf("verification tokens on /auth/v4 = %q, want the retry to carry the token once", f.hvTokens)
	}
}

// newForwardProxy is a minimal HTTP proxy: it forwards absolute-URL requests
// to their host and answers CONNECT (the TLS tunnel the CAPTCHA widget's real
// upstream needs) with a 502 after recording the target, so nothing leaves the
// machine. seen returns the forwarded request lines and the CONNECT targets.
func newForwardProxy(t *testing.T) (proxyURL string, seen func() (forwarded, connects []string)) {
	t.Helper()
	var mu sync.Mutex
	var forwarded, connects []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			mu.Lock()
			connects = append(connects, r.Host)
			mu.Unlock()
			http.Error(w, "no tunnels in tests", http.StatusBadGateway)
			return
		}
		mu.Lock()
		forwarded = append(forwarded, r.Method+" "+r.URL.String())
		mu.Unlock()
		out := r.Clone(r.Context())
		out.RequestURI = ""
		res, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		for k, vs := range res.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, res.Body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), forwarded...), append([]string(nil), connects...)
	}
}

// With ProxyURL set, every login request and the CAPTCHA widget's upstream
// traffic must leave through that proxy: Proton binds the verification token
// to the IP that solved the challenge.
func TestLoginThroughProxy(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.captchaMethods = []string{"captcha"}
	proxyURL, seen := newForwardProxy(t)

	opts := f.options()
	opts.ProxyURL = proxyURL
	opts.OnCaptchaPrompt = func(p CaptchaPrompt) {
		// Load the widget through the solver page's reverse proxy, as the
		// browser would; the local server must fetch it through the proxy.
		res, err := http.Get(p.URL + "core/v4/captcha?Token=" + fakeHVToken)
		if err == nil {
			res.Body.Close()
		}
		solveOnPrompt(t, "solved-token")(p)
	}
	res, err := Login(t.Context(), opts, fakeCreds())
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken == "" {
		t.Error("no access token")
	}

	forwarded, connects := seen()
	fakeHost := strings.TrimPrefix(f.front.URL, "http://")
	var logins int
	for _, line := range forwarded {
		if !strings.Contains(line, fakeHost) {
			t.Errorf("proxy forwarded a request to an unexpected host: %s", line)
		}
		if strings.HasSuffix(line, "/auth/v4") {
			logins++
		}
	}
	if logins != 2 {
		t.Errorf("POST /auth/v4 through the proxy = %d, want 2 (initial and retry); forwarded: %v", logins, forwarded)
	}
	if len(connects) == 0 || connects[0] != "mail-api.proton.me:443" {
		t.Errorf("the CAPTCHA widget was not fetched through the proxy: CONNECT targets = %v", connects)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hvTokens) != 2 || f.hvTokens[1] != "solved-token" {
		t.Errorf("verification tokens on /auth/v4 = %q", f.hvTokens)
	}
}

func TestLogin2FAWithStaticCode(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	f.accept2FA = func(code string) bool { return code == fakeTOTP }

	creds := fakeCreds()
	creds.TOTPCode = fakeTOTP
	if _, err := Login(t.Context(), f.options(), creds); err != nil {
		t.Fatal(err)
	}
	f.assertRevoked(t, 0)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.twoFACodes) != 1 || f.twoFACodes[0] != fakeTOTP {
		t.Errorf("2FA codes submitted = %v", f.twoFACodes)
	}
}

func TestLogin2FAWithSecret(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	// Accept the current and the previous 30-second window, so a step
	// boundary between generation and validation cannot flake the test.
	f.accept2FA = func(code string) bool {
		now := time.Now()
		for _, at := range []time.Time{now, now.Add(-30 * time.Second)} {
			if want, _ := generateTOTP(fakeTOTPSecret, at); want == code {
				return true
			}
		}
		return false
	}

	creds := fakeCreds()
	creds.TOTPSecret = fakeTOTPSecret
	if _, err := Login(t.Context(), f.options(), creds); err != nil {
		t.Fatal(err)
	}
}

type ctxMarker struct{}

func TestLogin2FAWithProvider(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	f.accept2FA = func(code string) bool { return code == fakeTOTP }

	calls := 0
	creds := fakeCreds()
	creds.TOTPProvider = func(ctx context.Context) (string, error) {
		calls++
		if ctx.Value(ctxMarker{}) != "login" {
			t.Error("provider did not receive Login's ctx")
		}
		return fakeTOTP, nil
	}
	ctx := context.WithValue(t.Context(), ctxMarker{}, "login")
	if _, err := Login(ctx, f.options(), creds); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("provider called %d times, want 1", calls)
	}
}

// Enabled is a bitmask. A security key alone is not something this package can
// satisfy and must say so rather than ask for a TOTP code; a key alongside
// TOTP changes nothing.
func TestLogin2FAMethods(t *testing.T) {
	t.Parallel()
	t.Run("FIDO2 only", func(t *testing.T) {
		t.Parallel()
		f := newFakeProton(t)
		f.twoFA = proton.HasFIDO2
		creds := fakeCreds()
		creds.TOTPCode = fakeTOTP
		_, err := Login(t.Context(), f.options(), creds)
		authErr := assertAuthError(t, err, ErrCode2FARequired)
		if !strings.Contains(authErr.Message, "not TOTP") {
			t.Errorf("message = %q", authErr.Message)
		}
		f.mu.Lock()
		codes := f.twoFACodes
		f.mu.Unlock()
		if len(codes) != 0 {
			t.Errorf("a TOTP code was submitted to a FIDO2-only account: %v", codes)
		}
		f.assertRevoked(t, 1)
	})
	t.Run("TOTP and FIDO2", func(t *testing.T) {
		t.Parallel()
		f := newFakeProton(t)
		f.twoFA = proton.HasTOTP | proton.HasFIDO2
		f.accept2FA = func(code string) bool { return code == fakeTOTP }
		creds := fakeCreds()
		creds.TOTPCode = fakeTOTP
		if _, err := Login(t.Context(), f.options(), creds); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLogin2FARequired(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP

	_, err := Login(t.Context(), f.options(), fakeCreds())
	assertAuthError(t, err, ErrCode2FARequired)
	f.assertRevoked(t, 1) // the half-authenticated session is not left behind
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.twoFACodes) != 0 {
		t.Errorf("a 2FA request was made without a code: %v", f.twoFACodes)
	}
}

func TestLogin2FAProviderError(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	sentinel := errors.New("authenticator unavailable")

	creds := fakeCreds()
	creds.TOTPProvider = func(context.Context) (string, error) { return "", sentinel }
	_, err := Login(t.Context(), f.options(), creds)
	assertAuthError(t, err, ErrCode2FARequired)
	if !errors.Is(err, sentinel) {
		t.Errorf("provider error not reachable through Unwrap: %v", err)
	}
	f.assertRevoked(t, 1)
}

// A provider that gives up because ctx ended (Ctrl-C at the prompt) is a
// cancellation, not a missing code, and the session is still revoked even
// though ctx is gone.
func TestLogin2FAProviderCancelled(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	creds := fakeCreds()
	creds.TOTPProvider = func(ctx context.Context) (string, error) {
		cancel()
		return "", fmt.Errorf("failed to read TOTP code: %w", ctx.Err())
	}
	_, err := Login(ctx, f.options(), creds)
	assertAuthError(t, err, ErrCodeCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err should wrap context.Canceled: %v", err)
	}
	f.assertRevoked(t, 1)
}

func TestLogin2FAMalformedSecret(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP

	creds := fakeCreds()
	creds.TOTPSecret = "not valid!"
	_, err := Login(t.Context(), f.options(), creds)
	authErr := assertAuthError(t, err, ErrCode2FARequired)
	if !strings.Contains(authErr.Message, "invalid TOTP secret") {
		t.Errorf("message = %q, want it to blame the secret", authErr.Message)
	}
}

func TestLogin2FARejected(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.twoFA = proton.HasTOTP
	f.accept2FA = func(string) bool { return false }

	creds := fakeCreds()
	creds.TOTPCode = "000000"
	_, err := Login(t.Context(), f.options(), creds)
	authErr := assertAuthError(t, err, ErrCode2FAFailed)
	if strings.Contains(authErr.Message, "422 POST") {
		t.Errorf("message still carries the transport prefix: %q", authErr.Message)
	}
	var apiErr *proton.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proton.PasswordWrong {
		t.Errorf("underlying APIError not reachable through Unwrap: %v", err)
	}
	f.assertRevoked(t, 1)
}

func TestLoginGetUserFails(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	f.failGetUser = true

	_, err := Login(t.Context(), f.options(), fakeCreds())
	authErr := assertAuthError(t, err, ErrCodeGetUser)
	if !strings.Contains(authErr.Message, "user service unavailable") {
		t.Errorf("message = %q, want Proton's own text", authErr.Message)
	}
	f.assertRevoked(t, 1)
}

func TestLoginTwoPasswordMode(t *testing.T) {
	t.Parallel()
	f := newFakeProton(t)
	onePassword, err := Login(t.Context(), f.options(), fakeCreds())
	if err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.passwordMode = 2
	f.mu.Unlock()

	t.Run("missing mailbox password", func(t *testing.T) {
		before := f.revoked()
		_, err := Login(t.Context(), f.options(), fakeCreds())
		assertAuthError(t, err, ErrCodeMailboxPasswordRequired)
		if got := f.revoked() - before; got != 1 {
			t.Errorf("sessions revoked = %d, want 1", got)
		}
	})

	// The development server encrypts the user's key with the login password,
	// so in two-password mode that password doubles as the correct mailbox
	// password and anything else is a wrong one.
	t.Run("wrong mailbox password is rejected", func(t *testing.T) {
		before := f.revoked()
		creds := fakeCreds()
		creds.MailboxPassword = "mailbox-secret"
		_, err := Login(t.Context(), f.options(), creds)
		assertAuthError(t, err, ErrCodeKeyPassword)
		if !strings.Contains(err.Error(), "mailbox password does not unlock") {
			t.Errorf("error = %q, want the mailbox password named", err)
		}
		if got := f.revoked() - before; got != 1 {
			t.Errorf("sessions revoked = %d, want 1: a fully authenticated session must not be left behind", got)
		}
	})

	t.Run("mailbox password unlocks the key", func(t *testing.T) {
		creds := fakeCreds()
		creds.MailboxPassword = fakePassword
		res, err := Login(t.Context(), f.options(), creds)
		if err != nil {
			t.Fatal(err)
		}
		if res.PasswordMode != PasswordModeTwo {
			t.Errorf("PasswordMode = %v, want two-password", res.PasswordMode)
		}
		if res.KeyPassword != onePassword.KeyPassword {
			t.Error("deriving from the same password should yield the same key password")
		}
	})

	t.Run("provider", func(t *testing.T) {
		calls := 0
		creds := fakeCreds()
		creds.MailboxPasswordProvider = func(context.Context) (string, error) { calls++; return fakePassword, nil }
		if _, err := Login(t.Context(), f.options(), creds); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("provider called %d times, want 1", calls)
		}
	})
}

func TestKeyPasswordSource(t *testing.T) {
	ctx := t.Context()
	t.Run("one-password uses login password", func(t *testing.T) {
		got, err := keyPasswordSource(ctx, PasswordModeOne, Credentials{Password: "login-pw", MailboxPassword: "ignored"})
		if err != nil || got != "login-pw" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("two-password uses mailbox password", func(t *testing.T) {
		got, err := keyPasswordSource(ctx, PasswordModeTwo, Credentials{Password: "login-pw", MailboxPassword: "mbox-pw"})
		if err != nil || got != "mbox-pw" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("two-password falls back to provider", func(t *testing.T) {
		got, err := keyPasswordSource(ctx, PasswordModeTwo, Credentials{
			Password:                "login-pw",
			MailboxPasswordProvider: func(context.Context) (string, error) { return "from-prompt", nil },
		})
		if err != nil || got != "from-prompt" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("two-password empty provider result errors", func(t *testing.T) {
		_, err := keyPasswordSource(ctx, PasswordModeTwo, Credentials{
			MailboxPasswordProvider: func(context.Context) (string, error) { return "", nil },
		})
		assertAuthError(t, err, ErrCodeMailboxPasswordRequired)
	})
	t.Run("two-password provider error is wrapped", func(t *testing.T) {
		sentinel := errors.New("boom")
		_, err := keyPasswordSource(ctx, PasswordModeTwo, Credentials{
			MailboxPasswordProvider: func(context.Context) (string, error) { return "", sentinel },
		})
		assertAuthError(t, err, ErrCodeMailboxPasswordRequired)
		if !errors.Is(err, sentinel) {
			t.Error("provider error not wrapped")
		}
	})
	t.Run("two-password provider cancelled", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := keyPasswordSource(cancelled, PasswordModeTwo, Credentials{
			MailboxPasswordProvider: func(ctx context.Context) (string, error) { return "", ctx.Err() },
		})
		assertAuthError(t, err, ErrCodeCancelled)
	})
	t.Run("two-password missing errors", func(t *testing.T) {
		_, err := keyPasswordSource(ctx, PasswordModeTwo, Credentials{Password: "login-pw"})
		assertAuthError(t, err, ErrCodeMailboxPasswordRequired)
	})
}

func TestResolve2FACode(t *testing.T) {
	ctx := t.Context()
	now := time.Unix(59, 0)
	fromSecret, err := generateTOTP(fakeTOTPSecret, now)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("static code wins", func(t *testing.T) {
		got, err := resolve2FACode(ctx, Credentials{TOTPCode: "111111", TOTPSecret: fakeTOTPSecret}, now)
		if err != nil || got != "111111" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("secret before provider", func(t *testing.T) {
		got, err := resolve2FACode(ctx, Credentials{
			TOTPSecret:   fakeTOTPSecret,
			TOTPProvider: func(context.Context) (string, error) { t.Error("provider must not be called"); return "", nil },
		}, now)
		if err != nil || got != fromSecret {
			t.Fatalf("got %q, %v; want %q", got, err, fromSecret)
		}
	})
	t.Run("provider", func(t *testing.T) {
		got, err := resolve2FACode(ctx, Credentials{TOTPProvider: func(context.Context) (string, error) { return "222222", nil }}, now)
		if err != nil || got != "222222" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("empty provider result", func(t *testing.T) {
		_, err := resolve2FACode(ctx, Credentials{TOTPProvider: func(context.Context) (string, error) { return "", nil }}, now)
		assertAuthError(t, err, ErrCode2FARequired)
	})
	t.Run("provider deadline is a cancellation", func(t *testing.T) {
		_, err := resolve2FACode(ctx, Credentials{TOTPProvider: func(context.Context) (string, error) {
			return "", fmt.Errorf("prompt: %w", context.DeadlineExceeded)
		}}, now)
		assertAuthError(t, err, ErrCodeCancelled)
	})
	t.Run("nothing supplied", func(t *testing.T) {
		_, err := resolve2FACode(ctx, Credentials{}, now)
		assertAuthError(t, err, ErrCode2FARequired)
	})
}

func TestPrimaryKey(t *testing.T) {
	if _, ok := primaryKey(nil); ok {
		t.Error("no keys must not yield a primary key")
	}
	if _, ok := primaryKey(proton.Keys{{ID: "a"}}); ok {
		t.Error("a non-primary key must not be picked")
	}
	key, ok := primaryKey(proton.Keys{{ID: "a"}, {ID: "b", Primary: true}})
	if !ok || key.ID != "b" {
		t.Errorf("primaryKey = %q, %v", key.ID, ok)
	}
}

func TestVerifyKeyPasswordRejectsGarbage(t *testing.T) {
	err := verifyKeyPassword(proton.Key{PrivateKey: []byte("not an armored key")}, []byte("x"))
	if err == nil {
		t.Error("an unparsable key must not verify")
	}
}

func TestPasswordModeString(t *testing.T) {
	if PasswordModeOne.String() != "one-password" || PasswordModeTwo.String() != "two-password" {
		t.Error("unexpected PasswordMode labels")
	}
	if PasswordMode(7).String() != "password mode 7" {
		t.Errorf("unknown mode = %q", PasswordMode(7))
	}
}
