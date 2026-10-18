package captcha

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyStripsCSPAndRewritesRedirectsAndCookies(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/core/v4/captcha" {
			t.Errorf("upstream path = %q", r.URL.Path)
		}
		if r.Host != upstreamHost {
			t.Errorf("upstream Host = %q, want %q", r.Host, upstreamHost)
		}
		w.Header().Set("Content-Security-Policy", "frame-ancestors https://calendar.proton.me;")
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Location", "http://"+upstreamHost+"/captcha/v1/frame?token=x")
		w.Header().Set("Set-Cookie", "Session-Id=abc; Domain=proton.me; Path=/; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Max-Age=31536000; Secure; SameSite=None; HttpOnly")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamHost = strings.TrimPrefix(upstream.URL, "http://")

	proxy, err := newProxy(upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(proxy)
	defer local.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Get(local.URL + "/core/v4/captcha?Token=x")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	for _, h := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Frame-Options"} {
		if v := res.Header.Get(h); v != "" {
			t.Errorf("%s not stripped: %q", h, v)
		}
	}
	if loc := res.Header.Get("Location"); loc != "/captcha/v1/frame?token=x" {
		t.Errorf("Location not made proxy-relative: %q", loc)
	}
	if c := res.Header.Get("Set-Cookie"); c != "Session-Id=abc; Path=/; HttpOnly" {
		t.Errorf("cookie attrs not stripped (persistence must not survive the session): %q", c)
	}
}

func TestProxyLeavesForeignRedirectsAlone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	proxy, err := newProxy(upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if loc := rec.Header().Get("Location"); loc != "https://elsewhere.example/x" {
		t.Errorf("foreign Location rewritten: %q", loc)
	}
}

func TestProxyRejectsBadUpstream(t *testing.T) {
	if _, err := newProxy("://bad", nil); err == nil {
		t.Error("expected an error for a malformed upstream URL")
	}
}

func TestStripCookieAttrs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a=b", "a=b"},
		{"a=b; Path=/; HttpOnly", "a=b; Path=/; HttpOnly"},
		{"a=b; Secure; SameSite=None; Domain=proton.me", "a=b"},
		{"a=b; Max-Age=60; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/", "a=b; Path=/"},
		{"a=b; SECURE; domain=x", "a=b"},
	}
	for _, c := range cases {
		if got := stripCookieAttrs(c.in); got != c.want {
			t.Errorf("stripCookieAttrs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTargets(t *testing.T) {
	legacy := LegacyTarget("hv 123")
	if legacy.Upstream != "https://mail-api.proton.me" {
		t.Errorf("legacy upstream = %q", legacy.Upstream)
	}
	if legacy.IframeSrc != "/core/v4/captcha?Token=hv+123&ForceWebMessaging=1" {
		t.Errorf("legacy iframeSrc = %q", legacy.IframeSrc)
	}
	if legacy.Modern {
		t.Error("legacy target must not enable the modern solve message")
	}

	demand := OnDemandTarget()
	if demand.Upstream != "https://account-api.proton.me" || !demand.Modern {
		t.Errorf("on-demand target = %+v", demand)
	}
}

func TestServerServesPageAndCollectsToken(t *testing.T) {
	srv, err := startServer(t.Context(), LegacyTarget("hv-token-123"), "user@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()

	res, err := http.Get(srv.url)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	body := string(page)

	if !strings.Contains(body, "core/v4/captcha?Token=hv-token-123") {
		t.Errorf("page missing captcha iframe URL:\n%s", body)
	}
	// The account being signed in is shown so multiple sequential CAPTCHAs
	// (one per account) are distinguishable.
	if !strings.Contains(body, "user@example.test") {
		t.Errorf("page missing account label:\n%s", body)
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}
	// The login page must match the Proton web client's message handling
	// (pm_captcha only); proton_captcha is scoped to the smoke-check app.
	if !strings.Contains(body, "pm_captcha") {
		t.Error("login page missing pm_captcha handling")
	}
	if strings.Contains(body, "proton_captcha") {
		t.Error("login page must not handle proton_captcha (web client uses pm_captcha only)")
	}

	res, err = http.Post(srv.url+"submit", "text/plain", strings.NewReader("solved-token"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("submit status = %d", res.StatusCode)
	}

	select {
	case token := <-srv.tokenCh:
		if token != "solved-token" {
			t.Errorf("token = %q", token)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for token")
	}
}

func TestServerModernPageHandlesProtonCaptchaMessage(t *testing.T) {
	srv, err := startServer(t.Context(), OnDemandTarget(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()

	res, err := http.Get(srv.url)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(page), "proton_captcha") {
		t.Error("smoke-check page must handle proton_captcha")
	}
}

func TestServerRejectsEmptySubmit(t *testing.T) {
	srv, err := startServer(t.Context(), LegacyTarget("hv"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()

	res, err := http.Post(srv.url+"submit", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("empty submit status = %d, want 400", res.StatusCode)
	}
}

// The server must not be reachable under a foreign Host (DNS rebinding) and
// /submit must refuse cross-origin posts; the legitimate page and its
// same-origin fetch keep working.
func TestServerRejectsForeignHostAndOrigin(t *testing.T) {
	srv, err := startServer(t.Context(), LegacyTarget("hv-token-123"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()

	rebound, err := http.NewRequest(http.MethodGet, srv.url, nil)
	if err != nil {
		t.Fatal(err)
	}
	rebound.Host = "evil.example"
	res, err := http.DefaultClient.Do(rebound)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("foreign Host status = %d, want %d", res.StatusCode, http.StatusMisdirectedRequest)
	}

	crossOrigin, err := http.NewRequest(http.MethodPost, srv.url+"submit", strings.NewReader("spoofed"))
	if err != nil {
		t.Fatal(err)
	}
	crossOrigin.Header.Set("Origin", "https://evil.example")
	res, err = http.DefaultClient.Do(crossOrigin)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin submit status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	select {
	case token := <-srv.tokenCh:
		t.Errorf("spoofed token was accepted: %q", token)
	default:
	}

	sameOrigin, err := http.NewRequest(http.MethodPost, srv.url+"submit", strings.NewReader("real-token"))
	if err != nil {
		t.Fatal(err)
	}
	sameOrigin.Header.Set("Origin", strings.TrimSuffix(srv.url, "/"))
	res, err = http.DefaultClient.Do(sameOrigin)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("same-origin submit status = %d, want 200", res.StatusCode)
	}
	select {
	case token := <-srv.tokenCh:
		if token != "real-token" {
			t.Errorf("token = %q", token)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for token")
	}
}

// submitToken posts token to the page's /submit endpoint, as the browser would.
func submitToken(t *testing.T, p Prompt, token string) {
	t.Helper()
	res, err := http.Post(p.URL+"submit", "text/plain", strings.NewReader(token))
	if err != nil {
		t.Errorf("submit: %v", err)
		return
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("submit status = %d", res.StatusCode)
	}
}

func TestSolveDeliversTokenAndReportsPrompt(t *testing.T) {
	var out bytes.Buffer
	var prompt Prompt
	token, err := Solve(t.Context(), LegacyTarget("hv-token-123"), Options{
		Account: "alice",
		Timeout: 5 * time.Second,
		Output:  &out,
		OnPrompt: func(p Prompt) {
			prompt = p
			submitToken(t, p, "solved-token")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "solved-token" {
		t.Errorf("token = %q", token)
	}
	if prompt.Account != "alice" || prompt.Port <= 0 || !strings.HasPrefix(prompt.URL, "http://127.0.0.1:") {
		t.Errorf("prompt = %+v", prompt)
	}
	text := out.String()
	for _, want := range []string{"as alice", prompt.URL, "ssh -L", "CAPTCHA solved."} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Opened the CAPTCHA") {
		t.Error("browser must not be opened when AutoOpen is false")
	}
}

func TestSolveIsSilentWithoutOutput(t *testing.T) {
	// A nil Output must not panic.
	token, err := Solve(t.Context(), LegacyTarget("hv"), Options{
		Timeout:  5 * time.Second,
		OnPrompt: func(p Prompt) { submitToken(t, p, "tok") },
	})
	if err != nil || token != "tok" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

func TestSolveTimesOut(t *testing.T) {
	start := time.Now()
	_, err := Solve(t.Context(), LegacyTarget("hv"), Options{Timeout: 30 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want one wrapping context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout message", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout was not honoured")
	}
}

func TestSolveHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	_, err := Solve(ctx, LegacyTarget("hv"), Options{
		Timeout:  time.Minute,
		OnPrompt: func(Prompt) { cancel() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// The widget proxy must not write to the standard logger: an abandoned request
// (browser closed, or the server shutting down after a solve) is dropped
// silently, and any other upstream failure is reported in the page as a 502.
func TestProxyErrorsStayOffTheStandardLogger(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(prev) })

	failing := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("upstream unreachable")
	})
	proxy, err := newProxy("https://example.invalid", failing)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/captcha/v1/assets/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream unreachable") {
		t.Errorf("body = %q, want the upstream error", rec.Body.String())
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/captcha/v1/assets/", nil).WithContext(ctx))
	if rec.Body.Len() != 0 {
		t.Errorf("abandoned request got a body: %q", rec.Body.String())
	}

	if logged.Len() != 0 {
		t.Errorf("proxy wrote to the standard logger: %q", logged.String())
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The browser's POST to /submit must get its 200 even though Solve returns,
// and closes the server, as soon as the token is in hand. The submit is made
// off the OnPrompt goroutine so that Solve is free to race it, as a real
// browser does.
func TestSolveSubmitResponseCompletesBeforeServerCloses(t *testing.T) {
	for i := range 30 {
		submitted := make(chan error, 1)
		token, err := Solve(t.Context(), LegacyTarget("hv"), Options{
			Timeout: 5 * time.Second,
			OnPrompt: func(p Prompt) {
				go func() {
					res, err := http.Post(p.URL+"submit", "text/plain", strings.NewReader("tok"))
					if err == nil {
						res.Body.Close()
						if res.StatusCode != http.StatusOK {
							err = errors.New("submit status " + res.Status)
						}
					}
					submitted <- err
				}()
			},
		})
		if err != nil || token != "tok" {
			t.Fatalf("round %d: token = %q, err = %v", i, token, err)
		}
		if err := <-submitted; err != nil {
			t.Fatalf("round %d: the page's submit failed although the token was delivered: %v", i, err)
		}
	}
}
