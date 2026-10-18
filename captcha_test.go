package protonauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Arsylk/proton-auth/internal/captcha"
)

// SolveCaptcha shares Login's error contract: every failure is a *AuthError
// with a code a caller can branch on.
func TestSolveCaptchaRejectsEmptyToken(t *testing.T) {
	_, err := SolveCaptcha(t.Context(), "", CaptchaOptions{})
	assertAuthError(t, err, ErrCodeInvalidInput)
}

func TestSolveCaptchaRejectsInvalidProxy(t *testing.T) {
	_, err := SolveCaptcha(t.Context(), "hv", CaptchaOptions{ProxyURL: "://bad"})
	assertAuthError(t, err, ErrCodeInvalidInput)
	if !strings.Contains(err.Error(), "invalid proxy URL") {
		t.Errorf("err = %v", err)
	}
}

func TestSolveCaptchaTimesOut(t *testing.T) {
	_, err := SolveCaptcha(t.Context(), "hv", CaptchaOptions{Timeout: 20 * time.Millisecond})
	assertAuthError(t, err, ErrCodeCaptcha)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestSolveCaptchaReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := SolveCaptcha(ctx, "hv", CaptchaOptions{})
	assertAuthError(t, err, ErrCodeCancelled)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}

func TestSolveCaptchaDeliversTokenThroughPrompt(t *testing.T) {
	var out bytes.Buffer
	var prompt CaptchaPrompt
	token, err := SolveCaptcha(t.Context(), "hv-token-123", CaptchaOptions{
		Account: "alice",
		Timeout: 5 * time.Second,
		Output:  &out,
		OnPrompt: func(p CaptchaPrompt) {
			prompt = p
			res, err := http.Get(p.URL)
			if err != nil {
				t.Error(err)
				return
			}
			page, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if !strings.Contains(string(page), "Token=hv-token-123") || !strings.Contains(string(page), "alice") {
				t.Errorf("unexpected solver page:\n%s", page)
			}
			res, err = http.Post(p.URL+"submit", "text/plain", strings.NewReader("solved-token"))
			if err != nil {
				t.Error(err)
				return
			}
			res.Body.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "solved-token" {
		t.Errorf("token = %q", token)
	}
	if prompt.Account != "alice" || prompt.Port <= 0 {
		t.Errorf("prompt = %+v", prompt)
	}
	if !strings.Contains(out.String(), prompt.URL) {
		t.Errorf("output does not mention the URL:\n%s", out.String())
	}
}

// The public default and the solver's own default must agree: the solver
// resolves a zero Timeout to its constant, and the docs promise this one.
func TestDefaultCaptchaTimeout(t *testing.T) {
	if DefaultCaptchaTimeout != captcha.DefaultTimeout {
		t.Errorf("DefaultCaptchaTimeout = %v, solver default = %v", DefaultCaptchaTimeout, captcha.DefaultTimeout)
	}
}
