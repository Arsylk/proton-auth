package protonauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	proton "github.com/henrybear327/go-proton-api"
)

func hvError() error {
	// Mirrors how catchAPIError wraps the decoded APIError.
	return fmt.Errorf("422 POST /auth/v4: %w", &proton.APIError{
		Status:  422,
		Code:    proton.HumanVerificationRequired,
		Message: "Human verification required",
		Details: map[string]any{
			"HumanVerificationToken":   "hv-token-123",
			"HumanVerificationMethods": []any{"captcha", "email"},
		},
	})
}

func TestAsHumanVerification(t *testing.T) {
	hv, ok := asHumanVerification(hvError())
	if !ok {
		t.Fatal("expected human verification details")
	}
	if hv.Token != "hv-token-123" {
		t.Errorf("token = %q", hv.Token)
	}
	if !hv.supportsCaptcha() {
		t.Errorf("expected captcha in methods %v", hv.Methods)
	}
}

func TestAsHumanVerificationOtherErrors(t *testing.T) {
	if _, ok := asHumanVerification(fmt.Errorf("plain error")); ok {
		t.Error("plain error should not parse as human verification")
	}
	if _, ok := asHumanVerification(fmt.Errorf("wrap: %w", &proton.APIError{Code: proton.PasswordWrong})); ok {
		t.Error("non-9001 APIError should not parse as human verification")
	}
	noToken := &proton.APIError{Code: proton.HumanVerificationRequired, Details: map[string]any{"HumanVerificationMethods": []any{"captcha"}}}
	if _, ok := asHumanVerification(noToken); ok {
		t.Error("a 9001 without a token should not parse")
	}
	noDetails := &proton.APIError{Code: proton.HumanVerificationRequired}
	if _, ok := asHumanVerification(noDetails); ok {
		t.Error("a 9001 without details should not parse")
	}
}

func TestHVTransportInjectsHeaders(t *testing.T) {
	var authToken, authType, infoToken, userToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/v4":
			authToken = r.Header.Get("X-Pm-Human-Verification-Token")
			authType = r.Header.Get("X-Pm-Human-Verification-Token-Type")
		case "/api/auth/v4/info":
			infoToken = r.Header.Get("X-Pm-Human-Verification-Token")
		case "/api/core/v4/users":
			userToken = r.Header.Get("X-Pm-Human-Verification-Token")
		}
	}))
	defer upstream.Close()

	client := &http.Client{Transport: newHVTransport(nil, "solved-token", hvTokenTypeCaptcha)}
	for _, request := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/auth/v4/info"},
		{http.MethodPost, "/api/auth/v4"},
		{http.MethodGet, "/api/core/v4/users"},
	} {
		req, err := http.NewRequest(request.method, upstream.URL+request.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}

	if authToken != "solved-token" || authType != "captcha" {
		t.Errorf("auth headers = %q, %q", authToken, authType)
	}
	if infoToken != "" || userToken != "" {
		t.Errorf("verification token leaked to other requests: info=%q user=%q", infoToken, userToken)
	}
}
