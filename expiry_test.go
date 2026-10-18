package protonauth

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respWith(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestExpiryCaptureReadsExpiresIn(t *testing.T) {
	const body = `{"Code":1000,"AccessToken":"a","RefreshToken":"r","UID":"u","ExpiresIn":86400}`
	var got int
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) { return respWith(200, body), nil })
	cap := newExpiryCapture(base, &got)

	req, _ := http.NewRequest(http.MethodPost, "https://mail.proton.me/api/auth/v4", nil)
	resp, err := cap.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got != 86400 {
		t.Fatalf("ExpiresIn = %d, want 86400", got)
	}
	// The body must still be readable for go-proton-api to decode.
	read, _ := io.ReadAll(resp.Body)
	if string(read) != body {
		t.Fatalf("body was consumed: got %q", read)
	}
}

func TestExpiryCaptureIgnoresNonLoginAndErrors(t *testing.T) {
	cases := []struct {
		name, method, path string
		status             int
	}{
		{"info endpoint", http.MethodPost, "/auth/v4/info", 200},
		{"2fa endpoint", http.MethodPost, "/auth/v4/2fa", 200},
		{"GET", http.MethodGet, "/auth/v4", 200},
		{"non-200", http.MethodPost, "/auth/v4", 422},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := -1
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return respWith(c.status, `{"ExpiresIn":99}`), nil
			})
			req, _ := http.NewRequest(c.method, "https://x"+c.path, nil)
			if _, err := newExpiryCapture(base, &got).RoundTrip(req); err != nil {
				t.Fatal(err)
			}
			if got != -1 {
				t.Fatalf("ExpiresIn was captured (%d) but should have been ignored", got)
			}
		})
	}
}
