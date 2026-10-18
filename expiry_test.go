package protonauth

import (
	"errors"
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
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { return respWith(http.StatusOK, body), nil })
	capture := newExpiryCapture(base, &got)

	req, _ := http.NewRequest(http.MethodPost, "https://mail.proton.me/api/auth/v4", nil)
	resp, err := capture.RoundTrip(req)
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
			base := roundTripFunc(func(*http.Request) (*http.Response, error) {
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

// failingBody errors on the first read.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

// A body that cannot be read is a dead connection: the read error is returned
// as the transport's error (http.Client then wraps it in a *url.Error, which
// Login classifies as ErrCodeConnection) and ExpiresIn stays unknown.
func TestExpiryCaptureBodyReadFailure(t *testing.T) {
	got := -1
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}}, nil
	})
	req, _ := http.NewRequest(http.MethodPost, "https://x/auth/v4", nil)
	resp, err := newExpiryCapture(base, &got).RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("RoundTrip error = %v, want the read failure", err)
	}
	if resp != nil {
		t.Errorf("response = %v, want nil with the error", resp)
	}
	if got != -1 {
		t.Errorf("ExpiresIn = %d, want untouched", got)
	}
}

// idleCloser is a transport that counts CloseIdleConnections calls.
type idleCloser struct {
	roundTripFunc
	closed int
}

func (c *idleCloser) CloseIdleConnections() { c.closed++ }

// go-proton-api's Manager.Close is http.Client.CloseIdleConnections, which
// reaches the real pool only if every wrapper in between forwards it.
func TestWrapperTransportsForwardCloseIdleConnections(t *testing.T) {
	base := &idleCloser{roundTripFunc: func(*http.Request) (*http.Response, error) { return nil, nil }}
	var expiresIn int
	wrapped := newExpiryCapture(newHVTransport(base, "tok", hvTokenTypeCaptcha), &expiresIn)
	wrapped.CloseIdleConnections()
	if base.closed != 1 {
		t.Errorf("CloseIdleConnections reached the base transport %d times, want 1", base.closed)
	}
	// A base without the method is simply left alone.
	plain := newExpiryCapture(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }), &expiresIn)
	plain.CloseIdleConnections()
}
