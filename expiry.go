package protonauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// expiryCapture reads Proton's ExpiresIn from the raw SRP login response.
//
// Proton's AuthResponse carries ExpiresIn (the access-token lifetime in
// seconds; verified against ProtonMail/WebClients
// packages/shared/lib/authentication/interface.ts), but every go-proton-api
// fork decodes /auth/v4 into an Auth struct without that field, so the value is
// otherwise lost. This round-tripper tees the successful response body, reads
// ExpiresIn, and leaves the body intact for go-proton-api to decode normally.
type expiryCapture struct {
	base      http.RoundTripper
	expiresIn *int // seconds; written only on a successful /auth/v4 response
}

var _ http.RoundTripper = (*expiryCapture)(nil)

func newExpiryCapture(base http.RoundTripper, out *int) *expiryCapture {
	if base == nil {
		base = http.DefaultTransport
	}
	return &expiryCapture{base: base, expiresIn: out}
}

func (c *expiryCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// Only the SRP login POST carries the token lifetime. HasSuffix excludes
	// the sibling endpoints /auth/v4/info, /auth/v4/modulus and /auth/v4/2fa.
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/auth/v4") || resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		// The connection died mid-body. Report that rather than handing
		// go-proton-api an empty body, whose decode error would hide the
		// cause; http.Client wraps it in a *url.Error, which Login classifies
		// as ErrCodeConnection.
		return nil, fmt.Errorf("reading the login response: %w", readErr)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	var parsed struct{ ExpiresIn int }
	if json.Unmarshal(body, &parsed) == nil && parsed.ExpiresIn > 0 {
		*c.expiresIn = parsed.ExpiresIn
	}
	return resp, nil
}

// CloseIdleConnections forwards to the wrapped transport. go-proton-api's
// Manager.Close is http.Client.CloseIdleConnections, which only reaches a
// transport that offers this method; without the forwarding, the connection
// pool a login owns would outlive the login.
func (c *expiryCapture) CloseIdleConnections() { closeIdle(c.base) }

// closeIdle closes rt's idle connections if it knows how to.
func closeIdle(rt http.RoundTripper) {
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
