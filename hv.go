package protonauth

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	proton "github.com/henrybear327/go-proton-api"
)

// hvTokenTypeCaptcha is the X-Pm-Human-Verification-Token-Type for a token
// obtained by solving a CAPTCHA.
const hvTokenTypeCaptcha = "captcha"

// humanVerification holds the parsed Details of a Code=9001 APIError.
type humanVerification struct {
	Token   string
	Methods []string
}

// isHumanVerification reports whether err is (or wraps) Proton's Code=9001
// answer, with or without usable details.
func isHumanVerification(err error) bool {
	apiErr, ok := errors.AsType[*proton.APIError](err)
	return ok && apiErr.Code == proton.HumanVerificationRequired
}

// asHumanVerification extracts human verification details from an auth error.
// ok is false when the error isn't a HumanVerificationRequired APIError, or
// when it carries no token.
func asHumanVerification(err error) (humanVerification, bool) {
	apiErr, ok := errors.AsType[*proton.APIError](err)
	if !ok || apiErr.Code != proton.HumanVerificationRequired {
		return humanVerification{}, false
	}

	details, ok := apiErr.Details.(map[string]any)
	if !ok {
		return humanVerification{}, false
	}

	hv := humanVerification{}
	hv.Token, _ = details["HumanVerificationToken"].(string)

	if methods, ok := details["HumanVerificationMethods"].([]any); ok {
		for _, m := range methods {
			if s, ok := m.(string); ok {
				hv.Methods = append(hv.Methods, s)
			}
		}
	}

	return hv, hv.Token != ""
}

func (hv humanVerification) supportsCaptcha() bool {
	return slices.Contains(hv.Methods, hvTokenTypeCaptcha)
}

// hvTransport injects the human verification headers Proton expects on the
// retried login request after the user has solved the challenge.
type hvTransport struct {
	base      http.RoundTripper
	token     string
	tokenType string
}

var _ http.RoundTripper = (*hvTransport)(nil)

func newHVTransport(base http.RoundTripper, token, tokenType string) *hvTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &hvTransport{base: base, token: token, tokenType: tokenType}
}

func (t *hvTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	// The token proves the retried authentication request only. Do not attach
	// it to AuthInfo or to authenticated requests made with the returned client.
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/auth/v4") {
		req.Header.Set("X-Pm-Human-Verification-Token", t.token)
		req.Header.Set("X-Pm-Human-Verification-Token-Type", t.tokenType)
	}
	return t.base.RoundTrip(req)
}

// CloseIdleConnections forwards to the wrapped transport; see expiryCapture.
func (t *hvTransport) CloseIdleConnections() { closeIdle(t.base) }
