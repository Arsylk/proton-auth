// Package proxy builds the HTTP transport a login and its CAPTCHA solve share,
// optionally routed through a proxy, so every Proton-facing request exits from
// the IP the HumanVerificationToken was issued to.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Transport returns a transport the caller owns, routed through proxyURL (for
// example http://user:pass@host:port or socks5://host:port) when it is
// non-empty. It is a clone of http.DefaultTransport rather than the shared
// default itself, so closing its idle connections once the login is over
// touches nothing else in the process.
//
// responseHeaderTimeout, when positive, bounds how long each request waits for
// the response headers after the request is written; together with the
// clone's dial and TLS handshake timeouts it keeps a silent or stalled peer
// from hanging a login whose context has no deadline.
//
// The error never quotes proxyURL: the URL may carry a password, and a
// malformed one (a space or '#' in that password, say) is exactly what makes
// parsing fail.
func Transport(proxyURL string, responseHeaderTimeout time.Duration) (*http.Transport, error) {
	tr := newTransport()
	if responseHeaderTimeout > 0 {
		tr.ResponseHeaderTimeout = responseHeaderTimeout
	}
	if proxyURL == "" {
		return tr, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", withoutURL(err))
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid proxy URL: a scheme and host are required (e.g. http://host:port)")
	}
	tr.Proxy = http.ProxyURL(u)
	return tr, nil
}

// withoutURL strips a *url.Error, whose message repeats the whole URL, down to
// its cause.
func withoutURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

// newTransport clones http.DefaultTransport while it still is an
// *http.Transport, or builds an equivalent one when the program replaced the
// default with another RoundTripper, so this package never panics on a type
// assertion it does not control.
func newTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
