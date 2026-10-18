package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Without a proxy the transport is still the login's own: closing its idle
// connections must not reach the process-wide http.DefaultTransport.
func TestProxyTransportEmptyIsOwned(t *testing.T) {
	tr, err := Transport("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil || http.RoundTripper(tr) == http.DefaultTransport {
		t.Errorf("Transport(\"\") = %v, want a clone distinct from http.DefaultTransport", tr)
	}
	if tr.Proxy == nil {
		t.Error("the clone lost the environment proxy settings")
	}
}

func TestProxyTransportRoutesThroughProxy(t *testing.T) {
	var hits atomic.Int32
	// A stand-in HTTP proxy: any request through it increments the counter.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	tr, err := Transport(proxy.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: tr}
	res, err := client.Get("http://example.com/anything")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if hits.Load() == 0 {
		t.Error("request did not go through the proxy")
	}
}

func TestProxyTransportInvalidURL(t *testing.T) {
	for _, bad := range []string{"://bad", "localhost:8080", "/no-scheme", "http://"} {
		_, err := Transport(bad, 0)
		if err == nil {
			t.Errorf("Transport(%q) accepted a malformed URL", bad)
			continue
		}
		if !strings.Contains(err.Error(), "invalid proxy URL") {
			t.Errorf("Transport(%q) error = %q", bad, err)
		}
	}
}

// A proxy URL carries credentials, and a password that breaks parsing is the
// common way to get here; the error must not echo it. It ends up in
// AuthError.Message and the CLI's JSON.
func TestProxyTransportErrorOmitsCredentials(t *testing.T) {
	for _, bad := range []string{
		"http://alice:Sup3r Secret@proxy.example:8080", // space in the password
		"http://alice:Sup3r%Secret@proxy.example:8080", // bad escape
		"alice:Sup3rSecret@proxy.example:8080",         // no scheme
	} {
		_, err := Transport(bad, 0)
		if err == nil {
			t.Errorf("Transport(%q) accepted a malformed URL", bad)
			continue
		}
		if msg := err.Error(); strings.Contains(msg, "Sup3r") || strings.Contains(msg, "alice") {
			t.Errorf("Transport(%q) leaks the credentials: %q", bad, msg)
		}
	}
}

// A program may replace http.DefaultTransport with its own RoundTripper; the
// library must then still build a usable transport rather than panic.
func TestProxyTransportSurvivesReplacedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })

	tr, err := Transport("http://127.0.0.1:9", 0)
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil || tr.Proxy == nil {
		t.Errorf("transport = %+v, want one with the proxy set", tr)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A peer that accepts the connection and then says nothing must not hang the
// caller: the response-header timeout turns it into a timeout error, which the
// library classifies as a connection failure.
func TestProxyTransportResponseHeaderTimeout(t *testing.T) {
	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	// Cleanups run last-in first-out: the handler must be released before
	// Close waits for it.
	t.Cleanup(silent.Close)
	t.Cleanup(func() { close(release) })

	tr, err := Transport("", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	start := time.Now()
	res, err := client.Get(silent.URL)
	if err == nil {
		res.Body.Close()
		t.Fatal("request to a silent server returned without error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("err = %v, want a net.Error timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want roughly the 50ms timeout", elapsed)
	}
}
