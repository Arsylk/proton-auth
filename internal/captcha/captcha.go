// Package captcha serves Proton's CAPTCHA widget from a throwaway local HTTP
// server and captures the solved token. It is the mechanism behind
// protonauth.SolveCaptcha and the CLI's -captcha-test smoke check. It is
// internal because its targets and wire details are not a stable API.
package captcha

import (
	"context"
	_ "embed" // page.html, the solver page
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cli/browser"
)

// DefaultTimeout is how long Solve waits for the user when Options.Timeout is
// zero.
const DefaultTimeout = 10 * time.Minute

// Prompt describes a running solver page.
type Prompt struct {
	URL     string
	Port    int
	Account string
}

// Options configures Solve.
type Options struct {
	// Account is a label shown on the page. Optional.
	Account string
	// Transport carries the reverse proxy's requests to Proton, so that a
	// proxy-routed login and the solve share one exit IP. Nil means
	// http.DefaultTransport.
	Transport http.RoundTripper
	// AutoOpen opens the page in the default browser.
	AutoOpen bool
	// Timeout bounds the wait for a token. Zero means DefaultTimeout.
	Timeout time.Duration
	// OnPrompt is called once the page is listening. Optional.
	OnPrompt func(Prompt)
	// Output receives human-readable instruction lines. Nil is silent.
	Output io.Writer
}

// Target describes what the wrapper page frames: the upstream host to
// reverse-proxy and the iframe src, a path+query relative to the local server.
type Target struct {
	Upstream  string
	IframeSrc string
	// Modern marks the self-initialising captcha app, which posts a different
	// solve message than the login widget; see page.
	Modern bool
}

// host is the API subdomain matching go-proton-api's default host
// (mail.proton.me/api). The captcha must be proxied from the subdomain's
// root, not the /api prefix: with a valid token, /core/v4/captcha hands off
// to the captcha app at root-relative /captcha/v1/..., which only exists on
// the API subdomain.
const host = "https://mail-api.proton.me"

// LegacyTarget renders a real HumanVerificationToken through the
// /core/v4/captcha wrapper, which binds the challenge to that token (it
// bootstraps into Proton's captcha app with the token + purpose). The solved
// result verifies against Proton's token, which is what a login retry needs.
func LegacyTarget(hvToken string) Target {
	return Target{
		Upstream:  host,
		IframeSrc: "/core/v4/captcha?Token=" + url.QueryEscape(hvToken) + "&ForceWebMessaging=1",
	}
}

// appHost serves Proton's self-contained CAPTCHA app. Unlike the
// /core/v4/captcha wrapper, /captcha/v1/assets/ self-initialises via
// /captcha/v1/api/init and renders a solvable challenge for any token, so a
// smoke check can show the widget without a live Code=9001.
const appHost = "https://account-api.proton.me"

// OnDemandTarget renders the self-initialising app for a smoke check. The
// token it yields cannot authenticate a login; use LegacyTarget for that.
func OnDemandTarget() Target {
	return Target{
		Upstream:  appHost,
		IframeSrc: "/captcha/v1/assets/?purpose=signup&token=on-demand-test",
		Modern:    true,
	}
}

// page wraps Proton's captcha page in an iframe and posts the solved token
// back to the local server. The captcha is proxied through this server
// (Proton's CSP forbids framing it from non-Proton origins), so the iframe is
// same-origin. The real login flow speaks Proton's web-messaging format,
// matching the Proton web client: {type: 'pm_captcha', token}, plus
// {type: 'pm_height', height} to size the frame. The smoke check renders
// Proton's self-initialising app, which instead posts
// {type: 'proton_captcha', token, protoncaptcha: true}; that format is wired
// up only for Target.Modern, so the login page stays identical to the web
// client's.
//
//go:embed page.html
var pageHTML string

// page is the wrapper page, parsed once; see page.html for the markup.
var page = template.Must(template.New("captcha").Parse(pageHTML))

// newProxy proxies requests to Proton's API host so the captcha page and any
// resources it fetches are same-origin with the wrapper page.
func newProxy(upstream string, transport http.RoundTripper) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid captcha upstream %q: %w", upstream, err)
	}
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
		},
		// The default handler logs every failure through the standard logger,
		// which would interleave with the caller's output. A request whose
		// context is already done has nobody left to answer: the browser went
		// away, or the server is shutting down after a solve. Anything else
		// is shown in the page, where the user is looking.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return
			}
			http.Error(w, "captcha proxy: "+err.Error(), http.StatusBadGateway)
		},
		ModifyResponse: func(res *http.Response) error {
			// Proton's frame-ancestors would block our iframe; the page only
			// needs to run in this throwaway local context.
			res.Header.Del("Content-Security-Policy")
			res.Header.Del("Content-Security-Policy-Report-Only")
			res.Header.Del("X-Frame-Options")

			// Keep upstream redirects on the proxy instead of escaping to
			// the real host (where framing would be blocked again).
			if loc := res.Header.Get("Location"); loc != "" {
				if u, err := url.Parse(loc); err == nil && u.Host == target.Host {
					u.Scheme, u.Host = "", ""
					res.Header.Set("Location", u.String())
				}
			}

			// Drop cookie attributes that keep them from sticking on
			// http://127.0.0.1 (Domain=proton.me, Secure, SameSite=None).
			if cookies := res.Header.Values("Set-Cookie"); len(cookies) > 0 {
				rewritten := make([]string, 0, len(cookies))
				for _, c := range cookies {
					rewritten = append(rewritten, stripCookieAttrs(c))
				}
				res.Header.Del("Set-Cookie")
				for _, c := range rewritten {
					res.Header.Add("Set-Cookie", c)
				}
			}
			return nil
		},
	}, nil
}

// stripCookieAttrs removes the Domain, Secure and SameSite attributes so the
// cookie is accepted for the local plain-http proxy origin, and Expires and
// Max-Age so it dies with the browser session. Cookies are not port-scoped:
// a persistent cookie stored for 127.0.0.1 here would ride along to every
// local http server the browser talks to later, and the widget only needs it
// for the minutes the solve takes.
func stripCookieAttrs(cookie string) string {
	// parts[0] is name=value and is never an attribute, even for a cookie
	// named Domain; only the attributes after it are filtered.
	parts := strings.Split(cookie, ";")
	attrs := slices.DeleteFunc(parts[1:], func(p string) bool {
		attr := strings.ToLower(strings.TrimSpace(p))
		return attr == "secure" || strings.HasPrefix(attr, "domain=") || strings.HasPrefix(attr, "samesite=") ||
			strings.HasPrefix(attr, "expires=") || strings.HasPrefix(attr, "max-age=")
	})
	return strings.Join(slices.Concat(parts[:1], attrs), ";")
}

// server serves the wrapper page on a local port, reverse-proxies Proton's
// captcha, and delivers the solved captcha token on tokenCh.
type server struct {
	url     string
	port    int
	tokenCh chan string
	http    *http.Server
}

func (s *server) close() { _ = s.http.Close() }

func startServer(ctx context.Context, target Target, account string, transport http.RoundTripper) (*server, error) {
	proxy, err := newProxy(target.Upstream, transport)
	if err != nil {
		return nil, err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local captcha server: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("local captcha server has a %T address, want TCP", listener.Addr())
	}

	tokenCh := make(chan string, 1)
	localAddr := tcpAddr.String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			proxy.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, map[string]any{
			"IframeURL":   target.IframeSrc,
			"AllowModern": target.Modern,
			"Account":     account,
		})
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		// A cross-origin POST to 127.0.0.1 is a CORS "simple request" that
		// browsers deliver, so a malicious page could poison the token
		// channel blind. The wrapper page's own fetch is same-origin; its
		// Origin header is either absent or the local origin.
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+localAddr {
			http.Error(w, "cross-origin submit rejected", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil || len(body) == 0 {
			http.Error(w, "empty token", http.StatusBadRequest)
			return
		}
		// Put the complete response on the wire before handing the token
		// over: Solve returns and closes the server the moment it has it,
		// and a 200 still sitting in the handler's buffer would be cut off,
		// so the page would report a delivery failure for a token that
		// arrived. With the length declared, the flush is the whole reply.
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		select {
		case tokenCh <- string(body):
		default:
		}
	})

	// Requests must carry our own Host. A DNS-rebound domain resolving to
	// 127.0.0.1 would otherwise be same-origin with this server and could
	// read the page (which embeds the HumanVerificationToken) or relay
	// arbitrary requests to Proton through the proxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != localAddr {
			http.Error(w, "unexpected host", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()

	return &server{
		url:     "http://" + localAddr + "/",
		port:    tcpAddr.Port,
		tokenCh: tokenCh,
		http:    srv,
	}, nil
}

// writeLine writes one instruction line to w (nothing if w is nil). These are
// the messages a user must act on, chiefly the URL to open and the headless
// port-forward hint, so they are plain output, not structured logs.
func writeLine(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// Solve serves the target on a local HTTP server, reports the page through
// opts.OnPrompt and opts.Output, optionally opens it in the user's browser,
// and waits for the solved token.
//
// When opts.Timeout (or DefaultTimeout) elapses the error wraps
// context.DeadlineExceeded; when ctx is cancelled first the error is ctx.Err().
func Solve(ctx context.Context, target Target, opts Options) (string, error) {
	srv, err := startServer(ctx, target, opts.Account, opts.Transport)
	if err != nil {
		return "", err
	}
	defer srv.close()

	prompt := Prompt{URL: srv.url, Port: srv.port, Account: opts.Account}
	if opts.OnPrompt != nil {
		opts.OnPrompt(prompt)
	}

	forAccount := ""
	if opts.Account != "" {
		forAccount = " as " + opts.Account
	}
	writeLine(opts.Output, "Proton requires a CAPTCHA to sign in%s.", forAccount)
	writeLine(opts.Output, "Open this URL in a browser to solve it: %s", prompt.URL)
	writeLine(opts.Output,
		"(on a headless machine, forward the port first: ssh -L %[1]d:127.0.0.1:%[1]d <host>)", prompt.Port)

	if opts.AutoOpen {
		if err := openBrowser(prompt.URL); err != nil {
			writeLine(opts.Output, "Could not open a browser automatically (%v); open the URL above yourself.", err)
		} else {
			writeLine(opts.Output, "Opened the CAPTCHA in your browser.")
		}
	}

	writeLine(opts.Output, "Waiting for the CAPTCHA to be solved...")

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case token := <-srv.tokenCh:
		writeLine(opts.Output, "CAPTCHA solved.")
		return token, nil
	case <-wait.Done():
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("timed out waiting for the CAPTCHA after %v: %w", timeout, wait.Err())
	}
}

// silenceBrowser runs once before the first browser launch. cli/browser hands
// the launcher's stdout and stderr to the process's own streams, and browsers
// such as Chromium derivatives log child-process noise there, which would
// otherwise interleave with the prompt lines on Output.
var silenceBrowser = sync.OnceFunc(func() {
	browser.Stdout = io.Discard
	browser.Stderr = io.Discard
})

// openBrowser opens url in the user's default browser with the launcher's own
// output discarded.
func openBrowser(url string) error {
	silenceBrowser()
	return browser.OpenURL(url)
}
