# proton-auth

[![Go Reference](https://pkg.go.dev/badge/github.com/Arsylk/proton-auth.svg)](https://pkg.go.dev/github.com/Arsylk/proton-auth)
[![CI](https://github.com/Arsylk/proton-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Arsylk/proton-auth/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Arsylk/proton-auth)](https://goreportcard.com/report/github.com/Arsylk/proton-auth)
[![License: MIT](https://img.shields.io/github/license/Arsylk/proton-auth)](LICENSE)

A small, auditable Go library and CLI that performs **Proton SRP login** and
transparently solves the **CAPTCHA** (human-verification, API `Code=9001`)
challenge that blocks many headless and community Proton clients. This is an
independent community project: it is not affiliated with, endorsed by or
supported by Proton AG.

It builds on ProtonMail's [go-proton-api](https://github.com/ProtonMail/go-proton-api)
(via the [henrybear327 fork](https://github.com/henrybear327/go-proton-api), see
[why](#why-the-henrybear327-fork)) and adds only the pieces go-proton-api
leaves to the caller:

- **SRP login with optional 2FA**: a static TOTP code, a code generated from a
  base32 secret, or a code supplied on demand through a callback (TOTP only; a
  security key cannot be driven headlessly). Two-password accounts are
  supported.
- **Browser-assisted CAPTCHA solving**: Proton's widget is reverse-proxied on a
  throwaway `127.0.0.1` server so it frames same-origin, the solved token is
  captured, and the login is retried with the verification header attached.
  Works headless over an SSH port forward.
- **Optional proxy routing** so the login and the CAPTCHA solve exit from one
  IP (Proton binds the verification token to the issuing IP).

It only authenticates. It does not store credentials and holds no state between
runs. The CLI's JSON contract and error codes stay compatible with the Go login
helper in [lumo-tamer](https://github.com/ZeroTricks/lumo-tamer), which
inspired this project.

## Installation

Requires Go 1.26 or newer.

```sh
# library
go get github.com/Arsylk/proton-auth

# CLI
go install github.com/Arsylk/proton-auth/cmd/proton-auth@latest
```

Prebuilt CLI binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/Arsylk/proton-auth/releases).

## Library

```go
import protonauth "github.com/Arsylk/proton-auth"

res, err := protonauth.Login(ctx, protonauth.Options{
    CaptchaAutoOpen: true,
    Output:          os.Stderr, // CAPTCHA instructions; nil = silent
}, protonauth.Credentials{
    Username:   username,
    Password:   password,
    TOTPSecret: totpSecret, // optional; or TOTPCode, or TOTPProvider
})
if err != nil {
    if authErr, ok := errors.AsType[*protonauth.AuthError](err); ok {
        switch authErr.Code {
        case protonauth.ErrCode2FARequired:
            // ask for a 2FA code and retry
        case protonauth.ErrCodeCaptcha, protonauth.ErrCodeConnection:
            // nothing wrong with the credentials; retry later
        }
    }
    return err
}
// res.AccessToken, res.RefreshToken, res.UID, res.UserID, res.KeyPassword
// res.ExpiresIn   seconds, exactly as Proton reported it (0 if unknown)
// res.PasswordMode protonauth.PasswordModeOne or PasswordModeTwo
```

`Login` returns plain strings, so your module does not need to import this
module's go-proton-api fork. Every error is a `*protonauth.AuthError` with a
stable `Code` (see [error codes](#error-codes)) that separates Proton's verdict
on the credentials from an unsolved CAPTCHA, a connection failure, a cancelled
context and unusable input, plus a human-friendly `Message`; the underlying
go-proton-api, network or context error is reachable with `errors.As` and
`errors.Is` through `Unwrap`. If Proton has issued a session but the login
still fails (a wrong mailbox password, a rejected 2FA code, a cancellation),
`Login` revokes it before returning, so a failed attempt leaves nothing behind.

**Two-password accounts.** Set `Credentials.MailboxPassword`, or
`MailboxPasswordProvider` to supply it on demand. On a one-password account
both are ignored and the login password unlocks the keys. `Result.PasswordMode`
tells you which happened.

**Providers.** `TOTPProvider` and `MailboxPasswordProvider` are
`func(ctx context.Context) (string, error)` and receive `Login`'s ctx. A prompt
that returns `ctx.Err()` when the ctx ends makes `Login` fail with
`ErrCodeCancelled` instead of blaming the missing value.

**Token expiry.** `ExpiresIn` is reported exactly as Proton sends it, with no
safety margin, and it is accurate: the access token stops working at that
moment. The lifetime is Proton's choice per session and varies widely (24
hours on one account, 30 minutes on a freshly created account with 2FA were
both observed), so derive your refresh policy from the reported value and use
`RefreshToken` with Proton's `POST /auth/v4/refresh` to obtain a new pair,
rather than logging in again (in the observed 30-minute case the refreshed
token was granted 24 hours).

**Rendering the CAPTCHA prompt yourself.** `Options.Output` receives text a
person can act on. A GUI, bot or daemon can instead set
`Options.OnCaptchaPrompt`, which is called with the page's `URL`, `Port` and
`Account` as soon as the local server is listening:

```go
opts := protonauth.Options{
    CaptchaTimeout: 5 * time.Minute, // default 10 minutes; ctx applies too
    RequestTimeout: 15 * time.Second, // per request, default 30 seconds
    OnCaptchaPrompt: func(p protonauth.CaptchaPrompt) {
        notify(fmt.Sprintf("open %s to finish signing in as %s", p.URL, p.Account))
    },
}
```

**Proxy.** `Options.ProxyURL` (`http://user:pass@host:port` or
`socks5://host:port`) routes both the login and the proxied CAPTCHA widget
through one connection pool, so the token is issued to and consumed from the
same IP. A malformed value fails with `ErrCodeInvalidInput`; the URL, which
may carry a password, is never echoed in the error.

See the [package documentation](https://pkg.go.dev/github.com/Arsylk/proton-auth)
for runnable examples and every option.

### Only the CAPTCHA solver (any go-proton-api fork)

If you already drive your own login against a different fork (for example
rclone's `github.com/rclone/go-proton-api`) and only need to get past the
CAPTCHA, call `SolveCaptcha` with the `HumanVerificationToken` from the
`Code=9001` response's `Details`, then retry your login with the returned token:

```go
token, err := protonauth.SolveCaptcha(ctx, hvToken, protonauth.CaptchaOptions{
    Account:  username,  // label on the page, optional
    AutoOpen: true,
    ProxyURL: proxyURL,  // same proxy as the login, if any
    Output:   os.Stderr,
})
// retry the login with the headers
//   X-Pm-Human-Verification-Token:      token
//   X-Pm-Human-Verification-Token-Type: captcha
```

This path shares no Proton types across the module boundary, and its errors
are the same `*AuthError` values as `Login`'s: `ErrCodeInvalidInput`,
`ErrCodeCancelled` or `ErrCodeCaptcha`.

## CLI

```sh
proton-auth            # interactive: prompts for username, password, 2FA, mailbox password
```

The result is JSON on stdout (or the file given by `-o`, created with mode
0600). Prompts and CAPTCHA instructions go to stderr. On success:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "uid": "...",
  "userID": "...",
  "keyPassword": "...",
  "expiresAt": "2026-01-01T00:00:00Z",
  "passwordMode": 1
}
```

On failure `{"error": "...", "errorCode": 1001}` is written to stdout and the
process exits 1. A `-o` file is never touched by a failure, so tokens saved
there by an earlier run survive a failed re-login; stderr says so.
`passwordMode` is 1 for a single-password account and 2 for a two-password
account. `expiresAt` comes from Proton's reported lifetime, or from
`-expiry-fallback-hours` when Proton reports none. Lifetimes vary per session
(from 30 minutes to 24 hours were observed), so refresh with `refreshToken`
before `expiresAt` instead of assuming a fixed window.

### Non-interactive use

Supply the credentials through flags or environment variables; flags win.
When both the username and the password are supplied nothing is prompted for,
so a missing 2FA code or mailbox password is a fatal error with guidance
instead of a prompt.

| Flag | Environment | Meaning |
|------|-------------|---------|
| `-username` | `PROTON_AUTH_USERNAME` | Proton username or email |
| `-password` | `PROTON_AUTH_PASSWORD` | login password (see the note below) |
| `-password-stdin` | | read the password from the first line of stdin |
| `-totp` | `PROTON_AUTH_TOTP` | current 2FA code |
| `-totp-secret` | `PROTON_AUTH_TOTP_SECRET` | base32 2FA secret; codes are generated |
| `-mailbox-password` | `PROTON_AUTH_MAILBOX_PASSWORD` | second password of a two-password account |

```sh
# password from a secret store, never on the command line
pass show proton | proton-auth -username me@proton.me -password-stdin -totp-secret "$TOTP_SECRET"
```

**Keep passwords off the command line.** A `-password` argument is visible to
other users on the machine through the process list and lands in your shell
history. Use the environment variable, `-password-stdin`, or the prompt.

### Other flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-o PATH` | stdout | write the JSON result to this file, left with mode 0600 even if it existed; a failure leaves it untouched |
| `-captcha-auto-open` | `true` | open the browser when a CAPTCHA is required |
| `-captcha-timeout` | `10m` | how long to wait for the CAPTCHA to be solved |
| `-request-timeout` | `30s` | how long each request may wait for Proton's response headers; retries mean an unreachable host fails after a few multiples |
| `-captcha-test` | | open the CAPTCHA widget without logging in, to check the wiring, then exit |
| `-proxy URL` | | route the login and the CAPTCHA solve through this proxy |
| `-host-url URL` | production | Proton API base URL, for tests against a fake server |
| `-app-version` | rclone Drive client | `X-Pm-Appversion` header |
| `-user-agent` | desktop Chrome | `User-Agent` header |
| `-expiry-fallback-hours` | `12` | `expiresAt` margin when Proton reports no lifetime |
| `-version` | | print the version and exit |

Exit status is 0 on success and 1 on any failure, including a failure to write
the `-o` file. Ctrl-C at any prompt or during a CAPTCHA wait exits 1 with
`errorCode` 1011 and `"login cancelled: context canceled"`, after revoking a
session Proton had already issued; a second Ctrl-C ends the process at once.

### CAPTCHA on a headless host

The CAPTCHA needs a browser, but not on the same machine. The CLI prints the
local URL and port; forward the port and open the URL on your workstation:

```sh
ssh -L 43121:127.0.0.1:43121 user@host    # port from the CLI's output
```

Run `proton-auth -captcha-test` once to check that the local server and the
browser launch work before relying on it. It accepts the same
`-captcha-auto-open`, `-captcha-timeout` and `-proxy` flags as a real login.
To exercise the complete login-time flow instead, sign in with
`-app-version Other` (go-proton-api's default identity): Proton reliably
answers that client with a CAPTCHA demand, so the solve-and-retry path runs
against the real API.

## How the CAPTCHA solve works

1. Proton answers the SRP login with `Code=9001` carrying a
   `HumanVerificationToken` and the allowed methods. If `captcha` is among
   them, the library proceeds; otherwise it fails with `ErrCodeCaptcha` and
   the list of methods.
2. A server on `127.0.0.1:<random port>` serves a small wrapper page and
   reverse-proxies Proton's CAPTCHA endpoint, removing the
   `Content-Security-Policy` / `X-Frame-Options` headers that forbid framing it
   and rewriting cookies to session cookies for the local origin.
3. The wrapper page frames `/core/v4/captcha?Token=<HumanVerificationToken>`
   same-origin and listens for the widget's `pm_captcha` web message, exactly
   like Proton's own web client.
4. The solved token is posted back to the local server, the server shuts down,
   and the login is retried once with `X-Pm-Human-Verification-Token` set.

The solve is bounded by `CaptchaTimeout` (10 minutes by default) and by the
caller's context.

## Security considerations

- Every field of the result (tokens, UID, key password) unlocks the account.
  The CLI prints them to stdout; redirect or use `-o` accordingly.
- The local CAPTCHA server binds to loopback only, exists for one solve,
  rejects requests with a foreign `Host` (DNS rebinding) and token submissions
  with a foreign `Origin`, and does not persist cookies. Other processes
  running as you can reach it, as with any loopback service.
- Stripping Proton's framing protections is confined to that throwaway local
  context; nothing is proxied for anyone but the local browser.
- Nothing is written to disk by the library. The CLI writes only to the `-o`
  path you give it, and only on success.
- A login that fails after Proton has issued a session (a wrong mailbox
  password, a rejected 2FA code, a cancellation) revokes that session before
  returning, so nothing stays alive that nobody holds the tokens to.
- A malformed `ProxyURL` / `-proxy` is reported without echoing the URL, which
  may carry a password.

See [SECURITY.md](SECURITY.md) for the full notes and how to report issues.

## Client identity headers

go-proton-api does not set `X-Pm-Appversion` / `User-Agent` to values Proton's
servers expect from a web or desktop client, and the pair strongly affects how
often Proton demands a CAPTCHA. `DefaultAppVersion` therefore identifies the
client as rclone's Proton Drive backend (`macos-drive@1.0.0-alpha.1+rclone`)
and `DefaultUserAgent` as desktop Chrome. Both are configurable through
`Options` or the `-app-version` / `-user-agent` flags. You are presenting your
client to Proton as another one; make sure that is acceptable to you under
Proton's terms of service.

## Why the henrybear327 fork

The upstream `github.com/ProtonMail/go-proton-api` (v0.4.0 at the time of
writing) has no option to set the `User-Agent` header, which this library needs
for the reason above. The [henrybear327](https://github.com/henrybear327/go-proton-api)
fork adds `WithUserAgent` plus the Drive endpoints used by
[Proton-API-Bridge](https://github.com/henrybear327/Proton-API-Bridge) (the
lineage of rclone's Proton Drive backend) and by lumo-tamer, so consumers in
that family share one copy of the package. The auth, user and salt code this
library calls is identical to upstream.

The fork is a 2023 snapshot and is pinned by version. If it goes stale the
fallback is to vendor the `WithUserAgent` option onto upstream; nothing else
in this library depends on fork-only code. Because `Login` returns plain
strings, your module never has to import the fork itself.

## Error codes

`AuthError.Code` and the CLI's `errorCode` are stable; consumers may branch on
them.

| Code | Constant | Meaning |
|------|----------|---------|
| 1000 | (CLI only) | the CLI could not read the credentials |
| 1001 | `ErrCodeLogin` | Proton rejected the login: wrong credentials, abuse lock, or a protocol failure |
| 1002 | `ErrCode2FARequired` | account has 2FA but no usable TOTP code, secret or provider was supplied, or its second factor is not TOTP |
| 1003 | `ErrCode2FAFailed` | the supplied 2FA code was rejected |
| 1004 | `ErrCodeMailboxPasswordRequired` | two-password account, but no mailbox password was supplied |
| 1006 | `ErrCodeGetUser` | authenticated, but fetching the user failed |
| 1007 | `ErrCodeKeyPassword` | no primary key, fetching salts or deriving the key password failed, or the (mailbox) password does not unlock the primary key |
| 1008 | `ErrCodeInvalidInput` | no username or password, or a malformed `ProxyURL`; nothing was sent to Proton |
| 1009 | `ErrCodeCaptcha` | human verification demanded but not completed: no CAPTCHA offered, the solve timed out, or the token was not accepted |
| 1010 | `ErrCodeConnection` | Proton could not be reached (DNS, connect, TLS, proxy); the credentials were not judged |
| 1011 | `ErrCodeCancelled` | the context ended before the login completed (Ctrl-C in the CLI) |

1005 is unused. Codes are never renumbered or reused. `AuthError.Err` carries
the cause: `errors.Is(err, context.DeadlineExceeded)` tells a CAPTCHA timeout
from the other `ErrCodeCaptcha` cases, and `errors.As` reaches the
`*proton.APIError` or `*url.Error` behind the others.

## Development

```sh
go test -race ./...
make check        # what CI runs: tidy check, lint, race tests, govulncheck
```

The tests run offline against go-proton-api's development server; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the lint steps CI runs and the project
conventions. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE). The underlying go-proton-api and Proton's crypto libraries are
MIT as well, so importing this library places no licensing obligation on your
program beyond keeping the copyright notices.
