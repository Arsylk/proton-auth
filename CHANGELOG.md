# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until 1.0.0 the Go API may still
change between minor versions; such changes are called out below.

## [0.1.0] - 2026-10-18

First public release, under the MIT license. The project grew out of the Go
login helper in [lumo-tamer](https://github.com/ZeroTricks/lumo-tamer) and
keeps that helper's CLI contract (the JSON fields and the error codes); the
notes below say what changed relative to it, for anyone moving over. They are
not breaking changes of a released version of this module, since there was
none.

### Added

- `Options.RequestTimeout` / `CaptchaOptions.RequestTimeout` and the exported
  `DefaultRequestTimeout` (30 seconds): every request to Proton now waits a
  bounded time for its response headers, so an unreachable or stalled API
  fails with `ErrCodeConnection` instead of hanging a login whose context
  has no deadline. The CLI exposes it as `-request-timeout`.
- `PasswordModeUnknown`, the explicit zero value of `PasswordMode`.
- `SolveCaptcha` returns the same `*AuthError` values as `Login`
  (`ErrCodeInvalidInput`, `ErrCodeCancelled`, `ErrCodeCaptcha`) instead of
  untyped errors.
- `ErrCodeInvalidInput`, `ErrCodeCaptcha`, `ErrCodeConnection` and
  `ErrCodeCancelled` (1008 to 1011), so a consumer can tell Proton's verdict on
  the credentials (`ErrCodeLogin`) from an unsolved CAPTCHA, an unreachable
  API, a cancelled context and a caller error. All of these were
  `ErrCodeLogin` before.
- `Login` revokes the session Proton has already issued when a later step
  fails (a rejected 2FA code, a wrong mailbox password, a failed user or salt
  fetch, a cancellation), best effort within five seconds, instead of leaving
  it alive with tokens nobody holds.
- `Credentials.TOTPProvider` and `MailboxPasswordProvider` receive `Login`'s
  `context.Context`; a provider that returns the context's error makes `Login`
  fail with `ErrCodeCancelled` rather than `ErrCode2FARequired`.
- A retried login that Proton answers with another human-verification demand
  (the solved token was not accepted, typically because it was solved from a
  different IP) fails with `ErrCodeCaptcha` and says so.
- `Options.OnCaptchaPrompt` and `CaptchaOptions.OnPrompt`: a structured hook
  that receives the solver page's URL, port and account label, for callers
  that render the CAPTCHA prompt themselves instead of parsing `Output`.
- `Options.CaptchaTimeout` / `CaptchaOptions.Timeout` and the exported
  `DefaultCaptchaTimeout` (10 minutes). The solve previously had a fixed limit.
- `Options.HostURL` to point the login at a non-default API host (used by the
  test suite against go-proton-api's development server).
- `Login` verifies the derived key password by unlocking the account's primary
  key, so a wrong mailbox password on a two-password account fails immediately
  with `ErrCodeKeyPassword` instead of yielding a key password that only fails
  in whatever consumes it.
- `AuthError.Err` with `Unwrap`, so `errors.As` reaches the underlying
  `*proton.APIError` or `*url.Error` and `errors.Is` sees
  `context.DeadlineExceeded` or `context.Canceled`.
- `ErrCode` type (with `String`) for the stable error codes, and the
  `PasswordMode` type with `PasswordModeOne` / `PasswordModeTwo`.
- CLI: `-password-stdin` (read the password from stdin without prompting),
  `-captcha-timeout`, `-version`, and a non-TTY fallback so prompts work when
  stdin is a pipe. Ctrl-C cancels cleanly at every prompt and during a CAPTCHA
  wait; a second Ctrl-C ends the process at once.
- End-to-end tests of `Login` against go-proton-api's development server,
  including the CAPTCHA retry, CAPTCHA followed by 2FA, 2FA, two-password
  mode, session revocation, and the login and CAPTCHA widget both leaving
  through `ProxyURL`; runnable examples on pkg.go.dev; CI, lint, vulnerability
  scanning and release automation.

### Changed

- `SolveCaptcha` takes `(ctx, hvToken, CaptchaOptions)` instead of six
  positional arguments.
- `RunCaptchaTest` is not part of the library. The smoke check lives in the
  CLI (`proton-auth -captcha-test`).
- `AuthError.Code` is an `ErrCode` and `Result.PasswordMode` is a
  `PasswordMode`. The numeric values are unchanged.
- Only the TOTP bit of Proton's 2FA status triggers the TOTP step. An account
  whose sole second factor is a security key fails with `ErrCode2FARequired`
  naming the reason instead of being asked for a code.
- The login and its CAPTCHA solve share one transport (and one proxy
  connection pool), which `Login` releases when it returns.
- A malformed `TOTPSecret` fails with `ErrCode2FARequired` and a message
  naming the secret, instead of a generic "2FA required".
- The library does not write go-proton-api's resty error lines to stderr;
  every failure is returned through `AuthError` instead.
- A wrong-credentials failure (`ErrCodeLogin`) carries Proton's own message
  (for example "This email address does not exist") plus a short hint, instead
  of a fixed "Incorrect password (or username)".
- CLI: a failure never touches the `-o` file. The error JSON goes to stdout
  and, when `-o` was given, a line to stderr as well. Previously the file was
  overwritten with the error object, destroying a result saved by an earlier
  run.
- CLI: `-captcha-test` honours `-captcha-auto-open`, `-captcha-timeout` and
  `-proxy`, so the wiring can be checked on a headless host too.
- A failed attempt to open the browser automatically is reported on `Output`
  instead of being silent.
- The CLI exits 1 when the `-o` file cannot be written; it previously printed
  the error and exited 0 with the tokens lost.
- Error messages and comments do not name CLI flags, and the solver page does
  not carry the branding of the project this grew out of.
- Dependencies updated; this clears the reachable GO-2026-4550 advisory in
  `github.com/cloudflare/circl`. The module requires Go 1.26.

### Fixed

- A connection that dies while the login response body is being read now
  fails with `ErrCodeConnection` and the read error, instead of a misleading
  JSON decode error.
- The `-o` file is left with mode 0600 even when it already existed with a
  looser mode; before, the mode of an existing file was kept.
- A malformed `ProxyURL` / `-proxy` was echoed in the error message, and so in
  `AuthError.Message` and the CLI's JSON, although the URL may carry a
  password (a password that breaks parsing being the usual cause). The URL is
  no longer quoted, and the failure is `ErrCodeInvalidInput`.
- The solver page could report "Could not deliver the token" although the
  token had arrived: the local server was closed before the `/submit`
  response had been flushed. The response is now complete on the wire before
  the token is handed over.
- `Login` left its idle connections open: go-proton-api's `Manager.Close`
  relies on the transport forwarding `CloseIdleConnections`, which the
  wrapping transports did not do, and the shared `http.DefaultTransport` was
  used instead of one the login owns.
- `Login` no longer panics on an account without a primary key; it returns
  `ErrCodeKeyPassword`.
- Replacing `http.DefaultTransport` with a non-`*http.Transport` no longer
  panics the proxy setup.
- The CAPTCHA solver no longer leaks the browser launcher's output (Chromium
  derivatives log child-process noise on stderr) or the widget proxy's
  "proxy error: context canceled" line into the caller's output.

[0.1.0]: https://github.com/Arsylk/proton-auth/releases/tag/v0.1.0
