# proton-auth

A small, auditable Go library and CLI that performs **Proton SRP login** and
transparently solves the **CAPTCHA** (human-verification, API `Code=9001`)
challenge that blocks many headless and community Proton clients.

It builds on ProtonMail's official [go-proton-api](https://github.com/ProtonMail/go-proton-api)
(via the [henrybear327](https://github.com/henrybear327/go-proton-api) fork) and adds only
the pieces go-proton-api leaves to the caller:

- SRP login with optional **2FA** (static TOTP code, auto-generated from a base32
  secret, or supplied on demand via a callback);
- **browser-assisted CAPTCHA solving**: Proton's widget is reverse-proxied on a
  throwaway `127.0.0.1` server so it frames same-origin, the solved token is
  captured, and the login is retried with the verification header attached;
- optional **proxy** routing so the login and the CAPTCHA solve exit from one IP
  (Proton binds the verification token to the issuing IP).

> This is extracted from [lumo-tamer](https://github.com/ZeroTricks/lumo-tamer).
> It only authenticates. It does not store credentials, and it holds no state
> between runs. The module path above is a placeholder until the repo is published.

## As a binary (any language)

```
go build -o proton-auth ./cmd/proton-auth
./proton-auth                 # interactive: prompts for username/password/2FA
```

It prints JSON to stdout (or the file given by `-o`). On success:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "uid": "...",
  "userID": "...",
  "keyPassword": "...",
  "expiresAt": "2026-01-01T00:00:00Z"
}
```

On failure: `{"error": "...", "errorCode": 1001}`. The process exits non-zero.

Non-interactive: set `-username`/`-password` (or `PROTON_AUTH_USERNAME` /
`PROTON_AUTH_PASSWORD`), plus `-totp`/`PROTON_AUTH_TOTP` or
`-totp-secret`/`PROTON_AUTH_TOTP_SECRET` for 2FA. For a two-password-mode
account, also set `-mailbox-password`/`PROTON_AUTH_MAILBOX_PASSWORD` (the second
password). Flags win over env. A CAPTCHA still needs a browser; the URL is
printed so you can forward the port from a headless host
(`ssh -L <port>:127.0.0.1:<port> <host>`).

The success JSON also carries `passwordMode` (1 = single, 2 = two-password).

`./proton-auth -captcha-test` opens the CAPTCHA widget without logging in, to
verify the local server and browser wiring.

## As a Go library (same go-proton-api fork)

```go
import protonauth "github.com/Arsylk/proton-auth"

res, err := protonauth.Login(ctx, protonauth.Options{
    CaptchaAutoOpen: true,
    Output:          os.Stderr, // nil = silent
}, protonauth.Credentials{Username: u, Password: p, TOTPSecret: secret})
// res.AccessToken, res.RefreshToken, res.UID, res.UserID, res.KeyPassword
// res.ExpiresIn is Proton's access-token lifetime in seconds (0 if unknown).
// res.PasswordMode is 1 (single) or 2 (two-password).
```

For a two-password account, set `Credentials.MailboxPassword` (the second
password), or `Credentials.MailboxPasswordProvider` to supply it on demand; on a
one-password account both are ignored and the login password unlocks the keys.

`Login` returns plain strings, so callers do not depend on this module's proton
fork for the result. The library writes nothing on its own; pass `Options.Output`
to receive the CAPTCHA instructions a user must act on. `ExpiresIn` is reported
exactly as Proton sends it, with no safety margin applied; derive your own
expiry and refresh policy from it.

## As a Go library (different go-proton-api fork)

If you already drive your own login against a different fork (e.g. rclone's
`github.com/rclone/go-proton-api`) and only need to get past the CAPTCHA, call
`SolveCaptcha` with the `HumanVerificationToken` from the `Code=9001` response
and inject the returned token into your retry:

```go
token, err := protonauth.SolveCaptcha(ctx, hvToken, account, true /*openBrowser*/, proxyURL, os.Stderr)
// retry login with header X-Pm-Human-Verification-Token: token
//                         X-Pm-Human-Verification-Token-Type: captcha
```

This path shares no Proton types across the module boundary.

## Error codes

| code | meaning |
|------|---------|
| 1001 | SRP login failed (bad credentials, CAPTCHA give-up, network) |
| 1002 | account has 2FA but no code/secret/provider was supplied |
| 1003 | the supplied 2FA code was rejected |
| 1004 | two-password account, but no mailbox password was supplied |
| 1006 | authenticated, but fetching the user failed |
| 1007 | fetching salts or deriving the key password failed |

(1000 is reserved for the CLI: failure to read interactive credentials.)
