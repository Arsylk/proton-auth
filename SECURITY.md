# Security

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/Arsylk/proton-auth/security/advisories/new)
rather than a public issue. You should get an acknowledgement within a week.
Fixes ship as a new patch release with a note in `CHANGELOG.md`; credit is
given unless you ask otherwise.

## What this software handles

`protonauth.Login` receives a Proton username, password, optionally a TOTP
secret and a mailbox password, and returns session tokens plus the derived key
password. Every field of `Result` unlocks the account and must be treated as a
secret by the caller. The library keeps nothing between calls and writes
nothing to disk; the CLI writes the result only where you tell it to (stdout,
or a file it leaves with mode 0600 even when the file already existed with a
looser mode), and never touches that file on a failure, so a saved result is
not replaced by an error object.

A login that fails after Proton has issued a session (a wrong mailbox
password, a rejected 2FA code, a cancelled context) revokes that session
before returning, best effort and within a few seconds: the caller never sees
its tokens, so nothing should stay alive under them.

Error messages never echo `Options.ProxyURL` / `-proxy`, which may carry a
password; a malformed value, which is often one whose password broke the
parser, is reported as "invalid proxy URL" with the parser's reason only.

## The local CAPTCHA server

When Proton demands a CAPTCHA, the library starts a throwaway HTTP server on
`127.0.0.1` with a random port and reverse-proxies Proton's widget through it,
stripping Proton's `Content-Security-Policy` and `X-Frame-Options` headers so
the widget can be framed by the local page. Mitigations in place:

- The server binds to the loopback interface only and lives for the duration
  of one solve (at most `CaptchaTimeout`, 10 minutes by default).
- Requests must carry the server's own `Host`, defeating DNS rebinding from a
  page that resolves a public name to 127.0.0.1.
- The `/submit` endpoint that receives the solved token rejects any request
  with a foreign `Origin`, so another page open in the browser cannot inject a
  token.
- Cookies set by Proton through the proxy are rewritten to session cookies
  without `Domain`, so they do not persist for other local servers.
- The local page embeds the `HumanVerificationToken` for the pending login.
  It is single-purpose and short-lived, and useless without the password.

Other software running as the same user on the same machine can reach the
server, as with any loopback service. This is the same trust boundary as the
browser session itself.

## Credentials on the command line

`proton-auth -password ...` exposes the password to other local users through
the process list and to your shell history. Prefer `PROTON_AUTH_PASSWORD`,
`-password-stdin`, or the interactive prompt.

## Headers sent to Proton

By default the client identifies itself with `DefaultAppVersion` and
`DefaultUserAgent`, which name rclone's Proton Drive client. Both are
configurable. Using an alternative client is your responsibility under
Proton's terms of service.
