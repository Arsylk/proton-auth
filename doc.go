// Package protonauth performs Proton SRP authentication and transparently
// solves the CAPTCHA (human-verification, API Code=9001) challenge that blocks
// many headless and community Proton clients. It is an independent community
// project, not affiliated with or endorsed by Proton AG.
//
// It wraps ProtonMail's go-proton-api (through the henrybear327 fork, which
// adds the User-Agent option this package needs) and supplies the pieces that
// library leaves to the caller:
//
//   - SRP login with optional 2FA: a static TOTP code, a code generated from a
//     base32 secret, or a code supplied on demand through a callback;
//   - browser-assisted CAPTCHA solving: Proton's widget is reverse-proxied on
//     a throwaway 127.0.0.1 server so it frames same-origin, the solved token
//     is captured, and the login is retried with the verification header;
//   - optional routing of every Proton-facing request through one proxy, so
//     the login and the CAPTCHA solve share the IP the token was issued to.
//
// Login returns plain string tokens, so a caller does not have to import this
// module's go-proton-api fork. Callers already driving their own login against
// a different fork can call SolveCaptcha to obtain a verification token and
// inject it into their own retry. The bundled cmd/proton-auth exposes the same
// functionality as a binary with a stable JSON contract for non-Go consumers.
//
// Every error Login returns is a *AuthError. Use errors.As to reach its stable
// ErrCode, which separates Proton's verdict on the credentials (ErrCodeLogin)
// from an unsolved CAPTCHA, a connection failure, a cancelled context and
// unusable input, and, through Unwrap, the underlying go-proton-api, network
// or context error.
//
// The package keeps no state between calls, never stores credentials, revokes
// any session a failed login leaves behind, and writes nothing unless
// Options.Output or Options.OnCaptchaPrompt is set.
package protonauth
