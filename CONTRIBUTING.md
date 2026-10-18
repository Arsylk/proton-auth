# Contributing

Thanks for your interest. This is a small, security-sensitive library, so the
bar is "boring and well-tested" rather than "feature-rich".

## Development

Requires Go 1.26 or newer.

```sh
go build ./...
go vet ./...
go test -race ./...
```

The test suite runs entirely offline: it drives `Login` against
go-proton-api's development server, with a small interception layer in
`auth_test.go` that adds CAPTCHA challenges, 2FA and two-password mode. No
Proton account is needed, and no test opens a browser.

CI additionally runs `go mod tidy -diff`, `go mod verify`, `golangci-lint`
(config in `.golangci.yml`, version pinned in the workflow and the Makefile)
and `govulncheck`, and tests on Go 1.26 and the current release across Linux,
macOS and Windows. `make check` runs the same steps locally:

```sh
make check        # tidy-check, lint, race tests, govulncheck
make lint         # golangci-lint only
make fmt          # gofmt and goimports through golangci-lint
```

## Conventions

- Import the go-proton-api fork as `proton` everywhere
  (`proton "github.com/henrybear327/go-proton-api"`).
- The library never writes to stdout/stderr on its own and never stores
  anything. User-facing text goes through `Options.Output`; structured events
  through `Options.OnCaptchaPrompt`.
- Library code must not know about CLI flags. The CLI is a thin layer over the
  library in `cmd/proton-auth`; CAPTCHA mechanics live in `internal/captcha`.
- Error codes (`ErrCode*`) and the CLI's JSON field names are a stable
  contract. Add new codes rather than renumbering, and never reuse a retired
  one.
- Anything that changes the public API gets a line in `CHANGELOG.md`.

## Pull requests

1. Open an issue first for anything beyond a small fix, so the approach can be
   agreed before you spend time on it.
2. Keep PRs focused. Tests go in the same PR as the change.
3. Make sure `go test -race ./...` and the lint steps above pass.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities.
