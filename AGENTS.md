# AGENTS.md

Guidance for AI coding agents working in this repository.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build, test and lint steps and
the conventions, and [README.md](README.md) for the contracts that must not
drift: the error codes, the CLI's JSON field names and exit status, and the
option names.

## Facts the code does not state

- Proton's production API demands a CAPTCHA on every login that identifies
  as `X-Pm-Appversion: Other`; the default identity usually gets none. Use
  `-app-version Other` to exercise the CAPTCHA path against the real API.
- Proton's reported token lifetime is exact and varied from 30 minutes to
  24 hours across accounts. Never assume a fixed window.
- The test suite runs offline against go-proton-api's development server. No
  test may open a browser or reach proton.me.
- `make check` runs what CI runs; golangci-lint is pinned in the Makefile and
  in `.github/workflows/ci.yml`, change both together.
