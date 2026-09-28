# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately. Don't open a public issue for them.

- **Preferred:** GitHub private vulnerability reporting. Open the
  repository's **Security** tab and choose **Report a vulnerability**. This
  creates a private security advisory that only the maintainers can see.
- **Email:** abhinav@codebuckets.in, with "tlsx security" in the subject.

Include the tlsx version or commit, the Go version, and a description or
reproducer. You will get an answer within 7 days. Fixes are released as new
tlsx versions with a GitHub security advisory. Reporters are credited
unless they prefer not to be.

## Scope

- **Vulnerabilities in tlsx's additions** (files `x_*.go`, `internal/`
  packages written for tlsx, the `// tlsx` hooks): report them here.
- **Vulnerabilities in code tlsx carries unchanged from Go's crypto/tls**:
  report them to the Go project (https://go.dev/security/policy). Go's
  fixes reach tlsx through an upstream sync (UPSTREAM.md); tlsx releases a
  new version when a Go security release changes crypto/tls. If you aren't
  sure which applies, report here and we will forward it.

## Supported versions

Only the latest tlsx release is supported. It tracks the latest Go
release; see the `Base:` line in UPSTREAM.md.
