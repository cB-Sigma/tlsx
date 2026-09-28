# Contributing to tlsx

Thank you for helping. tlsx is a fork of Go's crypto/tls. Most of its code
is Go's, and keeping it easy to sync with Go comes first.

## Ground rules

- **Licence.** Contributions are accepted under the BSD-3-Clause licence of
  this repository (LICENSE). By sending a pull request you confirm that you
  wrote the change, or have the right to contribute it under that licence.
- **Provenance.**
  - Say where every piece of code, data or text comes from.
  - Don't copy code from other projects unless their licence allows it in a
    BSD-3-Clause project. When you do, keep their notice, name the source in
    NOTICE and add the file to `scripts/provenance-notes.tsv`.
  - Test vectors from standards are welcome; cite the document and section
    where they are used.
  - Don't paste text from standards documents.
- **No endorsement wording.** Don't write anything that suggests the Go
  project, The Go Authors or Google endorse tlsx.

## Where changes go

- **New features.** Put them in files named `x_*.go`, or under `internal/`.
  - Keep changes to Go's files (the ones without the `x_` prefix) to small
    hooks.
  - Mark each changed line with `// tlsx`.
  - A Go file you change for the first time gets the line
    `// Changes for tlsx: Copyright <year> <you> (see NOTICE)` under Go's
    header. Never change Go's header itself.
- **Fixes to Go's code.** Report them to Go first
  (https://go.dev/issue); tlsx picks them up with the next sync. A security
  fix that can't wait goes into tlsx as a marked hook, with a link to the
  upstream issue.
- **Upstream syncs.** Follow UPSTREAM.md.
- **Blame.** Go's lines keep their Go authors in `git blame` once you run
  `git config blame.ignoreRevsFile .git-blame-ignore-revs` (GitHub does this
  by itself). Keep mechanical rewrites in commits of their own, titled
  `mechanical: ...`, and add them to `.git-blame-ignore-revs`; the sync
  script does this for its rewrite commits.

## Before sending a pull request

```
gofmt -l .
go vet ./...
go test -race ./...
scripts/provenance.sh
```

- **Interoperability tests.** The OpenSSL and GnuTLS tests run when
  OpenSSL 3 and GnuTLS are on PATH. Add an interoperability test for each
  new protocol feature that another implementation supports. Say in the
  README's Verification section how the feature is checked.
- **Tests.** New behaviour needs tests that fail without the change.
- **Commit messages.** Use a plain sentence about the behaviour, prefixed
  by the area, for example `psk: refuse identities longer than 65535 bytes`.
