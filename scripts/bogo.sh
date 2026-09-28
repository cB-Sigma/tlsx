#!/usr/bin/env bash
# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# bogo.sh: run BoringSSL's BoGo TLS conformance suite against tlsx.
#
#   scripts/bogo.sh [options]
#
# Options:
#   --local-dir DIR  use (or git clone into) a BoringSSL checkout at DIR
#                    instead of the module cache
#   --filter GLOB    run only the BoGo tests matching GLOB
#   --report FILE    write BoGo's HTML report to FILE
#   --summary FILE   write the results as JSON to FILE (default:
#                    bogo-summary.json in the system's temporary directory)
#
# The shim is Go's bogo_shim_test.go with tlsx's flags (x_bogo_test.go).
# BoringSSL is fetched at the revision the shim pins (boringsslModVer),
# with "go mod download" through GOPROXY, or with git for --local-dir;
# nothing of BoringSSL is kept in this repository. The expected failures
# are Go's bogo_config.json plus tlsx's bogo_config_tlsx.json.
# Exit status: that of go test (0: no unexpected result).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
args=()
summary=""
while [ $# -gt 0 ]; do
	case "$1" in
	--local-dir) args+=("-bogo-local-dir=$2"); shift ;;
	--filter) args+=("-bogo-filter=$2"); shift ;;
	--report) args+=("-bogo-html-report=$2"); shift ;;
	--summary) summary="$2"; shift ;;
	*) echo "usage: $0 [--local-dir DIR] [--filter GLOB] [--report FILE] [--summary FILE]" >&2; exit 1 ;;
	esac
	shift
done
[ -n "$summary" ] || summary="${TMPDIR:-/tmp}/bogo-summary.json"
args+=("-bogo-tlsx-summary=$summary")

log="$(mktemp)"
cd "$root"
status=0
TLSX_BOGO=1 go test -run '^TestBogoSuite$' -count=1 -v -timeout 60m . -args "${args[@]}" > "$log" 2>&1 || status=$?

# Unexpected failures, then the counts the test logged.
grep -E -e '^    --- FAIL' "$log" || true
grep -E -e 'bogo_shim_test.go:[0-9]+: (bogo failed|failed)' -e 'but passed: remove it' "$log" || true
grep -E -e 'BoGo v[0-9]' "$log" | sed 's/^ *x_bogo_test.go:[0-9]*: //' || true
echo "results: $summary"
echo "log: $log"
[ "$status" -eq 0 ] && echo "BoGo: ok" || echo "BoGo: FAILED (go test exit $status)"
exit "$status"
