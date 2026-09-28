#!/usr/bin/env bash
# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# sync-upstream.sh: bring a Go release's crypto/tls changes into tlsx.
#
#   scripts/sync-upstream.sh go1.27.2            # write the upstream diff, dry-run it
#   scripts/sync-upstream.sh latest              # the same for the latest stable Go
#   scripts/sync-upstream.sh go1.27.2 --apply    # merge it (conflict markers in files)
#
# The diff is between the base recorded in UPSTREAM.md and the new release,
# after the same mechanical rewrite on both sides (upstream-lib.sh), so it
# only conflicts where upstream touched lines tlsx changed. --apply merges
# each file three ways (git merge-file): tlsx's file, the rewritten base
# and the rewritten new release. Files upstream added are copied in; files
# upstream removed are removed when tlsx left them unchanged. testdata/ is
# taken from the new release.
#
# Toolchains come through GOTOOLCHAIN (the Go module proxy) unless they are
# in the module cache already.
#
# Output: the patch in upstream-<base>-<new>.patch at the repository root
# (git-ignored) and a Markdown summary on stdout, also written to
# $SYNC_SUMMARY when that is set (used by CI). Exit status: 0 no change or
# clean, 1 error, 2 conflicts or hunks that do not apply.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
. "$root/scripts/upstream-lib.sh"

new="${1:?usage: $0 goX.Y.Z|latest [--apply]}"
apply="${2:-}"
if [ "$new" = latest ]; then
	new="$(curl -fsSL 'https://go.dev/dl/?mode=json' | sed -n 's/.*"version": *"\(go[0-9.]*\)".*/\1/p' | head -1)"
	[ -n "$new" ] || { echo "could not read the latest Go release from go.dev/dl" >&2; exit 1; }
fi
base="$(sed -n 's/^Base: *\(go[0-9.]*\).*/\1/p' "$root/UPSTREAM.md" | head -1)"
[ -n "$base" ] || { echo "no 'Base: goX.Y.Z' line in UPSTREAM.md" >&2; exit 1; }

summary() { if [ -n "${SYNC_SUMMARY:-}" ]; then tee -a "$SYNC_SUMMARY"; else cat; fi; }

if [ "$base" = "$new" ]; then
	echo "tlsx is at $base, the requested release: nothing to do." | summary
	exit 0
fi

# The work directory (two extracted Go trees) is left in the system's
# temporary directory for inspection; nothing here deletes directories.
work="$(mktemp -d)"
echo "work directory: $work" >&2
extract "$(goroot "$base")" "$work/a"
extract "$(goroot "$new")" "$work/b"

patchfile="$root/upstream-$base-$new.patch"
(cd "$work" && diff -ruN a b) > "$patchfile" || true
if [ ! -s "$patchfile" ]; then
	rm -f "$patchfile"
	echo "No upstream change in the files tlsx carries between $base and $new." | summary
	exit 0
fi
hunks="$(grep -c '^@@' "$patchfile" || true)"
{
	echo "## Upstream sync $base -> $new"
	echo
	echo "Upstream diff: $hunks hunks in $(grep -c '^diff ' "$patchfile") files ($(basename "$patchfile"))."
	echo
} | summary

status=0
if [ "$apply" != "--apply" ]; then
	out="$( (cd "$root" && patch -p1 --dry-run --forward < "$patchfile") 2>&1 || true)"
	failed="$(printf '%s\n' "$out" | grep -E 'hunks? (FAILED|failed|ignored)' || true)"
	{
		echo "Dry run of \`patch -p1\`:"
		echo
		echo '```'
		printf '%s\n' "$out"
		echo '```'
	} | summary
	[ -z "$failed" ] || status=2
	exit "$status"
fi

conflicts=()
removed=()
added=()
(cd "$work/b" && find . -type f | sort) > "$work/files-b"
(cd "$work/a" && find . -type f | sort) > "$work/files-a"
while IFS= read -r rel; do
	rel="${rel#./}"
	ours="$root/$rel"
	case "$rel" in
	testdata/* | internal/bigmod/testdata/*)
		mkdir -p "$(dirname "$ours")"
		cp "$work/b/$rel" "$ours"
		continue ;;
	esac
	if [ ! -e "$work/a/$rel" ]; then
		if [ -e "$ours" ]; then
			cmp -s "$ours" "$work/b/$rel" || conflicts+=("$rel (upstream added a file tlsx already has)")
		else
			mkdir -p "$(dirname "$ours")"
			cp "$work/b/$rel" "$ours"
			added+=("$rel")
		fi
		continue
	fi
	if [ ! -e "$ours" ]; then
		conflicts+=("$rel (tlsx does not have this upstream file)")
		continue
	fi
	if ! git merge-file -L tlsx -L "$base" -L "$new" "$ours" "$work/a/$rel" "$work/b/$rel"; then
		conflicts+=("$rel")
	fi
done < "$work/files-b"
while IFS= read -r rel; do
	rel="${rel#./}"
	[ -e "$work/b/$rel" ] && continue
	ours="$root/$rel"
	[ -e "$ours" ] || continue
	if cmp -s "$ours" "$work/a/$rel"; then
		rm -- "$ours"
		removed+=("$rel")
	else
		conflicts+=("$rel (removed upstream, changed in tlsx)")
	fi
done < "$work/files-a"

{
	echo "Merged with \`git merge-file\`."
	echo
	[ ${#added[@]} -eq 0 ] || { echo "Added from upstream:"; printf -- '- %s\n' "${added[@]}"; echo; }
	[ ${#removed[@]} -eq 0 ] || { echo "Removed (gone upstream, unchanged in tlsx):"; printf -- '- %s\n' "${removed[@]}"; echo; }
	if [ ${#conflicts[@]} -eq 0 ]; then
		echo "No conflicts."
	else
		echo "Conflicts to resolve by hand (look for <<<<<<< tlsx):"
		printf -- '- %s\n' "${conflicts[@]}"
		status=2
	fi
	echo
	echo "Then: set 'Base: $new' in UPSTREAM.md, regenerate common_string.go (UPSTREAM.md),"
	echo "gofmt, go vet ./..., go test -race ./... (OpenSSL and GnuTLS interop run when installed),"
	echo "scripts/provenance.sh, and delete $(basename "$patchfile")."
} | summary
exit "$status"
