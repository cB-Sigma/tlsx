#!/usr/bin/env bash
# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# sync-upstream.sh: bring a Go release into tlsx as a git merge of Go's own
# history (UPSTREAM.md).
#
#   scripts/sync-upstream.sh [options] goX.Y.Z|latest
#   scripts/sync-upstream.sh [options] --continue   # after resolving conflicts
#
# Options:
#   --go-repo DIR   clone of https://go.googlesource.com/go (default:
#                   $TLSX_GO_REPO, else go-upstream next to this repository)
#   --no-fetch      do not fetch the Go clone first
#   --no-test       skip the checks at the end
#
# Steps, on the current branch (normally main), with a clean working tree:
#   1. Fetch the Go clone (tags included).
#   2. Filter Go's history with scripts/filter-upstream.sh for the base tag
#      (UPSTREAM.md's "Base:") and the new one. The filtered base must be
#      the commit tlsx already has as upstream/<base>: the filter is
#      deterministic, so a different ID means the filter or Go's history
#      changed, and the sync stops. The new tag is fetched as
#      upstream/<new>.
#   3. git merge upstream/<new>. A conflicted file is retried three ways
#      on rewritten texts: tlsx's side as is, the old release (upstream/<base>)
#      and the new one, both rewritten. That settles conflicts caused by the
#      rewrite, and those between release branches (Go's backports appear on
#      both sides); a file tlsx never changed simply becomes the new
#      release's. Files tlsx does not carry stay deleted. What is left keeps
#      conflict markers: resolve, git add, and run again with --continue.
#   4. Commit the mechanical rewrite (upstream-lib.sh) of the files upstream
#      changed on its own, titled "mechanical: ...". Merge Go's changes to
#      the files tlsx carries as copies (the BoGo shim, UPSTREAM_COPIED) and
#      commit them apart; a conflict there is left for a hand update and
#      reported. Then commit the record:
#      "Base:" in UPSTREAM.md, docs/upstream-commit-map.txt, PROVENANCE.md,
#      and the rewrite commit's ID appended to .git-blame-ignore-revs (so
#      git blame passes over it to Go's commits).
#   5. gofmt, go vet, go test -race (OpenSSL and GnuTLS interop run when
#      installed, unless TLSX_SKIP_INTEROP=1), provenance check. Tests use
#      GOTOOLCHAIN=<new> unless GOTOOLCHAIN is set.
#
# Still by hand afterwards: regenerate common_string.go when upstream
# changed common.go's constants (UPSTREAM.md), bump go.mod's go line when
# the release needs it, and add a CHANGELOG entry.
#
# A Markdown summary goes to stdout, and to $SYNC_SUMMARY when set (CI).
# Exit status: 0 done, 1 error, 2 conflicts left, 3 checks failed.
# Work directories (the filtered repository, rewritten texts) are left in
# the system's temporary directory; nothing here deletes directories.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
. "$root/scripts/upstream-lib.sh"
cd "$root"

gorepo="${TLSX_GO_REPO:-$(dirname "$root")/go-upstream}"
fetch=1 test=1 cont=0 new=""
while [ $# -gt 0 ]; do
	case "$1" in
	--go-repo) gorepo="$2"; shift ;;
	--no-fetch) fetch=0 ;;
	--no-test) test=0 ;;
	--continue) cont=1 ;;
	go1.* | latest) new="$1" ;;
	*) echo "usage: $0 [--go-repo DIR] [--no-fetch] [--no-test] goX.Y.Z|latest|--continue" >&2; exit 1 ;;
	esac
	shift
done

summary() { if [ -n "${SYNC_SUMMARY:-}" ]; then tee -a "$SYNC_SUMMARY"; else cat; fi; }
state="$(git rev-parse --git-path tlsx-sync)"
map=docs/upstream-commit-map.txt

base="$(sed -n 's/^Base: *\(go[0-9.]*\).*/\1/p' UPSTREAM.md | head -1)"
[ -n "$base" ] || { echo "no 'Base: goX.Y.Z' line in UPSTREAM.md" >&2; exit 1; }

# finish: steps 4 and 5, once the merge is committed.
finish() {
	local new="$1" work="$2" f changed=() mech=""
	while IFS= read -r f; do changed+=("$f"); done < <(git diff --name-only "upstream/$base" "upstream/$new")
	# 4a. The mechanical rewrite, alone in its commit, so that
	# .git-blame-ignore-revs can pass over it.
	rewrite "$root" "${changed[@]+"${changed[@]}"}"
	git add -u
	if git diff --cached --quiet; then
		echo "Nothing to rewrite." | summary
	else
		git commit -q -m "mechanical: rewrite Go-internal imports in Go $new's changes (no functional change)" \
			-m "The rewrite of scripts/upstream-lib.sh, applied by scripts/sync-upstream.sh to the files upstream changed between $base and $new. This commit authors no code: the lines it touches are Go's code by The Go Authors, edited only by the script. It is listed in .git-blame-ignore-revs."
		mech="$(git rev-parse HEAD)"
		echo "Rewrite committed: $(git log -1 --format='%h %s')" | summary
	fi
	# 4b. The files carried as copies, outside the filtered history.
	sync_copied "$new"
	# 4c. The record of the sync.
	sed "s/^Base: *go[0-9.]*/Base: $new/" UPSTREAM.md > UPSTREAM.md.sync && mv UPSTREAM.md.sync UPSTREAM.md
	mkdir -p "$(dirname "$map")"
	commit_map "$work" "upstream/$new" > "$map.sync" && mv "$map.sync" "$map"
	[ -z "$mech" ] || printf '# mechanical: rewrite of Go %s'"'"'s changes\n%s\n' "$new" "$mech" >> .git-blame-ignore-revs
	scripts/provenance.sh || echo "warning: scripts/provenance.sh failed; regenerate PROVENANCE.md by hand" >&2
	git add -u
	git add -- "$map" .git-blame-ignore-revs
	git commit -q -m "tlsx: record the sync to Go $new" \
		-m "scripts/sync-upstream.sh: the Base line in UPSTREAM.md, the commit map, PROVENANCE.md and .git-blame-ignore-revs."
	echo "Record committed: $(git log -1 --format='%h %s')" | summary
	: > "$state" # no sync in progress
	[ "$test" = 1 ] || return 0
	checks "$new"
}

# sync_copied NEW: merge Go's changes between the base release and NEW
# into the files tlsx carries as copies, on rewritten texts, and commit
# them. A conflicted file is left as it is; the merge with conflict markers
# is kept in a temporary directory and reported.
sync_copied() {
	local new="$1" f tmp merged=() conflicted=()
	tmp="$(mktemp -d)"
	mkdir -p "$tmp/b" "$tmp/n" "$tmp/o"
	for f in "${UPSTREAM_COPIED[@]}"; do
		git -C "$gorepo" cat-file blob "$base:src/crypto/tls/$f" > "$tmp/b/$f" 2> /dev/null || continue
		if ! git -C "$gorepo" cat-file blob "$new:src/crypto/tls/$f" > "$tmp/n/$f" 2> /dev/null; then
			conflicted+=("$f (removed in Go $new)")
			continue
		fi
		cmp -s "$tmp/b/$f" "$tmp/n/$f" && continue
		rewrite "$tmp/b" "$f"
		rewrite "$tmp/n" "$f"
		cp -- "$f" "$tmp/o/$f"
		if git merge-file -L tlsx -L "$base" -L "$new" "$tmp/o/$f" "$tmp/b/$f" "$tmp/n/$f"; then
			cmp -s "$tmp/o/$f" "$f" && continue # tlsx already has the change
			cp -- "$tmp/o/$f" "$f"
			git add -- "$f"
			merged+=("$f")
		else
			conflicted+=("$f (merge with conflict markers: $tmp/o/$f)")
		fi
	done
	if [ ${#merged[@]} -gt 0 ]; then
		git commit -q -m "tlsx: merge Go $new's changes to the BoGo files copied from Go" \
			-m "These files are Go's, Copyright The Go Authors (BSD-3-Clause), carried as copies outside the filtered history (UPSTREAM.md). scripts/sync-upstream.sh merged the changes between Go $base and $new: ${merged[*]}."
		echo "Copied BoGo files updated: ${merged[*]}" | summary
	fi
	if [ ${#conflicted[@]} -gt 0 ]; then
		{ echo "Copied files to update by hand:"; printf -- '- %s\n' "${conflicted[@]}"; } | summary
	fi
}

checks() {
	local tc="${GOTOOLCHAIN:-$1}" status=0 out report
	report="$(mktemp)"
	# A brace group with a redirection runs in this shell, so status sticks.
	{
		echo
		echo "### Checks (GOTOOLCHAIN=$tc)"
		echo
		echo '```'
		out="$(git ls-files -z '*.go' | xargs -0 gofmt -l 2>&1)"
		if [ -n "$out" ]; then printf 'gofmt: FAILED\n%s\n' "$out"; status=3; else echo "gofmt: ok"; fi
		if out="$(GOTOOLCHAIN="$tc" go vet ./... 2>&1)"; then echo "go vet: ok"; else
			printf 'go vet: FAILED\n%s\n' "$(printf '%s\n' "$out" | tail -n 40)"; status=3; fi
		if out="$(GOTOOLCHAIN="$tc" go test -race -count=1 -timeout 20m ./... 2>&1)"; then echo "go test -race: ok"; else
			echo "go test -race: FAILED"; status=3; fi
		printf '%s\n' "$out" | tail -n 40
		if out="$(scripts/provenance.sh --check 2>&1)"; then echo "provenance: ok"; else
			printf 'provenance: FAILED\n%s\n' "$(printf '%s\n' "$out" | tail -n 20)"; status=3; fi
		echo '```'
	} > "$report"
	summary < "$report"
	return "$status"
}

# commit_map WORK REF: Go commit and tlsx commit, oldest first, for every
# upstream commit reachable from REF, merged with the existing map.
commit_map() {
	local work="$1" ref="$2"
	{
		[ -e "$map" ] && grep -v '^#' "$map"
		awk 'NR > 1 && $2 !~ /^0+$/ { print $2, $1 }' "$work/filter-repo/commit-map" | sort > "$work/new-to-old"
		git -C "$work" rev-list --reverse --topo-order "refs/tags/$ref" |
			awk 'NR == FNR { go[$1] = $2; next } { print go[$1], $1 }' "$work/new-to-old" -
	} | awk '!seen[$0]++' > "$work/map.body"
	echo "# Go commit (go.googlesource.com/go) -> tlsx commit, oldest first."
	echo "# Written by scripts/sync-upstream.sh from git filter-repo's commit-map;"
	echo "# the filter is scripts/filter-upstream.sh (UPSTREAM.md)."
	cat "$work/map.body"
}

if [ "$cont" = 1 ]; then
	[ -s "$state" ] || { echo "no sync in progress ($state)" >&2; exit 1; }
	read -r base new work < "$state"
	if [ -n "$(git diff --name-only --diff-filter=U)" ]; then
		echo "unmerged files remain:" >&2; git diff --name-only --diff-filter=U >&2; exit 2
	fi
	if git rev-parse -q --verify MERGE_HEAD > /dev/null; then
		git commit -q --no-edit
	fi
	finish "$new" "$work"
	exit $?
fi

[ -n "$new" ] || { echo "usage: $0 [options] goX.Y.Z|latest|--continue" >&2; exit 1; }
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "the working tree has changes; commit or stash them first" >&2; exit 1; }
[ -d "$gorepo" ] || { echo "no Go clone at $gorepo (--go-repo, TLSX_GO_REPO)" >&2; exit 1; }

# 1. Fetch Go.
if [ "$fetch" = 1 ]; then
	git -C "$gorepo" fetch -q --tags origin
fi
if [ "$new" = latest ]; then
	new="$(git -C "$gorepo" tag -l 'go1.*' | grep -E '^go1\.[0-9]+(\.[0-9]+)?$' |
		awk -F. '{ printf "%d %d %s\n", $2, ($3 == "" ? 0 : $3), $0 }' | sort -n -k1,1 -k2,2 | tail -1 | cut -d' ' -f3)"
fi
if [ "$base" = "$new" ]; then
	echo "tlsx is at $base, the requested release: nothing to do." | summary
	exit 0
fi
git -C "$gorepo" rev-parse -q --verify "refs/tags/$new" > /dev/null || { echo "no tag $new in $gorepo" >&2; exit 1; }

# 2. Filter, check determinism, fetch.
tmp="$(mktemp -d)"
work="$tmp/filtered"
echo "work directory: $tmp" >&2
"$root/scripts/filter-upstream.sh" "$gorepo" "$work" "$base" "$new" > "$tmp/filter.log" 2>&1 ||
	{ tail -n 20 "$tmp/filter.log" >&2; echo "filter-upstream.sh failed" >&2; exit 1; }
have="$(git rev-parse -q --verify "refs/tags/upstream/$base^{commit}" || true)"
got="$(git -C "$work" rev-parse "refs/tags/upstream/$base^{commit}")"
if [ "$have" != "$got" ]; then
	echo "Determinism check failed: upstream/$base is ${have:-missing} here, the filter gives $got." | summary
	exit 1
fi
git fetch -q "$work" "refs/tags/upstream/$new:refs/tags/upstream/$new"
{
	echo "## Upstream sync $base -> $new"
	echo
	echo "Filtered upstream/$base reproduces $have (deterministic)."
	echo "upstream/$new is $(git rev-parse --short "upstream/$new"): $(git rev-list --count "upstream/$base..upstream/$new") upstream commits not in $base."
	echo
} | summary
echo "$base $new $work" > "$state"

# 3. Merge.
if git merge -q --no-ff --no-edit -m "tlsx: merge Go $new" "upstream/$new" > "$tmp/merge.log" 2>&1; then
	echo "Merged without conflicts." | summary
else
	resolved=() left=()
	while IFS= read -r f; do
		s1="$(git ls-files -u -- "$f" | awk '$3 == 1 { print $2 }')"
		s2="$(git ls-files -u -- "$f" | awk '$3 == 2 { print $2 }')"
		s3="$(git ls-files -u -- "$f" | awk '$3 == 3 { print $2 }')"
		if [ -z "$s2" ] && [ -n "$s3" ]; then
			git rm -q --cached -- "$f"
			[ ! -e "$f" ] || mv -- "$f" "$tmp/dropped.$(basename "$f")"
			resolved+=("$f (not carried by tlsx: kept deleted)")
			continue
		fi
		mkdir -p "$tmp/b/$(dirname "$f")" "$tmp/n/$(dirname "$f")" "$tmp/o/$(dirname "$f")"
		# The base of the retry is the old release itself, not the merge
		# base: between release branches (go1.26.x to go1.27.y) Go's
		# backports sit on both sides, and the difference between the two
		# releases is what tlsx needs (as the patch-based sync did).
		if git cat-file -e "upstream/$base:$f" 2> /dev/null; then git cat-file blob "upstream/$base:$f" > "$tmp/b/$f"
		elif [ -n "$s1" ]; then git cat-file blob "$s1" > "$tmp/b/$f"; else : > "$tmp/b/$f"; fi
		if [ -n "$s3" ]; then git cat-file blob "$s3" > "$tmp/n/$f"; else : > "$tmp/n/$f"; fi
		if [ -n "$s2" ]; then git cat-file blob "$s2" > "$tmp/o/$f"; else : > "$tmp/o/$f"; fi
		rewrite "$tmp/b" "$f"
		rewrite "$tmp/n" "$f"
		if [ -z "$s3" ] && cmp -s "$tmp/o/$f" "$tmp/b/$f"; then
			git rm -q -- "$f"
			resolved+=("$f (removed upstream, unchanged in tlsx)")
		elif [ -n "$s3" ] && git merge-file -L tlsx -L "$base" -L "$new" "$tmp/o/$f" "$tmp/b/$f" "$tmp/n/$f"; then
			cp "$tmp/o/$f" "$f"
			git add -- "$f"
			resolved+=("$f")
		else
			[ -z "$s3" ] || cp "$tmp/o/$f" "$f"
			left+=("$f")
		fi
	done < <(git diff --name-only --diff-filter=U)
	{
		[ ${#resolved[@]} -eq 0 ] || { echo "Conflicts settled on the rewritten texts:"; printf -- '- %s\n' "${resolved[@]}"; echo; }
	} | summary
	if [ ${#left[@]} -gt 0 ]; then
		{
			echo "Conflicts to resolve by hand (look for <<<<<<< tlsx), then git add and"
			echo "\`scripts/sync-upstream.sh --continue\`:"
			printf -- '- %s\n' "${left[@]}"
		} | summary
		exit 2
	fi
	git commit -q --no-edit
	echo "Merge committed: $(git log -1 --format='%h %s')" | summary
fi

# 4 and 5.
finish "$new" "$work"
