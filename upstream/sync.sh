#!/usr/bin/env bash
# upstream/sync.sh - keep the mirrored copy of Go's crypto/tls in sync.
#
# The directories listed in upstream/files.txt are copies of Go standard
# library sources ("upstream-owned"). They are produced mechanically:
#
#   pristine(version) = copy files.txt dirs from $GOROOT/src of that Go
#                       version, minus exclude.txt, with imports.txt rewrites.
#
# The committed tree is pristine(upstream/VERSION) plus the small "[uTLS]"
# hunks recorded in upstream/utls.patch, plus uTLS-owned u_*.go files.
#
# Commands:
#   sync.sh pristine <goversion> <outdir>  write pristine(goversion) to outdir
#   sync.sh update <goversion>             rebase the mirror onto a new Go
#                                          release with a per-file 3-way merge
#   sync.sh diff                           print the [uTLS] patch: the diff
#                                          between pristine(VERSION) and the tree
#   sync.sh check                          fail if upstream/utls.patch is stale
#
# <goversion> is a Go release name such as go1.27.0. Sources come from the
# active toolchain when it matches, otherwise from the golang.org/toolchain
# module on the Go module proxy (no git access to go.googlesource.com needed).
#
# See docs/UPSTREAM_SYNC.md for the full procedure.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
UP="$ROOT/upstream"
MODULE=$(sed -n 's/^module[[:space:]]\{1,\}//p' "$ROOT/go.mod")

die() { echo "sync.sh: $*" >&2; exit 1; }

# goroot_src prints the GOROOT/src directory for the given Go release.
goroot_src() {
	local v=$1 gr dir
	gr=$(go env GOROOT)
	if [ "$(head -n1 "$gr/VERSION" 2>/dev/null)" = "$v" ]; then
		echo "$gr/src"
		return
	fi
	# Sources are identical for every GOOS/GOARCH; linux-amd64 is always published.
	dir=$(cd "$(mktemp -d)" && GOFLAGS= GO111MODULE=on GOTOOLCHAIN=local \
		go mod download -json "golang.org/toolchain@v0.0.1-$v.linux-amd64" |
		sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
	[ -n "$dir" ] && [ -d "$dir/src" ] || die "cannot download sources for $v"
	echo "$dir/src"
}

# config_lines prints non-comment, non-empty lines of an upstream/*.txt file.
config_lines() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$UP/$1"; }

is_excluded() { config_lines exclude.txt | awk '{print $1}' | grep -qxF "$1"; }

# rewrite_imports edits a .go file in place according to imports.txt.
rewrite_imports() {
	local f=$1 old new
	while read -r old new; do
		new=${new//@MODULE@/$MODULE}
		# Only touch import specs: optional name, the quoted path, end of line.
		sed -i -E "s#^([[:space:]]*(import[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*[[:space:]]+)?)\"${old//./\\.}\"([[:space:]]*)\$#\1\"$new\"\4#" "$f"
	done < <(config_lines imports.txt)
}

# pristine <goversion> <outdir>
pristine() {
	local v=$1 out=$2 src updir local mode f base
	src=$(goroot_src "$v")
	mkdir -p "$out"
	while read -r updir local mode; do
		mkdir -p "$out/$local"
		for f in "$src/$updir"/*; do
			[ -f "$f" ] || continue
			base=$(basename "$f")
			case "$mode" in
			go) [[ "$base" == *.go ]] || continue ;;
			all) ;;
			*) die "bad mode $mode in files.txt" ;;
			esac
			is_excluded "$local/$base" && continue
			cp "$f" "$out/$local/$base"
			[[ "$base" == *.go ]] && rewrite_imports "$out/$local/$base"
		done
	done < <(config_lines files.txt)
}

# mirrored_files <tree> lists mirrored file paths (relative) present in tree,
# excluding uTLS-owned u_*.go files.
mirrored_files() {
	local tree=$1 updir local mode
	while read -r updir local mode; do
		[ -d "$tree/$local" ] || continue
		find "$tree/$local" -maxdepth 1 -type f ! -name 'u_*' -printf "$local/%f\n"
	done < <(config_lines files.txt) | sort
}

cmd_diff() {
	local tmp f
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN
	pristine "$(cat "$UP/VERSION")" "$tmp/a"
	{ mirrored_files "$tmp/a"; mirrored_files "$ROOT"; } | sort -u | while read -r f; do
		# Show added/removed mirrored files too, so nothing slips through.
		(cd "$tmp/a" && [ -e "$f" ] || exit 0; true)
		diff -u --label "a/$f" --label "b/$f" \
			"$( [ -e "$tmp/a/$f" ] && echo "$tmp/a/$f" || echo /dev/null)" \
			"$( [ -e "$ROOT/$f" ] && echo "$ROOT/$f" || echo /dev/null)" || true
	done
}

cmd_check() {
	local tmp
	tmp=$(mktemp)
	cmd_diff > "$tmp"
	if ! cmp -s "$tmp" "$UP/utls.patch"; then
		diff -u "$UP/utls.patch" "$tmp" | head -n 80 >&2 || true
		rm -f "$tmp"
		die "upstream/utls.patch is stale: run 'upstream/sync.sh diff > upstream/utls.patch' and review the change"
	fi
	rm -f "$tmp"
	echo "upstream/utls.patch is up to date ($(cat "$UP/VERSION"))"
}

cmd_update() {
	local new=$1 old tmp f conflicts=0 added=0 removed=0
	old=$(cat "$UP/VERSION")
	[ "$old" != "$new" ] || die "already at $new"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN
	echo "pristine $old ..."
	pristine "$old" "$tmp/old"
	echo "pristine $new ..."
	pristine "$new" "$tmp/new"

	while read -r f; do
		local o="$tmp/old/$f" n="$tmp/new/$f" l="$ROOT/$f"
		if [ -e "$n" ] && [ ! -e "$o" ]; then
			if [ -e "$l" ]; then
				echo "CONFLICT (add/add): $f exists locally and was added upstream" >&2
				conflicts=$((conflicts + 1))
			else
				mkdir -p "$(dirname "$l")"
				cp "$n" "$l"
				added=$((added + 1))
				echo "added    $f"
			fi
		elif [ -e "$o" ] && [ ! -e "$n" ]; then
			if [ ! -e "$l" ]; then
				continue
			elif cmp -s "$o" "$l"; then
				rm "$l"
				removed=$((removed + 1))
				echo "removed  $f"
			else
				echo "CONFLICT (modify/delete): $f was deleted upstream but carries [uTLS] hunks" >&2
				conflicts=$((conflicts + 1))
			fi
		elif [ -e "$o" ] && [ -e "$n" ] && [ -e "$l" ]; then
			cmp -s "$o" "$n" && continue
			if ! git merge-file -L "uTLS" -L "$old" -L "$new" "$l" "$o" "$n"; then
				echo "CONFLICT (content): $f" >&2
				conflicts=$((conflicts + 1))
			else
				echo "merged   $f"
			fi
		fi
	done < <({ mirrored_files "$tmp/old"; mirrored_files "$tmp/new"; } | sort -u)

	echo "$new" > "$UP/VERSION"
	echo
	echo "upstream $old -> $new: $added added, $removed removed, $conflicts conflict(s)"
	if [ "$conflicts" -gt 0 ]; then
		echo "Resolve the conflict markers, then follow docs/UPSTREAM_SYNC.md." >&2
		return 1
	fi
	echo "Next: go build ./... && go test ./..., then 'upstream/sync.sh diff > upstream/utls.patch'."
}

case "${1:-}" in
pristine) [ $# -eq 3 ] || die "usage: sync.sh pristine <goversion> <outdir>"; pristine "$2" "$3" ;;
update) [ $# -eq 2 ] || die "usage: sync.sh update <goversion>"; cmd_update "$2" ;;
diff) cmd_diff ;;
check) cmd_check ;;
*) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
