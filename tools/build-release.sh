#!/usr/bin/env bash
# Build the release tree <out>/magicauth/ from the allowlist (SPEC 4.9, 15 step 1).
# Used by the E2E suite (Playground mounts the tree) and for the release zip.
#
#   tools/build-release.sh [--src DIR] [--out DIR] [--zip]
#
#   --src DIR  plugin tree to package (default: this repo), e.g. a worktree of 1.0.5.
#   --out DIR  write DIR/magicauth/ (default: build/ in the repo). Only DIR/magicauth/
#              and, with --zip, DIR/magicauth-<version>.zip are replaced.
#   --zip      also write DIR/magicauth-<version>.zip (one top-level magicauth/ folder),
#              after compiling a .mo for every languages/*.po in the tree with msgfmt
#              (gettext; MSGFMT overrides the command). WordPress before 6.5 reads
#              only .mo, and the gitignored local copies may be stale or missing.
#
# Copies the working tree, so uncommitted changes are included. Fails when an
# allowlisted path is missing, when a vendor, tests, tools, node_modules or .git
# directory ends up in the tree, or when the vendored passkeys library ships
# without its LICENSE. Refuses an --out whose magicauth/ is, or contains, the
# source tree or this repo.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
root="$repo"
out="$repo/build"
want_zip=0

while [ $# -gt 0 ]; do
	case "$1" in
		--src)
			root="$(cd "${2:?--src needs a directory}" && pwd -P)"
			shift 2
			;;
		--out)
			out="${2:?--out needs a directory}"
			shift 2
			;;
		--zip)
			want_zip=1
			shift
			;;
		-h | --help)
			sed -n '2,19p' "$0"
			exit 0
			;;
		*)
			echo "build-release: unknown argument: $1" >&2
			exit 2
			;;
	esac
done

allowlist=(LICENSE assets includes languages magicauth.php readme.txt templates uninstall.php)

for item in "${allowlist[@]}"; do
	if [ ! -e "$root/$item" ]; then
		echo "build-release: missing allowlisted path: $item" >&2
		exit 1
	fi
done

mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
dest="$out/magicauth"

# rm -rf "$dest" must never reach a source tree: refuse when out is a source
# root, or dest is a source root or one of its ancestors. test -ef compares
# inodes, so case-insensitive file systems and symlinks are covered.
for src in "$root" "$repo"; do
	if [ "$out" -ef "$src" ]; then
		echo "build-release: refusing to build into a source tree root: $out" >&2
		exit 1
	fi
	p="$src"
	while :; do
		if [ "$p" -ef "$dest" ]; then
			echo "build-release: refusing to replace $dest, it is or contains the source tree $src" >&2
			exit 1
		fi
		[ "$p" = / ] && break
		p="$(dirname "$p")"
	done
done

rm -rf "$dest"
mkdir "$dest"
for item in "${allowlist[@]}"; do
	cp -R "$root/$item" "$dest/"
done

# OS and patch debris never ships.
find "$dest" \( -name '.DS_Store' -o -name '._*' -o -name '.gitkeep' -o -name '*.orig' -o -name '*.rej' \) -exec rm -f {} +

forbidden="$(find "$dest" -type d \( -iname vendor -o -name tests -o -name tools -o -name node_modules -o -name .git \) -print)"
if [ -n "$forbidden" ]; then
	echo "build-release: forbidden directories in the release tree:" >&2
	echo "$forbidden" >&2
	exit 1
fi

if [ -d "$dest/includes/ThirdParty/Passkeys" ] && [ ! -f "$dest/includes/ThirdParty/Passkeys/LICENSE" ]; then
	echo "build-release: includes/ThirdParty/Passkeys has no LICENSE" >&2
	exit 1
fi

version="$(sed -n 's/^ \* Version:[[:space:]]*//p' "$root/magicauth.php" | head -n 1 | tr -d '[:space:]')"
if [ -z "$version" ]; then
	echo "build-release: no Version header in magicauth.php" >&2
	exit 1
fi

if [ "$want_zip" -eq 1 ]; then
	zip_name="magicauth-$version.zip"
	rm -f "$out/$zip_name"
	msgfmt="${MSGFMT:-msgfmt}"
	for po in "$dest"/languages/*.po; do
		[ -f "$po" ] || continue
		if ! command -v "$msgfmt" > /dev/null 2>&1; then
			echo "build-release: msgfmt not found (install gettext); the zip needs a .mo per .po" >&2
			exit 1
		fi
		if ! "$msgfmt" -c -o "${po%.po}.mo" "$po"; then
			echo "build-release: msgfmt failed for languages/$(basename "$po")" >&2
			exit 1
		fi
	done
fi

echo "build-release: $dest (MagicAuth $version, $(find "$dest" -type f | wc -l | tr -d ' ') files)"

if [ "$want_zip" -eq 1 ]; then
	(cd "$out" && zip -rqX "$zip_name" magicauth)
	echo "build-release: $out/$zip_name"
fi
