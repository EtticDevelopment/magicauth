#!/usr/bin/env bash
# Produce includes/ThirdParty/Passkeys from the upstream commit pinned in UPSTREAM (SPEC 4.9).
# This script is the only way that directory is made; never edit it by hand.
#
#   tools/passkeys-php/vendor.sh [--check] [--src DIR] [--out DIR [--upto N]]
#
#   --check    rebuild into a temp dir and diff -r against includes/ThirdParty/Passkeys;
#              exit 1 on any difference (CI job vendored-library).
#   --src DIR  use an existing git clone of the upstream repo instead of fetching URL.
#              COMMIT and the src/ TREE hash are verified either way.
#   --out DIR  write the tree to DIR (must not exist) instead of includes/ThirdParty/Passkeys.
#   --upto N   with --out: apply only the first N patches (to rebase a patch after an update).
#
# Steps: fetch the pinned commit, verify COMMIT and TREE, export src/, LICENSE and NOTICE.md;
# R0 (namespace MagicAuth\ThirdParty\Passkeys, delete the five require_once lines of
# WebAuthn.php, insert the ABSPATH guard after each namespace line); apply patches/*.patch in
# order (patch -p1 --forward --fuzz=0; any reject or backup file fails); php -l every file;
# write VENDORED.md (pin, patch list with reasons, Plugin Check record, sha256 per file).
# Needs bash, git, tar, perl, patch, diff and php (PHP=... selects the binary).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd "$here/../.." && pwd -P)"
target="$repo/includes/ThirdParty/Passkeys"
php="${PHP:-php}"

mode=write
src=""
out=""
upto=""

die() {
	echo "vendor.sh: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
		--check)
			mode=check
			shift
			;;
		--src)
			src="$(cd "${2:?--src needs a directory}" && pwd -P)"
			shift 2
			;;
		--out)
			out="${2:?--out needs a directory}"
			shift 2
			;;
		--upto)
			upto="${2:?--upto needs a number}"
			shift 2
			;;
		-h | --help)
			sed -n '2,18p' "$0"
			exit 0
			;;
		*)
			echo "vendor.sh: unknown argument: $1" >&2
			exit 2
			;;
	esac
done

if [ -n "$upto" ]; then
	[ -n "$out" ] || die "--upto needs --out (a partial tree is never installed)"
	case "$upto" in
		'' | *[!0-9]*) die "--upto needs a number" ;;
	esac
fi
if [ "$mode" = check ] && [ -n "$out" ]; then
	die "--check and --out cannot be combined"
fi
if [ -n "$out" ] && [ -e "$out" ]; then
	die "--out $out already exists"
fi

# UPSTREAM is KEY=VALUE data; read, never sourced.
pin() {
	local value
	value="$(sed -n "s/^$1=//p" "$here/UPSTREAM" | head -n 1)"
	[ -n "$value" ] || die "UPSTREAM has no $1"
	printf '%s' "$value"
}
url="$(pin URL)"
tag="$(pin TAG)"
commit="$(pin COMMIT)"
tree="$(pin TREE)"
date="$(pin DATE)"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "UPSTREAM COMMIT is not a 40-hex SHA"
[[ "$tree" =~ ^[0-9a-f]{40}$ ]] || die "UPSTREAM TREE is not a 40-hex SHA"
[[ "$url" =~ ^https:// ]] || die "UPSTREAM URL must be https"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/passkeys-php.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# 1. Pinned commit, verified.
if [ -n "$src" ]; then
	git_dir="$src"
else
	git_dir="$tmp/upstream"
	git init -q "$git_dir"
	if ! git -C "$git_dir" fetch -q --depth 1 "$url" "$commit" 2>/dev/null; then
		git -C "$git_dir" fetch -q "$url" '+refs/tags/*:refs/tags/*' || die "cannot fetch $url"
	fi
fi
got="$(git -C "$git_dir" rev-parse --verify --quiet "$commit^{commit}" || true)"
[ "$got" = "$commit" ] || die "commit $commit not found in $git_dir"
got="$(git -C "$git_dir" rev-parse --verify --quiet "$commit:src" || true)"
[ "$got" = "$tree" ] || die "src/ tree of $commit is ${got:-missing}, UPSTREAM pins $tree"

# 2. Export (from the commit, never a working tree).
mkdir "$tmp/export"
git -C "$git_dir" archive --format=tar "$commit" src LICENSE NOTICE.md | tar -xf - -C "$tmp/export"
stage="$tmp/Passkeys"
mkdir "$stage"
cp -R "$tmp/export/src/." "$stage/"
cp "$tmp/export/LICENSE" "$tmp/export/NOTICE.md" "$stage/"

expected="Attestation/AttestationObject.php
Attestation/AuthenticatorData.php
Binary/ByteBuffer.php
CBOR/CborDecoder.php
WebAuthn.php
WebAuthnException.php"
got="$(cd "$stage" && find . -type f -name '*.php' | sed 's|^\./||' | LC_ALL=C sort)"
[ "$got" = "$expected" ] || die "upstream src/ file set changed; review it and update vendor.sh:
$got"

# 3. R0, mechanical.
php_files=()
while IFS= read -r f; do
	php_files+=("$stage/$f")
done <<< "$expected"

lines_before="$(wc -l < "$stage/WebAuthn.php")"
perl -ni -e 'print unless /^require_once \x27[A-Za-z\/]+\.php\x27;\s*$/' "$stage/WebAuthn.php"
lines_after="$(wc -l < "$stage/WebAuthn.php")"
[ $((lines_before - lines_after)) -eq 5 ] || die "R0 expected to delete 5 require_once lines, deleted $((lines_before - lines_after))"

for f in "${php_files[@]}"; do
	perl -pi -e 's/\bReportUri\\Passkeys\b/MagicAuth\\ThirdParty\\Passkeys/g' "$f"
	[ "$(grep -c '^namespace [A-Za-z\\]*;[[:space:]]*$' "$f")" -eq 1 ] || die "R0: expected one namespace line in $f"
	perl -pi -e 'if (/^namespace [A-Za-z\\]+;\s*$/) { $_ .= "defined( \x27ABSPATH\x27 ) || exit;\n" }' "$f"
	if grep -n 'ReportUri' "$f" >&2; then
		die "R0: ReportUri left in $f"
	fi
	if grep -nE '^[[:space:]]*(require|include)(_once)?[[:space:](]' "$f" >&2; then
		die "R0: require/include left in $f"
	fi
done

# 4. Patches, in order.
patches=()
for p in "$here"/patches/[0-9][0-9][0-9][0-9]-*.patch; do
	[ -e "$p" ] && patches+=("$p")
done
[ "${#patches[@]}" -gt 0 ] || [ -n "$upto" ] || die "no patches in $here/patches"
applied=0
for p in ${patches[@]+"${patches[@]}"}; do
	if [ -n "$upto" ] && [ "$applied" -ge "$upto" ]; then
		break
	fi
	if ! (cd "$stage" && patch -p1 --forward --batch --fuzz=0 --silent < "$p"); then
		die "patch failed: $(basename "$p")"
	fi
	debris="$(find "$stage" \( -name '*.orig' -o -name '*.rej' \) -print)"
	[ -z "$debris" ] || die "patch $(basename "$p") did not apply cleanly: $debris"
	applied=$((applied + 1))
done

# 5. Lint.
for f in "${php_files[@]}"; do
	"$php" -l "$f" > /dev/null || die "php -l failed: $f"
done

# 6. VENDORED.md.
{
	echo "# Vendored library: report-uri/passkeys-php"
	echo
	echo "Generated by \`tools/passkeys-php/vendor.sh\` (SPEC 4.9). Never edit this directory by hand:"
	echo "\`tools/passkeys-php/vendor.sh --check\` (CI job \`vendored-library\`) fails on any difference."
	echo
	echo "| | |"
	echo "|---|---|"
	echo "| Upstream | $url |"
	echo "| Tag | $tag |"
	echo "| Commit | \`$commit\` |"
	echo "| \`src/\` tree | \`$tree\` |"
	echo "| Vendored | $date |"
	echo "| Namespace | \`MagicAuth\\ThirdParty\\Passkeys\` (upstream \`ReportUri\\Passkeys\`) |"
	echo "| License | MIT, \`LICENSE\` and \`NOTICE.md\` copied unchanged |"
	echo
	echo "## R0 (mechanical, in vendor.sh)"
	echo
	echo "- Namespace \`ReportUri\\Passkeys\` renamed to \`MagicAuth\\ThirdParty\\Passkeys\` in every PHP file."
	echo "- The five \`require_once\` lines of \`WebAuthn.php\` deleted (the plugin autoloader loads the classes;"
	echo "  top-level code fails Plugin Check)."
	echo "- \`defined( 'ABSPATH' ) || exit;\` inserted after each \`namespace\` line."
	echo
	echo "## Patches (\`patch -p1 --forward --fuzz=0\`, in this order)"
	echo
	n=0
	for p in ${patches[@]+"${patches[@]}"}; do
		if [ -n "$upto" ] && [ "$n" -ge "$upto" ]; then
			break
		fi
		subject="$(sed -n 's/^Subject: //p' "$p" | head -n 1)"
		reason="$(sed -n 's/^Reason: //p' "$p" | head -n 1)"
		[ -n "$subject" ] && [ -n "$reason" ] || die "$(basename "$p") needs Subject: and Reason: header lines"
		echo "- \`$(basename "$p")\`: $subject. $reason"
		n=$((n + 1))
	done
	echo
	echo "## Plugin Check"
	echo
	if [ -f "$here/PLUGIN-CHECK.md" ]; then
		cat "$here/PLUGIN-CHECK.md"
	else
		echo "Not recorded."
	fi
	echo
	echo "## SHA-256"
	echo
	echo "| File | sha256 |"
	echo "|---|---|"
	(cd "$stage" && find . -type f ! -name VENDORED.md | sed 's|^\./||' | LC_ALL=C sort) | while IFS= read -r f; do
		echo "| \`$f\` | \`$("$php" -r 'echo hash_file( "sha256", $argv[1] );' "$stage/$f")\` |"
	done
} > "$stage/VENDORED.md"

# 7. Install, compare or hand out.
if [ "$mode" = check ]; then
	[ -d "$target" ] || die "--check: $target does not exist"
	if ! diff -r -x .DS_Store "$stage" "$target" >&2; then
		die "--check: includes/ThirdParty/Passkeys differs from a fresh build of $tag ($commit)"
	fi
	echo "vendor.sh --check: includes/ThirdParty/Passkeys matches $tag ($commit) plus ${#patches[@]} patches"
	exit 0
fi

if [ -n "$out" ]; then
	mkdir -p "$(dirname "$out")"
	mv "$stage" "$out"
	echo "vendor.sh: wrote $out ($applied of ${#patches[@]} patches)"
	exit 0
fi

mkdir -p "$(dirname "$target")"
rm -rf "$target.new"
mv "$stage" "$target.new"
rm -rf "$target"
mv "$target.new" "$target"
echo "vendor.sh: wrote includes/ThirdParty/Passkeys from $tag ($commit) plus ${#patches[@]} patches"
