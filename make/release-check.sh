#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Pre-release check without the full test suite (make test runs that):
#   - every code module builds and vets, with and without the edictadev tag;
#   - every tracked Go file is gofmt-clean;
#   - module hygiene (make/check-mods.sh);
#   - the guard tests: layering, module parity, import guards, doc links;
#   - the command line pin (test/clipin);
#   - the vector manifest;
#   - no Cyrillic in tracked text, no event wording, and no built binary
#     tracked.
# Every step runs; the script lists the failed ones and exits 1 if any did.
set -u
cd "$(dirname "$0")/.."
GO=${GO:-go}
export GOWORK=off

MODS=". plugins/celestia services/gate services/signer services/cli examples"

failed=""
step() {
	name=$1
	shift
	echo "== $name"
	if "$@"; then
		echo "ok   $name"
	else
		echo "FAIL $name"
		failed="$failed
  $name"
	fi
}

build_all() {
	rc=0
	for m in $MODS; do
		"$GO" -C "$m" build ./... || { echo "build failed: $m" >&2; rc=1; }
		"$GO" -C "$m" build -tags edictadev ./... || { echo "build -tags edictadev failed: $m" >&2; rc=1; }
	done
	return $rc
}

vet_all() {
	rc=0
	for m in $MODS; do
		"$GO" -C "$m" vet ./... || { echo "vet failed: $m" >&2; rc=1; }
		"$GO" -C "$m" vet -tags edictadev ./... || { echo "vet -tags edictadev failed: $m" >&2; rc=1; }
	done
	return $rc
}

gofmt_clean() {
	out=$(git ls-files -z '*.go' | xargs -0 gofmt -l) || return 1
	[ -z "$out" ] && return 0
	echo "not gofmt-clean:" >&2
	echo "$out" >&2
	return 1
}

guards() {
	"$GO" test -count=1 ./test/layering ./test/modparity ./test/importguard ./test/doclinks
}

clipin() {
	"$GO" test -count=1 -timeout 30m -tags clipin ./test/clipin
}

manifest() {
	shasum -a 256 -c --quiet spec/vectors/MANIFEST.sha256
}

# git grep exits 1 when nothing matches, 0 on a match, above 1 on an error.
none_of() {
	git grep -I -n "$@"
	rc=$?
	case $rc in
	1) return 0 ;;
	0) return 1 ;;
	*) echo "git grep failed ($rc)" >&2; return 1 ;;
	esac
}

no_cyrillic() {
	none_of -P '\p{Cyrillic}' -- ':!journal/'
}

# The bracket keeps this file from matching its own pattern.
no_event_wording() {
	none_of -i -E 'hack[a]thon|ship[y]ard'
}

tracked_binaries() {
	found=$(git ls-files -z | xargs -0 perl -e '
		for my $f (@ARGV) {
			next if -l $f || !-f $f;
			open(my $fh, "<", $f) or next;
			binmode $fh;
			read($fh, my $b, 4);
			close $fh;
			print "$f\n" if $b =~ /^(\x7fELF|\xfe\xed\xfa[\xce\xcf]|[\xce\xcf]\xfa\xed\xfe|\xca\xfe\xba\xbe|MZ)/;
		}') || return 1
	[ -z "$found" ] && return 0
	echo "built binaries tracked:" >&2
	echo "$found" >&2
	return 1
}

step "build (plain and edictadev)" build_all
step "vet (plain and edictadev)" vet_all
step "gofmt" gofmt_clean
step "check-mods" make/check-mods.sh
step "guards: layering, modparity, importguard, doclinks" guards
step "command line pin" clipin
step "vector manifest" manifest
step "no Cyrillic" no_cyrillic
step "no event wording" no_event_wording
step "no tracked binaries" tracked_binaries

if [ -n "$failed" ]; then
	echo "release-check FAILED:$failed"
	exit 1
fi
echo "release-check passed"
