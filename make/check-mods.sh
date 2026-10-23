#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Module hygiene of the code modules (the vector generators are independent
# on purpose; only their tidiness is checked):
#   - the root go.mod has no replace;
#   - every in-repo require of a nested module is v0.0.0 with a relative
#     replace to its directory, the root one included;
#   - nothing requires the examples module;
#   - no go.work file is tracked;
#   - go mod tidy leaves every go.mod and go.sum unchanged, the vector
#     generator modules under spec/vectors/tools included.
# The fork replace block is compared across the heavy modules by
# test/modparity, which the check-mods target runs too.
set -eu
cd "$(dirname "$0")/.."
GO=${GO:-go}
export GOWORK=off

ROOT=github.com/vgonkivs/edicta
NESTED="plugins/celestia services/gate services/signer services/cli examples"
fail=0
err() { echo "check-mods: $*" >&2; fail=1; }

if grep -Eq '^[[:space:]]*replace([[:space:]]|\()' go.mod; then
	err "go.mod: the root module must not carry replace directives"
fi

for m in $NESTED; do
	up=$(echo "$m" | awk -F/ '{ s = ""; for (i = 0; i < NF; i++) s = s "../"; print s }')
	grep -qx "replace $ROOT => $up" "$m/go.mod" || err "$m/go.mod: missing replace $ROOT => $up"
	# In-repo requires: "<path> <version>" inside or outside a require block.
	sed -n -E "s#^[[:space:]]*(require[[:space:]]+)?($ROOT(/[^[:space:]]+)?)[[:space:]]+(v[^[:space:]]+).*#\2 \4#p" "$m/go.mod" |
	while read -r path ver; do
		[ "$ver" = v0.0.0 ] || { echo "check-mods: $m/go.mod: $path must be required at v0.0.0, not $ver" >&2; echo x; continue; }
		rel=${path#"$ROOT"}
		rel=${rel#/}
		grep -qx "replace $path => $up$rel" "$m/go.mod" ||
			{ echo "check-mods: $m/go.mod: missing replace $path => $up$rel" >&2; echo x; }
	done | grep -q x && fail=1
done

for f in $(git ls-files '*go.mod'); do
	[ "$f" = examples/go.mod ] && continue
	if grep -Eq "^[[:space:]]*(require[[:space:]]+)?$ROOT/examples[[:space:]]+v" "$f"; then
		err "$f requires the examples module; nothing may"
	fi
done

if git ls-files | grep -Eq '(^|/)go\.work(\.sum)?$'; then
	err "a go.work file is tracked"
fi

GENERATORS=$(git ls-files 'spec/vectors/tools/*/go.mod' | xargs -n1 dirname)
for m in . $NESTED $GENERATORS; do
	"$GO" -C "$m" mod tidy -diff >/dev/null || err "$m: go mod tidy would change go.mod or go.sum (go -C $m mod tidy -diff)"
done

exit $fail
